import json
import os
import re

import httpx
import requests
from authlib.integrations.base_client.errors import OAuthError
from authlib.jose import JsonWebKey, jwt
from authlib.jose.errors import BadSignatureError, DecodeError, InvalidTokenError
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749.errors import InvalidClientError, InvalidGrantError
from requests import RequestException

### Params

MAX_TOKEN_LEN = 16_384
_DEFAULT_SECRETS_PATH = "./client_secrets.json"

ACCESS_MODE_AUTHENTICATED = "authenticated"
ACCESS_MODE_READ_ONLY = "read_only"
ACCESS_MODE_OPEN = "open"

_ORCID_HTTPS_PREFIX = "https://orcid.org/"
_ORCID_HTTP_PREFIX = "http://orcid.org/"

### Exceptions

class MissingParameterError(Exception):
    """Raised when a required request parameter is missing."""

class AuthError(Exception):
    """Base exception for dataone-auth"""
    pass

class InsufficientScopeError(AuthError):
    """Raised when the token is valid but doesn't have the right scope"""
    pass

class TokenExtractionError(ValueError):
    """Raised when the Authorization header is missing or malformed."""
    pass

### Helpers

def load_client_secrets(filepath: str | None = None) -> dict:
    """Load client secrets from a JSON file.

    Args:
        filepath: Optional explicit path. Falls back to the
                    ``OIDC_CLIENT_SECRETS_FILE`` environment variable

    Returns:
        Parsed dict of client credentials.
    """
    # accept either explicit filepath argument or environment variable, with a default
    #  fallback
    resolved = (
        filepath
        or os.getenv("OIDC_CLIENT_SECRETS_FILE")
        or _DEFAULT_SECRETS_PATH
    )
    with open(resolved) as f:
        return json.load(f)

def extract_token_from_header(auth_header: str):
    """Extracts and validates a Bearer token. Raises ValueError on failure."""
   
    if not auth_header:
        raise TokenExtractionError("Missing Authorization header")

    if not auth_header.startswith("Bearer "):
        raise TokenExtractionError(
            "Invalid Authorization header format. Expected 'Bearer <token>'"
            )

    token = auth_header[7:].strip()
    
    if not token:
        raise TokenExtractionError("Token is empty")
        
    # Check JWT structure
    if token.count('.') != 2:
        raise TokenExtractionError("Token is malformed (invalid JWT structure)")

    # DoS protection
    if len(token) > MAX_TOKEN_LEN:
        raise TokenExtractionError("Token exceeds maximum allowed length")
    
    return token

def extract_orcid(claims: dict | None) -> str | None:
    """Extract a normalised ORCID iD URI from JWT claims.

    Reads the ``orcid`` claim.  The returned value is always the canonical
    HTTPS URI form (``https://orcid.org/XXXX-XXXX-XXXX-XXXX``).

    Args:
        claims: Decoded JWT claims dict, or ``None``.

    Returns:
        Canonical ORCID URI (e.g. ``"https://orcid.org/0000-0002-1825-0097"``),
        or ``None`` if the ``orcid`` claim is absent or malformed.
    """
    if not claims:
        return None

    raw = claims.get("orcid")

    if not raw or not isinstance(raw, str):
        return None

    # Strip http(s)://orcid.org/ prefix, leaving just the bare ID
    if raw.startswith(_ORCID_HTTPS_PREFIX):
        bare = raw[len(_ORCID_HTTPS_PREFIX):]
    elif raw.startswith(_ORCID_HTTP_PREFIX):
        bare = raw[len(_ORCID_HTTP_PREFIX):]
    else:
        bare = raw

    # Validate: XXXX-XXXX-XXXX-XXXX where the last character may be X (checksum digit)
    if not re.fullmatch(r"\d{4}-\d{4}-\d{4}-\d{3}[0-9X]", bare):
        return None

    return _ORCID_HTTPS_PREFIX + bare

def get_access_mode() -> str:
    """Get the current access mode from environment.
    
    Returns:
        str: One of 'read_only', 'open', or 'authenticated'. Defaults to 
        'authenticated'.
    """
    mode = os.getenv("ACCESS_MODE", "authenticated").lower()
    if mode not in (ACCESS_MODE_READ_ONLY, ACCESS_MODE_OPEN, ACCESS_MODE_AUTHENTICATED):
        return ACCESS_MODE_AUTHENTICATED
    return mode

### Factory

class AuthFactory:

    _registry = {
        "flask": "dataone.auth.FlaskAuthAdapter",
        "fastapi": "dataone.auth.FastAPIAuthAdapter",
        "starlette": "dataone.auth.FastAPIAuthAdapter",
    }

    @classmethod
    def create_client(cls, framework: str, secrets: dict, scopes: list):
        import_path = cls._registry.get(framework.lower())
        if not import_path:
            raise ValueError(f"Unsupported framework: {framework}")
            
        module_path, class_name = import_path.rsplit(".", 1)
        module = __import__(module_path, fromlist=[class_name])
        AdapterClass = getattr(module, class_name)
        
        return AdapterClass(secrets=secrets, scopes=scopes)

class BaseAuthAdapter:

    DEFAULT_PROVIDER_NAME = "dataone_oidc"
    DEFAULT_SCOPES = "openid email profile"

    def __init__(self, secrets, scopes):
        self.secrets = secrets
        self.scopes = scopes
        self.oauth = self._initialize_oauth()
        self._setup_providers()

    def _initialize_oauth(self):
        raise NotImplementedError

    def _setup_providers(self):

        base_scopes = self.DEFAULT_SCOPES.split()
        scope_request = " ".join(dict.fromkeys(base_scopes + self.scopes))

        self.oauth.register(
            name=self.DEFAULT_PROVIDER_NAME,
            client_id=self.secrets.get("client_id"),
            client_secret=self.secrets.get("client_secret"),
            server_metadata_url=self.secrets.get("server_metadata_url"),
            client_kwargs={"scope": scope_request}, 
    )

    ERROR_MAP = {
        TokenExtractionError: ("Invalid token or header", 401),
        DecodeError: ("Token decoding failed", 401),
        InvalidClientError: ("OIDC client authentication failed", 401),
        InvalidTokenError: ("Token validation failed", 401),
        InvalidGrantError: ("Invalid or expired refresh token", 401),
        BadSignatureError: ("Token signature verification failed", 401),
        OAuthError: ("Authorization failed", 401),
        OAuth2Error: ("An OAuth2 error occurred", 401),
        KeyError: ("Invalid token structure", 401),
        TypeError: ("Invalid token structure", 401),
        MissingParameterError: ("Missing required parameter", 400),
        ValueError: ("OIDC provider configuration error", 500),
        RequestException: ("Failed to fetch OIDC provider keys", 502),
    }

    def _resolve_error(self, exc: Exception):
        """Logic to determine message and status from an exception."""
        # Check for specific Authlib errors (handle imports or strings)
        for exc_type, (msg, code) in self.ERROR_MAP.items():
            # Parentheses let us wrap this logic across lines cleanly
            is_match = (
                isinstance(exc, exc_type) if not isinstance(exc_type, str) 
                else type(exc).__name__ == exc_type
            )
            
            if is_match:
                return msg, code
                
        return "Internal authentication error", 500

    def error_handler(self, exc: Exception):
        """This will be implemented by subclasses."""
        raise NotImplementedError

    def token_response(self, token: dict, message: str):
        """This will be implemented by subclasses."""
        raise NotImplementedError

    def get_jwks_keys(self):
        """Fetch and cache the JWKS signing keys from the OIDC provider.

        These keys are used to validate JWT token signatures. Care must be taken to 
        fetch them only from trustworthy sources (via the OIDC provider's metadata 
        endpoint over HTTPS). The keys may change periodically, so the cache will be
        invalidated and keys will be refetched on the next call after the application
        is restarted.

        Returns:
            authlib.jose.JsonWebKey: A ``JsonWebKeySet`` ready for ``jwt.decode``.

        Raises:
            ValueError: If the OIDC server metadata does not expose a ``jwks_uri``.
            requests.RequestException: If errors while fetching the JWKS.
        """

        if hasattr(self, '_cached_jwks'):
            return self._cached_jwks

        provider = getattr(self.oauth, self.DEFAULT_PROVIDER_NAME)
        metadata = provider.load_server_metadata()

        jwks_uri = metadata.get("jwks_uri")
        if not jwks_uri:
            raise ValueError("OIDC provider metadata missing 'jwks_uri'")

        jwks_uri = metadata.get("jwks_uri")
        if not jwks_uri:
            raise ValueError("OIDC provider metadata does not contain 'jwks_uri'")

        response = requests.get(jwks_uri, timeout=10)
        response.raise_for_status()
        self._cached_jwks = JsonWebKey.import_key_set(response.json())
        
        return self._cached_jwks

    def decode_and_validate_token(self, token_str: str):
        """Decode *and* full-validate a JWT against the OIDC provider's JWKS.
        
        Validates signature, issuer (iss), audience (aud), and authorized-party (azp)
         claims.
        """

        jwks = self.get_jwks_keys()
        
        provider = getattr(self.oauth, self.DEFAULT_PROVIDER_NAME)
        metadata = provider.load_server_metadata()
        issuer = metadata.get("issuer")

        client_id = self.secrets.get("client_id")

        claims = jwt.decode(
            token_str,
            jwks,
            claims_options={
                "iss": {"essential": True, "value": issuer},
                "aud": {"essential": True, "value": client_id},
                "azp": {"essential": True, "value": client_id},
            },
        )
        claims.validate()
        return claims
    
    def validate_and_extract_claims(self, token_str: str, required_scope: str = None):
        """Validate a token string and optionally check required scope.
        
        Args:
            token_str: The raw JWT string.
            required_scope: Optional scope string to validate.
            
        Returns:
            The validated claims dict.
            
        Raises:
            Exception: JoseError from Authlib if token is invalid/expired.
            InsufficientScopeError: If the token lacks the required scope.
        """
        claims = self.decode_and_validate_token(token_str)
        
        if required_scope:
            token_scopes = claims.get("scope", "").split()
            if required_scope not in token_scopes:
                raise InsufficientScopeError(
                    f"Required: '{required_scope}'."
                    "Available: {[s for s in token_scopes]}"
                )
        
        return claims

    def login(self, redirect_uri: str, request=None):
        raise NotImplementedError

    def authorize(self, request=None):
        raise NotImplementedError

    def refresh(self, request_json: dict):

        refresh_token = request_json.get("refresh_token")
        if not refresh_token:
            raise TokenExtractionError("Missing refresh_token in request body")
        
        scope = request_json.get("scope")
        # Call the specific implementation's fetch method
        return self._do_refresh(refresh_token, scope)

    def __getattr__(self, name):
        """
        Delegate all unknown attribute/method lookups to the underlying Authlib OAut
        object. This automatically exposes .register(), .init_app(), etc.
        """
        return getattr(self.oauth, name)

### Adapters

class FastAPIAuthAdapter(BaseAuthAdapter):
    def _initialize_oauth(self):
        from authlib.integrations.starlette_client import OAuth
        from fastapi.responses import JSONResponse
        self._response_class = JSONResponse
        return OAuth()

    def error_handler(self, exc: Exception):
        msg, code = self._resolve_error(exc)
        return self._response_class(
            status_code=code,
            content={
                "error": {
                    "message": msg,
                    "details": str(exc)
                }
            }
        )

    def token_response(self, token: dict, message: str = "Success"):
        return self._response_class(
            status_code=200,
            content={
                "message": message,
                "token": {
                    "access_token": token.get("access_token"),
                    "refresh_token": token.get("refresh_token"),
                }
            }
        )

    async def get_jwks_keys(self):
        """Async override for fetching JWKS."""
        if hasattr(self, '_cached_jwks'):
            return self._cached_jwks

        provider = getattr(self.oauth, self.DEFAULT_PROVIDER_NAME)
        # Starlette requires await here
        metadata = await provider.load_server_metadata()

        jwks_uri = metadata.get("jwks_uri")
        if not jwks_uri:
            raise ValueError("OIDC provider metadata missing 'jwks_uri'")

        # Non-blocking HTTP request
        async with httpx.AsyncClient() as client:
            response = await client.get(jwks_uri, timeout=10)
            response.raise_for_status()
            
        self._cached_jwks = JsonWebKey.import_key_set(response.json())
        return self._cached_jwks

    async def decode_and_validate_token(self, token_str: str):
        """Async override for decoding."""
        jwks = await self.get_jwks_keys()
        
        provider = getattr(self.oauth, self.DEFAULT_PROVIDER_NAME)
        # Starlette requires await here too
        metadata = await provider.load_server_metadata()
        issuer = metadata.get("issuer")

        client_id = self.secrets.get("client_id")

        claims = jwt.decode(
            token_str,
            jwks,
            claims_options={
                "iss": {"essential": True, "value": issuer},
                "aud": {"essential": True, "value": client_id},
                "azp": {"essential": True, "value": client_id},
            },
        )
        claims.validate()
        return claims

    async def validate_and_extract_claims(self,
        token_str: str,
        required_scope: str = None):
        """Async override for claim extraction."""
        claims = await self.decode_and_validate_token(token_str)
        
        if required_scope:
            token_scopes = claims.get("scope", "").split()
            if required_scope not in token_scopes:
                raise InsufficientScopeError(
                    f"Required: '{required_scope}'."
                    "Available: {[s for s in token_scopes]}"
                )
        
        return claims
    
    async def login(self, request, redirect_uri: str):
        """Returns a Starlette/FastAPI RedirectResponse."""
        # The Starlette client's authorize_redirect is async
        return await self.dataone_oidc.authorize_redirect(request, redirect_uri)

    async def authorize(self, request):
        """Exchanges code for token and returns a JSONResponse."""
        try:
            # Must await the token exchange in FastAPI
            token = await self.dataone_oidc.authorize_access_token(request)
            return self.token_response(token)
        except Exception as e:
            return self.error_handler(e)

    async def refresh(self, request_json: dict):
        """Logic to handle refresh token exchange."""
        refresh_token = request_json.get("refresh_token")
        if not refresh_token:
            # This triggers our mapped TokenExtractionError (401)
            return self.error_handler(TokenExtractionError("Missing refresh_token"))
        
        scope = request_json.get("scope")
        
        try:
            kwargs = {
                "grant_type": "refresh_token", 
                "refresh_token": refresh_token
            }
            if scope:
                kwargs["scope"] = scope
                
            # The Starlette fetch_access_token is async
            new_tokens = await self.dataone_oidc.fetch_access_token(**kwargs)
            return self.token_response(new_tokens, message="Token refresh successful")
        except Exception as e:
            return self.error_handler(e)

class FlaskAuthAdapter(BaseAuthAdapter):
    def _initialize_oauth(self):
        from authlib.integrations.flask_client import OAuth
        return OAuth()

    def error_handler(self, exc: Exception):
        from flask import jsonify
        msg, code = self._resolve_error(exc)
        return jsonify({
            "error": {
                "message": msg,
                "details": str(exc)
            }
        }), code

    def token_response(self, token: dict, message: str = "Success"):
        from flask import jsonify
        return jsonify({
            "message": message,
            "token": {
                "access_token": token.get("access_token"),
                "refresh_token": token.get("refresh_token"),
            }
        }), 200

    def login(self, redirect_uri: str):
        return self.dataone_oidc.authorize_redirect(redirect_uri)

    def authorize(self):
        try:
            token = self.dataone_oidc.authorize_access_token()
            return self.token_response(token)
        except Exception as e:
            return self.error_handler(e)

    def _do_refresh(self, refresh_token, scope=None):
        try:
            kwargs = {"grant_type": "refresh_token", "refresh_token": refresh_token}
            if scope:
                kwargs["scope"] = scope
            new_tokens = self.dataone_oidc.fetch_access_token(**kwargs)
            return self.token_response(new_tokens)
        except Exception as e:
            return self.error_handler(e)

