"""Authentication and token validation utilities for DataONE authorization.

This module provides helpers to load OIDC client secrets, extract and validate Bearer
tokens, decode JWT claims, and enforce access and scope checks used by the DataONE
auth flow. The package can be used with multiple web frameworks via the AuthFactory,
which uses specific adapters (e.g., FlaskAuthAdapter, FastAPIAuthAdapter) to integrate
with the request handling and dependency injection patterns of each framework. The base
adapter handles the core logic of OIDC provider setup, token validation, and error
handling, while the adapters implement the framework-specific request processing and
response formatting. This design allows for flexible integration with different Python
web frameworks without hard dependencies on any particular framework.
"""

import base64
import datetime as dt
import functools
import json
import os
import re
from typing import Any

import httpx
import requests
from authlib.integrations.base_client.errors import OAuthError
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749.errors import InvalidClientError, InvalidGrantError
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
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


class AuthError(Exception):
    """Base exception for dataone-auth."""


class MissingParameterError(AuthError):
    """Raised when a required request parameter is missing."""


class InsufficientScopeError(AuthError):
    """Raised when the token is valid but doesn't have the right scope."""


class TokenExtractionError(AuthError):
    """Raised when the Authorization header is missing or malformed."""


class InvalidTokenError(AuthError):
    """Raised when claims like iss or aud do not match expectations."""


class ConfigurationError(AuthError):
    """Raised when there is an issue with the configuration."""


### Helpers


def load_client_secrets(filepath: str | None = None) -> dict:
    """Load client secrets from a JSON file.

    Args:
        filepath: Optional explicit path. Falls back to the ``OIDC_CLIENT_SECRETS_FILE``
                  environment variable, then finally to the default path of
                  "./client_secrets.json"

    Returns:
        Parsed dict of client credentials.

    Raises:
        ConfigurationError: If the secrets file cannot be found at the resolved path,
                            or if the file does not contain valid JSON.
    """
    # accept either explicit filepath argument or environment variable, with a default
    #  fallback
    resolved = (
        filepath or os.getenv("OIDC_CLIENT_SECRETS_FILE") or _DEFAULT_SECRETS_PATH
    )
    try:
        with open(resolved) as f:
            return json.load(f)
    except FileNotFoundError:
        raise ConfigurationError(f"Could not find OIDC secrets file at {resolved}")
    except json.JSONDecodeError:
        raise ConfigurationError(f"OIDC secrets file at {resolved} is not valid JSON")


def extract_token_from_header(auth_header: str | None):
    """Extracts and validates a Bearer token from an auth header string.

    Args:
        auth_header: Auth header as a string (e.g., "Bearer <token>").

    Returns:
        The extracted JWT token.

    Raises:
        MissingParameterError: If no header is supplied.
        TokenExtractionError: If the token is empty, malformed, or exceeds the allowed
                              length.
    """

    if not auth_header:
        raise MissingParameterError("Missing Authorization header")

    if not auth_header.startswith("Bearer "):
        raise TokenExtractionError(
            "Invalid Authorization header format. Expected 'Bearer <token>'"
        )

    token = auth_header[7:].strip()

    if not token:
        raise TokenExtractionError("Token is empty")

    # Check JWT structure
    if token.count(".") != 2:
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
        bare = raw[len(_ORCID_HTTPS_PREFIX) :]
    elif raw.startswith(_ORCID_HTTP_PREFIX):
        bare = raw[len(_ORCID_HTTP_PREFIX) :]
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


def decode_claims(token_str, jwks, client_id, issuer):
    """Decodes and validates a JWT using joserfc.

    Args:
        token_str: The raw encoded JWT string.
        jwks: The KeySet object returned by _get_jwks_keys.
        client_id: The expected audience (aud) and authorized party (azp).
        issuer: The expected issuer (iss) URI of the token.

    Returns:
        The validated claims object.

    Raises:
        ValueError: If the issuer, audience, or azp claims do not match
                    the expected values.
    """
    token = jwt.decode(token_str, jwks)

    # standard joserfc validation (checks exp, nbf, etc.)
    claims = token.claims
    registry = jwt.JWTClaimsRegistry()
    registry.validate(claims)

    if claims.get("iss") != issuer:
        raise InvalidTokenError("Invalid issuer")
    if claims.get("aud") != client_id:
        raise InvalidTokenError("Invalid audience")
    if claims.get("azp") and claims.get("azp") != client_id:
        raise InvalidTokenError("Invalid authorized party (azp)")

    return claims

def is_token_valid(token: str | None, buffer_minutes: int = 1) -> bool:
    """Check if a JWT token unexpired.

    Args:
        token: The raw JWT string to validate.
        buffer_minutes: A safety margin added to the current time to account for network
                        lag.

    Returns:
        True if the token is valid and unexpired, False otherwise.
    """
    if not token:
        return False
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return False
        payload = parts[1]
        payload += "=" * ((4 - len(payload) % 4) % 4)
        exp = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8")).get("exp")
    except Exception:
        return False

    if not exp:
        return False
    expiry_time = dt.datetime.fromtimestamp(exp, tz=dt.UTC)
    e = expiry_time > (dt.datetime.now(dt.UTC) + dt.timedelta(minutes=buffer_minutes))
    return e

def parse_tokens_dict(tokens: str | dict[str, Any]) -> dict[str, str]:
    """Parse and normalize a raw token payload into a validated dictionary.

    Args:
        tokens: A raw JSON string or dictionary containing OIDC tokens.

    Returns:
        A dictionary containing verified 'access_token' and/or 'refresh_token' keys.

    Raises:
        ValueError: If the input is malformed, missing key fields, or contains empty 
                    strings.
    """
    if isinstance(tokens, str):
        try:
            tokens = json.loads(tokens)
        except json.JSONDecodeError as e:
            raise ValueError(f"'tokens' could not be parsed as JSON: {e}")

    if not isinstance(tokens, dict):
        raise ValueError("'tokens' must be a dictionary or a JSON string")

    if "token" in tokens and isinstance(tokens["token"], dict):
        tokens = tokens["token"]

    if not any(key in tokens for key in ("access_token", "refresh_token")):
        raise ValueError(
            "'tokens' must contain at least one of 'access_token' or 'refresh_token'"
        )

    normalized: dict[str, str] = {}
    for key in ("access_token", "refresh_token"):
        if key in tokens and tokens[key] is not None:
            val = tokens[key]
            if not isinstance(val, str) or len(val.strip()) == 0:
                raise ValueError(f"'{key}' must be a non-empty string")
            normalized[key] = val

    return normalized

def refresh_tokens(refresh_url: str,
                   refresh_token: str,
                   session: requests.Session | None = None) -> dict:
    """Exchange a refresh token for a new token payload.

    Args:
        refresh_url: The API endpoint URL used for token renewal.
        refresh_token: The OIDC refresh token string.
        session: An optional requests session to use for the network request.

    Returns:
        A dictionary containing the fresh token payload.

    Raises:
        requests.exceptions.HTTPError: If the server returns an unsuccessful status
                                    code.
    """
    client = session or requests.Session()
    response = client.post(refresh_url, json={"refresh_token": refresh_token})
    response.raise_for_status()
    return response.json()

### Factory


class AuthFactory:
    """Factory for generating framework-specific authentication adapters.

    This factory uses a registry and dynamic imports to instantiate the correct
    adapter (e.g., Flask or FastAPI) based on the running application. This pattern
    ensures that a Flask application does not need to install FastAPI/Starlette
    dependencies, and vice versa.
    """

    _registry = {
        "flask": "dataone.auth.FlaskAuthAdapter",
        "fastapi": "dataone.auth.FastAPIAuthAdapter",
        "starlette": "dataone.auth.FastAPIAuthAdapter",
    }

    @classmethod
    def create_client(cls, framework: str, secrets: dict, scopes: list):
        """Creates and returns the appropriate authentication adapter.

        Args:
            framework: A string identifying the target web framework (e.g., "flask",
                       "fastapi").
            secrets: A dictionary containing the OIDC client credentials, typically
                     loaded via `load_client_secrets()`.
            scopes: A list of default OIDC scopes to request from the authorization
                    server (e.g., ["ogdc:admin"]).

        Returns:
            BaseAuthAdapter: An instantiated, framework-specific adapter (such as
                             `FlaskAuthAdapter` or `FastAPIAuthAdapter`).

        Raises:
            ValueError: If the framework string is not found in the registry.
        """
        import_path = cls._registry.get(framework.lower())
        if not import_path:
            raise ValueError(f"Unsupported framework: {framework}")

        module_path, class_name = import_path.rsplit(".", 1)
        module = __import__(module_path, fromlist=[class_name])
        AdapterClass = getattr(module, class_name)

        return AdapterClass(secrets=secrets, scopes=scopes)


class BaseAuthAdapter:
    """Base adapter for handling OIDC authentication.

    This class manages the core Authlib registry initialization, OIDC provider
    setup, and access mode configuration. It is designed to be subclassed by
    framework-specific adapters (e.g., FlaskAuthAdapter, FastAPIAuthAdapter)
    that implement the actual request handling and dependency/decorator logic.

    Attributes:
        DEFAULT_PROVIDER_NAME (str): The internal registry name for the OIDC provider.
        DEFAULT_SCOPES (str): The standard base scopes requested during login.
        access_mode (str): The current operating mode ('authenticated', 'read_only',
                           or 'open'), loaded during initialization.
    """

    DEFAULT_PROVIDER_NAME = "dataone_oidc"
    DEFAULT_SCOPES = "openid email profile"

    ERROR_MAP = {
        TokenExtractionError: ("Invalid token or header", 401),
        JoseError: ("Token decoding or signature verification failed", 401),
        InvalidTokenError: ("Token validation failed", 401),
        InvalidClientError: ("OIDC client authentication failed", 401),
        InvalidGrantError: ("Invalid or expired refresh token", 401),
        OAuthError: ("Authorization failed", 401),
        OAuth2Error: ("An OAuth2 error occurred", 401),
        KeyError: ("Invalid token structure", 401),
        TypeError: ("Invalid token structure", 401),
        MissingParameterError: ("Missing required parameter", 400),
        ValueError: ("OIDC provider configuration error", 500),
        RequestException: ("Failed to fetch OIDC provider keys", 502),
        InsufficientScopeError: ("Insufficient scope", 403)
    }

    def __init__(self, secrets, scopes):
        """Initializes the base authentication adapter.

        Args:
            secrets: Dictionary of OIDC client credentials.
            scopes: List of additional OIDC scopes to request.
        """
        self.secrets = secrets
        self.scopes = scopes
        self.oauth = self._initialize_oauth()
        self._setup_providers()
        self.access_mode = get_access_mode()

    def _initialize_oauth(self):
        """This is implemented by subclasses."""
        raise NotImplementedError

    def _setup_providers(self):
        """Registers the OIDC provider using loaded secrets and scopes."""

        base_scopes = self.DEFAULT_SCOPES.split()
        scope_request = " ".join(dict.fromkeys(base_scopes + self.scopes))

        self.oauth.register(
            name=self.DEFAULT_PROVIDER_NAME,
            client_id=self.secrets.get("client_id"),
            client_secret=self.secrets.get("client_secret"),
            server_metadata_url=self.secrets.get("server_metadata_url"),
            client_kwargs={"scope": scope_request},
        )

    def _resolve_error(self, exc: Exception):
        """Resolves an exception to an error message and HTTP status code.

        Evaluates the exception against ERROR_MAP, matching by direct class type
        or class name (string) to avoid hard dependency imports.

        Args:
            exc: The caught exception to be resolved.

        Returns:
            A tuple containing the error message (str) and HTTP status code (int).
        """
        # Check for specific Authlib errors (handle imports or strings)
        for exc_type, (msg, code) in self.ERROR_MAP.items():
            # Parentheses let us wrap this logic across lines cleanly
            is_match = (
                isinstance(exc, exc_type)
                if not isinstance(exc_type, str)
                else type(exc).__name__ == exc_type
            )

            if is_match:
                return msg, code

        return "Internal authentication error", 500

    def _verify_scope(self, claims: dict, required_scope: str | None = None):
        """Internal helper to check if the required scope exists in claims."""
        if not required_scope:
            return

        token_scopes = claims.get("scope", "").split()
        if required_scope not in token_scopes:
            raise InsufficientScopeError(
                f"Required: '{required_scope}'. Available: {token_scopes}"
            )

    def _error_handler(self, exc: Exception):
        """This is implemented by subclasses."""
        raise NotImplementedError

    def _token_response(self, token: dict, message: str):
        """This is implemented by subclasses."""
        raise NotImplementedError

    def _get_jwks_keys(self):
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

        if hasattr(self, "_cached_jwks"):
            return self._cached_jwks

        provider = getattr(self.oauth, self.DEFAULT_PROVIDER_NAME)
        metadata = provider.load_server_metadata()

        jwks_uri = metadata.get("jwks_uri")
        if not jwks_uri:
            raise ValueError("OIDC provider metadata missing 'jwks_uri'")

        response = requests.get(jwks_uri, timeout=10)
        response.raise_for_status()

        # joserfc uses KeySet.import_key_set
        self._cached_jwks = KeySet.import_key_set(response.json())

        return self._cached_jwks

    def _decode_and_validate_token(self, token_str: str):
        """Decodes and validates a JWT using the provider's JWKS.

        Enforces signature validity as well as the exact issuer (iss),
        audience (aud), and authorized party (azp) claims.

        Args:
            token_str: The raw JWT string to validate.

        Returns:
            The validated token claims object.
        """
        jwks = self._get_jwks_keys()

        provider = getattr(self.oauth, self.DEFAULT_PROVIDER_NAME)
        metadata = provider.load_server_metadata()
        issuer = metadata.get("issuer")

        client_id = self.secrets.get("client_id")

        return decode_claims(token_str, jwks, client_id, issuer)

    def validate_and_extract_claims(self,
                                    token_str: str,
                                    required_scope: str | None = None):
        """Validate a token string and optionally check required scope.

        Args:
            token_str: The raw JWT string.
            required_scope: Optional scope string to validate.

        Returns:
            The validated claims dict.

        Raises:
            JoseError: If the token is invalid, expired, or has an incorrect
                       issuer/audience.
            InsufficientScopeError: If the token lacks the required scope.
        """
        claims = self._decode_and_validate_token(token_str)

        if required_scope:
            self._verify_scope(claims, required_scope)

        return claims

    def login(self, redirect_uri: str, request=None) -> Any:
        """This is implemented by subclasses."""
        raise NotImplementedError

    def authorize(self, request=None):
        """This is implemented by subclasses."""
        raise NotImplementedError

    def refresh(self, request_json: dict):
        """This is implemented by subclasses."""
        raise NotImplementedError

    def require_scope(self, required_scope: str, methods=None):
        """This is implemented by subclasses."""
        raise NotImplementedError

    def require_token(self, methods=None):
        """This is implemented by subclasses."""
        raise NotImplementedError

    def __getattr__(self, name):
        """
        Delegate all unknown attribute/method lookups to the underlying Authlib OAut
        object. This automatically exposes .register(), .init_app(), etc.
        """
        return getattr(self.oauth, name)


### Adapters


class FastAPIAuthAdapter(BaseAuthAdapter):
    def _initialize_oauth(self):
        """Initializes the Starlette-based OAuth registry for FastAPI.

        Sets the internal response class to FastAPI's JSONResponse and returns
        the instantiated Authlib OAuth object.
        """
        from authlib.integrations.starlette_client import OAuth
        from fastapi.responses import JSONResponse

        self._response_class = JSONResponse
        return OAuth()

    def _error_handler(self, exc: Exception):
        """Formats an exception into a FastAPI JSON response.

        Args:
            exc: The exception caught during authentication or request processing.

        Returns:
            A JSONResponse object containing the resolved HTTP status code
            and formatted error payload.
        """
        msg, code = self._resolve_error(exc)
        return self._response_class(
            status_code=code, content={"error": {"message": msg, "details": str(exc)}}
        )

    def _token_response(self, token: dict, message: str = "Success"):
        """Formats successful token data into a FastAPI JSON response.

        Args:
            token: A dictionary containing the token data (must include at least
                   'access_token' and 'refresh_token' keys).
            message: An optional success message to include in the response payload.
                     Defaults to "Success".

        Returns:
            A JSONResponse object with a 200 status code and the standardized
            token payload.
        """
        return self._response_class(
            status_code=200,
            content={
                "message": message,
                "token": {
                    "access_token": token.get("access_token"),
                    "refresh_token": token.get("refresh_token"),
                },
            },
        )

    async def _get_jwks_keys(self):
        """Asynchronously fetches and caches the OIDC provider's JWKS.

        Retrieves the provider metadata to find the `jwks_uri`, makes a non-blocking
        HTTP request to fetch the keys using `httpx`, and caches the parsed key set
        to prevent redundant network calls.

        Returns:
            The parsed JsonWebKey set.

        Raises:
            ValueError: If the provider metadata does not contain a 'jwks_uri'.
            httpx.HTTPStatusError: If the network request to the `jwks_uri` fails.
        """
        if hasattr(self, "_cached_jwks"):
            return self._cached_jwks

        provider = getattr(self.oauth, self.DEFAULT_PROVIDER_NAME)
        metadata = await provider.load_server_metadata()

        jwks_uri = metadata.get("jwks_uri")
        if not jwks_uri:
            raise ValueError("OIDC provider metadata missing 'jwks_uri'")

        async with httpx.AsyncClient() as client:
            response = await client.get(jwks_uri, timeout=10)
            response.raise_for_status()

        self._cached_jwks = KeySet.import_key_set(response.json())
        return self._cached_jwks

    async def _decode_and_validate_token(self, token_str: str):
        """Async override for decoding."""
        jwks = await self._get_jwks_keys()

        provider = getattr(self.oauth, self.DEFAULT_PROVIDER_NAME)
        # Starlette requires await here too
        metadata = await provider.load_server_metadata()
        issuer = metadata.get("issuer")

        client_id = self.secrets.get("client_id")

        return decode_claims(token_str, jwks, client_id, issuer)

    async def validate_and_extract_claims(self,
                                          token_str: str,
                                          required_scope: str | None = None):
        """Asynchronously decodes and validates a JWT using the provider's JWKS.

        This overrides the base method to support Starlette/FastAPI's asynchronous
        metadata and JWKS fetching. It enforces signature validity as well as exact
        matching for issuer (iss), audience (aud), and authorized party (azp) claims.

        Args:
            token_str: The raw JWT string to validate.

        Returns:
            The validated token claims object.
        """
        claims = await self._decode_and_validate_token(token_str)

        if required_scope:
            self._verify_scope(claims, required_scope)

        return claims

    async def login(self, redirect_uri: str, request: Any = None) -> Any:
        """Asynchronously initiates the OIDC login flow.

        Uses the Starlette OAuth client to generate a redirect response that
        sends the user to the authorization server.

        Args:
            request: The incoming Starlette or FastAPI Request object.
            redirect_uri: The callback URL where the authorization server will
                          redirect the user after authentication.

        Returns:
            A Starlette RedirectResponse object pointing to the OIDC provider.

        Example:
            @app.get("/login")
            async def login(request: Request):
                return await auth_adapter.login(
                    request=request,
                    redirect_uri=str(request.url_for("authorize"))
                )
        """
        # The Starlette client's authorize_redirect is async
        return await self.dataone_oidc.authorize_redirect(request, redirect_uri)

    async def authorize(self, request):
        """Asynchronously exchanges an authorization code for an access token.

        This method is designed to be used in the OIDC callback route. It
        processes the incoming redirect from the authorization server, extracts
        the code, and fetches the final tokens.

        Args:
            request: The incoming FastAPI Request object containing the auth code.

        Returns:
            A JSONResponse containing the extracted tokens on success, or a
            formatted error response on failure.

        Example:
            @app.get("/authorize")
            async def authorize(request: Request):
                return await auth_adapter.authorize(request=request)
        """
        try:
            # Must await the token exchange in FastAPI
            token = await self.dataone_oidc.authorize_access_token(request)
            return self._token_response(token)
        except Exception as e:
            return self._error_handler(e)

    async def refresh(self, request_json: dict):
        """Asynchronously exchanges a refresh token for new access tokens.

        Overrides the synchronous base method to accommodate FastAPI's async
        token fetching.

        Args:
            request_json: A dictionary (typically the parsed JSON body of the
                          request) containing at least a 'refresh_token'.

        Returns:
            A JSONResponse containing the new access and refresh tokens, or an
            error response if the token is missing or invalid.

        Example:
            @app.post("/refresh")
            async def refresh(request: Request):
                body = await request.json()
                return await auth_adapter.refresh(body)
        """
        refresh_token = request_json.get("refresh_token")
        if not refresh_token:
            # This triggers our mapped TokenExtractionError (401)
            return self._error_handler(TokenExtractionError("Missing refresh_token"))

        scope = request_json.get("scope")

        try:
            kwargs = {"grant_type": "refresh_token", "refresh_token": refresh_token}
            if scope:
                kwargs["scope"] = scope

            # The Starlette fetch_access_token is async
            new_tokens = await self.dataone_oidc.fetch_access_token(**kwargs)
            return self._token_response(new_tokens, message="Token refresh successful")
        except Exception as e:
            return self._error_handler(e)

    def require_scope(self, required_scope: str, methods = None):
        """Creates a FastAPI dependency to enforce scope requirements on routes.

        This method returns an async function designed to be injected into FastAPI
        endpoints using `Depends()`. It extracts the token, validates it against
        the requested scope, and returns the claims. If the adapter's access mode
        is not set to 'authenticated' (e.g., 'read_only'), validation is bypassed.

        Args:
            required_scope: The specific OAuth scope required to access the route
                            (e.g., "read:data" or "write:admin").
            methods: Optional list of HTTP method names (e.g., ['POST', 'PUT']) to
                     protect. If None, all methods are protected. If the current request
                     method is not in this list, authentication is bypassed.

        Returns:
            An asynchronous callable dependency that returns validated token claims.

        Raises:
            fastapi.HTTPException: If token validation fails. The internal exception
                                   is translated into a standard FastAPI HTTP error
                                   using the adapter's error handler.

        Example:
            from fastapi import Depends

            @app.get("/secure-data")
            async def get_secure_data(
                    claims: dict = Depends(auth_adapter.require_scope("read:data"))
            ):
                return {"message": "Access granted", "user": claims.get("sub")}
        """
        from fastapi import Request

        async def dependency(request: Request):
            from fastapi import HTTPException

            # Handle 'open' logic
            if self.access_mode == ACCESS_MODE_OPEN:
                return {}
            
            # Handle 'read only' logic
            if self.access_mode == ACCESS_MODE_READ_ONLY:
                if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
                    raise HTTPException(
                        status_code=403, 
                        detail="This API is currently in read-only mode."
                    )
                return {}

            try:
                auth_header = request.headers.get("Authorization")
                token = extract_token_from_header(auth_header)
                # This call is async in FastAPI
                claims = await self.validate_and_extract_claims(token, required_scope)
                return claims
            except Exception as e:
                # In FastAPI, we RAISE the error handler's result
                error_res = self._error_handler(e)
                raise HTTPException(
                    status_code=error_res.status_code,
                    detail=json.loads(error_res.body.decode())["error"],
                )

        return dependency

    def require_token(self, methods=None):
        """Creates a FastAPI dependency to enforce token requirements on routes.

        This method returns an async function designed to be injected into FastAPI
        endpoints using `Depends()`. It extracts the token, validates it, and returns
        the claims. If the adapter's access mode is not set to 'authenticated' (e.g.,
        'read_only'), validation is bypassed.

        Args:
            methods: Optional list of HTTP method names (e.g., ['POST', 'PUT']) to
                     protect. If None, all methods are protected. If the current request
                     method is not in this list, authentication is bypassed.

        Returns:
            An asynchronous callable dependency that returns validated token claims.

        Raises:
            fastapi.HTTPException: If token validation fails. The internal exception
                                   is translated into a standard FastAPI HTTP error
                                   using the adapter's error handler.

        Example:
            from fastapi import Depends

            @app.get("/secure-data")
            async def get_secure_data(
                    claims: dict = Depends(auth_adapter.require_token(methods=["POST"]))
            ):
                return {"message": "Access granted", "user": claims.get("sub")}
        """
        from fastapi import Request

        async def dependency(request: Request):
            from fastapi import HTTPException

            # Handle 'open' logic
            if self.access_mode == ACCESS_MODE_OPEN:
                return {}
            
            # Handle 'read only' logic
            if self.access_mode == ACCESS_MODE_READ_ONLY:
                if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
                    raise HTTPException(
                        status_code=403, 
                        detail="This API is currently in read-only mode."
                    )
                return {}

            try:
                auth_header = request.headers.get("Authorization")
                token = extract_token_from_header(auth_header)
                # This call is async in FastAPI
                claims = await self.validate_and_extract_claims(token)
                return claims
            except Exception as e:
                # In FastAPI, we RAISE the error handler's result
                error_res = self._error_handler(e)
                raise HTTPException(
                    status_code=error_res.status_code,
                    detail=json.loads(error_res.body.decode())["error"],
                )

        return dependency


class FlaskAuthAdapter(BaseAuthAdapter):
    def _initialize_oauth(self):
        """Initializes the Flask-based OAuth registry.

        Sets the internal response class to FastAPI's JSONResponse and returns
        the instantiated Authlib OAuth object.
        """
        from authlib.integrations.flask_client import OAuth

        return OAuth()

    def _error_handler(self, exc: Exception):
        """Formats an exception into a Flask JSON response.

        Args:
            exc: The exception caught during authentication or request processing.

        Returns:
            A flask.Response object containing the resolved HTTP status code
            and formatted error payload.
        """
        from flask import jsonify

        msg, code = self._resolve_error(exc)
        return jsonify({"error": {"message": msg, "details": str(exc)}}), code

    def _token_response(self, token: dict, message: str = "Success"):
        """Formats successful token data into a Flask JSON response.

        Args:
            token: A dictionary containing the token data (must include at least
                   'access_token' and 'refresh_token' keys).
            message: An optional success message to include in the response payload.
                     Defaults to "Success".

        Returns:
            A flask.Response object with a 200 status code and the standardized
            token payload.
        """
        from flask import jsonify

        return jsonify(
            {
                "message": message,
                "token": {
                    "access_token": token.get("access_token"),
                    "refresh_token": token.get("refresh_token"),
                },
            }
        ), 200

    def login(self, redirect_uri: str, request: Any = None) -> Any:
        """Initiates the OIDC login flow for Flask.

        Uses the Flask Authlib client to generate a redirect response that
        sends the user to the authorization server.

        Args:
            redirect_uri: The callback URL where the authorization server will
                          redirect the user after authentication.

        Returns:
            A Flask Response object (redirect) pointing to the OIDC provider.

        Example:
            @app.route("/login")
            def login():
                return auth_client.login(
                    redirect_uri=url_for("authorize", _external=True)
                )
        """
        return self.dataone_oidc.authorize_redirect(redirect_uri)

    def authorize(self):
        """Exchanges an authorization code for an access token in Flask.

        This method should be called within the OIDC callback route. It
        automatically handles the code exchange by accessing the global
        Flask request object.

        Returns:
            A Flask Response object (JSON) containing the tokens on success,
            or a formatted error response on failure.

        Example:
            @app.route("/authorize")
            def authorize():
                return auth_client.authorize()
        """
        try:
            token = self.dataone_oidc.authorize_access_token()
            return self._token_response(token)
        except Exception as e:
            return self._error_handler(e)

    def refresh(self, request_json: dict):
        """Executes the synchronous token refresh request for Flask.

        Args:
            request_json: A dictionary (the parsed JSON body) containing
                          at least a 'refresh_token'.

        Returns:
            A Flask Response object (JSON) containing the new tokens or
            an error response if the exchange fails.

        Example:
            @app.route("/refresh", methods=["POST"])
            def refresh_route():
                return auth_adapter.refresh(request.get_json())
        """
        refresh_token = request_json.get("refresh_token")
        if not refresh_token:
            # We return the error handler result instead of raising
            # to match the Flask return-style flow.
            return self._error_handler(TokenExtractionError("Missing refresh_token"))

        scope = request_json.get("scope")
        try:
            kwargs = {"grant_type": "refresh_token", "refresh_token": refresh_token}
            if scope:
                kwargs["scope"] = scope

            new_tokens = self.dataone_oidc.fetch_access_token(**kwargs)
            return self._token_response(new_tokens, message="Token refresh successful")
        except Exception as e:
            return self._error_handler(e)

    def require_scope(self, required_scope: str, methods = None):
        """Creates a Flask decorator to enforce scope requirements on routes.

        This method returns a decorator that extracts the Bearer token from the
        'Authorization' header, validates it, and injects the resulting claims
        into the decorated function as the first argument. If the adapter is in
        'read_only' or 'open' mode, validation is bypassed and 'None' is passed
        for the claims.

        Args:
            required_scope: The specific OAuth scope required to access the route
                            (e.g., "read:data").
            methods: Optional list of HTTP method names (e.g., ['POST', 'PUT']) to
                     protect. If None, all methods are protected. If the current request
                     method is not in this list, authentication is bypassed.

        Returns:
            A decorator function that wraps a Flask route handler.

        Example:
            @app.route("/secure-data")
            @auth_adapter.require_scope("read:data")
            def get_secure_data(claims):
                return {"message": "Access granted", "user": claims.get("sub")}
        """

        def decorator(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                from flask import request

                if self.access_mode != "authenticated":
                    return f(None, *args, **kwargs)

                if methods is not None and request.method not in methods:
                    return f(None, *args, **kwargs)

                try:
                    from flask import request

                    token = extract_token_from_header(
                        request.headers.get("Authorization")
                    )
                    claims = self.validate_and_extract_claims(token, required_scope)
                    # Pass claims into the route
                    return f(claims, *args, **kwargs)
                except Exception as e:
                    return self._error_handler(e)

            return decorated

        return decorator

    def require_token(self, methods=None):
        """Creates a Flask decorator to enforce token authentication on routes.

        This method returns a decorator that extracts the Bearer token from the
        'Authorization' header, validates it, and injects the resulting claims
        into the decorated function as the first argument. If the adapter is in
        'read_only' or 'open' mode, validation is bypassed and 'None' is passed
        for the claims.

        Args:
            methods: Optional list of HTTP method names (e.g., ['POST', 'PUT']) to
                     protect. If None, all methods are protected. If the current request
                     method is not in this list, authentication is bypassed.

        Returns:
            A decorator function that wraps a Flask route handler.

        Example:
            @app.route("/any-authenticated-user", methods=["GET", "POST"])
            @auth_adapter.require_token(methods=["POST"])
            def handle_data(claims):
                user_id = claims.get("sub") if claims else "Anonymous"
                return {"message": "Success", "user": user_id}
        """

        def decorator(f):
            @functools.wraps(f)
            def decorated(*args, **kwargs):
                from flask import request

                if self.access_mode != "authenticated":
                    return f(None, *args, **kwargs)

                # filter http methods
                if methods is not None and request.method not in methods:
                    return f(None, *args, **kwargs)

                try:
                    from flask import request

                    token = extract_token_from_header(
                        request.headers.get("Authorization")
                    )
                    claims = self.validate_and_extract_claims(token)
                    # Pass claims into the route
                    return f(claims, *args, **kwargs)
                except Exception as e:
                    return self._error_handler(e)

            return decorated

        return decorator
