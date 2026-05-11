import os
import re
import json
import requests
from authlib.jose import jwt, JsonWebKey

MAX_TOKEN_LEN = 16_384
_DEFAULT_SECRETS_PATH = "./client_secrets.json"

class MissingParameterError(Exception):
    """Raised when a required request parameter is missing."""


def load_client_secrets(filepath: str | None = None) -> dict:
    """Load client secrets from a JSON file.

    Args:
        filepath: Optional explicit path. Falls back to the
                    ``OIDC_CLIENT_SECRETS_FILE`` environment variable

    Returns:
        Parsed dict of client credentials.
    """
    # accept either explicit filepath argument or environment variable, with a default fallback
    resolved = (
        filepath
        or os.getenv("OIDC_CLIENT_SECRETS_FILE")
        or _DEFAULT_SECRETS_PATH
    )
    with open(resolved, "r") as f:
        return json.load(f)

def extract_token_from_header(auth_header: str):
    """Extracts and safely bounds a Bearer token from an Authorization header."""
   
    # check there is a token
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    
    # make sure it looks like a JWT token
    if token.count('.') != 2:
        return None

    token = auth_header[7:].strip()

    # caps the token length to prevent huge tokens from causing DoS issues in downstream processing.
    if len(token) > MAX_TOKEN_LEN:
        return None
    
    return token

_ORCID_HTTPS_PREFIX = "https://orcid.org/"
_ORCID_HTTP_PREFIX = "http://orcid.org/"

# leave this in as a helper
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

# probably remove
def get_access_mode() -> str:
    """Get the current access mode from environment.
    
    Returns:
        str: One of 'read_only', 'open', or 'authenticated'. Defaults to 'authenticated'.
    """
    mode = os.getenv("VB_ACCESS_MODE", ACCESS_MODE_AUTHENTICATED).lower()
    if mode not in (ACCESS_MODE_READ_ONLY, ACCESS_MODE_OPEN, ACCESS_MODE_AUTHENTICATED):
        logger.warning(f"Invalid access mode '{mode}', falling back to '{ACCESS_MODE_AUTHENTICATED}'")
        return ACCESS_MODE_AUTHENTICATED
    return mode

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

    DEFAULT_PROVIDER_NAME = "vegbank_oidc"
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

    def get_jwks_keys(self):
        """Fetch and cache the JWKS signing keys from the OIDC provider.

        These keys are used to validate JWT token signatures. Care must be taken to fetch
        them only from trustworthy sources (via the OIDC provider's metadata endpoint over
        HTTPS). The keys may change periodically, so the cache will be invalidated and keys
        will be refetched on the next call after the application is restarted.

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
        
        Validates signature, issuer (iss), audience (aud), and authorized-party (azp) claims.
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
                    f"Required: '{target_scope}'. Available: {[s for s in token_scopes]}"
                )
        
        return claims

    def __getattr__(self, name):
        """
        Delegate all unknown attribute/method lookups to the underlying Authlib OAuth object.
        This automatically exposes .register(), .init_app(), etc.
        """
        return getattr(self.oauth, name)

# adapters

class FastAPIAuthAdapter(BaseAuthAdapter):
    def _initialize_oauth(self):
        from authlib.integrations.starlette_client import OAuth
        return OAuth()

class FlaskAuthAdapter(BaseAuthAdapter):
    def _initialize_oauth(self):
        from authlib.integrations.flask_client import OAuth
        return OAuth()

# exceptions

class AuthError(Exception):
    """Base exception for dataone-auth"""
    pass

class InsufficientScopeError(AuthError):
    """Raised when the token is valid but doesn't have the right scope"""
    pass