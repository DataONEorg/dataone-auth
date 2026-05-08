import requests
from authlib.jose import jwt, JsonWebKey

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

    def get_jwks_keys():
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
        # 1. Do the crypto math (the method we wrote previously)
        claims = self.decode_and_validate_token(token_str)
        
        # 2. Scope check if required
        if required_scope:
            token_scopes = claims.get("scope", "").split()
            if required_scope not in token_scopes:
                raise InsufficientScopeError(
                    f"Insufficient scope. Required: {required_scope}. "
                    f"Available: {' '.join(token_scopes)}"
                )
        
        return claims

    def __getattr__(self, name):
        """
        Delegate all unknown attribute/method lookups to the underlying Authlib OAuth object.
        This automatically exposes .register(), .init_app(), etc.
        """
        return getattr(self.oauth, name)