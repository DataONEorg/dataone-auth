import os

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

    def __getattr__(self, name):
        """
        Delegate all unknown attribute/method lookups to the underlying Authlib OAuth object.
        This automatically exposes .register(), .init_app(), etc.
        """
        return getattr(self.oauth, name)