class BaseAuthAdapter:
    def __init__(self, config: dict):
        self.config = config
        self.oauth = self._initialize_oauth()
        self._setup_providers()

    def _initialize_oauth(self):
        raise NotImplementedError

    def _setup_providers(self):
        self.register(
            name="vegbank_oidc",
            #client_id=secrets.get("client_id"),
            #client_secret=secrets.get("client_secret"),
            #server_metadata_url=secrets.get("server_metadata_url"),
            #client_kwargs={"scope": scope_request},
    )

    def __getattr__(self, name):
        """
        Delegate all unknown attribute/method lookups to the underlying Authlib OAuth object.
        This automatically exposes .register(), .init_app(), etc.
        """
        return getattr(self.oauth, name)