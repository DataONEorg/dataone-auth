from .base import BaseAuthAdapter

class FlaskAuthAdapter(BaseAuthAdapter):
    def _initialize_oauth(self):
        from authlib.integrations.flask_client import OAuth
        return OAuth()

    def login(self, name: str, **kwargs):
        client = self.oauth.create_client(name)
        # Standard Flask is synchronous, no request object needed
        return client.authorize_redirect(**kwargs)