from .base import BaseAuthAdapter

class FlaskAuthAdapter(BaseAuthAdapter):
    def _initialize_oauth(self):
        from authlib.integrations.flask_client import OAuth
        return OAuth()