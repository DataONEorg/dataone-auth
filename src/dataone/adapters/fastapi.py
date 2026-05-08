from .base import BaseAuthAdapter

class FastAPIAuthAdapter(BaseAuthAdapter):
    def _initialize_oauth(self):
        from authlib.integrations.starlette_client import OAuth
        return OAuth()