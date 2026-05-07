from .base import BaseAuthAdapter

class FastAPIAuthAdapter(BaseAuthAdapter):
    def _initialize_oauth(self):
        from authlib.integrations.starlette_client import OAuth
        return OAuth()

    async def login(self, name: str, request, **kwargs):
        client = self.oauth.create_client(name)
        # FastAPI/Starlette is async and requires the request object
        return await client.authorize_redirect(request, **kwargs)