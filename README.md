# DataONE Auth Library for python services

- **Authors**: Rushiraj Nenuji, [0000-0003-4678-5213](https://orcid.org/0000-0003-4678-5213); Matthew B. Jones [0000-0003-0077-4738](https://orcid.org/0000-0003-0077-4738); and Jeanette Clark [0000-0003-4703-1974](https://orcid.org/0000-0003-4703-1974)
- **License**: [Apache 2](http://opensource.org/licenses/Apache-2.0)
- [Package source code on GitHub](https://github.com/DataONEorg/dataone-auth)
- [**Submit Bugs and feature requests**](https://github.com/DataONEorg/dataone-auth/issues)
- Contact us: support@dataone.org
- [DataONE discussions](https://github.com/DataONEorg/dataone/discussions)

The `dataone-auth` module provides a framework-agnostic OpenID Connect (OIDC) authentication adapter for Python applications. Using `joserfc` and `Authlib`, its core purpose is to handle JSON Web Token (JWT) validation so that DataONE Python applications can seamlessly integrate OIDC authentication, regardless of what framework that application uses. Currently, `dataone-auth` supports both Flask and FastAPI. To integrate `dataone-auth` into an existing app, the application only needs to create an auth client (`create_client`), use the `login`, `authorize`, `refresh` methods on the corresponding endpoints, and utilize the `require_scope` helper either as a decorator or `Depends` function to protect secure endpoints. For more detail on usage, see the examples below. 

DataONE creates open source, community projects.  We [welcome contributions](./CONTRIBUTING.md) in many forms, including code, graphics, documentation, bug reports, testing, etc.  Use the [DataONE discussions](https://github.com/DataONEorg/dataone/discussions) to discuss these contributions with us.

## Documentation

Documentation is a work in progress, and can be found in [docs](./docs).

## Development build

This is a python package, and built using the [uv](https://uv-astral.sh) build tool, among others.

To install locally, create a virtual environment for python.
Install `uv`, and then sync the package dependencies:

- `uv sync`.

Then import it in your code:
```python
import dataone.auth
```

To run tests, navigate to the root directory and run pytest:

- `uv run pytest` 

To run the code formatter and linter, use Ruff:

- `uv run ruff check .`

## Usage Examples

### Flask

Below is a minimal example for a Flask application. For the Flask implementation, applying `ProxyFix` is recommended to ensure correct redirect URIs when the app is running behind a reverse proxy or load balancer. Following standard Flask extension patterns, the `auth_client` must be explicitly bound to the application using `init_app()`. Once initialized, protect any endpoint by stacking the `@auth_client.require_scope(...)` decorator below the route definition. This automatically intercepts the Bearer token, validates the OIDC claims against the provider's JWKS, and injects the resulting claims dictionary into the view function.

```python
import json
import os
from flask import Flask, jsonify, request, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from dataone.auth import AuthFactory, load_client_secrets

# --- Constants & Logging ---
ACCESS_MODE_AUTHENTICATED = "authenticated"
scopes = ["ogdc:admin"]

# --- App Initialization ---
app = Flask(__name__)
app.config.update({"SECRET_KEY": os.getenv("FLASK_SECRET_KEY", os.urandom(32).hex())})

if not isinstance(app.wsgi_app, ProxyFix):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# --- Auth Setup ---
secrets = load_client_secrets()
auth_client = AuthFactory.create_client("flask", secrets, scopes)
auth_client.init_app(app)
app.extensions['dataone_auth'] = auth_client

# --- Routes ---
@app.route("/login")
def login():
    return auth_client.login(redirect_uri=url_for("authorize", _external=True))

@app.route("/authorize")
def authorize():
    return auth_client.authorize()

@app.route("/refresh", methods=["POST"])
def refresh_token():
    return auth_client.refresh(request_json=request.get_json(silent=True))

@app.route("/profile", methods=["GET"])
@auth_client.require_scope("ogdc:admin")
def profile(claims):
    """Protected resource endpoint requiring 'ogdc:admin' scope."""
    return jsonify({
        "message": f"Authorization succeeded, {claims.get('name', 'User')}",
        "claims": claims  # The claims object is already a dictionary!
    }), 200

# --- Execution ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int("4000"), debug=True)
```

### FastAPI

Below is a minimal example for a FastAPI application. Unlike Flask, FastAPI doesn't require an `init_app` step; the `auth_client` is ready to use immediately upon creation. Note that `SessionMiddleware` must be added to the app to handle the OIDC state and nonce during the browser-based login and authorization flow. For the API endpoints, the heavy lifting happens within the `Depends(auth_client.require_scope(...))` dependency, which automatically intercepts the Bearer token, validates the OIDC claims against the provider's JWKS, and injects the ready-to-use claims dictionary  into the route handler.

```python
import os
from fastapi import Depends, FastAPI, Request
from fastapi.security import HTTPBearer
from starlette.middleware.sessions import SessionMiddleware
from dataone.auth import AuthFactory, load_client_secrets

# --- Constants & Logging ---
ACCESS_MODE_AUTHENTICATED = "authenticated"
scopes = ["ogdc:admin"]

# --- App Initialization ---
app = FastAPI(title="DataONE OIDC API")
app.add_middleware(
    SessionMiddleware, 
    secret_key=os.getenv("SECRET_KEY", os.urandom(32).hex())
)

# --- Auth Setup ---
secrets = load_client_secrets()
auth_client = AuthFactory.create_client("fastapi", secrets, scopes)

security = HTTPBearer()
# --- Routes ---
@app.get("/login")
async def login(request: Request):
    return await auth_client.login(request, redirect_uri=str(request.url_for("authorize")))

@app.get("/authorize")
async def authorize(request: Request):
    return await auth_client.authorize(request)

@app.post("/refresh")
async def refresh(request: Request):
    return await auth_client.refresh(await request.json())

@app.get("/profile")
async def profile(claims: dict = Depends(auth_client.require_scope("ogdc:admin"))):
    """Protected resource endpoint."""
    return {
        "message": f"Authorization succeeded, {claims.get('name', 'User')}",
        "claims": claims
    }

# --- Execution ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=4000, proxy_headers=True, forwarded_allow_ips="*")
```

## License

```
Copyright [2024] [Regents of the University of California]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Acknowledgements

Work on this package was supported by:

- DataONE Network
- Arctic Data Center: NSF-PLR grant #2042102 to M. B. Jones, A. Budden, M. Schildhauer, and J. Dozier

Additional support was provided for collaboration by the National Center for Ecological Analysis and Synthesis, a Center funded by the University of California, Santa Barbara, and the State of California.

[![DataONE_footer](https://user-images.githubusercontent.com/6643222/162324180-b5cf0f5f-ae7a-4ca6-87c3-9733a2590634.png)](https://dataone.org)

[![nceas_footer](https://www.nceas.ucsb.edu/sites/default/files/2020-03/NCEAS-full%20logo-4C.png)](https://www.nceas.ucsb.edu)
