# Changes to application code

## Flask

### Initialize client


```
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import current_app, g
# Assuming the user imports your factory
from dataone.factory import AuthFactory 
from dataone.utils import load_client_secrets

def init_oauth(app) -> bool:
    """Initialise the OAuth client and register the OIDC provider."""
    
    mode = get_access_mode()
    if mode != ACCESS_MODE_AUTHENTICATED:
        logger.warning("Access mode '%s': skipping OAuth initialisation.", mode)
        return True

    try:
        vb_secrets = load_client_secrets()
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.warning("Could not load client secrets (%s). Auth unavailable.", exc)
        return False

    if not isinstance(app.wsgi_app, ProxyFix):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    vb_scopes = [SCOPE_ADMIN, SCOPE_CONTRIBUTOR, SCOPE_USER]

    auth_client = AuthFactory.create_client("flask", vb_secrets, vb_scopes)
    
    auth_client.init_app(app)
    
    # attach to app context so Flask routes can access it later
    app.extensions['dataone_auth'] = auth_client

    logger.info("OAuth client initialised.")
    return True
```

### Protect endpoints with decorator

```
def require_token(methods=None, required_scope=None):
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            mode = get_access_mode()
            if mode != ACCESS_MODE_AUTHENTICATED:
                return f(None, *args, **kwargs)
            
            if methods is not None and request.method not in methods:
                return f(None, *args, **kwargs)
            
            # Framework specific: Extract the token
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]

            # caps the token length to prevent huge tokens from causing DoS issues in downstream processing.
            if len(token) > MAX_TOKEN_LEN:
                return None       # triggers 401

            adapter = current_app.extensions['dataone_auth']

            try:
                claims = adapter.validate_and_extract_claims(token_str, required_scope)
            except InsufficientScopeError as e:
                # Framework specific: Return 403 Forbidden
                return jsonify({"error": str(e)}), 403
            except Exception as e:
                # Framework specific: Return 401 Unauthorized
                return jsonify({"error": f"Invalid token: {str(e)}"}), 401

            g.token_claims = claims
            return f(claims, *args, **kwargs)

        return decorated
    return decorator

```

```
def require_scope(required_scope: str, methods=None):
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            mode = get_access_mode()
            
            # In read_only or open mode, skip auth entirely
            if mode != ACCESS_MODE_AUTHENTICATED:
                logger.warning("Access mode '%s': skipping scope validation", mode)
                # Store None in g for consistency
                g.token_claims = None
                return f(*args, **kwargs)
            
            # If methods are specified, only enforce auth for those methods
            if methods is not None and request.method not in methods:
                # No auth required for this method; store None as claims
                g.token_claims = None
                return f(*args, **kwargs)
            
            adapter = current_app.extensions['dataone_auth']

            claims, error = adapter.validate_and_extract_claims(required_scope=required_scope)
            if error:
                return error

            g.token_claims = claims
            # Pass claims as keyword argument for explicit access in handlers
            kwargs['claims'] = claims
            return f(*args, **kwargs)

        return decorated

    return decorator
```

### API Endpoints

**login**

```
@auth_bp.route("/login", methods=["GET"])
def login():
    """Initiate the OIDC login flow.

    Sends the user to the provider's login page. After successful
    authentication the provider redirects back to the ``/authorize``
    callback.

    Args:
        (None)

    Returns:
        302 redirect to the provider's authorization endpoint.
        401/500 JSON error response if login fails.
        403 JSON response if authentication is disabled for the current access mode.

    """
    mode = get_access_mode()
    if mode != ACCESS_MODE_AUTHENTICATED:
        return _auth_error_response(f"Authentication is disabled in '{mode}' mode.", 403)

    adapter = current_app.extensions['dataone_auth']
    oidc_client = adapter.vegbank_oidc # maybe get this dynamically

    try:
        return adapter.authorize_redirect(url_for("main.auth.authorize", _external=True))
    except (OAuthError, RequestException) as exc:
        logger.warning("OIDC authorize_redirect error: %s", exc)
        return _token_error_response(exc)

```

**refresh**

```
@auth_bp.route("/refresh", methods=["POST"])
def refresh_token():
    """Re-validate the user session and return a new access token using the refresh token.

    When an access token expires, the client can call this endpoint with the refresh token 
    to obtain a new access token without requiring the user to log in again. The client 
    can also pass the desired scopes for the new access token, which must be a subset 
    of the original scopes granted to the refresh token.

    Parameters (in JSON body):
    - ``refresh_token`` (string, required): The refresh token issued by the OIDC provider.
    - ``scope`` (string, optional): Space-separated list of scopes to request for the new access token. If omitted, the new access token will have the same scopes as the original token.

    Returns:
    200 JSON with new ``access_token`` and ``refresh_token`` on success.
    400 JSON if the request is missing required parameters.
    401 JSON if the refresh token is invalid, expired, or if client authentication fails.
    500 JSON for unexpected server errors.
    """

    adapter = current_app.extensions.get('dataone_auth')

    # Get the refresh token and desired scopes from the JSON body
    data = request.get_json(silent=True)
    if not data:
        return _token_error_response(MissingParameterError("refresh_token"))

    user_refresh_token = data.get("refresh_token")
    if not user_refresh_token:
        return _token_error_response(MissingParameterError("refresh_token"))

    # The client should pass the scopes that it would like to request for the
    # new access token. If no scopes are provided, we will attempt to get a
    # new access token with the same scopes as the original token. The
    # requested scopes must match or be a subset of the original scopes granted
    # to the token, otherwise the OIDC provider will reject the request.
    requested_scope = data.get("scope")

    # Use Authlib to exchange the refresh token for a new access token
    try:
        oidc_client = adapter.vegbank_oidc # maybe get this dynamically
        if not requested_scope:
            # If no scope is provided, omit the scope parameter to get the same scopes as the original token
            new_tokens = oidc_client.fetch_access_token(
                grant_type="refresh_token",
                refresh_token=user_refresh_token,
            )
        else:
            new_tokens = oidc_client.fetch_access_token(
                grant_type="refresh_token",
                refresh_token=user_refresh_token,
                scope=requested_scope,
            )
        return _token_response(new_tokens, message="Authorization successful")
    except InvalidGrantError as exc:
        # The refresh token was invalid, expired, or revoked by the provider
        logger.debug("The refresh token is invalid or expired: %s", exc)
        return _token_error_response(exc)
    except InvalidClientError as exc:
        # The client_id or client_secret is wrong
        logger.warning("OIDC client authentication failed: %s", exc)
        return _token_error_response(exc)
    except OAuth2Error as exc:
        logger.debug("An OAuth2 error occurred: %s", exc)
        return _token_error_response(exc)
    except Exception as exc:
        # A safety net for non-OAuth errors (e.g., network issues)
        logger.error("Unexpected Exception during refresh: %s", exc, exc_info=True)
        return _token_error_response(exc)

```

**authorize**

```

@auth_bp.route("/authorize", methods=["GET"])
def authorize():
    """OIDC authorization callback endpoint.

    Keycloak redirects here after a successful login with a short-lived
    authorization code. This endpoint exchanges that code for an access
    token, stores the token and returns it to the caller.

    Returns:
        200 JSON with ``token`` on success.
        401 JSON with error details on failure.
        403 JSON response if authentication is disabled for the current access mode.
    """
    mode = get_access_mode()
    if mode != ACCESS_MODE_AUTHENTICATED:
        return _auth_error_response(f"Authentication is disabled in '{mode}' mode.", 403)

    adapter = current_app.extensions.get('dataone_auth')
    oidc_client = adapter.vegbank_oidc

    try:
        token = oidc_client.authorize_access_token()
    except (OAuthError, RequestException) as exc:
        logger.debug("OIDC token exchange error: %s", exc)
        return _token_error_response(exc)

    return _token_response(token, message="Authorization successful")

```

### Response/Error Classes

```
def _auth_error_response(message, status, details=None):
    """Generate a uniform JSON error response for authentication/authorization errors.

    All auth-related error responses should use this helper to guarantee a consistent ``{"error": {"message": ..., "details": ...}}`` object.

    Args:
        message: Error description.
        status: HTTP status code.
        details: Optional additional context (``str(exc)``).  Omitted from the response when *None*.

    Returns:
        Tuple of (JSON response, status code).
    """
    error = {"message": message}
    if details is not None:
        error["details"] = details
    return jsonify({"error": error}), status


def _token_error_response(exc):
    """Produce a uniform JSON error response for token validation/exchange failures."""
    error_map = {
        DecodeError: ("Token decoding failed", 401),
        InvalidClientError: ("OIDC client authentication failed", 401),
        InvalidTokenError: ("Token validation failed", 401),
        InvalidGrantError: ("Invalid or expired refresh token", 401),
        BadSignatureError: ("Token signature verification failed", 401),
        OAuthError: ("Authorization failed", 401),
        OAuth2Error: ("An OAuth2 error occurred", 401),
        KeyError: ("Invalid token structure", 401),
        TypeError: ("Invalid token structure", 401),
        MissingParameterError: ("Missing required parameter", 400),
        ValueError: ("OIDC provider configuration error", 500),
        _requests.RequestException: ("Failed to fetch OIDC provider keys", 502),
    }
    for exc_types, (message, status) in error_map.items():
        if isinstance(exc, exc_types):
            return _auth_error_response(message, status, details=str(exc))
    # Unexpected exception — treat as server error
    return _auth_error_response("Internal authentication error", 500, details=str(exc))


def _token_response(token: dict, message: str = "Token exchange successful"):
    """Produce a uniform JSON response with access and refresh tokens.
    
    Args:
        token: Dict containing token data with 'access_token' and 'refresh_token' keys.
        message: Optional message to include in response.
        
    Returns:
        Tuple of (JSON response, 200 status code).
    """
    return (
        jsonify(
            {
                "message": message,
                "token": {
                    "access_token": token.get("access_token"),
                    "refresh_token": token.get("refresh_token"),
                },
            }
        ),
        200,
    )

```

## FastAPI

```
from fastapi import FastAPI
from dataone.factory import AuthFactory
from dataone.auth import load_client_secrets
import logging

logger = logging.getLogger(__name__)

# 1. Create the FastAPI instance
app = FastAPI()

def init_auth_client():
    """Initialise the DataOne Auth Client for FastAPI."""
    
    try:
        ogdc_secrets = load_client_secrets()
    except Exception as exc:
        logger.warning("Auth unavailable: %s", exc)
        return None

    # Define ogdc-specific scopes if they differ, or use defaults
    ogdc_scopes = ["ogdc:admin", "ogdc:user"]

    # This might return an 'httpx' based Async client instead of a 'requests' one
    auth_client = AuthFactory.create_client("fastapi", ogdc_secrets, ogdc_scopes)
    
    return auth_client

# 3. Store it in the app state for easy access
app.state.auth = init_auth_client()

```