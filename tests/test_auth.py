"""Unit tests for auth.py helpers."""
import pytest
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from dataone.auth import (
    AuthFactory,
    InvalidTokenError,
    MissingParameterError,
    TokenExtractionError,
    decode_claims,
    extract_orcid,
    extract_token_from_header,
)


def test_extract_orcid_returns_https_uri_from_https_orcid_claim():
    """Test that extract_orcid returns the canonical HTTPS URI when the orcid claim is 
    already a full HTTPS URI."""
    claims = {"orcid": "https://orcid.org/0000-0002-1825-0097"}
    assert extract_orcid(claims) == "https://orcid.org/0000-0002-1825-0097"


def test_extract_orcid_normalises_http_orcid_claim_to_https():
    """Test that extract_orcid upgrades an http:// orcid claim URI to the canonical
     https:// URI."""
    claims = {"orcid": "http://orcid.org/0000-0002-1825-0097"}
    assert extract_orcid(claims) == "https://orcid.org/0000-0002-1825-0097"


def test_extract_orcid_normalises_bare_id_to_https_uri():
    """Test that extract_orcid expands a bare ORCID iD to the canonical HTTPS URI."""
    claims = {"orcid": "0000-0002-1825-0097"}
    assert extract_orcid(claims) == "https://orcid.org/0000-0002-1825-0097"


def test_extract_orcid_returns_none_for_none_input():
    """Test that extract_orcid returns None when called with None instead of a
     claims dict."""
    assert extract_orcid(None) is None


def test_extract_orcid_returns_none_for_empty_claims():
    """Test that extract_orcid returns None when called with an empty claims dict."""
    assert extract_orcid({}) is None

def test_extract_token_success():
    """Test standard valid Bearer token extraction."""
    token = "header.payload.signature"
    auth_header = f"Bearer {token}"
    assert extract_token_from_header(auth_header) == token

def test_extract_token_missing_header():
    """Test error when header is None or empty string."""
    with pytest.raises(MissingParameterError, match="Missing Authorization header"):
        extract_token_from_header("")

def test_extract_token_invalid_format():
    """Test error when 'Bearer ' prefix is missing."""
    with pytest.raises(TokenExtractionError,
     match="Invalid Authorization header format"):
        extract_token_from_header("Token abc.def.ghi")

def test_extract_token_empty_after_prefix():
    """Test error when header is just 'Bearer ' with no content."""
    with pytest.raises(TokenExtractionError, match="Token is empty"):
        extract_token_from_header("Bearer    ")

def test_extract_token_malformed_jwt():
    """Test error when token doesn't have 2 dots."""
    with pytest.raises(TokenExtractionError, match="Token is malformed"):
        extract_token_from_header("Bearer not-a-jwt")

def test_extract_token_too_long():
    """Test DoS protection for oversized tokens."""
    long_token = "a.b." + ("c" * 20000) # Exceeds default 16,384
    with pytest.raises(TokenExtractionError,
     match="Token exceeds maximum allowed length"):
        extract_token_from_header(f"Bearer {long_token}")

def test_decode_claims_success():
    # generate rsa key
    raw_key = RSAKey.generate_key(2048)
    
    # export to dict and strictly set a string 'kid'
    private_jwk = raw_key.as_dict(is_private=True)
    private_jwk['kid'] = 'test-key-id-1'
    
    # re-import the key so it officially has the kid, and create the public JWKS
    key = RSAKey.import_key(private_jwk)
    public_jwk = KeySet.import_key_set({"keys": [key.as_dict(is_private=False)]})
    
    # setup mock claims/headers
    header = {'alg': 'RS256', 'kid': 'test-key-id-1'}
    payload = {
        "iss": "https://auth.example.com",
        "aud": "my_client_id",
        "azp": "my_client_id",
        "sub": "12345",
        "scope": "openid profile"
    }
    
    # create a signed token
    token = jwt.encode(header, payload, key)

    # test
    result = decode_claims(
        token_str=token,
        jwks=public_jwk,
        client_id="my_client_id",
        issuer="https://auth.example.com"
    )

    assert result['sub'] == "12345"
    assert result['iss'] == "https://auth.example.com"


def test_decode_claims_invalid_issuer():
    raw_key = RSAKey.generate_key(2048)
    
    private_jwk = raw_key.as_dict(is_private=True)
    private_jwk['kid'] = 'test-key-id-2'
    
    key = RSAKey.import_key(private_jwk)
    public_jwk = KeySet.import_key_set({"keys": [key.as_dict(is_private=False)]})
    
    # token has 'wrong-issuer'
    header = {'alg': 'RS256', 'kid': 'test-key-id-2'}
    payload = {
        "iss": "wrong-issuer",
        "aud": "my_client_id",
        "azp": "my_client_id"
    }
    token = jwt.encode(header, payload, key)

    # should raise InvalidTokenError
    with pytest.raises(InvalidTokenError, match="Invalid issuer"):
        decode_claims(token, public_jwk, "my_client_id", "https://auth.example.com")
MOCK_SECRETS = {
    "client_id": "test client",
    "client_secret": "a string",
    "server_metadata_url": "https://url.com",
}

MOCK_SCOPES = ["vegbank:admin", "vegbank:contributor", "vegbank:user"]

def test_factory_returns_flask_adapter():
    # Skip test if Flask isn't installed in this environment
    pytest.importorskip("flask")
    
    from dataone.auth import FlaskAuthAdapter
    
    adapter = AuthFactory.create_client("flask",
     secrets=MOCK_SECRETS,
      scopes=MOCK_SCOPES)
    
    assert isinstance(adapter, FlaskAuthAdapter)
    assert adapter.secrets == MOCK_SECRETS

def test_factory_returns_fastapi_adapter():
    # Skip test if Starlette/FastAPI aren't installed in this environment
    pytest.importorskip("starlette")
    
    from dataone.auth import FastAPIAuthAdapter
    
    adapter = AuthFactory.create_client("fastapi",
     secrets=MOCK_SECRETS,
      scopes=MOCK_SCOPES)
    
    assert isinstance(adapter, FastAPIAuthAdapter)
    assert adapter.secrets == MOCK_SECRETS

def test_factory_raises_error_on_unknown_framework():

    with pytest.raises(ValueError, match="Unsupported framework"):
        AuthFactory.create_client("django",
         secrets=MOCK_SECRETS,
          scopes=MOCK_SCOPES)