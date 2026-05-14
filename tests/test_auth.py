"""Unit tests for auth.py helpers."""
import pytest

from dataone.auth import AuthFactory, extract_orcid


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