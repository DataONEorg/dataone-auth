# tests/test_factory.py
import pytest
from dataone.factory import AuthFactory

# Mock config to pass into our adapters
MOCK_CONFIG = {
    "GOOGLE_ID": "mock_id",
    "GOOGLE_SECRET": "mock_secret"
}

def test_factory_returns_flask_adapter():
    # Skip test if Flask isn't installed in this environment
    pytest.importorskip("flask")
    
    # Import inside the test to avoid top-level crashes
    from dataone.adapters.flask import FlaskAuthAdapter
    
    # Act
    adapter = AuthFactory.create_client("flask", config=MOCK_CONFIG)
    
    # Assert
    assert isinstance(adapter, FlaskAuthAdapter)
    assert adapter.config == MOCK_CONFIG

def test_factory_returns_fastapi_adapter():
    # Skip test if Starlette/FastAPI aren't installed in this environment
    pytest.importorskip("starlette")
    
    from dataone.adapters.fastapi import FastAPIAuthAdapter
    
    # Act
    adapter = AuthFactory.create_client("fastapi", config=MOCK_CONFIG)
    
    # Assert
    assert isinstance(adapter, FastAPIAuthAdapter)
    assert adapter.config == MOCK_CONFIG

def test_factory_raises_error_on_unknown_framework():
    # Act & Assert
    with pytest.raises(ValueError, match="Unsupported framework"):
        AuthFactory.create_client("django", config=MOCK_CONFIG)