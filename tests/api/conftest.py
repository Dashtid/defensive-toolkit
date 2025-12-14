"""
API Test Configuration

This conftest.py provides shared fixtures for all API tests and
configures the test environment (disabling rate limiting, etc.)
"""

import os

import pytest

# Disable rate limiting for tests before importing any API modules
os.environ["RATE_LIMIT_ENABLED"] = "false"

from api.main import app
from fastapi.testclient import TestClient


# Module-scoped TestClient to share across tests
@pytest.fixture(scope="module")
def test_client():
    """Provide a shared test client for the module"""
    return TestClient(app)


# Session-scoped auth token to minimize auth requests
@pytest.fixture(scope="module")
def module_auth_token():
    """Get authentication token once per module to avoid rate limiting"""
    client = TestClient(app)
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "changeme123"}
    )
    if response.status_code != 200:
        pytest.fail(f"Failed to get auth token: {response.json()}")
    return response.json()["access_token"]


@pytest.fixture(scope="module")
def module_auth_headers(module_auth_token):
    """Get authentication headers once per module"""
    return {"Authorization": f"Bearer {module_auth_token}"}


# Function-scoped fixtures that use the module token
@pytest.fixture
def auth_token(module_auth_token):
    """Alias for module_auth_token for backwards compatibility"""
    return module_auth_token


@pytest.fixture
def auth_headers(module_auth_headers):
    """Alias for module_auth_headers for backwards compatibility"""
    return module_auth_headers
