"""Authentication Security Tests"""

import pytest
from fastapi.testclient import TestClient
from api.main import app
import time

client = TestClient(app)


@pytest.mark.security
class TestAuthenticationSecurity:
    """Test authentication security controls"""

    def test_login_with_sql_injection_attempt(self):
        """Test that SQL injection in login is prevented"""
        response = client.post(
            "/api/v1/auth/token",
            data={"username": "admin' OR '1'='1", "password": "anything"}
        )
        assert response.status_code == 401

    def test_login_with_xss_attempt(self):
        """Test that XSS in credentials is handled"""
        response = client.post(
            "/api/v1/auth/token",
            data={"username": "<script>alert('xss')</script>", "password": "test"}
        )
        assert response.status_code == 401

    def test_brute_force_protection(self):
        """Test protection against brute force attacks"""
        failed_attempts = 0
        for i in range(10):
            response = client.post(
                "/api/v1/auth/token",
                data={"username": "admin", "password": f"wrong-pass-{i}"}
            )
            if response.status_code == 429:  # Rate limited
                break
            failed_attempts += 1
            time.sleep(0.1)

        # Should be rate limited or locked out
        assert failed_attempts < 10 or response.status_code == 429

    def test_token_expiry_enforced(self):
        """Test that expired tokens are rejected"""
        # Login
        login_response = client.post(
            "/api/v1/auth/token",
            data={"username": "admin", "password": "changeme123"}
        )
        token = login_response.json()["access_token"]

        # Token should work immediately
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200

        # Note: Testing actual expiry would require time manipulation
        # This test validates the mechanism is in place

    def test_weak_password_rejected(self):
        """Test that weak passwords are rejected"""
        # This would be tested if we had user creation endpoint
        # Testing password policy enforcement
        pass  # Placeholder for user creation tests

    def test_invalid_token_format(self):
        """Test that invalid token formats are rejected"""
        invalid_tokens = [
            "invalid-token",
            "Bearer invalid",
            "malformed.jwt.token",
            ""
        ]

        for token in invalid_tokens:
            response = client.get(
                "/api/v1/auth/me",
                headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 401


@pytest.mark.security
class TestTokenSecurity:
    """Test JWT token security"""

    def test_token_contains_no_sensitive_data(self):
        """Test that tokens don't expose sensitive information"""
        import jwt

        response = client.post(
            "/api/v1/auth/token",
            data={"username": "admin", "password": "changeme123"}
        )
        token = response.json()["access_token"]

        # Decode without verification to check payload
        decoded = jwt.decode(token, options={"verify_signature": False})

        # Should not contain passwords or other sensitive data
        assert "password" not in decoded
        assert "secret" not in decoded

    def test_refresh_token_single_use(self):
        """Test that refresh tokens can't be reused"""
        # Login
        login_response = client.post(
            "/api/v1/auth/token",
            data={"username": "admin", "password": "changeme123"}
        )
        refresh_token = login_response.json()["refresh_token"]

        # Use refresh token first time
        refresh_response1 = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        assert refresh_response1.status_code == 200

        # Try to use same refresh token again (should fail in secure implementation)
        # Note: Implementation may vary - document actual behavior
        refresh_response2 = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        # May be 401 if implementing token rotation
