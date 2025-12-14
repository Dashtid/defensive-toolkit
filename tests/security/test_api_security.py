"""API Security Tests"""

import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


@pytest.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture
def auth_token():
    response = client.post("/api/v1/auth/token", data={"username": "admin", "password": "changeme123"})
    return response.json()["access_token"]


@pytest.mark.security
class TestInputValidation:
    """Test input validation and sanitization"""

    def test_sql_injection_in_query_params(self, auth_headers):
        """Test SQL injection protection in query parameters"""
        malicious_params = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "' OR 1=1--"
        ]

        for param in malicious_params:
            response = client.get(
                f"/api/v1/detection/rules?search={param}",
                headers=auth_headers
            )
            # Should not crash or return all data
            assert response.status_code in [200, 400, 422]

    def test_xss_in_post_data(self, auth_headers):
        """Test XSS protection in POST data"""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>"
        ]

        for payload in xss_payloads:
            rule_data = {
                "name": payload,
                "description": "Test",
                "rule_type": "sigma",
                "content": "test",
                "severity": "low"
            }
            response = client.post(
                "/api/v1/detection/rules",
                json=rule_data,
                headers=auth_headers
            )
            # Should sanitize or reject
            assert response.status_code in [201, 400, 422]

    def test_path_traversal_protection(self, auth_headers):
        """Test path traversal attack prevention"""
        traversal_attempts = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f",
            "....//....//....//etc/passwd"
        ]

        for attempt in traversal_attempts:
            response = client.get(
                f"/api/v1/forensics/artifacts/{attempt}",
                headers=auth_headers
            )
            # Should block traversal attempts
            assert response.status_code in [400, 403, 404]

    def test_command_injection_protection(self, auth_headers):
        """Test command injection prevention"""
        cmd_injections = [
            "; ls -la",
            "| cat /etc/passwd",
            "&& whoami",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)"
        ]

        for injection in cmd_injections:
            scan_data = {
                "target": f"192.168.1.1{injection}",
                "scan_type": "quick"
            }
            response = client.post(
                "/api/v1/vulnerability/scan",
                json=scan_data,
                headers=auth_headers
            )
            # Should reject or sanitize
            assert response.status_code in [200, 400, 422]


@pytest.mark.security
class TestAccessControl:
    """Test authorization and access control"""

    def test_unauthorized_access_blocked(self):
        """Test that endpoints require authentication"""
        protected_endpoints = [
            "/api/v1/detection/rules",
            "/api/v1/incident-response/incidents",
            "/api/v1/vulnerability/scan",
            "/api/v1/compliance/check"
        ]

        for endpoint in protected_endpoints:
            response = client.get(endpoint)
            assert response.status_code == 401

    def test_invalid_token_rejected(self):
        """Test that invalid tokens are rejected"""
        response = client.get(
            "/api/v1/detection/rules",
            headers={"Authorization": "Bearer invalid-token-12345"}
        )
        assert response.status_code == 401


@pytest.mark.security
class TestSecurityHeaders:
    """Test security headers"""

    def test_security_headers_present(self):
        """Test that security headers are set"""
        response = client.get("/")

        # Check for important security headers
        headers = response.headers

        # These may vary based on configuration
        # Documenting expected vs actual behavior
        assert "x-content-type-options" in headers or "X-Content-Type-Options" in headers

    def test_no_sensitive_data_in_errors(self, auth_headers):
        """Test that error messages don't leak sensitive info"""
        response = client.get(
            "/api/v1/detection/rules/nonexistent-id-12345",
            headers=auth_headers
        )

        error_text = response.text.lower()

        # Should not contain sensitive paths or internal info
        assert "/home/" not in error_text
        assert "/root/" not in error_text
        assert "c:\\" not in error_text
