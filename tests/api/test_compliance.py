"""Compliance API Tests"""

import pytest
from api.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture
def auth_token():
    response = client.post("/api/v1/auth/token", data={"username": "admin", "password": "changeme123"})
    return response.json()["access_token"]


class TestComplianceEndpoints:
    """Test compliance framework endpoints"""

    def test_list_frameworks(self, auth_headers):
        """Test listing compliance frameworks"""
        response = client.get("/api/v1/compliance/frameworks", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Common frameworks
        framework_names = [f["name"] if isinstance(f, dict) else f for f in data]
        expected_frameworks = {"CIS", "NIST", "PCI-DSS", "HIPAA", "SOC2"}
        assert any(f in framework_names for f in expected_frameworks)

    def test_run_compliance_check(self, auth_headers):
        """Test running compliance check"""
        check_data = {
            "framework": "cis",
            "version": "8.0",
            "targets": ["192.168.1.100", "192.168.1.101"],
            "controls": ["1.1", "1.2", "2.1"]
        }
        response = client.post("/api/v1/compliance/check", json=check_data, headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "results" in data or "passed" in data

    def test_get_compliance_report(self, auth_headers):
        """Test getting compliance report"""
        response = client.get("/api/v1/compliance/reports?framework=cis&format=json", headers=auth_headers)
        assert response.status_code == 200

    def test_validate_policy(self, auth_headers):
        """Test policy validation"""
        policy_data = {
            "policy_file": "security_policy.yml",
            "target": "192.168.1.100",
            "strict_mode": True
        }
        response = client.post("/api/v1/compliance/policy/validate", json=policy_data, headers=auth_headers)
        assert response.status_code == 200
