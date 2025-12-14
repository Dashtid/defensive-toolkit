"""
Hardening API Tests

Tests for system hardening endpoints.
"""

import pytest
from api.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


@pytest.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture
def auth_token():
    response = client.post(
        "/api/v1/auth/token", data={"username": "admin", "password": "changeme123"}
    )
    return response.json()["access_token"]


class TestHardeningEndpoints:
    """Test system hardening operations"""

    def test_scan_system_linux(self, auth_headers):
        """Test hardening scan for Linux"""
        scan_data = {
            "target": "192.168.1.100",
            "scan_type": "full",
            "os_type": "linux",
            "compliance_frameworks": ["cis", "stig"],
        }
        response = client.post("/api/v1/hardening/scan", json=scan_data, headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data

    def test_scan_system_windows(self, auth_headers):
        """Test hardening scan for Windows"""
        scan_data = {
            "target": "192.168.1.101",
            "scan_type": "quick",
            "os_type": "windows",
            "compliance_frameworks": ["cis"],
        }
        response = client.post("/api/v1/hardening/scan", json=scan_data, headers=auth_headers)
        assert response.status_code == 200

    def test_list_hardening_scripts(self, auth_headers):
        """Test listing available hardening scripts"""
        response = client.get("/api/v1/hardening/scripts?os=linux", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_apply_hardening_dry_run(self, auth_headers):
        """Test applying hardening in dry-run mode"""
        apply_data = {
            "target": "192.168.1.100",
            "script_id": "linux-cis-level1",
            "dry_run": True,
            "backup": True,
        }
        response = client.post("/api/v1/hardening/apply", json=apply_data, headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "changes" in data or "preview" in data

    def test_check_compliance_cis(self, auth_headers):
        """Test CIS compliance check"""
        check_data = {"target": "192.168.1.100", "framework": "cis", "level": "level1"}
        response = client.post(
            "/api/v1/hardening/compliance", json=check_data, headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert "passed" in data or "score" in data

    def test_get_hardening_status(self, auth_headers):
        """Test getting hardening status for a target"""
        response = client.get("/api/v1/hardening/status?target=192.168.1.100", headers=auth_headers)
        assert response.status_code == 200
