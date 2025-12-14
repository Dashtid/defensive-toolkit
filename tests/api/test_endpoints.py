"""
API Endpoint Tests

Tests for all category routers.
"""

import pytest
from fastapi.testclient import TestClient

from defensive_toolkit.api.main import app

client = TestClient(app)


@pytest.fixture
def auth_token():
    """Fixture to get authentication token"""
    response = client.post(
        "/api/v1/auth/token", data={"username": "admin", "password": "changeme123"}
    )
    return response.json()["access_token"]


@pytest.fixture
def auth_headers(auth_token):
    """Fixture to get authentication headers"""
    return {"Authorization": f"Bearer {auth_token}"}


class TestHealthEndpoints:
    """Test health and root endpoints"""

    def test_root_endpoint(self):
        """Test root endpoint returns API info"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "version" in data

    def test_health_check(self):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "services" in data


class TestDetectionRulesEndpoints:
    """Test detection rules endpoints"""

    def test_list_rules(self, auth_headers):
        """Test listing detection rules"""
        response = client.get("/api/v1/detection/rules", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "rules" in data
        assert "total" in data

    def test_create_rule(self, auth_headers):
        """Test creating a detection rule"""
        rule_data = {
            "name": "Test Rule",
            "description": "Test description",
            "rule_type": "sigma",
            "content": "detection:\n  selection:\n    test: value",
            "severity": "medium",
            "tags": ["test"],
        }
        response = client.post("/api/v1/detection/rules", json=rule_data, headers=auth_headers)
        assert response.status_code == 201


class TestIncidentResponseEndpoints:
    """Test incident response endpoints"""

    def test_list_incidents(self, auth_headers):
        """Test listing incidents"""
        response = client.get("/api/v1/incident-response/incidents", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_create_incident(self, auth_headers):
        """Test creating an incident"""
        incident_data = {
            "title": "Test Incident",
            "description": "Test description",
            "severity": "high",
        }
        response = client.post(
            "/api/v1/incident-response/incidents", json=incident_data, headers=auth_headers
        )
        assert response.status_code == 201

    def test_list_playbooks(self, auth_headers):
        """Test listing IR playbooks"""
        response = client.get("/api/v1/incident-response/playbooks", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)


class TestThreatHuntingEndpoints:
    """Test threat hunting endpoints"""

    def test_list_queries(self, auth_headers):
        """Test listing threat hunting queries"""
        response = client.get("/api/v1/threat-hunting/queries", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)


class TestHardeningEndpoints:
    """Test hardening endpoints"""

    def test_scan_system(self, auth_headers):
        """Test hardening scan"""
        scan_data = {"target": "localhost", "os_type": "linux", "cis_level": "level_1"}
        response = client.post("/api/v1/hardening/scan", json=scan_data, headers=auth_headers)
        assert response.status_code == 200


class TestForensicsEndpoints:
    """Test forensics endpoints"""

    def test_list_artifact_types(self, auth_headers):
        """Test listing artifact types"""
        response = client.get("/api/v1/forensics/artifacts/types", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)


class TestVulnerabilityEndpoints:
    """Test vulnerability management endpoints"""

    def test_scan_target(self, auth_headers):
        """Test vulnerability scan"""
        scan_data = {"target": "192.168.1.1", "scan_type": "quick"}
        response = client.post("/api/v1/vulnerability/scan", json=scan_data, headers=auth_headers)
        assert response.status_code == 200


class TestAutomationEndpoints:
    """Test automation/SOAR endpoints"""

    def test_list_playbooks(self, auth_headers):
        """Test listing automation playbooks"""
        response = client.get("/api/v1/automation/playbooks", headers=auth_headers)
        assert response.status_code == 200


class TestComplianceEndpoints:
    """Test compliance endpoints"""

    def test_list_frameworks(self, auth_headers):
        """Test listing compliance frameworks"""
        response = client.get("/api/v1/compliance/frameworks", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_check_compliance(self, auth_headers):
        """Test compliance check"""
        check_data = {"framework": "cis", "target": "localhost"}
        response = client.post("/api/v1/compliance/check", json=check_data, headers=auth_headers)
        assert response.status_code == 200


class TestLogAnalysisEndpoints:
    """Test log analysis endpoints"""

    def test_list_log_sources(self, auth_headers):
        """Test listing log sources"""
        response = client.get("/api/v1/log-analysis/sources", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)


class TestMonitoringEndpoints:
    """Test monitoring endpoints"""

    def test_get_metrics(self, auth_headers):
        """Test getting monitoring metrics"""
        response = client.get("/api/v1/monitoring/metrics", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "cpu_usage_percent" in data
        assert "memory_usage_percent" in data

    def test_list_alerts(self, auth_headers):
        """Test listing monitoring alerts"""
        response = client.get("/api/v1/monitoring/alerts", headers=auth_headers)
        assert response.status_code == 200
