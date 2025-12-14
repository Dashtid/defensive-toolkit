"""Monitoring API Tests"""

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


class TestMonitoringEndpoints:
    """Test security monitoring endpoints"""

    def test_get_system_metrics(self, auth_headers):
        """Test getting system metrics"""
        response = client.get("/api/v1/monitoring/metrics?host=192.168.1.100", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "cpu_usage_percent" in data or "metrics" in data

    def test_list_alerts(self, auth_headers):
        """Test listing security alerts"""
        response = client.get(
            "/api/v1/monitoring/alerts?severity=critical&status=active", headers=auth_headers
        )
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_create_alert_rule(self, auth_headers):
        """Test creating alert rule"""
        alert_data = {
            "name": "High CPU Usage",
            "description": "Alert when CPU exceeds 90% for 5 minutes",
            "metric": "cpu_usage",
            "condition": "gt",
            "threshold": 90,
            "duration": "5m",
            "severity": "warning",
            "action": "email",
        }
        response = client.post(
            "/api/v1/monitoring/alerts/rules", json=alert_data, headers=auth_headers
        )
        assert response.status_code == 201 or response.status_code == 200

    def test_get_dashboard_data(self, auth_headers):
        """Test getting dashboard data"""
        response = client.get("/api/v1/monitoring/dashboard", headers=auth_headers)
        assert response.status_code == 200
