"""Log Analysis API Tests"""

import pytest
from defensive_toolkit.api.main import app
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


class TestLogAnalysisEndpoints:
    """Test log analysis endpoints"""

    def test_parse_logs(self, auth_headers):
        """Test log parsing"""
        parse_data = {
            "log_file": "/var/log/syslog",
            "log_type": "syslog",
            "parse_format": "json",
            "filters": {"severity": ["error", "critical"]},
        }
        response = client.post("/api/v1/log-analysis/parse", json=parse_data, headers=auth_headers)
        assert response.status_code == 200

    def test_detect_anomalies(self, auth_headers):
        """Test anomaly detection"""
        anomaly_data = {
            "log_source": "web-server",
            "time_range": "24h",
            "baseline_period": "7d",
            "sensitivity": "medium",
        }
        response = client.post(
            "/api/v1/log-analysis/anomalies", json=anomaly_data, headers=auth_headers
        )
        assert response.status_code == 200

    def test_correlate_events(self, auth_headers):
        """Test event correlation"""
        correlation_data = {
            "event_sources": ["firewall", "ids", "auth"],
            "time_window": "5m",
            "correlation_rules": ["brute-force", "port-scan"],
            "min_events": 5,
        }
        response = client.post(
            "/api/v1/log-analysis/correlate", json=correlation_data, headers=auth_headers
        )
        assert response.status_code == 200

    def test_generate_statistics(self, auth_headers):
        """Test log statistics generation"""
        stats_data = {
            "log_source": "all",
            "time_range": "24h",
            "group_by": "source_ip",
            "aggregations": ["count", "unique_users", "top_events"],
        }
        response = client.post("/api/v1/log-analysis/stats", json=stats_data, headers=auth_headers)
        assert response.status_code == 200
