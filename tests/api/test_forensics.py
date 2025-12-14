"""Forensics API Tests"""

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


class TestForensicsEndpoints:
    """Test forensics analysis endpoints"""

    def test_analyze_artifact(self, auth_headers):
        """Test forensic artifact analysis"""
        artifact_data = {
            "artifact_path": "/evidence/disk-image.dd",
            "artifact_type": "disk",
            "analysis_type": "full",
            "extract_metadata": True,
        }
        response = client.post(
            "/api/v1/forensics/analyze", json=artifact_data, headers=auth_headers
        )
        assert response.status_code == 200

    def test_generate_timeline(self, auth_headers):
        """Test forensic timeline generation"""
        timeline_data = {
            "source": "/evidence/disk-image.dd",
            "start_time": "2025-01-01T00:00:00Z",
            "end_time": "2025-01-31T23:59:59Z",
            "timezone": "UTC",
        }
        response = client.post(
            "/api/v1/forensics/timeline", json=timeline_data, headers=auth_headers
        )
        assert response.status_code == 200

    def test_collect_evidence(self, auth_headers):
        """Test evidence collection"""
        collect_data = {
            "target": "192.168.1.100",
            "collection_type": "live",
            "artifacts": ["memory", "processes", "network"],
            "output_path": "/evidence/case-001",
        }
        response = client.post("/api/v1/forensics/collect", json=collect_data, headers=auth_headers)
        assert response.status_code == 200

    def test_search_artifacts(self, auth_headers):
        """Test searching within artifacts"""
        search_data = {
            "artifact_path": "/evidence/disk-image.dd",
            "search_term": "malware.exe",
            "search_type": "filename",
            "case_sensitive": False,
        }
        response = client.post("/api/v1/forensics/search", json=search_data, headers=auth_headers)
        assert response.status_code == 200
