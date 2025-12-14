"""Automation & SOAR API Tests"""

import pytest
from fastapi.testclient import TestClient

from defensive_toolkit.api.main import app

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


class TestAutomationEndpoints:
    """Test automation and SOAR endpoints"""

    def test_list_playbooks(self, auth_headers):
        """Test listing SOAR playbooks"""
        response = client.get("/api/v1/automation/playbooks", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_execute_workflow(self, auth_headers):
        """Test executing SOAR workflow"""
        workflow_data = {
            "workflow_id": "phishing-response",
            "trigger_data": {
                "email_subject": "Urgent: Update credentials",
                "sender": "attacker@evil.com",
                "recipients": ["user@example.com"],
            },
            "auto_approve": False,
        }
        response = client.post(
            "/api/v1/automation/workflows/execute", json=workflow_data, headers=auth_headers
        )
        assert response.status_code == 200

    def test_get_workflow_status(self, auth_headers):
        """Test getting workflow execution status"""
        response = client.get(
            "/api/v1/automation/workflows/status?workflow_id=12345", headers=auth_headers
        )
        assert response.status_code == 200

    def test_create_integration(self, auth_headers):
        """Test creating external integration"""
        integration_data = {
            "name": "SIEM Integration",
            "type": "wazuh",
            "config": {
                "host": "wazuh.example.com",
                "port": 55000,
                "username": "api-user",
                "password": "test-password",
            },
            "enabled": True,
        }
        response = client.post(
            "/api/v1/automation/integrations", json=integration_data, headers=auth_headers
        )
        assert response.status_code == 201 or response.status_code == 200
