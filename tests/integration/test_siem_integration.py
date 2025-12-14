"""SIEM Integration Tests with Mocked Responses"""

from unittest.mock import patch

import pytest
from defensive_toolkit.api.main import app
from fastapi.testclient import TestClient

from tests.mocks.external_services import MockElasticClient, MockWazuhClient

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


@pytest.mark.integration
class TestWazuhIntegration:
    """Test Wazuh SIEM integration"""

    @patch("api.integrations.siem.WazuhClient", MockWazuhClient)
    def test_deploy_rule_to_wazuh(self, auth_headers):
        """Test deploying rule to Wazuh with mocked client"""
        deploy_data = {
            "rule_id": "test-rule-001",
            "siem_platform": "wazuh",
            "manager_host": "wazuh.test.com",
        }
        response = client.post(
            "/api/v1/detection/rules/deploy", json=deploy_data, headers=auth_headers
        )
        # Should succeed with mocked client
        assert response.status_code in [200, 201]


@pytest.mark.integration
class TestElasticIntegration:
    """Test Elastic SIEM integration"""

    @patch("api.integrations.siem.ElasticClient", MockElasticClient)
    def test_query_elastic_logs(self, auth_headers):
        """Test querying Elastic logs with mocked client"""
        query_data = {
            "platform": "elastic",
            "query": "event.action: 'logon' AND event.outcome: 'failure'",
            "time_range": "24h",
        }
        response = client.post(
            "/api/v1/threat-hunting/query", json=query_data, headers=auth_headers
        )
        assert response.status_code == 200
