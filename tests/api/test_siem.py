"""
SIEM Integration Router Tests (v1.7.5)

Comprehensive tests for SIEM connection management, querying, and health checks.
"""

from datetime import datetime, timedelta

import pytest
from api.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

# auth_token and auth_headers fixtures are provided by tests/api/conftest.py


@pytest.fixture
def sample_wazuh_connection():
    """Sample Wazuh connection configuration"""
    return {
        "name": "Test Wazuh",
        "platform": "wazuh",
        "host": "localhost",
        "port": 55000,
        "username": "wazuh-api",
        "password": "test-password",
        "auth_type": "basic",
        "use_ssl": True,
        "verify_ssl": False,
        "index_pattern": "wazuh-alerts-*",
        "enabled": True
    }


@pytest.fixture
def sample_elastic_connection():
    """Sample Elastic connection configuration"""
    return {
        "name": "Test Elastic",
        "platform": "elastic",
        "host": "localhost",
        "port": 9200,
        "username": "elastic",
        "password": "test-password",
        "auth_type": "basic",
        "use_ssl": True,
        "verify_ssl": False,
        "index_pattern": ".siem-signals-*",
        "enabled": True
    }


class TestSIEMConnections:
    """Test SIEM connection CRUD operations"""

    def test_list_connections_empty(self, auth_headers):
        """Test listing connections when none exist"""
        response = client.get("/api/v1/siem/connections", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "connections" in data
        assert "total" in data
        assert isinstance(data["connections"], list)

    def test_create_wazuh_connection(self, auth_headers, sample_wazuh_connection):
        """Test creating a Wazuh connection"""
        response = client.post(
            "/api/v1/siem/connections",
            json=sample_wazuh_connection,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == sample_wazuh_connection["name"]
        assert data["platform"] == "wazuh"
        assert data["host"] == sample_wazuh_connection["host"]
        assert data["port"] == sample_wazuh_connection["port"]
        # Password should be masked
        assert data["password"] == "***"
        assert "connection_id" in data

    def test_create_elastic_connection(self, auth_headers, sample_elastic_connection):
        """Test creating an Elastic connection"""
        response = client.post(
            "/api/v1/siem/connections",
            json=sample_elastic_connection,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == sample_elastic_connection["name"]
        assert data["platform"] == "elastic"

    def test_list_connections_after_create(self, auth_headers, sample_wazuh_connection):
        """Test listing connections after creation"""
        # Create a connection first
        client.post(
            "/api/v1/siem/connections",
            json=sample_wazuh_connection,
            headers=auth_headers
        )

        response = client.get("/api/v1/siem/connections", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1

    def test_get_connection_by_id(self, auth_headers, sample_wazuh_connection):
        """Test getting a specific connection"""
        # Create connection
        create_response = client.post(
            "/api/v1/siem/connections",
            json=sample_wazuh_connection,
            headers=auth_headers
        )
        connection_id = create_response.json()["connection_id"]

        # Get the connection
        response = client.get(
            f"/api/v1/siem/connections/{connection_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["connection_id"] == connection_id
        assert data["name"] == sample_wazuh_connection["name"]

    def test_get_nonexistent_connection(self, auth_headers):
        """Test getting a connection that doesn't exist"""
        response = client.get(
            "/api/v1/siem/connections/nonexistent-id",
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_update_connection(self, auth_headers, sample_wazuh_connection):
        """Test updating a connection"""
        # Create connection
        create_response = client.post(
            "/api/v1/siem/connections",
            json=sample_wazuh_connection,
            headers=auth_headers
        )
        connection_id = create_response.json()["connection_id"]

        # Update connection
        updated_config = sample_wazuh_connection.copy()
        updated_config["name"] = "Updated Wazuh"
        updated_config["port"] = 55001

        response = client.put(
            f"/api/v1/siem/connections/{connection_id}",
            json=updated_config,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Wazuh"
        assert data["port"] == 55001

    def test_delete_connection(self, auth_headers, sample_wazuh_connection):
        """Test deleting a connection"""
        # Create connection
        create_response = client.post(
            "/api/v1/siem/connections",
            json=sample_wazuh_connection,
            headers=auth_headers
        )
        connection_id = create_response.json()["connection_id"]

        # Delete connection
        response = client.delete(
            f"/api/v1/siem/connections/{connection_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

        # Verify deletion
        get_response = client.get(
            f"/api/v1/siem/connections/{connection_id}",
            headers=auth_headers
        )
        assert get_response.status_code == 404

    def test_delete_nonexistent_connection(self, auth_headers):
        """Test deleting a connection that doesn't exist"""
        response = client.delete(
            "/api/v1/siem/connections/nonexistent-id",
            headers=auth_headers
        )
        assert response.status_code == 404


class TestSIEMConnectionStatus:
    """Test SIEM connection status and health checks"""

    def test_get_connection_status(self, auth_headers, sample_wazuh_connection):
        """Test getting connection status (will fail connectivity but return status)"""
        # Create connection
        create_response = client.post(
            "/api/v1/siem/connections",
            json=sample_wazuh_connection,
            headers=auth_headers
        )
        connection_id = create_response.json()["connection_id"]

        # Get status - will fail since no actual SIEM is running
        response = client.get(
            f"/api/v1/siem/connections/{connection_id}/status",
            headers=auth_headers
        )
        # Should return 200 with error status, or handle connection error
        assert response.status_code in [200, 500, 503]

    def test_health_check_all_connections(self, auth_headers):
        """Test health check for all connections"""
        response = client.get("/api/v1/siem/health", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_connections" in data
        assert "healthy_count" in data
        assert "unhealthy_count" in data
        assert "results" in data
        assert "checked_at" in data


class TestSIEMQuerying:
    """Test SIEM query operations"""

    def test_query_alerts_missing_connection(self, auth_headers):
        """Test querying alerts with non-existent connection"""
        query_request = {
            "connection_id": "nonexistent-id",
            "time_from": (datetime.utcnow() - timedelta(hours=24)).isoformat(),
            "size": 10
        }
        response = client.post(
            "/api/v1/siem/query",
            json=query_request,
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_query_alerts_with_connection(self, auth_headers, sample_wazuh_connection):
        """Test querying alerts (connection will fail but validates request handling)"""
        # Create connection
        create_response = client.post(
            "/api/v1/siem/connections",
            json=sample_wazuh_connection,
            headers=auth_headers
        )
        connection_id = create_response.json()["connection_id"]

        query_request = {
            "connection_id": connection_id,
            "time_from": (datetime.utcnow() - timedelta(hours=24)).isoformat(),
            "time_to": datetime.utcnow().isoformat(),
            "query": "severity:high",
            "size": 10,
            "from_offset": 0
        }
        response = client.post(
            "/api/v1/siem/query",
            json=query_request,
            headers=auth_headers
        )
        # Will fail to connect but should handle gracefully
        assert response.status_code in [200, 500, 502, 503]

    def test_aggregate_alerts_missing_connection(self, auth_headers):
        """Test aggregation with non-existent connection"""
        agg_request = {
            "connection_id": "nonexistent-id",
            "time_from": (datetime.utcnow() - timedelta(hours=24)).isoformat(),
            "aggregation_type": "terms",
            "field": "rule.id",
            "size": 10
        }
        response = client.post(
            "/api/v1/siem/aggregate",
            json=agg_request,
            headers=auth_headers
        )
        assert response.status_code == 404


class TestSIEMAgentsAndRules:
    """Test SIEM agents and rules endpoints"""

    def test_list_agents_missing_connection(self, auth_headers):
        """Test listing agents with non-existent connection"""
        response = client.get(
            "/api/v1/siem/connections/nonexistent-id/agents",
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_list_rules_missing_connection(self, auth_headers):
        """Test listing rules with non-existent connection"""
        response = client.get(
            "/api/v1/siem/connections/nonexistent-id/rules",
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_list_indices_missing_connection(self, auth_headers):
        """Test listing indices with non-existent connection"""
        response = client.get(
            "/api/v1/siem/connections/nonexistent-id/indices",
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_get_dashboard_stats_missing_connection(self, auth_headers):
        """Test getting dashboard stats with non-existent connection"""
        response = client.get(
            "/api/v1/siem/connections/nonexistent-id/dashboard",
            headers=auth_headers
        )
        assert response.status_code == 404


class TestSIEMPlatforms:
    """Test SIEM platform information"""

    def test_list_supported_platforms(self, auth_headers):
        """Test listing supported SIEM platforms"""
        response = client.get("/api/v1/siem/platforms", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 4  # At least Wazuh, Elastic, OpenSearch, Graylog

        # Verify structure
        for platform in data:
            assert "platform" in platform
            assert "name" in platform
            assert "description" in platform
            assert "default_port" in platform
            assert "auth_types" in platform
            assert "features" in platform

    def test_platform_types_exist(self, auth_headers):
        """Test that expected platform types are present"""
        response = client.get("/api/v1/siem/platforms", headers=auth_headers)
        data = response.json()
        platform_types = [p["platform"] for p in data]

        assert "wazuh" in platform_types
        assert "elastic" in platform_types
        assert "opensearch" in platform_types
        assert "graylog" in platform_types


class TestSIEMAuthentication:
    """Test authentication requirements for SIEM endpoints"""

    def test_list_connections_requires_auth(self):
        """Test that listing connections requires authentication"""
        response = client.get("/api/v1/siem/connections")
        assert response.status_code == 401

    def test_create_connection_requires_auth(self, sample_wazuh_connection):
        """Test that creating connections requires authentication"""
        response = client.post(
            "/api/v1/siem/connections",
            json=sample_wazuh_connection
        )
        assert response.status_code == 401

    def test_health_check_requires_auth(self):
        """Test that health check requires authentication"""
        response = client.get("/api/v1/siem/health")
        assert response.status_code == 401

    def test_query_requires_auth(self):
        """Test that querying requires authentication"""
        query_request = {
            "connection_id": "test-id",
            "time_from": datetime.utcnow().isoformat(),
            "size": 10
        }
        response = client.post("/api/v1/siem/query", json=query_request)
        assert response.status_code == 401


class TestSIEMValidation:
    """Test input validation for SIEM endpoints"""

    def test_create_connection_invalid_platform(self, auth_headers):
        """Test creating connection with invalid platform"""
        invalid_config = {
            "name": "Invalid Platform",
            "platform": "invalid_platform",
            "host": "localhost",
            "port": 9200
        }
        response = client.post(
            "/api/v1/siem/connections",
            json=invalid_config,
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_create_connection_missing_required_fields(self, auth_headers):
        """Test creating connection with missing required fields"""
        invalid_config = {
            "name": "Missing Fields"
            # Missing platform, host, port
        }
        response = client.post(
            "/api/v1/siem/connections",
            json=invalid_config,
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_query_invalid_time_range(self, auth_headers, sample_wazuh_connection):
        """Test querying with invalid time range"""
        # Create connection first
        create_response = client.post(
            "/api/v1/siem/connections",
            json=sample_wazuh_connection,
            headers=auth_headers
        )
        connection_id = create_response.json()["connection_id"]

        # Query with invalid time
        query_request = {
            "connection_id": connection_id,
            "time_from": "invalid-datetime",
            "size": 10
        }
        response = client.post(
            "/api/v1/siem/query",
            json=query_request,
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_list_agents_invalid_limit(self, auth_headers, sample_wazuh_connection):
        """Test listing agents with invalid limit"""
        # Create connection
        create_response = client.post(
            "/api/v1/siem/connections",
            json=sample_wazuh_connection,
            headers=auth_headers
        )
        connection_id = create_response.json()["connection_id"]

        # Request with invalid limit
        response = client.get(
            f"/api/v1/siem/connections/{connection_id}/agents?limit=10000",
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_dashboard_stats_invalid_hours(self, auth_headers, sample_wazuh_connection):
        """Test dashboard stats with invalid hours parameter"""
        # Create connection
        create_response = client.post(
            "/api/v1/siem/connections",
            json=sample_wazuh_connection,
            headers=auth_headers
        )
        connection_id = create_response.json()["connection_id"]

        # Request with invalid hours
        response = client.get(
            f"/api/v1/siem/connections/{connection_id}/dashboard?hours=10000",
            headers=auth_headers
        )
        assert response.status_code == 422
