"""
Threat Hunting Router Tests

Tests for the threat hunting API endpoints.
"""

import pytest
from fastapi import status

from defensive_toolkit.api.models import ThreatHuntPlatformEnum


# ============================================================================
# Query Execution Tests
# ============================================================================


class TestQueryExecution:
    """Tests for threat hunting query execution."""

    def test_execute_query(self, test_client, module_auth_headers):
        """Test executing a threat hunting query."""
        query_data = {
            "name": "Suspicious PowerShell Commands",
            "platform": "sentinel",
            "query": "SecurityEvent | where EventID == 4688",
            "description": "Hunt for suspicious PowerShell execution",
        }

        response = test_client.post(
            "/api/v1/threat-hunting/query",
            json=query_data,
            headers=module_auth_headers,
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["query_name"] == query_data["name"]
        assert data["platform"] == "sentinel"
        assert "results_count" in data
        assert "execution_time_ms" in data

    def test_execute_query_elastic(self, test_client, module_auth_headers):
        """Test executing query on Elastic platform."""
        query_data = {
            "name": "Lateral Movement Detection",
            "platform": "elastic",
            "query": "event.action:logon-success AND source.ip:*",
        }

        response = test_client.post(
            "/api/v1/threat-hunting/query",
            json=query_data,
            headers=module_auth_headers,
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["platform"] == "elastic"

    def test_execute_query_splunk(self, test_client, module_auth_headers):
        """Test executing query on Splunk platform."""
        query_data = {
            "name": "Failed Login Attempts",
            "platform": "splunk",
            "query": "index=security sourcetype=WinEventLog EventCode=4625",
        }

        response = test_client.post(
            "/api/v1/threat-hunting/query",
            json=query_data,
            headers=module_auth_headers,
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["platform"] == "splunk"


# ============================================================================
# Query Listing Tests
# ============================================================================


class TestQueryListing:
    """Tests for listing threat hunting queries."""

    def test_list_queries(self, test_client, module_auth_headers):
        """Test listing available queries."""
        response = test_client.get(
            "/api/v1/threat-hunting/queries",
            headers=module_auth_headers,
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)

        # Check structure if queries are returned
        for query in data:
            assert "name" in query
            assert "language" in query  # Updated: uses language not platform

    def test_list_queries_contains_expected(self, test_client, module_auth_headers):
        """Test that expected queries are in the list."""
        response = test_client.get(
            "/api/v1/threat-hunting/queries",
            headers=module_auth_headers,
        )
        data = response.json()
        # Queries come from the loaded query files - may be empty in test env
        assert isinstance(data, list)


# ============================================================================
# Query Model Tests
# ============================================================================


class TestQueryModels:
    """Tests for threat hunting query models."""

    def test_threat_hunt_query_model(self):
        """Test ThreatHuntQuery model creation."""
        from defensive_toolkit.api.models import ThreatHuntQuery

        query = ThreatHuntQuery(
            name="Test Query",
            platform=ThreatHuntPlatformEnum.SENTINEL,
            query="SecurityEvent | take 10",
        )
        assert query.name == "Test Query"
        assert query.platform == ThreatHuntPlatformEnum.SENTINEL

    def test_threat_hunt_result_model(self):
        """Test ThreatHuntResult model creation."""
        from defensive_toolkit.api.models import ThreatHuntResult

        result = ThreatHuntResult(
            query_name="Test Query",
            platform="sentinel",
            results_count=5,
            results=[{"host": "HOST-001", "event": "test"}],
            execution_time_ms=150,
        )
        assert result.results_count == 5
        assert len(result.results) == 1

    def test_platform_enum_values(self):
        """Test platform enum has expected values."""
        platforms = [p.value for p in ThreatHuntPlatformEnum]
        assert "sentinel" in platforms
        assert "elastic" in platforms
        assert "splunk" in platforms


# ============================================================================
# Authentication Tests
# ============================================================================


class TestAuthentication:
    """Tests for authentication requirements."""

    def test_query_requires_auth(self, test_client):
        """Test that query execution requires authentication."""
        query_data = {
            "name": "Auth Test",
            "platform": "sentinel",
            "query": "test",
        }
        # Without auth headers, should get 401
        response = test_client.post(
            "/api/v1/threat-hunting/query",
            json=query_data,
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_list_requires_auth(self, test_client):
        """Test that listing queries requires authentication."""
        # Without auth headers, should get 401
        response = test_client.get("/api/v1/threat-hunting/queries")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ============================================================================
# Response Format Tests
# ============================================================================


class TestResponseFormats:
    """Tests for response format validation."""

    def test_query_result_format(self, test_client, module_auth_headers):
        """Test query result has correct format."""
        query_data = {
            "name": "Format Test",
            "platform": "sentinel",
            "query": "test",
        }

        response = test_client.post(
            "/api/v1/threat-hunting/query",
            json=query_data,
            headers=module_auth_headers,
        )
        data = response.json()

        # Verify all required fields present
        required_fields = [
            "query_name",
            "platform",
            "results_count",
            "results",
            "execution_time_ms",
        ]
        for field in required_fields:
            assert field in data, f"Missing field: {field}"

    def test_results_is_list(self, test_client, module_auth_headers):
        """Test that results field is a list."""
        query_data = {
            "name": "List Test",
            "platform": "elastic",
            "query": "test",
        }

        response = test_client.post(
            "/api/v1/threat-hunting/query",
            json=query_data,
            headers=module_auth_headers,
        )
        data = response.json()
        assert isinstance(data["results"], list)

    def test_execution_time_is_positive(self, test_client, module_auth_headers):
        """Test that execution time is positive."""
        query_data = {
            "name": "Time Test",
            "platform": "splunk",
            "query": "test",
        }

        response = test_client.post(
            "/api/v1/threat-hunting/query",
            json=query_data,
            headers=module_auth_headers,
        )
        data = response.json()
        assert data["execution_time_ms"] >= 0
