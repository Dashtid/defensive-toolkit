"""Automation (SOAR) API Router Tests.

Comprehensive tests for automation endpoints including:
- Playbook management (CRUD)
- Playbook execution
- Containment actions
- Enrichment actions
- Notification actions
"""

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from defensive_toolkit.api.main import app


@pytest.fixture(scope="module")
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture(scope="module")
def auth_token(client):
    """Get authentication token."""
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "changeme123"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture(scope="module")
def auth_headers(auth_token):
    """Create auth headers."""
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture(scope="module")
def write_auth_token(client):
    """Get authentication token with write scope."""
    response = client.post(
        "/api/v1/auth/token",
        data={
            "username": "admin",
            "password": "changeme123",
            "scope": "read write",
        },
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture(scope="module")
def write_auth_headers(write_auth_token):
    """Create auth headers with write scope."""
    return {"Authorization": f"Bearer {write_auth_token}"}


@pytest.fixture
def sample_playbook():
    """Sample playbook definition."""
    return {
        "name": "Test Playbook",
        "description": "A test playbook for security response",
        "tasks": [
            {
                "name": "Block IP",
                "action": "block_ip",
                "parameters": {"ip": "192.168.1.100"},
                "continue_on_failure": False,
            },
            {
                "name": "Send Alert",
                "action": "send_email",
                "parameters": {"to": "admin@example.com", "subject": "Alert"},
                "continue_on_failure": True,
            },
        ],
        "variables": {"incident_id": "INC-001"},
    }


@pytest.fixture
def mock_playbook_engine():
    """Mock PlaybookEngine."""
    mock = MagicMock()
    mock.variables = {}
    mock.execution_log = [
        {
            "timestamp": "2024-01-01T12:00:00",
            "task": "Block IP",
            "action": "block_ip",
            "parameters": {"ip": "192.168.1.100"},
            "success": True,
            "result": {"blocked": True},
        },
        {
            "timestamp": "2024-01-01T12:00:01",
            "task": "Send Alert",
            "action": "send_email",
            "parameters": {"to": "admin@example.com"},
            "success": True,
            "result": {"sent": True},
        },
    ]
    mock.execute_playbook.return_value = True
    return mock


@pytest.fixture
def mock_containment():
    """Mock containment module."""
    mock = MagicMock()
    mock.isolate_host.return_value = True
    mock.block_ip.return_value = True
    mock.quarantine_file.return_value = True
    mock.terminate_process.return_value = True
    mock.disable_user_account.return_value = True
    return mock


@pytest.fixture
def mock_enrichment():
    """Mock enrichment module."""
    mock = MagicMock()
    mock.enrich_ioc.return_value = {
        "ioc": "192.168.1.100",
        "type": "ip",
        "reputation": "malicious",
        "sources": {"virustotal": {"malicious": 10}},
    }
    mock.lookup_domain.return_value = {
        "domain": "example.com",
        "resolved_ips": ["93.184.216.34"],
        "whois": {"registrar": "Example Registrar"},
    }
    mock.geolocate_ip.return_value = {
        "ip": "8.8.8.8",
        "country": "United States",
        "city": "Mountain View",
        "latitude": 37.386,
        "longitude": -122.084,
    }
    return mock


@pytest.fixture
def mock_notification():
    """Mock notification module."""
    mock = MagicMock()
    mock.send_email.return_value = True
    mock.send_slack.return_value = True
    mock.send_webhook.return_value = True
    return mock


class TestPlaybookManagement:
    """Test playbook CRUD operations."""

    def test_list_playbooks(self, client, auth_headers):
        """Test listing playbooks."""
        response = client.get(
            "/api/v1/automation/playbooks",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "playbooks" in data
        assert "total" in data
        assert isinstance(data["playbooks"], list)

    def test_create_playbook(self, client, write_auth_headers, sample_playbook):
        """Test creating a playbook."""
        response = client.post(
            "/api/v1/automation/playbooks",
            json=sample_playbook,
            headers=write_auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "playbook_id" in data
        assert data["name"] == sample_playbook["name"]
        assert data["status"] == "created"
        assert data["tasks_count"] == len(sample_playbook["tasks"])

    def test_create_playbook_with_auth(self, client, auth_headers, sample_playbook):
        """Test creating a playbook with authenticated user."""
        # Admin user gets write scope by default
        response = client.post(
            "/api/v1/automation/playbooks",
            json=sample_playbook,
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert "playbook_id" in response.json()

    def test_get_playbook(self, client, write_auth_headers, sample_playbook):
        """Test getting a specific playbook."""
        # First create a playbook
        create_response = client.post(
            "/api/v1/automation/playbooks",
            json=sample_playbook,
            headers=write_auth_headers,
        )
        playbook_id = create_response.json()["playbook_id"]

        # Then get it
        response = client.get(
            f"/api/v1/automation/playbooks/{playbook_id}",
            headers=write_auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["playbook_id"] == playbook_id
        assert data["name"] == sample_playbook["name"]
        assert len(data["tasks"]) == len(sample_playbook["tasks"])

    def test_get_playbook_not_found(self, client, auth_headers):
        """Test getting a non-existent playbook."""
        response = client.get(
            "/api/v1/automation/playbooks/nonexistent-id",
            headers=auth_headers,
        )
        assert response.status_code == 404

    def test_delete_playbook(self, client, write_auth_headers, sample_playbook):
        """Test deleting a playbook."""
        # Create a playbook first
        create_response = client.post(
            "/api/v1/automation/playbooks",
            json=sample_playbook,
            headers=write_auth_headers,
        )
        playbook_id = create_response.json()["playbook_id"]

        # Delete it
        response = client.delete(
            f"/api/v1/automation/playbooks/{playbook_id}",
            headers=write_auth_headers,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "deleted"

        # Verify it's gone
        get_response = client.get(
            f"/api/v1/automation/playbooks/{playbook_id}",
            headers=write_auth_headers,
        )
        assert get_response.status_code == 404

    def test_delete_playbook_not_found(self, client, auth_headers):
        """Test deleting a non-existent playbook returns 404."""
        response = client.delete(
            "/api/v1/automation/playbooks/nonexistent-id",
            headers=auth_headers,
        )
        assert response.status_code == 404


class TestPlaybookExecution:
    """Test playbook execution endpoints."""

    def test_execute_playbook(
        self, client, write_auth_headers, sample_playbook, mock_playbook_engine
    ):
        """Test executing a playbook."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_playbook_engine",
            return_value=mock_playbook_engine,
        ):
            response = client.post(
                "/api/v1/automation/execute",
                json={
                    "playbook": sample_playbook,
                    "variables": {"extra_var": "value"},
                    "dry_run": False,
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert "execution_id" in data
            assert data["playbook_name"] == sample_playbook["name"]
            assert data["status"] in ["completed", "failed"]
            assert "execution_log" in data

    def test_execute_playbook_dry_run(
        self, client, write_auth_headers, sample_playbook, mock_playbook_engine
    ):
        """Test executing a playbook in dry run mode."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_playbook_engine",
            return_value=mock_playbook_engine,
        ):
            response = client.post(
                "/api/v1/automation/execute",
                json={
                    "playbook": sample_playbook,
                    "variables": {},
                    "dry_run": True,
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["dry_run"] is True

    def test_execute_playbook_not_in_executions(
        self, client, auth_headers
    ):
        """Test getting status of execution not in cache."""
        response = client.get(
            "/api/v1/automation/execute/unknown-execution-id/status",
            headers=auth_headers,
        )
        assert response.status_code == 404

    def test_preview_playbook(
        self, client, auth_headers, sample_playbook, mock_playbook_engine
    ):
        """Test previewing a playbook (dry run)."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_playbook_engine",
            return_value=mock_playbook_engine,
        ):
            response = client.post(
                "/api/v1/automation/preview",
                json={
                    "playbook": sample_playbook,
                    "variables": {},
                    "dry_run": False,  # Will be forced to True
                },
                headers=auth_headers,
            )
            # Preview requires write scope internally
            assert response.status_code in [200, 403]

    def test_get_execution_status_not_found(self, client, auth_headers):
        """Test getting status of non-existent execution."""
        response = client.get(
            "/api/v1/automation/execute/nonexistent-id/status",
            headers=auth_headers,
        )
        assert response.status_code == 404

    def test_get_execution_logs_not_found(self, client, auth_headers):
        """Test getting logs of non-existent execution."""
        response = client.get(
            "/api/v1/automation/execute/nonexistent-id/logs",
            headers=auth_headers,
        )
        assert response.status_code == 404


class TestContainmentActions:
    """Test containment action endpoints."""

    def test_isolate_host(self, client, write_auth_headers, mock_containment):
        """Test isolating a host."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_containment_actions",
            return_value=mock_containment,
        ):
            response = client.post(
                "/api/v1/automation/actions/containment/isolate",
                json={
                    "hostname": "infected-host.local",
                    "method": "firewall",
                    "dry_run": False,
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["action"] == "isolate_host"
            assert data["success"] is True
            assert "infected-host.local" in data["message"]

    def test_isolate_host_dry_run(self, client, write_auth_headers, mock_containment):
        """Test isolating a host in dry run mode."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_containment_actions",
            return_value=mock_containment,
        ):
            response = client.post(
                "/api/v1/automation/actions/containment/isolate",
                json={
                    "hostname": "test-host",
                    "method": "edr",
                    "dry_run": True,
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["dry_run"] is True

    def test_block_ip(self, client, write_auth_headers, mock_containment):
        """Test blocking an IP address."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_containment_actions",
            return_value=mock_containment,
        ):
            response = client.post(
                "/api/v1/automation/actions/containment/block-ip",
                json={
                    "ip_address": "10.0.0.100",
                    "direction": "both",
                    "duration": 3600,
                    "dry_run": False,
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["action"] == "block_ip"
            assert data["success"] is True

    def test_quarantine_file(self, client, write_auth_headers, mock_containment):
        """Test quarantining a file."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_containment_actions",
            return_value=mock_containment,
        ):
            response = client.post(
                "/api/v1/automation/actions/containment/quarantine",
                json={
                    "file_path": "/tmp/malware.exe",
                    "quarantine_dir": "/quarantine",
                    "dry_run": False,
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["action"] == "quarantine_file"
            assert data["success"] is True

    def test_terminate_process_by_name(self, client, write_auth_headers, mock_containment):
        """Test terminating a process by name."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_containment_actions",
            return_value=mock_containment,
        ):
            response = client.post(
                "/api/v1/automation/actions/containment/terminate",
                json={
                    "process_name": "malware.exe",
                    "dry_run": False,
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["action"] == "terminate_process"
            assert data["success"] is True

    def test_terminate_process_by_pid(self, client, write_auth_headers, mock_containment):
        """Test terminating a process by PID."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_containment_actions",
            return_value=mock_containment,
        ):
            response = client.post(
                "/api/v1/automation/actions/containment/terminate",
                json={
                    "pid": 1234,
                    "dry_run": False,
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["action"] == "terminate_process"

    def test_terminate_process_missing_identifier(self, client, write_auth_headers):
        """Test terminating a process without name or PID fails."""
        response = client.post(
            "/api/v1/automation/actions/containment/terminate",
            json={"dry_run": False},
            headers=write_auth_headers,
        )
        assert response.status_code == 400
        assert "process_name or pid" in response.json()["detail"]

    def test_disable_user(self, client, write_auth_headers, mock_containment):
        """Test disabling a user account."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_containment_actions",
            return_value=mock_containment,
        ):
            response = client.post(
                "/api/v1/automation/actions/containment/disable-user",
                json={
                    "username": "compromised_user",
                    "dry_run": False,
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["action"] == "disable_user_account"
            assert data["success"] is True

    def test_containment_without_auth(self, client):
        """Test containment actions require authentication."""
        response = client.post(
            "/api/v1/automation/actions/containment/isolate",
            json={"hostname": "test", "method": "firewall", "dry_run": True},
        )
        assert response.status_code == 401


class TestEnrichmentActions:
    """Test enrichment action endpoints."""

    def test_enrich_ioc(self, client, auth_headers, mock_enrichment):
        """Test IOC enrichment."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_enrichment_actions",
            return_value=mock_enrichment,
        ):
            response = client.post(
                "/api/v1/automation/actions/enrichment/ioc",
                json={
                    "ioc": "192.168.1.100",
                    "ioc_type": "ip",
                    "sources": ["virustotal", "abuseipdb"],
                },
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["ioc"] == "192.168.1.100"
            assert data["type"] == "ip"
            assert "reputation" in data
            assert "sources" in data

    def test_enrich_hash_ioc(self, client, auth_headers, mock_enrichment):
        """Test hash IOC enrichment."""
        mock_enrichment.enrich_ioc.return_value = {
            "ioc": "abc123hash",
            "type": "hash",
            "reputation": "unknown",
            "sources": {},
        }
        with patch(
            "defensive_toolkit.api.routers.automation.get_enrichment_actions",
            return_value=mock_enrichment,
        ):
            response = client.post(
                "/api/v1/automation/actions/enrichment/ioc",
                json={
                    "ioc": "abc123hash",
                    "ioc_type": "hash",
                    "sources": ["virustotal"],
                },
                headers=auth_headers,
            )
            assert response.status_code == 200
            assert response.json()["type"] == "hash"

    def test_lookup_domain(self, client, auth_headers, mock_enrichment):
        """Test domain lookup."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_enrichment_actions",
            return_value=mock_enrichment,
        ):
            response = client.get(
                "/api/v1/automation/actions/enrichment/domain/example.com",
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["domain"] == "example.com"
            assert "resolved_ips" in data
            assert "whois" in data

    def test_geolocate_ip(self, client, auth_headers, mock_enrichment):
        """Test IP geolocation."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_enrichment_actions",
            return_value=mock_enrichment,
        ):
            response = client.get(
                "/api/v1/automation/actions/enrichment/geolocate/8.8.8.8",
                headers=auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["ip"] == "8.8.8.8"
            assert data["country"] == "United States"
            assert "latitude" in data
            assert "longitude" in data


class TestNotificationActions:
    """Test notification action endpoints."""

    def test_send_email(self, client, write_auth_headers, mock_notification):
        """Test sending email notification."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_notification_actions",
            return_value=mock_notification,
        ):
            response = client.post(
                "/api/v1/automation/actions/notification/email",
                json={
                    "to": "admin@example.com",
                    "subject": "Security Alert",
                    "body": "A security incident has been detected.",
                    "dry_run": False,
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["action"] == "send_email"
            assert data["success"] is True

    def test_send_slack(self, client, write_auth_headers, mock_notification):
        """Test sending Slack notification."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_notification_actions",
            return_value=mock_notification,
        ):
            response = client.post(
                "/api/v1/automation/actions/notification/slack",
                json={
                    "webhook_url": "https://hooks.slack.com/test",
                    "message": "Security Alert: Incident detected",
                    "dry_run": False,
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["action"] == "send_slack"
            assert data["success"] is True

    def test_send_webhook(self, client, write_auth_headers, mock_notification):
        """Test sending generic webhook."""
        with patch(
            "defensive_toolkit.api.routers.automation.get_notification_actions",
            return_value=mock_notification,
        ):
            response = client.post(
                "/api/v1/automation/actions/notification/webhook",
                json={
                    "url": "https://api.example.com/webhook",
                    "payload": {"event": "alert", "severity": "high"},
                    "dry_run": False,
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["action"] == "send_webhook"
            assert data["success"] is True

    def test_notification_without_auth(self, client):
        """Test notification actions require authentication."""
        response = client.post(
            "/api/v1/automation/actions/notification/email",
            json={
                "to": "test@example.com",
                "subject": "Test",
                "body": "Test",
                "dry_run": True,
            },
        )
        assert response.status_code == 401


class TestAvailableActions:
    """Test available actions listing."""

    def test_list_available_actions(self, client, auth_headers):
        """Test listing all available actions."""
        response = client.get(
            "/api/v1/automation/actions",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "actions" in data
        assert "containment" in data["actions"]
        assert "enrichment" in data["actions"]
        assert "notification" in data["actions"]
        assert data["total"] == 11

    def test_containment_actions_listed(self, client, auth_headers):
        """Test containment actions are listed."""
        response = client.get(
            "/api/v1/automation/actions",
            headers=auth_headers,
        )
        containment = response.json()["actions"]["containment"]
        action_names = [a["name"] for a in containment]
        assert "isolate_host" in action_names
        assert "block_ip" in action_names
        assert "quarantine_file" in action_names

    def test_enrichment_actions_listed(self, client, auth_headers):
        """Test enrichment actions are listed."""
        response = client.get(
            "/api/v1/automation/actions",
            headers=auth_headers,
        )
        enrichment = response.json()["actions"]["enrichment"]
        action_names = [a["name"] for a in enrichment]
        assert "enrich_ioc" in action_names
        assert "lookup_domain" in action_names
        assert "geolocate_ip" in action_names


class TestServiceUnavailable:
    """Test handling of unavailable services."""

    def test_playbook_engine_http_exception(self, client, write_auth_headers, sample_playbook):
        """Test handling when playbook engine raises HTTPException."""
        from fastapi import HTTPException

        with patch(
            "defensive_toolkit.api.routers.automation.get_playbook_engine",
            side_effect=HTTPException(
                status_code=503,
                detail="Playbook engine module not available",
            ),
        ):
            response = client.post(
                "/api/v1/automation/execute",
                json={
                    "playbook": sample_playbook,
                    "variables": {},
                    "dry_run": False,
                },
                headers=write_auth_headers,
            )
            assert response.status_code == 503

    def test_containment_module_unavailable(self, client, write_auth_headers):
        """Test handling when containment module is unavailable."""
        from fastapi import HTTPException

        with patch(
            "defensive_toolkit.api.routers.automation.get_containment_actions",
            side_effect=HTTPException(
                status_code=503,
                detail="Containment actions module not available",
            ),
        ):
            response = client.post(
                "/api/v1/automation/actions/containment/isolate",
                json={"hostname": "test", "method": "firewall", "dry_run": True},
                headers=write_auth_headers,
            )
            assert response.status_code == 503

    def test_enrichment_module_unavailable(self, client, auth_headers):
        """Test handling when enrichment module is unavailable."""
        from fastapi import HTTPException

        with patch(
            "defensive_toolkit.api.routers.automation.get_enrichment_actions",
            side_effect=HTTPException(
                status_code=503,
                detail="Enrichment actions module not available",
            ),
        ):
            response = client.post(
                "/api/v1/automation/actions/enrichment/ioc",
                json={"ioc": "test", "ioc_type": "ip", "sources": []},
                headers=auth_headers,
            )
            assert response.status_code == 503


class TestAuthentication:
    """Test authentication requirements."""

    def test_playbooks_require_auth(self, client):
        """Test playbooks endpoint requires authentication."""
        response = client.get("/api/v1/automation/playbooks")
        assert response.status_code == 401

    def test_actions_require_auth(self, client):
        """Test actions endpoint requires authentication."""
        response = client.get("/api/v1/automation/actions")
        assert response.status_code == 401

    def test_execute_requires_auth(self, client):
        """Test execute endpoint requires authentication."""
        response = client.post(
            "/api/v1/automation/execute",
            json={"playbook": {"name": "test", "description": "test", "tasks": []}},
        )
        assert response.status_code == 401
