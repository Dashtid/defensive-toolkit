"""
Incident Response Router Tests

Comprehensive tests for the incident response API endpoints including:
- Incident CRUD operations
- Runbook management
- Runbook execution
- Approval workflow
- Evidence chain management
- Rollback functionality
"""

import pytest
from datetime import datetime
from fastapi import status
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from defensive_toolkit.api.main import app
from defensive_toolkit.api.models import (
    Incident,
    IncidentStatusEnum,
    SeverityEnum,
    StatusEnum,
    RunbookExecutionModeEnum,
)
from defensive_toolkit.api.routers import incident_response


# Test fixtures
@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def auth_headers():
    """Mock authentication headers."""
    return {"Authorization": "Bearer test-token"}


@pytest.fixture
def mock_auth():
    """Mock authentication for all requests."""
    with patch(
        "defensive_toolkit.api.dependencies.get_current_active_user",
        return_value="test_user",
    ):
        with patch(
            "defensive_toolkit.api.dependencies.require_write_scope",
            return_value="test_user",
        ):
            yield


@pytest.fixture(autouse=True)
def clear_databases():
    """Clear in-memory databases before each test."""
    incident_response.incidents_db.clear()
    incident_response.executions_db.clear()
    incident_response.approvals_db.clear()
    yield
    incident_response.incidents_db.clear()
    incident_response.executions_db.clear()
    incident_response.approvals_db.clear()


@pytest.fixture
def sample_incident():
    """Sample incident data."""
    return {
        "title": "Suspicious PowerShell Activity",
        "description": "Detected encoded PowerShell commands on HOST-001",
        "severity": "high",
        "source": "EDR Alert",
        "affected_assets": ["HOST-001"],
        "assigned_to": "analyst@example.com",
    }


@pytest.fixture
def sample_runbook_request():
    """Sample runbook execution request."""
    return {
        "runbook_id": "malware-response",
        "mode": "dry_run",
        "target_host": "HOST-001",
        "incident_id": "INC-TEST-001",
        "variables": {"severity": "high"},
    }


# ============================================================================
# Incident CRUD Tests
# ============================================================================


class TestIncidentManagement:
    """Tests for incident CRUD operations."""

    def test_list_incidents_empty(self, client, mock_auth):
        """Test listing incidents when none exist."""
        response = client.get("/api/v1/incident-response/incidents")
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == []

    def test_create_incident(self, client, mock_auth, sample_incident):
        """Test creating a new incident."""
        response = client.post(
            "/api/v1/incident-response/incidents",
            json=sample_incident,
        )
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["status"] == "success"
        assert "incident_id" in data["data"]
        assert data["data"]["incident_id"].startswith("INC-")

    def test_get_incident(self, client, mock_auth, sample_incident):
        """Test retrieving a specific incident."""
        # Create incident first
        create_response = client.post(
            "/api/v1/incident-response/incidents",
            json=sample_incident,
        )
        incident_id = create_response.json()["data"]["incident_id"]

        # Get the incident
        response = client.get(f"/api/v1/incident-response/incidents/{incident_id}")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["id"] == incident_id
        assert data["title"] == sample_incident["title"]
        assert data["status"] == "new"

    def test_get_incident_not_found(self, client, mock_auth):
        """Test retrieving non-existent incident."""
        response = client.get("/api/v1/incident-response/incidents/INC-NONEXISTENT")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_update_incident(self, client, mock_auth, sample_incident):
        """Test updating an existing incident."""
        # Create incident
        create_response = client.post(
            "/api/v1/incident-response/incidents",
            json=sample_incident,
        )
        incident_id = create_response.json()["data"]["incident_id"]

        # Update incident
        updated_data = sample_incident.copy()
        updated_data["status"] = "investigating"
        updated_data["severity"] = "critical"

        response = client.put(
            f"/api/v1/incident-response/incidents/{incident_id}",
            json=updated_data,
        )
        assert response.status_code == status.HTTP_200_OK

        # Verify update
        get_response = client.get(f"/api/v1/incident-response/incidents/{incident_id}")
        data = get_response.json()
        assert data["status"] == "investigating"
        assert data["severity"] == "critical"

    def test_update_incident_not_found(self, client, mock_auth, sample_incident):
        """Test updating non-existent incident."""
        response = client.put(
            "/api/v1/incident-response/incidents/INC-NONEXISTENT",
            json=sample_incident,
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_delete_incident(self, client, mock_auth, sample_incident):
        """Test deleting an incident."""
        # Create incident
        create_response = client.post(
            "/api/v1/incident-response/incidents",
            json=sample_incident,
        )
        incident_id = create_response.json()["data"]["incident_id"]

        # Delete incident
        response = client.delete(f"/api/v1/incident-response/incidents/{incident_id}")
        assert response.status_code == status.HTTP_200_OK

        # Verify deletion
        get_response = client.get(f"/api/v1/incident-response/incidents/{incident_id}")
        assert get_response.status_code == status.HTTP_404_NOT_FOUND

    def test_delete_incident_not_found(self, client, mock_auth):
        """Test deleting non-existent incident."""
        response = client.delete("/api/v1/incident-response/incidents/INC-NONEXISTENT")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_list_incidents_with_filters(self, client, mock_auth, sample_incident):
        """Test listing incidents with filters."""
        # Create multiple incidents
        client.post("/api/v1/incident-response/incidents", json=sample_incident)

        low_severity = sample_incident.copy()
        low_severity["title"] = "Low severity incident"
        low_severity["severity"] = "low"
        client.post("/api/v1/incident-response/incidents", json=low_severity)

        # Filter by severity
        response = client.get(
            "/api/v1/incident-response/incidents",
            params={"severity_filter": "high"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 1
        assert data[0]["severity"] == "high"

    def test_list_incidents_pagination(self, client, mock_auth, sample_incident):
        """Test incident list pagination."""
        # Create 5 incidents
        for i in range(5):
            incident = sample_incident.copy()
            incident["title"] = f"Incident {i}"
            client.post("/api/v1/incident-response/incidents", json=incident)

        # Get with limit
        response = client.get(
            "/api/v1/incident-response/incidents",
            params={"limit": 2, "offset": 0},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()) == 2

        # Get with offset
        response = client.get(
            "/api/v1/incident-response/incidents",
            params={"limit": 2, "offset": 2},
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.json()) == 2

    def test_incident_closed_sets_closed_at(self, client, mock_auth, sample_incident):
        """Test that closing an incident sets closed_at timestamp."""
        # Create incident
        create_response = client.post(
            "/api/v1/incident-response/incidents",
            json=sample_incident,
        )
        incident_id = create_response.json()["data"]["incident_id"]

        # Close the incident
        updated_data = sample_incident.copy()
        updated_data["status"] = "closed"

        client.put(
            f"/api/v1/incident-response/incidents/{incident_id}",
            json=updated_data,
        )

        # Verify closed_at is set
        get_response = client.get(f"/api/v1/incident-response/incidents/{incident_id}")
        data = get_response.json()
        assert data["status"] == "closed"
        assert data.get("closed_at") is not None


# ============================================================================
# Runbook Management Tests
# ============================================================================


class TestRunbookManagement:
    """Tests for runbook listing and retrieval."""

    def test_list_runbooks_no_yaml(self, client, mock_auth):
        """Test listing runbooks when YAML not available."""
        with patch.object(incident_response, "YAML_AVAILABLE", False):
            response = client.get("/api/v1/incident-response/runbooks")
            assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    def test_list_runbooks_empty_dir(self, client, mock_auth):
        """Test listing runbooks with empty directory."""
        with patch.object(incident_response, "YAML_AVAILABLE", True):
            with patch.object(incident_response, "RUNBOOKS_DIR") as mock_dir:
                mock_dir.exists.return_value = False
                response = client.get("/api/v1/incident-response/runbooks")
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["total"] == 0

    def test_get_runbook_not_found(self, client, mock_auth):
        """Test getting non-existent runbook."""
        with patch.object(incident_response, "YAML_AVAILABLE", True):
            response = client.get("/api/v1/incident-response/runbooks/nonexistent")
            assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_get_runbook_no_yaml(self, client, mock_auth):
        """Test getting runbook when YAML not available."""
        with patch.object(incident_response, "YAML_AVAILABLE", False):
            response = client.get("/api/v1/incident-response/runbooks/test")
            assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


# ============================================================================
# Runbook Execution Tests
# ============================================================================


class TestRunbookExecution:
    """Tests for runbook execution functionality."""

    def test_execute_runbook_no_yaml(self, client, mock_auth, sample_runbook_request):
        """Test executing runbook when YAML not available."""
        with patch.object(incident_response, "YAML_AVAILABLE", False):
            response = client.post(
                "/api/v1/incident-response/runbooks/execute",
                json=sample_runbook_request,
            )
            assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    def test_execute_runbook_not_found(self, client, mock_auth, sample_runbook_request):
        """Test executing non-existent runbook."""
        with patch.object(incident_response, "YAML_AVAILABLE", True):
            response = client.post(
                "/api/v1/incident-response/runbooks/execute",
                json=sample_runbook_request,
            )
            assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_list_executions_empty(self, client, mock_auth):
        """Test listing executions when none exist."""
        response = client.get("/api/v1/incident-response/executions")
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == []

    def test_get_execution_not_found(self, client, mock_auth):
        """Test getting non-existent execution."""
        response = client.get("/api/v1/incident-response/executions/EXE-NONEXISTENT")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_list_executions_with_filter(self, client, mock_auth):
        """Test listing executions with status filter."""
        # Add a mock execution
        incident_response.executions_db["EXE-001"] = {
            "execution_id": "EXE-001",
            "runbook_name": "Test Runbook",
            "runbook_version": "1.0.0",
            "incident_id": "INC-001",
            "status": "success",
            "mode": "dry_run",
            "started_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "completed_at": None,
            "current_step": 0,
            "total_steps": 5,
            "steps_completed": 5,
            "steps_failed": 0,
            "steps_skipped": 0,
            "steps_awaiting": 0,
            "step_results": [],
            "variables": {},
            "analyst": "test_user",
            "target_host": "HOST-001",
        }

        response = client.get(
            "/api/v1/incident-response/executions",
            params={"status_filter": "success"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 1
        assert data[0]["status"] == "success"

    def test_get_execution_status(self, client, mock_auth):
        """Test getting execution status."""
        # Add a mock execution
        incident_response.executions_db["EXE-002"] = {
            "execution_id": "EXE-002",
            "runbook_name": "Test Runbook",
            "runbook_version": "1.0.0",
            "incident_id": "INC-002",
            "status": "in_progress",
            "mode": "normal",
            "started_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "completed_at": None,
            "current_step": 2,
            "total_steps": 5,
            "steps_completed": 2,
            "steps_failed": 0,
            "steps_skipped": 0,
            "steps_awaiting": 0,
            "step_results": [],
            "variables": {"test": "value"},
            "analyst": "test_user",
            "target_host": "HOST-002",
        }

        response = client.get("/api/v1/incident-response/executions/EXE-002")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["execution_id"] == "EXE-002"
        assert data["current_step"] == 2
        assert data["total_steps"] == 5


# ============================================================================
# Approval Workflow Tests
# ============================================================================


class TestApprovalWorkflow:
    """Tests for approval workflow functionality."""

    def test_list_pending_approvals_empty(self, client, mock_auth):
        """Test listing approvals when none exist."""
        response = client.get("/api/v1/incident-response/approvals")
        assert response.status_code == status.HTTP_200_OK
        assert response.json() == []

    def test_get_approval_not_found(self, client, mock_auth):
        """Test getting non-existent approval."""
        response = client.get("/api/v1/incident-response/approvals/APPROVAL-NONEXISTENT")
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_decide_approval_not_found(self, client, mock_auth):
        """Test deciding on non-existent approval."""
        response = client.post(
            "/api/v1/incident-response/approvals/APPROVAL-NONEXISTENT/decide",
            json={"approved": True},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_list_pending_approvals(self, client, mock_auth):
        """Test listing pending approvals."""
        from defensive_toolkit.api.models import PendingApproval
        from datetime import timedelta

        # Add mock approval
        approval = PendingApproval(
            approval_id="APR-001",
            execution_id="EXE-001",
            step_name="Isolate Host",
            action="isolate_host",
            severity="high",
            description="Isolate the compromised host",
            parameters={"host": "HOST-001"},
            requested_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        incident_response.approvals_db["APR-001"] = approval

        response = client.get("/api/v1/incident-response/approvals")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert len(data) == 1
        assert data[0]["approval_id"] == "APR-001"

    def test_get_approval(self, client, mock_auth):
        """Test getting approval details."""
        from defensive_toolkit.api.models import PendingApproval
        from datetime import timedelta

        approval = PendingApproval(
            approval_id="APR-002",
            execution_id="EXE-002",
            step_name="Block IP",
            action="block_ip",
            severity="critical",
            description="Block malicious IP address",
            parameters={"ip": "10.0.0.1"},
            requested_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        incident_response.approvals_db["APR-002"] = approval

        response = client.get("/api/v1/incident-response/approvals/APR-002")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["approval_id"] == "APR-002"
        assert data["action"] == "block_ip"

    def test_approve_action(self, client, mock_auth):
        """Test approving an action."""
        from defensive_toolkit.api.models import PendingApproval
        from datetime import timedelta

        # Create execution and approval
        incident_response.executions_db["EXE-003"] = {
            "execution_id": "EXE-003",
            "runbook_name": "Test",
            "runbook_version": "1.0.0",
            "incident_id": "INC-003",
            "status": "pending",
            "mode": "normal",
            "started_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "completed_at": None,
            "current_step": 1,
            "total_steps": 2,
            "steps_completed": 0,
            "steps_failed": 0,
            "steps_skipped": 0,
            "steps_awaiting": 1,
            "step_results": [
                {"step_name": "Block IP", "status": "awaiting_approval"}
            ],
            "variables": {},
            "analyst": "test_user",
            "target_host": "HOST-003",
        }

        approval = PendingApproval(
            approval_id="APR-003",
            execution_id="EXE-003",
            step_name="Block IP",
            action="block_ip",
            severity="high",
            description="Block IP",
            parameters={},
            requested_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        incident_response.approvals_db["APR-003"] = approval

        response = client.post(
            "/api/v1/incident-response/approvals/APR-003/decide",
            json={"approved": True},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "success"
        assert "APR-003" not in incident_response.approvals_db

    def test_deny_action(self, client, mock_auth):
        """Test denying an action."""
        from defensive_toolkit.api.models import PendingApproval
        from datetime import timedelta

        incident_response.executions_db["EXE-004"] = {
            "execution_id": "EXE-004",
            "runbook_name": "Test",
            "runbook_version": "1.0.0",
            "incident_id": "INC-004",
            "status": "pending",
            "mode": "normal",
            "started_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "completed_at": None,
            "current_step": 1,
            "total_steps": 2,
            "steps_completed": 0,
            "steps_failed": 0,
            "steps_skipped": 0,
            "steps_awaiting": 1,
            "step_results": [
                {"step_name": "Risky Action", "status": "awaiting_approval"}
            ],
            "variables": {},
            "analyst": "test_user",
            "target_host": "HOST-004",
        }

        approval = PendingApproval(
            approval_id="APR-004",
            execution_id="EXE-004",
            step_name="Risky Action",
            action="risky_action",
            severity="critical",
            description="A risky action",
            parameters={},
            requested_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        incident_response.approvals_db["APR-004"] = approval

        response = client.post(
            "/api/v1/incident-response/approvals/APR-004/decide",
            json={"approved": False, "reason": "Too risky"},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["data"]["decision"] == "denied"


# ============================================================================
# Evidence Chain Tests
# ============================================================================


class TestEvidenceChain:
    """Tests for evidence chain functionality."""

    def test_get_evidence_chain_execution_not_found(self, client, mock_auth):
        """Test getting evidence for non-existent execution."""
        response = client.get(
            "/api/v1/incident-response/executions/EXE-NONEXISTENT/evidence"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_get_evidence_chain_no_evidence(self, client, mock_auth):
        """Test getting evidence when none exists."""
        incident_response.executions_db["EXE-005"] = {
            "execution_id": "EXE-005",
            "runbook_name": "Test",
            "runbook_version": "1.0.0",
            "incident_id": "INC-005",
            "status": "success",
            "mode": "dry_run",
            "started_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "completed_at": datetime.utcnow().isoformat(),
            "current_step": 3,
            "total_steps": 3,
            "steps_completed": 3,
            "steps_failed": 0,
            "steps_skipped": 0,
            "steps_awaiting": 0,
            "step_results": [],
            "variables": {},
            "analyst": "test_user",
            "target_host": "HOST-005",
        }

        response = client.get("/api/v1/incident-response/executions/EXE-005/evidence")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["evidence_count"] == 0

    def test_download_evidence_not_found(self, client, mock_auth):
        """Test downloading evidence for non-existent execution."""
        response = client.get(
            "/api/v1/incident-response/executions/EXE-NONEXISTENT/evidence/download"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_download_evidence_no_package(self, client, mock_auth):
        """Test downloading when no evidence package exists."""
        incident_response.executions_db["EXE-006"] = {
            "execution_id": "EXE-006",
            "runbook_name": "Test",
            "runbook_version": "1.0.0",
            "incident_id": "INC-006",
            "status": "success",
            "mode": "normal",
            "started_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "completed_at": datetime.utcnow().isoformat(),
            "current_step": 3,
            "total_steps": 3,
            "steps_completed": 3,
            "steps_failed": 0,
            "steps_skipped": 0,
            "steps_awaiting": 0,
            "step_results": [],
            "variables": {},
            "analyst": "test_user",
            "target_host": "HOST-006",
        }

        response = client.get(
            "/api/v1/incident-response/executions/EXE-006/evidence/download"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


# ============================================================================
# Rollback Tests
# ============================================================================


class TestRollback:
    """Tests for rollback functionality."""

    def test_rollback_execution_not_found(self, client, mock_auth):
        """Test rollback for non-existent execution."""
        response = client.post(
            "/api/v1/incident-response/executions/EXE-NONEXISTENT/rollback",
            json={"confirm": True},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_rollback_not_confirmed(self, client, mock_auth):
        """Test rollback without confirmation."""
        incident_response.executions_db["EXE-007"] = {
            "execution_id": "EXE-007",
            "runbook_name": "Test",
            "runbook_version": "1.0.0",
            "incident_id": "INC-007",
            "status": "success",
            "mode": "normal",
            "started_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "completed_at": datetime.utcnow().isoformat(),
            "current_step": 3,
            "total_steps": 3,
            "steps_completed": 3,
            "steps_failed": 0,
            "steps_skipped": 0,
            "steps_awaiting": 0,
            "step_results": [],
            "variables": {},
            "analyst": "test_user",
            "target_host": "HOST-007",
        }

        response = client.post(
            "/api/v1/incident-response/executions/EXE-007/rollback",
            json={"confirm": False},
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_rollback_success(self, client, mock_auth):
        """Test successful rollback."""
        incident_response.executions_db["EXE-008"] = {
            "execution_id": "EXE-008",
            "runbook_name": "Test",
            "runbook_version": "1.0.0",
            "incident_id": "INC-008",
            "status": "success",
            "mode": "normal",
            "started_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "completed_at": datetime.utcnow().isoformat(),
            "current_step": 3,
            "total_steps": 3,
            "steps_completed": 3,
            "steps_failed": 0,
            "steps_skipped": 0,
            "steps_awaiting": 0,
            "step_results": [],
            "variables": {},
            "analyst": "test_user",
            "target_host": "HOST-008",
        }

        response = client.post(
            "/api/v1/incident-response/executions/EXE-008/rollback",
            json={"confirm": True},
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "success"


# ============================================================================
# Legacy Playbook Tests
# ============================================================================


class TestLegacyPlaybooks:
    """Tests for legacy playbook endpoints."""

    def test_execute_playbook_legacy(self, client, mock_auth):
        """Test legacy playbook execution."""
        response = client.post(
            "/api/v1/incident-response/playbooks/execute",
            json={
                "playbook_name": "ransomware-response",
                "target_host": "HOST-001",
            },
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "execution_id" in data
        assert data["status"] == "success"

    def test_list_playbooks_legacy(self, client, mock_auth):
        """Test listing legacy playbooks."""
        response = client.get("/api/v1/incident-response/playbooks")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
