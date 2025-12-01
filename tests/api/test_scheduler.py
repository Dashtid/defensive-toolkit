"""
Scheduler API Router Tests (v1.7.6)

Comprehensive tests for scheduled job management, execution, and scheduler operations.
"""

import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)

# auth_token and auth_headers fixtures are provided by tests/api/conftest.py


@pytest.fixture
def sample_cron_job():
    """Sample cron-scheduled job configuration"""
    return {
        "name": "Daily Vulnerability Scan",
        "description": "Run vulnerability scans every day at midnight",
        "job_type": "vulnerability_scan",
        "schedule_type": "cron",
        "cron_expression": "0 0 * * *",
        "timezone": "UTC",
        "priority": "high",
        "timeout_seconds": 3600,
        "max_retries": 3,
        "retry_delay_seconds": 300,
        "concurrent_allowed": False,
        "parameters": {
            "target": "192.168.1.0/24",
            "scanner": "trivy",
            "scan_type": "full"
        },
        "notify_on_success": False,
        "notify_on_failure": True,
        "notification_channels": ["email"],
        "tags": ["security", "daily"]
    }


@pytest.fixture
def sample_interval_job():
    """Sample interval-scheduled job configuration"""
    return {
        "name": "SIEM Health Check",
        "description": "Check SIEM connection health every 5 minutes",
        "job_type": "siem_health_check",
        "schedule_type": "interval",
        "interval_seconds": 300,
        "priority": "medium",
        "timeout_seconds": 60,
        "concurrent_allowed": False,
        "parameters": {
            "include_metrics": True
        },
        "tags": ["siem", "monitoring"]
    }


@pytest.fixture
def sample_onetime_job():
    """Sample one-time job configuration"""
    run_time = datetime.utcnow() + timedelta(hours=1)
    return {
        "name": "One-Time Backup",
        "description": "Execute a one-time backup",
        "job_type": "backup",
        "schedule_type": "once",
        "run_at": run_time.isoformat(),
        "priority": "low",
        "parameters": {
            "backup_type": "full",
            "compress": True
        },
        "tags": ["backup", "maintenance"]
    }


class TestScheduledJobCRUD:
    """Test scheduled job CRUD operations"""

    def test_list_jobs_empty(self, auth_headers):
        """Test listing jobs when none exist"""
        response = client.get("/api/v1/scheduler/jobs", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "jobs" in data
        assert "total" in data
        assert "active_count" in data
        assert "paused_count" in data
        assert "disabled_count" in data

    def test_create_cron_job(self, auth_headers, sample_cron_job):
        """Test creating a cron-scheduled job"""
        response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == sample_cron_job["name"]
        assert data["job_type"] == "vulnerability_scan"
        assert data["schedule_type"] == "cron"
        assert data["cron_expression"] == "0 0 * * *"
        assert "job_id" in data
        assert data["status"] == "active"

    def test_create_interval_job(self, auth_headers, sample_interval_job):
        """Test creating an interval-scheduled job"""
        response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_interval_job,
            headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == sample_interval_job["name"]
        assert data["schedule_type"] == "interval"
        assert data["interval_seconds"] == 300

    def test_create_onetime_job(self, auth_headers, sample_onetime_job):
        """Test creating a one-time job"""
        response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_onetime_job,
            headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()
        assert data["schedule_type"] == "once"

    def test_get_job_by_id(self, auth_headers, sample_cron_job):
        """Test getting a specific job"""
        # Create job
        create_response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id = create_response.json()["job_id"]

        # Get job
        response = client.get(
            f"/api/v1/scheduler/jobs/{job_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["job_id"] == job_id
        assert data["name"] == sample_cron_job["name"]

    def test_get_nonexistent_job(self, auth_headers):
        """Test getting a job that doesn't exist"""
        response = client.get(
            "/api/v1/scheduler/jobs/nonexistent-job-id",
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_update_job(self, auth_headers, sample_cron_job):
        """Test updating a job"""
        # Create job
        create_response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id = create_response.json()["job_id"]

        # Update job
        update_data = {
            "name": "Updated Vulnerability Scan",
            "priority": "critical",
            "cron_expression": "0 6 * * *"
        }
        response = client.put(
            f"/api/v1/scheduler/jobs/{job_id}",
            json=update_data,
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Vulnerability Scan"
        assert data["priority"] == "critical"
        assert data["cron_expression"] == "0 6 * * *"

    def test_delete_job(self, auth_headers, sample_cron_job):
        """Test deleting a job"""
        # Create job
        create_response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id = create_response.json()["job_id"]

        # Delete job
        response = client.delete(
            f"/api/v1/scheduler/jobs/{job_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

        # Verify deletion
        get_response = client.get(
            f"/api/v1/scheduler/jobs/{job_id}",
            headers=auth_headers
        )
        assert get_response.status_code == 404

    def test_delete_nonexistent_job(self, auth_headers):
        """Test deleting a job that doesn't exist"""
        response = client.delete(
            "/api/v1/scheduler/jobs/nonexistent-job-id",
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_list_jobs_with_filters(self, auth_headers, sample_cron_job, sample_interval_job):
        """Test listing jobs with filters"""
        # Create multiple jobs
        client.post("/api/v1/scheduler/jobs", json=sample_cron_job, headers=auth_headers)
        client.post("/api/v1/scheduler/jobs", json=sample_interval_job, headers=auth_headers)

        # Filter by job type
        response = client.get(
            "/api/v1/scheduler/jobs?job_type=vulnerability_scan",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        for job in data["jobs"]:
            assert job["job_type"] == "vulnerability_scan"

        # Filter by tag
        response = client.get(
            "/api/v1/scheduler/jobs?tag=security",
            headers=auth_headers
        )
        assert response.status_code == 200


class TestJobControl:
    """Test job control operations (pause/resume)"""

    def test_pause_job(self, auth_headers, sample_cron_job):
        """Test pausing a job"""
        # Create job
        create_response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id = create_response.json()["job_id"]

        # Pause job
        response = client.post(
            f"/api/v1/scheduler/jobs/{job_id}/pause",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

        # Verify paused status
        get_response = client.get(
            f"/api/v1/scheduler/jobs/{job_id}",
            headers=auth_headers
        )
        assert get_response.json()["status"] == "paused"

    def test_resume_job(self, auth_headers, sample_cron_job):
        """Test resuming a paused job"""
        # Create and pause job
        create_response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id = create_response.json()["job_id"]
        client.post(f"/api/v1/scheduler/jobs/{job_id}/pause", headers=auth_headers)

        # Resume job
        response = client.post(
            f"/api/v1/scheduler/jobs/{job_id}/resume",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

        # Verify active status
        get_response = client.get(
            f"/api/v1/scheduler/jobs/{job_id}",
            headers=auth_headers
        )
        assert get_response.json()["status"] == "active"

    def test_resume_non_paused_job(self, auth_headers, sample_cron_job):
        """Test resuming a job that isn't paused"""
        # Create job (active by default)
        create_response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id = create_response.json()["job_id"]

        # Try to resume (should fail)
        response = client.post(
            f"/api/v1/scheduler/jobs/{job_id}/resume",
            headers=auth_headers
        )
        assert response.status_code == 400

    def test_pause_nonexistent_job(self, auth_headers):
        """Test pausing a job that doesn't exist"""
        response = client.post(
            "/api/v1/scheduler/jobs/nonexistent-id/pause",
            headers=auth_headers
        )
        assert response.status_code == 404


class TestJobExecution:
    """Test job execution operations"""

    def test_trigger_job(self, auth_headers, sample_cron_job):
        """Test manually triggering a job"""
        # Create job
        create_response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id = create_response.json()["job_id"]

        # Trigger job
        response = client.post(
            f"/api/v1/scheduler/jobs/{job_id}/run",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert "execution_id" in data
        assert data["job_id"] == job_id
        assert data["status"] in ["pending", "running", "completed"]

    def test_trigger_nonexistent_job(self, auth_headers):
        """Test triggering a job that doesn't exist"""
        response = client.post(
            "/api/v1/scheduler/jobs/nonexistent-id/run",
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_list_executions(self, auth_headers, sample_cron_job):
        """Test listing job executions"""
        # Create and trigger job
        create_response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id = create_response.json()["job_id"]
        client.post(f"/api/v1/scheduler/jobs/{job_id}/run", headers=auth_headers)

        # List executions
        response = client.get("/api/v1/scheduler/executions", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "executions" in data
        assert "total" in data
        assert "running_count" in data
        assert "pending_count" in data

    def test_list_executions_with_job_filter(self, auth_headers, sample_cron_job):
        """Test listing executions filtered by job ID"""
        # Create and trigger job
        create_response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id = create_response.json()["job_id"]
        client.post(f"/api/v1/scheduler/jobs/{job_id}/run", headers=auth_headers)

        # List executions for specific job
        response = client.get(
            f"/api/v1/scheduler/executions?job_id={job_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        for exec in data["executions"]:
            assert exec["job_id"] == job_id

    def test_get_execution_by_id(self, auth_headers, sample_cron_job):
        """Test getting a specific execution"""
        # Create and trigger job
        create_response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id = create_response.json()["job_id"]
        trigger_response = client.post(
            f"/api/v1/scheduler/jobs/{job_id}/run",
            headers=auth_headers
        )
        execution_id = trigger_response.json()["execution_id"]

        # Get execution
        response = client.get(
            f"/api/v1/scheduler/executions/{execution_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["execution_id"] == execution_id

    def test_get_nonexistent_execution(self, auth_headers):
        """Test getting an execution that doesn't exist"""
        response = client.get(
            "/api/v1/scheduler/executions/nonexistent-exec-id",
            headers=auth_headers
        )
        assert response.status_code == 404

    def test_cancel_execution(self, auth_headers, sample_cron_job):
        """Test cancelling an execution"""
        # Create and trigger job
        create_response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id = create_response.json()["job_id"]
        trigger_response = client.post(
            f"/api/v1/scheduler/jobs/{job_id}/run",
            headers=auth_headers
        )
        execution_id = trigger_response.json()["execution_id"]

        # Cancel execution (may fail if already completed)
        response = client.post(
            f"/api/v1/scheduler/executions/{execution_id}/cancel",
            headers=auth_headers
        )
        # Either succeeds or fails because execution already completed
        assert response.status_code in [200, 400]

    def test_cancel_nonexistent_execution(self, auth_headers):
        """Test cancelling an execution that doesn't exist"""
        response = client.post(
            "/api/v1/scheduler/executions/nonexistent-exec-id/cancel",
            headers=auth_headers
        )
        assert response.status_code == 404


class TestSchedulerManagement:
    """Test scheduler management operations"""

    def test_get_scheduler_stats(self, auth_headers):
        """Test getting scheduler statistics"""
        response = client.get("/api/v1/scheduler/stats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "scheduler_status" in data
        assert "uptime_seconds" in data
        assert "jobs_total" in data
        assert "jobs_active" in data
        assert "executions_today" in data
        assert "queue_length" in data
        assert "running_jobs" in data

    def test_scheduler_health_check(self, auth_headers):
        """Test scheduler health check"""
        response = client.get("/api/v1/scheduler/health", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "healthy" in data
        assert "status" in data
        assert "checks" in data
        assert "worker_count" in data
        assert "queue_healthy" in data
        assert "storage_healthy" in data

    def test_pause_scheduler(self, auth_headers):
        """Test pausing the scheduler"""
        response = client.post("/api/v1/scheduler/pause", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

        # Verify paused
        health_response = client.get("/api/v1/scheduler/health", headers=auth_headers)
        assert health_response.json()["status"] == "paused"

    def test_resume_scheduler(self, auth_headers):
        """Test resuming the scheduler"""
        # First pause
        client.post("/api/v1/scheduler/pause", headers=auth_headers)

        # Then resume
        response = client.post("/api/v1/scheduler/resume", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

        # Verify running
        health_response = client.get("/api/v1/scheduler/health", headers=auth_headers)
        assert health_response.json()["status"] == "running"


class TestCronValidation:
    """Test cron expression validation"""

    def test_validate_valid_cron(self, auth_headers):
        """Test validating a valid cron expression"""
        response = client.post(
            "/api/v1/scheduler/cron/validate",
            json={"cron_expression": "0 0 * * *", "timezone": "UTC", "count": 5},
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["expression"] == "0 0 * * *"
        assert "description" in data
        assert "next_runs" in data
        assert len(data["next_runs"]) == 5

    def test_validate_invalid_cron(self, auth_headers):
        """Test validating an invalid cron expression"""
        response = client.post(
            "/api/v1/scheduler/cron/validate",
            json={"cron_expression": "invalid cron", "timezone": "UTC", "count": 5},
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
        assert "error" in data

    def test_validate_common_cron_patterns(self, auth_headers):
        """Test validating common cron patterns"""
        patterns = [
            "* * * * *",       # Every minute
            "*/5 * * * *",     # Every 5 minutes
            "0 * * * *",       # Every hour
            "0 0 * * *",       # Daily at midnight
            "0 0 * * 0",       # Weekly on Sunday
            "0 0 1 * *",       # Monthly on the 1st
        ]

        for pattern in patterns:
            response = client.post(
                "/api/v1/scheduler/cron/validate",
                json={"cron_expression": pattern, "timezone": "UTC", "count": 3},
                headers=auth_headers
            )
            assert response.status_code == 200
            data = response.json()
            assert data["valid"] is True


class TestJobTypes:
    """Test job type information endpoints"""

    def test_list_job_types(self, auth_headers):
        """Test listing all available job types"""
        response = client.get("/api/v1/scheduler/job-types", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "job_types" in data
        assert "categories" in data
        assert len(data["job_types"]) >= 1

        # Verify job type structure
        for job_type in data["job_types"]:
            assert "job_type" in job_type
            assert "name" in job_type
            assert "description" in job_type
            assert "category" in job_type
            assert "required_parameters" in job_type
            assert "optional_parameters" in job_type
            assert "parameter_schema" in job_type
            assert "default_timeout_seconds" in job_type

    def test_job_types_include_expected_types(self, auth_headers):
        """Test that expected job types are present"""
        response = client.get("/api/v1/scheduler/job-types", headers=auth_headers)
        data = response.json()
        job_types = [jt["job_type"] for jt in data["job_types"]]

        expected_types = [
            "vulnerability_scan",
            "compliance_check",
            "siem_health_check",
            "security_report",
            "backup"
        ]

        for expected in expected_types:
            assert expected in job_types


class TestBulkActions:
    """Test bulk job actions"""

    def test_bulk_pause_jobs(self, auth_headers, sample_cron_job, sample_interval_job):
        """Test bulk pausing multiple jobs"""
        # Create multiple jobs
        job_ids = []
        for job_config in [sample_cron_job, sample_interval_job]:
            response = client.post(
                "/api/v1/scheduler/jobs",
                json=job_config,
                headers=auth_headers
            )
            job_ids.append(response.json()["job_id"])

        # Bulk pause
        response = client.post(
            "/api/v1/scheduler/bulk-action",
            json={"job_ids": job_ids, "action": "pause"},
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["action"] == "pause"
        assert data["total_requested"] == len(job_ids)
        assert data["succeeded"] == len(job_ids)
        assert data["failed"] == 0

    def test_bulk_resume_jobs(self, auth_headers, sample_cron_job, sample_interval_job):
        """Test bulk resuming multiple jobs"""
        # Create and pause jobs
        job_ids = []
        for job_config in [sample_cron_job, sample_interval_job]:
            response = client.post(
                "/api/v1/scheduler/jobs",
                json=job_config,
                headers=auth_headers
            )
            job_id = response.json()["job_id"]
            job_ids.append(job_id)
            client.post(f"/api/v1/scheduler/jobs/{job_id}/pause", headers=auth_headers)

        # Bulk resume
        response = client.post(
            "/api/v1/scheduler/bulk-action",
            json={"job_ids": job_ids, "action": "resume"},
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["succeeded"] == len(job_ids)

    def test_bulk_delete_jobs(self, auth_headers, sample_cron_job, sample_interval_job):
        """Test bulk deleting multiple jobs"""
        # Create jobs
        job_ids = []
        for job_config in [sample_cron_job, sample_interval_job]:
            response = client.post(
                "/api/v1/scheduler/jobs",
                json=job_config,
                headers=auth_headers
            )
            job_ids.append(response.json()["job_id"])

        # Bulk delete
        response = client.post(
            "/api/v1/scheduler/bulk-action",
            json={"job_ids": job_ids, "action": "delete"},
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["succeeded"] == len(job_ids)

        # Verify deletion
        for job_id in job_ids:
            get_response = client.get(
                f"/api/v1/scheduler/jobs/{job_id}",
                headers=auth_headers
            )
            assert get_response.status_code == 404

    def test_bulk_action_with_nonexistent_jobs(self, auth_headers):
        """Test bulk action with some non-existent jobs"""
        response = client.post(
            "/api/v1/scheduler/bulk-action",
            json={"job_ids": ["nonexistent-1", "nonexistent-2"], "action": "pause"},
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["failed"] == 2
        assert data["succeeded"] == 0


class TestJobDependencies:
    """Test job dependency management"""

    def test_get_job_dependencies_empty(self, auth_headers, sample_cron_job):
        """Test getting dependencies when none exist"""
        # Create job
        create_response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id = create_response.json()["job_id"]

        # Get dependencies
        response = client.get(
            f"/api/v1/scheduler/jobs/{job_id}/dependencies",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["job_id"] == job_id
        assert "dependencies" in data
        assert "dependents" in data

    def test_add_job_dependency(self, auth_headers, sample_cron_job, sample_interval_job):
        """Test adding a job dependency"""
        # Create two jobs
        response1 = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id_1 = response1.json()["job_id"]

        response2 = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_interval_job,
            headers=auth_headers
        )
        job_id_2 = response2.json()["job_id"]

        # Add dependency: job_id_1 depends on job_id_2
        response = client.post(
            f"/api/v1/scheduler/jobs/{job_id_1}/dependencies",
            json={
                "depends_on_job_id": job_id_2,
                "condition": "success",
                "description": "Must complete before running"
            },
            headers=auth_headers
        )
        assert response.status_code == 200

        # Verify dependency
        deps_response = client.get(
            f"/api/v1/scheduler/jobs/{job_id_1}/dependencies",
            headers=auth_headers
        )
        data = deps_response.json()
        assert len(data["dependencies"]) == 1
        assert data["dependencies"][0]["depends_on_job_id"] == job_id_2

    def test_add_circular_dependency(self, auth_headers, sample_cron_job, sample_interval_job):
        """Test that circular dependencies are rejected"""
        # Create two jobs
        response1 = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id_1 = response1.json()["job_id"]

        response2 = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_interval_job,
            headers=auth_headers
        )
        job_id_2 = response2.json()["job_id"]

        # Add dependency: job_id_1 depends on job_id_2
        client.post(
            f"/api/v1/scheduler/jobs/{job_id_1}/dependencies",
            json={"depends_on_job_id": job_id_2, "condition": "success"},
            headers=auth_headers
        )

        # Try to add circular dependency: job_id_2 depends on job_id_1
        response = client.post(
            f"/api/v1/scheduler/jobs/{job_id_2}/dependencies",
            json={"depends_on_job_id": job_id_1, "condition": "success"},
            headers=auth_headers
        )
        assert response.status_code == 400
        assert "circular" in response.json()["detail"].lower()

    def test_remove_job_dependency(self, auth_headers, sample_cron_job, sample_interval_job):
        """Test removing a job dependency"""
        # Create two jobs and add dependency
        response1 = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id_1 = response1.json()["job_id"]

        response2 = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_interval_job,
            headers=auth_headers
        )
        job_id_2 = response2.json()["job_id"]

        client.post(
            f"/api/v1/scheduler/jobs/{job_id_1}/dependencies",
            json={"depends_on_job_id": job_id_2, "condition": "success"},
            headers=auth_headers
        )

        # Remove dependency
        response = client.delete(
            f"/api/v1/scheduler/jobs/{job_id_1}/dependencies/{job_id_2}",
            headers=auth_headers
        )
        assert response.status_code == 200

        # Verify removal
        deps_response = client.get(
            f"/api/v1/scheduler/jobs/{job_id_1}/dependencies",
            headers=auth_headers
        )
        assert len(deps_response.json()["dependencies"]) == 0

    def test_get_dependencies_nonexistent_job(self, auth_headers):
        """Test getting dependencies for non-existent job"""
        response = client.get(
            "/api/v1/scheduler/jobs/nonexistent-id/dependencies",
            headers=auth_headers
        )
        assert response.status_code == 404


class TestSchedulerAuthentication:
    """Test authentication requirements for scheduler endpoints"""

    def test_list_jobs_requires_auth(self):
        """Test that listing jobs requires authentication"""
        response = client.get("/api/v1/scheduler/jobs")
        assert response.status_code == 401

    def test_create_job_requires_auth(self, sample_cron_job):
        """Test that creating jobs requires authentication"""
        response = client.post("/api/v1/scheduler/jobs", json=sample_cron_job)
        assert response.status_code == 401

    def test_trigger_job_requires_auth(self):
        """Test that triggering jobs requires authentication"""
        response = client.post("/api/v1/scheduler/jobs/some-id/run")
        assert response.status_code == 401

    def test_scheduler_stats_requires_auth(self):
        """Test that scheduler stats requires authentication"""
        response = client.get("/api/v1/scheduler/stats")
        assert response.status_code == 401

    def test_scheduler_health_requires_auth(self):
        """Test that scheduler health requires authentication"""
        response = client.get("/api/v1/scheduler/health")
        assert response.status_code == 401


class TestSchedulerValidation:
    """Test input validation for scheduler endpoints"""

    def test_create_cron_job_without_expression(self, auth_headers):
        """Test creating cron job without cron expression"""
        invalid_job = {
            "name": "Invalid Cron Job",
            "job_type": "vulnerability_scan",
            "schedule_type": "cron",
            # Missing cron_expression
        }
        response = client.post(
            "/api/v1/scheduler/jobs",
            json=invalid_job,
            headers=auth_headers
        )
        assert response.status_code == 400

    def test_create_interval_job_without_interval(self, auth_headers):
        """Test creating interval job without interval_seconds"""
        invalid_job = {
            "name": "Invalid Interval Job",
            "job_type": "siem_health_check",
            "schedule_type": "interval",
            # Missing interval_seconds
        }
        response = client.post(
            "/api/v1/scheduler/jobs",
            json=invalid_job,
            headers=auth_headers
        )
        assert response.status_code == 400

    def test_create_onetime_job_without_run_at(self, auth_headers):
        """Test creating one-time job without run_at"""
        invalid_job = {
            "name": "Invalid One-Time Job",
            "job_type": "backup",
            "schedule_type": "once",
            # Missing run_at
        }
        response = client.post(
            "/api/v1/scheduler/jobs",
            json=invalid_job,
            headers=auth_headers
        )
        assert response.status_code == 400

    def test_create_onetime_job_with_past_time(self, auth_headers):
        """Test creating one-time job with past run_at"""
        past_time = datetime.utcnow() - timedelta(hours=1)
        invalid_job = {
            "name": "Past One-Time Job",
            "job_type": "backup",
            "schedule_type": "once",
            "run_at": past_time.isoformat()
        }
        response = client.post(
            "/api/v1/scheduler/jobs",
            json=invalid_job,
            headers=auth_headers
        )
        assert response.status_code == 400

    def test_create_job_with_invalid_cron(self, auth_headers):
        """Test creating job with invalid cron expression"""
        invalid_job = {
            "name": "Invalid Cron",
            "job_type": "vulnerability_scan",
            "schedule_type": "cron",
            "cron_expression": "invalid cron expression"
        }
        response = client.post(
            "/api/v1/scheduler/jobs",
            json=invalid_job,
            headers=auth_headers
        )
        assert response.status_code == 400

    def test_update_job_with_invalid_cron(self, auth_headers, sample_cron_job):
        """Test updating job with invalid cron expression"""
        # Create valid job
        create_response = client.post(
            "/api/v1/scheduler/jobs",
            json=sample_cron_job,
            headers=auth_headers
        )
        job_id = create_response.json()["job_id"]

        # Try to update with invalid cron
        response = client.put(
            f"/api/v1/scheduler/jobs/{job_id}",
            json={"cron_expression": "not valid"},
            headers=auth_headers
        )
        assert response.status_code == 400

    def test_list_executions_invalid_hours(self, auth_headers):
        """Test listing executions with invalid hours parameter"""
        response = client.get(
            "/api/v1/scheduler/executions?hours=1000",
            headers=auth_headers
        )
        assert response.status_code == 422

    def test_list_jobs_invalid_limit(self, auth_headers):
        """Test listing jobs with invalid limit parameter"""
        response = client.get(
            "/api/v1/scheduler/jobs?limit=500",
            headers=auth_headers
        )
        assert response.status_code == 422
