"""
Hardening API Tests

Comprehensive tests for system hardening endpoints including:
- Linux CIS Benchmark scanning
- Scan result retrieval
- Remediation script generation
- Benchmark information endpoints
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from defensive_toolkit.api.main import app

client = TestClient(app)


# =============================================================================
# Fixtures (using conftest.py for auth_headers, adding test-specific fixtures)
# =============================================================================


@pytest.fixture
def readonly_auth_token():
    """Get auth token for analyst user (read-only scope)."""
    response = client.post(
        "/api/v1/auth/token", data={"username": "analyst", "password": "analyst123"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture
def readonly_auth_headers(readonly_auth_token):
    """Auth headers for read-only user."""
    return {"Authorization": f"Bearer {readonly_auth_token}"}


@pytest.fixture
def mock_scan_result():
    """Mock scan result for testing."""
    from defensive_toolkit.hardening.linux.cis_benchmarks import (
        HardeningScanResult,
        HardeningCheck,
    )

    checks = [
        HardeningCheck(
            check_id="SSH-001",
            title="SSH Protocol Version",
            description="Ensure SSH Protocol 2 is used",
            category="ssh",
            severity="high",
            passed=True,
            current_value="SSH2 (default)",
            expected_value="Protocol 2 only",
            remediation="Remove 'Protocol 1' from /etc/ssh/sshd_config",
            cis_reference="5.2.4",
        ),
        HardeningCheck(
            check_id="SSH-002",
            title="SSH Root Login",
            description="Ensure SSH root login is disabled",
            category="ssh",
            severity="high",
            passed=False,
            current_value="yes",
            expected_value="no or prohibit-password",
            remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
            cis_reference="5.2.10",
        ),
        HardeningCheck(
            check_id="FILE-001",
            title="/etc/passwd Permissions",
            description="Ensure permissions on /etc/passwd are configured",
            category="file_permissions",
            severity="high",
            passed=True,
            current_value="0644",
            expected_value="0644",
            remediation="chmod 644 /etc/passwd",
            cis_reference="6.1.2",
        ),
        HardeningCheck(
            check_id="FILE-002",
            title="/etc/shadow Permissions",
            description="Ensure permissions on /etc/shadow are configured",
            category="file_permissions",
            severity="critical",
            passed=False,
            current_value="0644",
            expected_value="0640 or more restrictive",
            remediation="chmod 640 /etc/shadow",
            cis_reference="6.1.3",
        ),
    ]

    return HardeningScanResult(
        target="localhost",
        os_type="linux",
        cis_level=1,
        total_checks=4,
        passed=2,
        failed=2,
        skipped=0,
        compliance_percentage=50.0,
        checks=checks,
        categories={
            "ssh": {"passed": 1, "failed": 1},
            "file_permissions": {"passed": 1, "failed": 1},
        },
    )


# =============================================================================
# Benchmark Info Endpoints Tests
# =============================================================================


class TestBenchmarkEndpoints:
    """Tests for benchmark listing and details endpoints."""

    def test_list_benchmarks(self, auth_headers):
        """Test listing available benchmarks."""
        response = client.get("/api/v1/hardening/benchmarks", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "benchmarks" in data
        assert "total" in data
        assert data["total"] == 3

        # Verify benchmark structure
        benchmark_ids = [b["id"] for b in data["benchmarks"]]
        assert "cis-linux-l1" in benchmark_ids
        assert "cis-linux-l2" in benchmark_ids
        assert "cis-windows" in benchmark_ids

    def test_list_benchmarks_without_auth(self):
        """Test listing benchmarks without authentication."""
        response = client.get("/api/v1/hardening/benchmarks")
        assert response.status_code == 401

    def test_get_benchmark_details_linux_l1(self, auth_headers):
        """Test getting CIS Linux Level 1 benchmark details."""
        response = client.get(
            "/api/v1/hardening/benchmarks/cis-linux-l1", headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["benchmark_id"] == "cis-linux-l1"
        assert data["os_type"] == "linux"
        assert "checks" in data
        assert len(data["checks"]) == 18
        assert "categories" in data
        assert "ssh" in data["categories"]

    def test_get_benchmark_details_linux_l2(self, auth_headers):
        """Test getting CIS Linux Level 2 benchmark details."""
        response = client.get(
            "/api/v1/hardening/benchmarks/cis-linux-l2", headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["benchmark_id"] == "cis-linux-l2"
        assert "CIS Linux Level 2" in data["name"]

    def test_get_benchmark_not_found(self, auth_headers):
        """Test getting non-existent benchmark."""
        response = client.get(
            "/api/v1/hardening/benchmarks/invalid-benchmark", headers=auth_headers
        )
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()


# =============================================================================
# Recommendations Endpoint Tests
# =============================================================================


class TestRecommendationsEndpoint:
    """Tests for hardening recommendations endpoint."""

    def test_get_recommendations(self, auth_headers):
        """Test getting prioritized recommendations."""
        response = client.get("/api/v1/hardening/recommendations", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "recommendations" in data
        assert "total" in data
        assert data["total"] == 5

        # Verify recommendations are prioritized
        priorities = [r["priority"] for r in data["recommendations"]]
        assert priorities == sorted(priorities)

        # Verify recommendation structure
        first_rec = data["recommendations"][0]
        assert "title" in first_rec
        assert "category" in first_rec
        assert "impact" in first_rec
        assert "description" in first_rec

    def test_get_recommendations_without_auth(self):
        """Test getting recommendations without authentication."""
        response = client.get("/api/v1/hardening/recommendations")
        assert response.status_code == 401


# =============================================================================
# Linux Scan Endpoint Tests
# =============================================================================


class TestLinuxScanEndpoint:
    """Tests for Linux hardening scan endpoint."""

    def test_scan_linux_system(self, auth_headers, mock_scan_result):
        """Test running Linux hardening scan."""
        with patch(
            "defensive_toolkit.api.routers.hardening.get_linux_scanner"
        ) as mock_scanner:
            scanner_instance = MagicMock()
            scanner_instance.run_all_checks.return_value = mock_scan_result
            mock_scanner.return_value = scanner_instance

            scan_data = {"target": "localhost", "os_type": "linux", "cis_level": 1}

            response = client.post(
                "/api/v1/hardening/scan/linux", json=scan_data, headers=auth_headers
            )

            assert response.status_code == 200
            data = response.json()
            assert "scan_id" in data
            assert data["target"] == "localhost"
            assert data["os_type"] == "linux"
            assert data["cis_level"] == 1
            assert data["total_checks"] == 4
            assert data["passed"] == 2
            assert data["failed"] == 2
            assert data["compliance_percentage"] == 50.0
            assert len(data["checks"]) == 4

    def test_scan_linux_wrong_os_type(self, auth_headers):
        """Test Linux scan rejects non-linux OS type."""
        scan_data = {"target": "localhost", "os_type": "windows", "cis_level": 1}

        response = client.post(
            "/api/v1/hardening/scan/linux", json=scan_data, headers=auth_headers
        )

        assert response.status_code == 400
        assert "linux systems only" in response.json()["detail"].lower()

    def test_scan_linux_cis_level_2(self, auth_headers, mock_scan_result):
        """Test Linux scan with CIS Level 2."""
        with patch(
            "defensive_toolkit.api.routers.hardening.get_linux_scanner"
        ) as mock_scanner:
            mock_scan_result.cis_level = 2
            scanner_instance = MagicMock()
            scanner_instance.run_all_checks.return_value = mock_scan_result
            mock_scanner.return_value = scanner_instance

            scan_data = {"target": "localhost", "os_type": "linux", "cis_level": 2}

            response = client.post(
                "/api/v1/hardening/scan/linux", json=scan_data, headers=auth_headers
            )

            assert response.status_code == 200
            data = response.json()
            assert data["cis_level"] == 2

    def test_scan_linux_without_auth(self):
        """Test Linux scan without authentication."""
        scan_data = {"target": "localhost", "os_type": "linux", "cis_level": 1}

        response = client.post("/api/v1/hardening/scan/linux", json=scan_data)
        assert response.status_code == 401


# =============================================================================
# Windows Scan Endpoint Tests
# =============================================================================


class TestWindowsScanEndpoint:
    """Tests for Windows hardening scan endpoint."""

    def test_scan_windows_not_implemented(self, auth_headers):
        """Test Windows scan returns 501 Not Implemented."""
        scan_data = {"target": "localhost", "os_type": "windows", "cis_level": 1}

        response = client.post(
            "/api/v1/hardening/scan/windows", json=scan_data, headers=auth_headers
        )

        assert response.status_code == 501
        assert "not yet implemented" in response.json()["detail"].lower()


# =============================================================================
# Generic Scan Endpoint Tests
# =============================================================================


class TestGenericScanEndpoint:
    """Tests for generic hardening scan endpoint."""

    def test_scan_routes_to_linux(self, auth_headers, mock_scan_result):
        """Test generic scan routes to Linux scanner."""
        with patch(
            "defensive_toolkit.api.routers.hardening.get_linux_scanner"
        ) as mock_scanner:
            scanner_instance = MagicMock()
            scanner_instance.run_all_checks.return_value = mock_scan_result
            mock_scanner.return_value = scanner_instance

            scan_data = {"target": "localhost", "os_type": "linux", "cis_level": 1}

            response = client.post(
                "/api/v1/hardening/scan", json=scan_data, headers=auth_headers
            )

            assert response.status_code == 200
            assert response.json()["os_type"] == "linux"

    def test_scan_routes_to_windows(self, auth_headers):
        """Test generic scan routes to Windows scanner (returns 501)."""
        scan_data = {"target": "localhost", "os_type": "windows", "cis_level": 1}

        response = client.post(
            "/api/v1/hardening/scan", json=scan_data, headers=auth_headers
        )

        assert response.status_code == 501

    def test_scan_unsupported_os(self, auth_headers):
        """Test generic scan rejects unsupported OS type."""
        scan_data = {"target": "localhost", "os_type": "macos", "cis_level": 1}

        response = client.post(
            "/api/v1/hardening/scan", json=scan_data, headers=auth_headers
        )

        assert response.status_code == 400
        assert "unsupported os type" in response.json()["detail"].lower()


# =============================================================================
# Scan Results Retrieval Tests
# =============================================================================


class TestScanResultsRetrieval:
    """Tests for scan result retrieval endpoints."""

    @pytest.fixture
    def stored_scan_id(self, auth_headers, mock_scan_result):
        """Create a scan and return its ID."""
        with patch(
            "defensive_toolkit.api.routers.hardening.get_linux_scanner"
        ) as mock_scanner:
            scanner_instance = MagicMock()
            scanner_instance.run_all_checks.return_value = mock_scan_result
            mock_scanner.return_value = scanner_instance

            scan_data = {"target": "localhost", "os_type": "linux", "cis_level": 1}

            response = client.post(
                "/api/v1/hardening/scan/linux", json=scan_data, headers=auth_headers
            )

            return response.json()["scan_id"]

    def test_get_scan_result(self, auth_headers, stored_scan_id):
        """Test retrieving scan results by ID."""
        response = client.get(
            f"/api/v1/hardening/scan/{stored_scan_id}", headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == stored_scan_id
        assert "checks" in data
        assert "categories" in data

    def test_get_scan_result_not_found(self, auth_headers):
        """Test retrieving non-existent scan."""
        response = client.get(
            "/api/v1/hardening/scan/non-existent-id", headers=auth_headers
        )

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_get_scan_summary(self, auth_headers, stored_scan_id):
        """Test retrieving scan summary."""
        response = client.get(
            f"/api/v1/hardening/scan/{stored_scan_id}/summary", headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["target"] == "localhost"
        assert data["os_type"] == "linux"
        assert data["cis_level"] == 1
        assert data["compliance_percentage"] == 50.0
        assert "critical_failures" in data
        assert "high_failures" in data
        assert "categories" in data

    def test_get_scan_summary_not_found(self, auth_headers):
        """Test retrieving summary for non-existent scan."""
        response = client.get(
            "/api/v1/hardening/scan/non-existent-id/summary", headers=auth_headers
        )

        assert response.status_code == 404

    def test_get_failed_checks(self, auth_headers, stored_scan_id):
        """Test retrieving failed checks from scan."""
        response = client.get(
            f"/api/v1/hardening/scan/{stored_scan_id}/failed", headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == stored_scan_id
        assert data["total_failed"] == 2
        assert len(data["checks"]) == 2

        # Verify all returned checks are failed
        for check in data["checks"]:
            assert check["passed"] is False

    def test_get_failed_checks_filter_severity(self, auth_headers, stored_scan_id):
        """Test filtering failed checks by severity."""
        response = client.get(
            f"/api/v1/hardening/scan/{stored_scan_id}/failed?severity=critical",
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["severity_filter"] == "critical"

        for check in data["checks"]:
            assert check["severity"] == "critical"

    def test_get_failed_checks_not_found(self, auth_headers):
        """Test retrieving failed checks for non-existent scan."""
        response = client.get(
            "/api/v1/hardening/scan/non-existent-id/failed", headers=auth_headers
        )

        assert response.status_code == 404


# =============================================================================
# Remediation Endpoint Tests
# =============================================================================


class TestRemediationEndpoint:
    """Tests for remediation script generation endpoint."""

    @pytest.fixture
    def stored_scan_id_for_remediation(self, auth_headers, mock_scan_result):
        """Create a scan and return its ID for remediation tests."""
        with patch(
            "defensive_toolkit.api.routers.hardening.get_linux_scanner"
        ) as mock_scanner:
            scanner_instance = MagicMock()
            scanner_instance.run_all_checks.return_value = mock_scan_result
            mock_scanner.return_value = scanner_instance

            scan_data = {"target": "localhost", "os_type": "linux", "cis_level": 1}

            response = client.post(
                "/api/v1/hardening/scan/linux", json=scan_data, headers=auth_headers
            )

            return response.json()["scan_id"]

    def test_generate_remediation_dry_run(
        self, auth_headers, stored_scan_id_for_remediation
    ):
        """Test generating remediation script in dry-run mode."""
        with patch(
            "defensive_toolkit.api.routers.hardening.get_linux_scanner"
        ) as mock_scanner:
            scanner_instance = MagicMock()
            scanner_instance.checks = []
            scanner_instance.get_remediation_script.return_value = (
                "#!/bin/bash\necho 'Remediation script'"
            )
            mock_scanner.return_value = scanner_instance

            remediation_data = {"dry_run": True}

            response = client.post(
                f"/api/v1/hardening/remediate/{stored_scan_id_for_remediation}",
                json=remediation_data,
                headers=auth_headers,
            )

            assert response.status_code == 200
            data = response.json()
            assert data["scan_id"] == stored_scan_id_for_remediation
            assert data["dry_run"] is True
            assert "script" in data
            assert data["script"] is not None

    def test_generate_remediation_specific_checks(
        self, auth_headers, stored_scan_id_for_remediation
    ):
        """Test generating remediation for specific checks."""
        with patch(
            "defensive_toolkit.api.routers.hardening.get_linux_scanner"
        ) as mock_scanner:
            scanner_instance = MagicMock()
            scanner_instance.checks = []
            scanner_instance.get_remediation_script.return_value = "#!/bin/bash\n"
            mock_scanner.return_value = scanner_instance

            remediation_data = {"check_ids": ["SSH-002"], "dry_run": True}

            response = client.post(
                f"/api/v1/hardening/remediate/{stored_scan_id_for_remediation}",
                json=remediation_data,
                headers=auth_headers,
            )

            assert response.status_code == 200

    def test_remediation_not_found(self, auth_headers):
        """Test remediation for non-existent scan."""
        remediation_data = {"dry_run": True}

        response = client.post(
            "/api/v1/hardening/remediate/non-existent-id",
            json=remediation_data,
            headers=auth_headers,
        )

        assert response.status_code == 404

    def test_remediation_requires_write_scope(
        self, readonly_auth_headers, stored_scan_id_for_remediation
    ):
        """Test remediation requires write scope."""
        remediation_data = {"dry_run": True}

        response = client.post(
            f"/api/v1/hardening/remediate/{stored_scan_id_for_remediation}",
            json=remediation_data,
            headers=readonly_auth_headers,
        )

        # Should be 403 Forbidden for read-only user
        assert response.status_code == 403


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling scenarios."""

    def test_scanner_unavailable(self, auth_headers):
        """Test handling when scanner module is unavailable."""
        from fastapi import HTTPException, status

        with patch(
            "defensive_toolkit.api.routers.hardening.get_linux_scanner"
        ) as mock_scanner:
            # Mock to raise HTTPException as the real function does on ImportError
            mock_scanner.side_effect = HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Linux hardening scanner module not available",
            )

            scan_data = {"target": "localhost", "os_type": "linux", "cis_level": 1}

            response = client.post(
                "/api/v1/hardening/scan/linux", json=scan_data, headers=auth_headers
            )

            # get_linux_scanner raises HTTPException 503 on import error
            assert response.status_code == 503

    def test_scan_internal_error(self, auth_headers):
        """Test handling internal scan errors."""
        with patch(
            "defensive_toolkit.api.routers.hardening.get_linux_scanner"
        ) as mock_scanner:
            scanner_instance = MagicMock()
            scanner_instance.run_all_checks.side_effect = Exception(
                "Internal scan error"
            )
            mock_scanner.return_value = scanner_instance

            scan_data = {"target": "localhost", "os_type": "linux", "cis_level": 1}

            response = client.post(
                "/api/v1/hardening/scan/linux", json=scan_data, headers=auth_headers
            )

            assert response.status_code == 500
            assert "scan failed" in response.json()["detail"].lower()


# =============================================================================
# Validation Tests
# =============================================================================


class TestValidation:
    """Tests for request validation."""

    def test_scan_default_values(self, auth_headers, mock_scan_result):
        """Test scan uses default values when not specified."""
        with patch(
            "defensive_toolkit.api.routers.hardening.get_linux_scanner"
        ) as mock_scanner:
            scanner_instance = MagicMock()
            scanner_instance.run_all_checks.return_value = mock_scan_result
            mock_scanner.return_value = scanner_instance

            # Empty request body should use defaults
            response = client.post(
                "/api/v1/hardening/scan/linux", json={}, headers=auth_headers
            )

            assert response.status_code == 200
            data = response.json()
            assert data["target"] == "localhost"
            assert data["cis_level"] == 1

    def test_remediation_default_dry_run(
        self, auth_headers, mock_scan_result
    ):
        """Test remediation defaults to dry_run=True."""
        # First create a scan
        with patch(
            "defensive_toolkit.api.routers.hardening.get_linux_scanner"
        ) as mock_scanner:
            scanner_instance = MagicMock()
            scanner_instance.run_all_checks.return_value = mock_scan_result
            mock_scanner.return_value = scanner_instance

            scan_response = client.post(
                "/api/v1/hardening/scan/linux", json={}, headers=auth_headers
            )
            scan_id = scan_response.json()["scan_id"]

            # Now test remediation with empty body
            scanner_instance.checks = []
            scanner_instance.get_remediation_script.return_value = "#!/bin/bash\n"

            response = client.post(
                f"/api/v1/hardening/remediate/{scan_id}",
                json={},
                headers=auth_headers,
            )

            assert response.status_code == 200
            assert response.json()["dry_run"] is True
