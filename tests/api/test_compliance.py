"""
Compliance API Tests

Comprehensive tests for compliance framework endpoints including:
- CIS Controls v8 compliance checking
- NIST 800-53 compliance checking
- Framework control mapping
- Policy validation
- Configuration drift detection
- Compliance reporting
"""

import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException, status
from unittest.mock import patch, MagicMock

from defensive_toolkit.api.main import app

client = TestClient(app)


# =============================================================================
# Fixtures (using conftest.py for auth_headers)
# =============================================================================


@pytest.fixture
def mock_cis_checker():
    """Mock CIS checker with sample results."""
    checker = MagicMock()
    checker.run_all_checks.return_value = {
        "compliance_summary": {
            "total": 18,
            "passed": 14,
            "failed": 4,
            "not_applicable": 0,
            "compliance_percentage": 77.8,
        },
        "controls_checked": [
            {
                "control": 1,
                "title": "Inventory and Control of Enterprise Assets",
                "checks": [
                    {
                        "safeguard": "1.1",
                        "title": "Hardware Asset Inventory",
                        "status": "PASS",
                        "details": "Asset inventory exists",
                    },
                    {
                        "safeguard": "1.2",
                        "title": "Software Asset Inventory",
                        "status": "FAIL",
                        "details": "Incomplete inventory",
                    },
                ],
            }
        ],
    }
    checker.generate_report.return_value = "<html>Report</html>"
    return checker


@pytest.fixture
def mock_nist_checker():
    """Mock NIST checker with sample results."""
    checker = MagicMock()
    checker.run_all_checks.return_value = {
        "compliance_summary": {
            "total": 50,
            "passed": 40,
            "failed": 10,
            "not_applicable": 0,
            "compliance_percentage": 80.0,
        },
        "controls_checked": [],
    }
    checker.generate_report.return_value = "NIST Report"
    return checker


@pytest.fixture
def mock_framework_mapper():
    """Mock framework mapper with sample mappings."""
    mapper = MagicMock()
    mapper.map_control.return_value = {
        "title": "Access Control",
        "mappings": {
            "nist": ["AC-1", "AC-2"],
            "iso": ["A.9.1.1"],
            "pci": ["7.1", "7.2"],
        },
    }
    mapper.find_overlaps.return_value = [
        {"control": "Access Control", "frameworks": ["CIS", "NIST", "PCI"]}
    ]
    mapper.generate_coverage_matrix.return_value = {
        "AC-1": {"covered": True, "mapped_from": ["CIS-6"]},
        "AC-2": {"covered": False, "mapped_from": []},
    }
    mapper.recommend_implementation_order.return_value = [
        {"control": "CIS-6", "satisfies": ["NIST-AC", "PCI-7"], "priority": 1}
    ]
    return mapper


@pytest.fixture
def mock_policy_checker():
    """Mock policy checker with sample results."""
    checker = MagicMock()
    checker.check_all_policies.return_value = [
        {"policy": "password_length", "status": "pass"},
        {"policy": "ssh_config", "status": "fail"},
    ]
    checker.generate_report.return_value = {"passed": 1, "failed": 1}
    return checker


@pytest.fixture
def mock_drift_detector():
    """Mock drift detector with sample results."""
    detector = MagicMock()
    detector.create_baseline.return_value = {"files": 3, "timestamp": "2025-12-28"}
    detector.detect_drift.return_value = [
        {"file": "/etc/ssh/sshd_config", "status": "modified"},
        {"file": "/etc/passwd", "status": "unchanged"},
    ]
    detector.generate_report.return_value = {"drifted_files": 1}
    detector.generate_diff.return_value = "--- a\n+++ b\n@@ -1 +1 @@\n-old\n+new"
    return detector


# =============================================================================
# CIS Controls Endpoints Tests
# =============================================================================


class TestCISEndpoints:
    """Tests for CIS Controls compliance endpoints."""

    def test_run_cis_checks(self, auth_headers, mock_cis_checker):
        """Test running CIS compliance checks."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_cis_checker"
        ) as mock_get:
            mock_get.return_value = mock_cis_checker

            request_data = {"output_format": "json"}
            response = client.post(
                "/api/v1/compliance/cis/run",
                json=request_data,
                headers=auth_headers,
            )

            assert response.status_code == 200
            data = response.json()
            assert "compliance_summary" in data
            assert "controls_checked" in data
            assert data["compliance_summary"]["passed"] == 14

    def test_run_cis_checks_specific_controls(self, auth_headers, mock_cis_checker):
        """Test running specific CIS controls."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_cis_checker"
        ) as mock_get:
            mock_get.return_value = mock_cis_checker

            request_data = {"controls": [1, 2, 3], "output_format": "json"}
            response = client.post(
                "/api/v1/compliance/cis/run",
                json=request_data,
                headers=auth_headers,
            )

            assert response.status_code == 200
            mock_cis_checker.run_all_checks.assert_called_once_with(controls=[1, 2, 3])

    def test_run_cis_checks_without_auth(self):
        """Test CIS checks require authentication."""
        response = client.post("/api/v1/compliance/cis/run", json={})
        assert response.status_code == 401

    def test_list_cis_controls(self, auth_headers):
        """Test listing CIS controls."""
        response = client.get("/api/v1/compliance/cis/controls", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 18
        assert data[0]["id"] == 1
        assert "title" in data[0]

    def test_cis_checker_unavailable(self, auth_headers):
        """Test handling when CIS checker is unavailable."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_cis_checker"
        ) as mock_get:
            mock_get.side_effect = HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="CIS Checker module not available",
            )

            response = client.post(
                "/api/v1/compliance/cis/run",
                json={},
                headers=auth_headers,
            )

            assert response.status_code == 503


# =============================================================================
# NIST 800-53 Endpoints Tests
# =============================================================================


class TestNISTEndpoints:
    """Tests for NIST 800-53 compliance endpoints."""

    def test_run_nist_checks(self, auth_headers, mock_nist_checker):
        """Test running NIST compliance checks."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_nist_checker"
        ) as mock_get:
            mock_get.return_value = mock_nist_checker

            request_data = {"impact_level": "moderate", "output_format": "json"}
            response = client.post(
                "/api/v1/compliance/nist/run",
                json=request_data,
                headers=auth_headers,
            )

            assert response.status_code == 200
            data = response.json()
            assert "compliance_summary" in data
            mock_get.assert_called_once_with(impact_level="moderate")

    def test_run_nist_checks_specific_families(self, auth_headers, mock_nist_checker):
        """Test running specific NIST control families."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_nist_checker"
        ) as mock_get:
            mock_get.return_value = mock_nist_checker

            request_data = {"families": ["AC", "AU"], "impact_level": "high"}
            response = client.post(
                "/api/v1/compliance/nist/run",
                json=request_data,
                headers=auth_headers,
            )

            assert response.status_code == 200
            mock_nist_checker.run_all_checks.assert_called_once_with(
                families=["AC", "AU"]
            )

    def test_run_nist_checks_high_impact(self, auth_headers, mock_nist_checker):
        """Test NIST checks with high impact level."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_nist_checker"
        ) as mock_get:
            mock_get.return_value = mock_nist_checker

            request_data = {"impact_level": "high"}
            response = client.post(
                "/api/v1/compliance/nist/run",
                json=request_data,
                headers=auth_headers,
            )

            assert response.status_code == 200
            mock_get.assert_called_once_with(impact_level="high")

    def test_list_nist_families(self, auth_headers):
        """Test listing NIST control families."""
        response = client.get("/api/v1/compliance/nist/families", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 6
        family_ids = [f["id"] for f in data]
        assert "AC" in family_ids
        assert "AU" in family_ids


# =============================================================================
# Framework Mapping Endpoints Tests
# =============================================================================


class TestFrameworkMappingEndpoints:
    """Tests for control mapping endpoints."""

    def test_get_control_mapping(self, auth_headers, mock_framework_mapper):
        """Test getting control mapping."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_framework_mapper"
        ) as mock_get:
            mock_get.return_value = mock_framework_mapper

            response = client.get(
                "/api/v1/compliance/mapping/CIS-6",
                headers=auth_headers,
            )

            assert response.status_code == 200
            data = response.json()
            assert data["control_id"] == "CIS-6"
            assert "mappings" in data
            assert "nist" in data["mappings"]

    def test_get_control_mapping_not_found(self, auth_headers, mock_framework_mapper):
        """Test getting mapping for non-existent control."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_framework_mapper"
        ) as mock_get:
            mock_framework_mapper.map_control.return_value = None
            mock_get.return_value = mock_framework_mapper

            response = client.get(
                "/api/v1/compliance/mapping/INVALID-99",
                headers=auth_headers,
            )

            assert response.status_code == 404

    def test_get_framework_overlaps(self, auth_headers, mock_framework_mapper):
        """Test finding framework overlaps."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_framework_mapper"
        ) as mock_get:
            mock_get.return_value = mock_framework_mapper

            response = client.get(
                "/api/v1/compliance/mapping/overlaps?frameworks=CIS,NIST,PCI",
                headers=auth_headers,
            )

            assert response.status_code == 200
            data = response.json()
            assert "frameworks" in data
            assert "overlaps" in data
            assert data["frameworks"] == ["CIS", "NIST", "PCI"]

    def test_get_coverage_matrix(self, auth_headers, mock_framework_mapper):
        """Test generating coverage matrix."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_framework_mapper"
        ) as mock_get:
            mock_get.return_value = mock_framework_mapper

            response = client.get(
                "/api/v1/compliance/mapping/coverage?target_framework=NIST",
                headers=auth_headers,
            )

            assert response.status_code == 200
            data = response.json()
            assert data["target_framework"] == "NIST"
            assert "coverage" in data
            assert "coverage_percentage" in data

    def test_get_implementation_recommendations(
        self, auth_headers, mock_framework_mapper
    ):
        """Test getting implementation recommendations."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_framework_mapper"
        ) as mock_get:
            mock_get.return_value = mock_framework_mapper

            response = client.get(
                "/api/v1/compliance/mapping/recommendations?frameworks=CIS,NIST",
                headers=auth_headers,
            )

            assert response.status_code == 200
            data = response.json()
            assert isinstance(data, list)
            assert len(data) > 0
            assert "priority" in data[0]


# =============================================================================
# Policy Validation Endpoints Tests
# =============================================================================


class TestPolicyValidationEndpoints:
    """Tests for policy validation endpoints."""

    def test_validate_policy(self, auth_headers, mock_policy_checker):
        """Test validating a policy file."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_policy_checker"
        ) as mock_get:
            mock_get.return_value = mock_policy_checker

            request_data = {"policy_file": "security_policy.yml"}
            response = client.post(
                "/api/v1/compliance/policy/validate",
                json=request_data,
                headers=auth_headers,
            )

            assert response.status_code == 200
            data = response.json()
            assert data["policy_file"] == "security_policy.yml"
            assert "results" in data
            assert "report" in data

    def test_validate_policy_not_found(self, auth_headers):
        """Test validating non-existent policy file."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_policy_checker"
        ) as mock_get:
            mock_get.side_effect = HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Policy file not found: missing.yml",
            )

            request_data = {"policy_file": "missing.yml"}
            response = client.post(
                "/api/v1/compliance/policy/validate",
                json=request_data,
                headers=auth_headers,
            )

            assert response.status_code == 404


# =============================================================================
# Configuration Drift Detection Tests
# =============================================================================


class TestDriftDetectionEndpoints:
    """Tests for configuration drift detection endpoints."""

    def test_create_drift_baseline(self, auth_headers, mock_drift_detector, tmp_path):
        """Test creating a configuration baseline."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_drift_detector"
        ) as mock_get:
            mock_get.return_value = mock_drift_detector
            with patch("pathlib.Path.mkdir"):
                request_data = {
                    "config_files": ["/etc/ssh/sshd_config", "/etc/passwd"],
                    "baseline_name": "test_baseline",
                }
                response = client.post(
                    "/api/v1/compliance/drift/create-baseline",
                    json=request_data,
                    headers=auth_headers,
                )

                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "success"
                assert "baselines/test_baseline.json" in data["data"]["baseline_file"]

    def test_create_baseline_requires_write_scope(self, tmp_path):
        """Test that baseline creation requires write scope."""
        # Get read-only token
        auth_response = client.post(
            "/api/v1/auth/token",
            data={"username": "analyst", "password": "analyst123"},
        )
        readonly_token = auth_response.json()["access_token"]
        readonly_headers = {"Authorization": f"Bearer {readonly_token}"}

        request_data = {
            "config_files": ["/etc/ssh/sshd_config"],
            "baseline_name": "test_baseline",
        }
        response = client.post(
            "/api/v1/compliance/drift/create-baseline",
            json=request_data,
            headers=readonly_headers,
        )

        assert response.status_code == 403

    def test_detect_drift(self, auth_headers, mock_drift_detector, tmp_path):
        """Test detecting configuration drift."""
        # Create a mock baseline file
        baseline_path = tmp_path / "baseline.json"
        baseline_path.write_text('{"files": {}}')

        with patch(
            "defensive_toolkit.api.routers.compliance.get_drift_detector"
        ) as mock_get:
            mock_get.return_value = mock_drift_detector
            with patch("pathlib.Path.exists", return_value=True):
                request_data = {"baseline_file": str(baseline_path)}
                response = client.post(
                    "/api/v1/compliance/drift/detect",
                    json=request_data,
                    headers=auth_headers,
                )

                assert response.status_code == 200
                data = response.json()
                assert "drift_detected" in data
                assert "results" in data

    def test_detect_drift_baseline_not_found(self, auth_headers):
        """Test drift detection with missing baseline."""
        with patch("pathlib.Path.exists", return_value=False):
            request_data = {"baseline_file": "nonexistent.json"}
            response = client.post(
                "/api/v1/compliance/drift/detect",
                json=request_data,
                headers=auth_headers,
            )

            assert response.status_code == 404

    def test_get_drift_diff(self, auth_headers, mock_drift_detector):
        """Test getting drift diff."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_drift_detector"
        ) as mock_get:
            mock_get.return_value = mock_drift_detector
            with patch("pathlib.Path.exists", return_value=True):
                response = client.get(
                    "/api/v1/compliance/drift/diff?baseline_file=baseline.json&file_path=/etc/ssh/sshd_config",
                    headers=auth_headers,
                )

                assert response.status_code == 200
                data = response.json()
                assert "file_path" in data
                assert "diff" in data


# =============================================================================
# Reporting Endpoints Tests
# =============================================================================


class TestReportingEndpoints:
    """Tests for compliance reporting endpoints."""

    def test_generate_cis_report(self, auth_headers, mock_cis_checker):
        """Test generating CIS compliance report."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_cis_checker"
        ) as mock_get:
            mock_get.return_value = mock_cis_checker

            request_data = {
                "framework": "cis",
                "output_format": "html",
                "include_evidence": True,
            }
            response = client.post(
                "/api/v1/compliance/report/generate",
                json=request_data,
                headers=auth_headers,
            )

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["data"]["framework"] == "cis"

    def test_generate_nist_report(self, auth_headers, mock_nist_checker):
        """Test generating NIST compliance report."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_nist_checker"
        ) as mock_get:
            mock_get.return_value = mock_nist_checker

            request_data = {"framework": "nist_800_53", "output_format": "json"}
            response = client.post(
                "/api/v1/compliance/report/generate",
                json=request_data,
                headers=auth_headers,
            )

            assert response.status_code == 200

    def test_generate_report_unsupported_framework(self, auth_headers):
        """Test report generation for unsupported framework."""
        request_data = {"framework": "hipaa", "output_format": "html"}
        response = client.post(
            "/api/v1/compliance/report/generate",
            json=request_data,
            headers=auth_headers,
        )

        assert response.status_code == 400


# =============================================================================
# Summary & Status Endpoints Tests
# =============================================================================


class TestSummaryEndpoints:
    """Tests for compliance summary endpoints."""

    def test_get_compliance_summary(self, auth_headers):
        """Test getting compliance summary."""
        response = client.get("/api/v1/compliance/summary", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert "frameworks" in data
        assert "overall_status" in data
        assert "last_updated" in data

    def test_list_frameworks(self, auth_headers):
        """Test listing supported frameworks."""
        response = client.get("/api/v1/compliance/frameworks", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert "cis" in data
        assert "nist_800_53" in data

    def test_list_frameworks_without_auth(self):
        """Test listing frameworks requires authentication."""
        response = client.get("/api/v1/compliance/frameworks")
        assert response.status_code == 401


# =============================================================================
# Legacy Endpoint Tests
# =============================================================================


class TestLegacyEndpoints:
    """Tests for legacy compliance endpoints."""

    def test_legacy_check_endpoint_cis(self, auth_headers, mock_cis_checker):
        """Test legacy check endpoint with CIS framework."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_cis_checker"
        ) as mock_get:
            mock_get.return_value = mock_cis_checker

            request_data = {
                "framework": "cis",
                "target": "192.168.1.100",
                "controls": ["1.1", "1.2"],
            }
            response = client.post(
                "/api/v1/compliance/check",
                json=request_data,
                headers=auth_headers,
            )

            assert response.status_code == 200
            data = response.json()
            assert data["framework"] == "cis"
            assert "total_controls" in data
            assert "compliance_percentage" in data

    def test_legacy_check_endpoint_nist(self, auth_headers, mock_nist_checker):
        """Test legacy check endpoint with NIST framework."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_nist_checker"
        ) as mock_get:
            mock_get.return_value = mock_nist_checker

            request_data = {
                "framework": "nist_800_53",
                "target": "192.168.1.100",
            }
            response = client.post(
                "/api/v1/compliance/check",
                json=request_data,
                headers=auth_headers,
            )

            assert response.status_code == 200

    def test_legacy_check_unsupported_framework(self, auth_headers):
        """Test legacy check with unsupported framework returns placeholder."""
        request_data = {
            "framework": "hipaa",
            "target": "192.168.1.100",
        }
        response = client.post(
            "/api/v1/compliance/check",
            json=request_data,
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = response.json()
        assert data["total_controls"] == 0


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling scenarios."""

    def test_cis_check_internal_error(self, auth_headers):
        """Test CIS check internal error handling."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_cis_checker"
        ) as mock_get:
            checker = MagicMock()
            checker.run_all_checks.side_effect = Exception("Database connection failed")
            mock_get.return_value = checker

            response = client.post(
                "/api/v1/compliance/cis/run",
                json={},
                headers=auth_headers,
            )

            assert response.status_code == 500
            assert "failed" in response.json()["detail"].lower()

    def test_nist_check_internal_error(self, auth_headers):
        """Test NIST check internal error handling."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_nist_checker"
        ) as mock_get:
            checker = MagicMock()
            checker.run_all_checks.side_effect = Exception("Check failed")
            mock_get.return_value = checker

            response = client.post(
                "/api/v1/compliance/nist/run",
                json={},
                headers=auth_headers,
            )

            assert response.status_code == 500

    def test_mapping_internal_error(self, auth_headers):
        """Test control mapping internal error handling."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_framework_mapper"
        ) as mock_get:
            mapper = MagicMock()
            mapper.map_control.side_effect = Exception("Mapping failed")
            mock_get.return_value = mapper

            response = client.get(
                "/api/v1/compliance/mapping/CIS-1",
                headers=auth_headers,
            )

            assert response.status_code == 500


# =============================================================================
# Validation Tests
# =============================================================================


class TestValidation:
    """Tests for request validation."""

    def test_cis_invalid_output_format(self, auth_headers):
        """Test CIS check with invalid output format."""
        request_data = {"output_format": "invalid"}
        response = client.post(
            "/api/v1/compliance/cis/run",
            json=request_data,
            headers=auth_headers,
        )

        assert response.status_code == 422

    def test_nist_invalid_impact_level(self, auth_headers):
        """Test NIST check with invalid impact level."""
        request_data = {"impact_level": "invalid"}
        response = client.post(
            "/api/v1/compliance/nist/run",
            json=request_data,
            headers=auth_headers,
        )

        assert response.status_code == 422

    def test_baseline_name_validation(self, auth_headers):
        """Test baseline name length validation."""
        request_data = {"config_files": ["/etc/passwd"], "baseline_name": ""}
        response = client.post(
            "/api/v1/compliance/drift/create-baseline",
            json=request_data,
            headers=auth_headers,
        )

        assert response.status_code == 422


# =============================================================================
# Helper Function Import Error Tests
# =============================================================================


class TestHelperImportErrors:
    """Tests for helper function import error handling."""

    def test_cis_checker_import_error(self, auth_headers):
        """Test CIS checker import error handling."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_cis_checker"
        ) as mock_get:
            mock_get.side_effect = HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="CIS Checker module not available",
            )
            response = client.post(
                "/api/v1/compliance/cis/run",
                json={},
                headers=auth_headers,
            )
            assert response.status_code == 503
            assert "CIS Checker" in response.json()["detail"]

    def test_nist_checker_import_error(self, auth_headers):
        """Test NIST checker import error handling."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_nist_checker"
        ) as mock_get:
            mock_get.side_effect = HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="NIST Checker module not available",
            )
            response = client.post(
                "/api/v1/compliance/nist/run",
                json={},
                headers=auth_headers,
            )
            assert response.status_code == 503
            assert "NIST Checker" in response.json()["detail"]

    def test_framework_mapper_import_error(self, auth_headers):
        """Test framework mapper import error handling."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_framework_mapper"
        ) as mock_get:
            mock_get.side_effect = HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Framework Mapper module not available",
            )
            response = client.get(
                "/api/v1/compliance/mapping/CIS-1",
                headers=auth_headers,
            )
            assert response.status_code == 503
            assert "Framework Mapper" in response.json()["detail"]

    def test_policy_checker_import_error(self, auth_headers):
        """Test policy checker import error handling."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_policy_checker"
        ) as mock_get:
            mock_get.side_effect = HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Policy Checker module not available",
            )
            response = client.post(
                "/api/v1/compliance/policy/validate",
                json={"policy_file": "/path/to/policy.yaml"},
                headers=auth_headers,
            )
            assert response.status_code == 503
            assert "Policy Checker" in response.json()["detail"]

    def test_drift_detector_import_error(self, auth_headers):
        """Test drift detector import error handling."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_drift_detector"
        ) as mock_get:
            mock_get.side_effect = HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Drift Detector module not available",
            )
            response = client.post(
                "/api/v1/compliance/drift/create-baseline",
                json={"config_files": ["/etc/passwd"], "baseline_name": "test"},
                headers=auth_headers,
            )
            # Router catches all exceptions and returns 500
            assert response.status_code == 500
            assert "Baseline creation failed" in response.json()["detail"]


# =============================================================================
# Additional Exception Path Tests
# =============================================================================


class TestAdditionalExceptionPaths:
    """Tests for additional exception handling paths."""

    def test_framework_overlaps_exception(self, auth_headers):
        """Test framework overlaps exception handling."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_framework_mapper"
        ) as mock_get:
            mapper = MagicMock()
            # Method is find_overlaps, not get_overlapping_controls
            mapper.find_overlaps.side_effect = Exception("Overlap check failed")
            mock_get.return_value = mapper

            # Query parameter is comma-separated string, not list
            response = client.get(
                "/api/v1/compliance/mapping/overlaps?frameworks=CIS,NIST",
                headers=auth_headers,
            )
            assert response.status_code == 500
            assert "overlap" in response.json()["detail"].lower()

    def test_coverage_matrix_exception(self, auth_headers):
        """Test coverage matrix exception handling."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_framework_mapper"
        ) as mock_get:
            mapper = MagicMock()
            # Method is generate_coverage_matrix
            mapper.generate_coverage_matrix.side_effect = Exception("Matrix generation failed")
            mock_get.return_value = mapper

            # target_framework is required
            response = client.get(
                "/api/v1/compliance/mapping/coverage?target_framework=CIS",
                headers=auth_headers,
            )
            assert response.status_code == 500

    def test_drift_detection_exception(self, auth_headers):
        """Test drift detection exception handling."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_drift_detector"
        ) as mock_get:
            detector = MagicMock()
            detector.detect_drift.side_effect = Exception("Drift detection failed")
            mock_get.return_value = detector
            with patch("pathlib.Path.exists", return_value=True):
                response = client.post(
                    "/api/v1/compliance/drift/detect",
                    json={"baseline_file": "baseline.json", "config_files": ["/etc/passwd"]},
                    headers=auth_headers,
                )
                assert response.status_code == 500
                assert "drift" in response.json()["detail"].lower()

    def test_report_generation_exception(self, auth_headers, mock_cis_checker):
        """Test report generation exception handling."""
        with patch(
            "defensive_toolkit.api.routers.compliance.get_cis_checker"
        ) as mock_get:
            mock_cis_checker.run_all_checks.side_effect = Exception("Report generation failed")
            mock_get.return_value = mock_cis_checker

            response = client.post(
                "/api/v1/compliance/report/generate",
                json={"framework": "cis", "output_format": "html"},
                headers=auth_headers,
            )
            assert response.status_code == 500
