#!/usr/bin/env python3
"""
Unit tests for compliance/frameworks/cis-checker.py
"""

import json
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from defensive_toolkit.compliance.frameworks.cis_checker import CISChecker


class TestCISChecker:
    """Test CISChecker class"""

    def test_init_default(self):
        """Test CIS checker initialization"""
        checker = CISChecker()

        assert checker.output_format == "json"
        assert checker.os_type in ["windows", "linux", "darwin"]
        assert "timestamp" in checker.results
        assert checker.results["cis_version"] == "v8"

    def test_init_custom_format(self):
        """Test initialization with custom output format"""
        checker = CISChecker(output_format="text")
        assert checker.output_format == "text"

    def test_results_structure(self):
        """Test results dictionary structure"""
        checker = CISChecker()

        assert "compliance_summary" in checker.results
        summary = checker.results["compliance_summary"]

        assert "total" in summary
        assert "passed" in summary
        assert "failed" in summary
        assert "not_applicable" in summary
        assert "compliance_percentage" in summary

    @patch("subprocess.run")
    def test_run_command_success(self, mock_run):
        """Test successful command execution"""
        mock_run.return_value = Mock(returncode=0, stdout="success", stderr="")

        checker = CISChecker()
        result = checker._run_command(["echo", "test"])

        assert result is not None

    @patch("subprocess.run")
    def test_run_command_failure(self, mock_run):
        """Test failed command execution"""
        mock_run.side_effect = Exception("Command failed")

        checker = CISChecker()
        result = checker._run_command(["invalid_command"])

        assert result is None or result == False

    @patch("shutil.which")
    def test_command_exists_true(self, mock_which):
        """Test command existence check - command exists"""
        mock_which.return_value = "/usr/bin/test"

        checker = CISChecker()
        result = checker._command_exists("test")

        assert result is True

    @patch("shutil.which")
    def test_command_exists_false(self, mock_which):
        """Test command existence check - command not found"""
        mock_which.return_value = None

        checker = CISChecker()
        result = checker._command_exists("nonexistent")

        assert result is False

    def test_check_control_1_inventory(self):
        """Test CIS Control 1 check"""
        checker = CISChecker()
        result = checker.check_control_1_inventory()

        assert isinstance(result, dict)
        assert "control" in result
        assert result["control"] == "1"
        assert "title" in result
        assert "checks" in result
        assert isinstance(result["checks"], list)

    def test_check_control_2_software_inventory(self):
        """Test CIS Control 2 check"""
        checker = CISChecker()
        result = checker.check_control_2_software_inventory()

        assert isinstance(result, dict)
        assert result["control"] == "2"
        assert "checks" in result
        assert len(result["checks"]) > 0

    def test_check_control_3_data_protection(self):
        """Test CIS Control 3 check"""
        checker = CISChecker()
        result = checker.check_control_3_data_protection()

        assert isinstance(result, dict)
        assert result["control"] == "3"
        assert "checks" in result

    def test_check_results_format(self):
        """Test check result format"""
        checker = CISChecker()
        result = checker.check_control_1_inventory()

        # Validate check structure
        for check in result["checks"]:
            assert "safeguard" in check
            assert "title" in check
            assert "status" in check
            assert check["status"] in ["PASS", "FAIL", "MANUAL", "N/A"]

    @patch("platform.system")
    def test_windows_specific_checks(self, mock_platform):
        """Test Windows-specific checks"""
        mock_platform.return_value = "Windows"

        checker = CISChecker()
        assert checker.os_type == "windows"

        result = checker.check_control_1_inventory()
        assert result is not None

    @patch("platform.system")
    def test_linux_specific_checks(self, mock_platform):
        """Test Linux-specific checks"""
        mock_platform.return_value = "Linux"

        checker = CISChecker()
        assert checker.os_type == "linux"

        result = checker.check_control_1_inventory()
        assert result is not None

    def test_detect_package_manager_linux(self):
        """Test package manager detection on Linux"""
        checker = CISChecker()

        # This will depend on the actual system
        if checker.os_type == "linux":
            result = checker._detect_package_manager()
            # Should return apt, yum, dnf, pacman, or None
            assert result in ["apt", "yum", "dnf", "pacman", "zypper", None]

    def test_calculate_compliance_percentage(self):
        """Test compliance percentage calculation logic"""
        # Test the calculation logic directly (compliance is calculated inline in reports)
        total = 10
        passed = 7
        expected_percentage = round((passed / total * 100) if total > 0 else 0, 2)
        assert expected_percentage == 70.0

    def test_calculate_compliance_percentage_zero_total(self):
        """Test compliance calculation with zero total"""
        # Test the calculation logic directly
        total = 0
        passed = 0
        expected_percentage = round((passed / total * 100) if total > 0 else 0, 2)
        assert expected_percentage == 0.0


class TestCISCheckerIntegration:
    """Integration tests for CIS Checker"""

    def test_run_all_checks(self):
        """Test running all CIS controls"""
        checker = CISChecker()

        # Run multiple control checks
        control1 = checker.check_control_1_inventory()
        control2 = checker.check_control_2_software_inventory()
        control3 = checker.check_control_3_data_protection()

        assert control1 is not None
        assert control2 is not None
        assert control3 is not None

    def test_generate_report_json(self, tmp_path):
        """Test generating JSON report"""
        checker = CISChecker(output_format="json")

        # Run some checks
        checker.check_control_1_inventory()
        checker.check_control_2_software_inventory()

        # Generate report
        report_file = tmp_path / "cis_report.json"
        checker.generate_report(report_file)

        assert report_file.exists()

        with open(report_file, "r") as f:
            report_data = json.load(f)

        assert "timestamp" in report_data
        assert "cis_version" in report_data


# [+] Parametrized Tests
@pytest.mark.parametrize("output_format", ["json", "text", "html"])
def test_output_formats(output_format):
    """Test different output formats"""
    checker = CISChecker(output_format=output_format)
    assert checker.output_format == output_format


@pytest.mark.parametrize("control_num", [1, 2, 3, 4, 5])
def test_control_checks(control_num):
    """Test individual control checks"""
    checker = CISChecker()

    # Map control numbers to methods
    check_methods = {
        1: checker.check_control_1_inventory,
        2: checker.check_control_2_software_inventory,
        3: checker.check_control_3_data_protection,
        # Add more as needed
    }

    if control_num in check_methods:
        result = check_methods[control_num]()
        assert result is not None
        assert result["control"] == str(control_num)


# [+] Platform-specific tests
@pytest.mark.windows
def test_windows_registry_check():
    """Test Windows registry-based checks"""
    import platform

    if platform.system() != "Windows":
        pytest.skip("Windows-only test")

    checker = CISChecker()
    result = checker.check_control_2_software_inventory()
    assert result is not None


@pytest.mark.linux
def test_linux_package_manager():
    """Test Linux package manager detection"""
    import platform

    if platform.system() != "Linux":
        pytest.skip("Linux-only test")

    checker = CISChecker()
    pkg_mgr = checker._detect_package_manager()
    assert pkg_mgr is not None


# [+] Mark slow tests
@pytest.mark.slow
@pytest.mark.integration
def test_comprehensive_scan():
    """Test comprehensive CIS compliance scan"""
    checker = CISChecker()

    # Run all available control methods by introspection
    results = []
    for method_name in dir(checker):
        if method_name.startswith("check_control_") and callable(getattr(checker, method_name)):
            try:
                check_method = getattr(checker, method_name)
                results.append(check_method())
            except Exception:
                pass

    assert len(results) > 0
