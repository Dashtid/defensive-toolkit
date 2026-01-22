"""
Tests for Windows hardening scanner.

Tests the WindowsHardeningScanner class functionality including:
- Scanner initialization
- Individual security checks
- Cross-platform behavior (returns N/A on non-Windows)
- Remediation script generation
- run_all_checks aggregation

All tests use mocking to ensure they run on Linux CI.
"""

from unittest.mock import MagicMock, patch

import pytest


class TestWindowsHardeningScannerInit:
    """Tests for WindowsHardeningScanner initialization."""

    def test_scanner_initialization_default(self):
        """Test scanner initializes with default values."""
        with patch("platform.system", return_value="Linux"):
            from defensive_toolkit.hardening.windows.cis_benchmarks import (
                WindowsHardeningScanner,
            )

            scanner = WindowsHardeningScanner()
            assert scanner.target == "localhost"
            assert scanner.cis_level == 1
            assert scanner.is_windows is False
            assert scanner.checks == []

    def test_scanner_initialization_custom(self):
        """Test scanner initializes with custom values."""
        with patch("platform.system", return_value="Linux"):
            from defensive_toolkit.hardening.windows.cis_benchmarks import (
                WindowsHardeningScanner,
            )

            scanner = WindowsHardeningScanner(target="remote-host", cis_level=2)
            assert scanner.target == "remote-host"
            assert scanner.cis_level == 2

    def test_scanner_detects_windows(self):
        """Test scanner correctly detects Windows platform."""
        with patch("platform.system", return_value="Windows"):
            with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=1):
                from defensive_toolkit.hardening.windows.cis_benchmarks import (
                    WindowsHardeningScanner,
                )

                scanner = WindowsHardeningScanner()
                assert scanner.is_windows is True


class TestWindowsHardeningScannerNonWindows:
    """Tests for scanner behavior on non-Windows systems."""

    @pytest.fixture
    def scanner(self):
        """Create scanner on non-Windows system."""
        with patch("platform.system", return_value="Linux"):
            from defensive_toolkit.hardening.windows.cis_benchmarks import (
                WindowsHardeningScanner,
            )

            return WindowsHardeningScanner()

    def test_bitlocker_check_non_windows(self, scanner):
        """Test BitLocker check returns N/A on non-Windows."""
        check = scanner.check_bitlocker_encryption()
        assert check.check_id == "WIN-ENC-001"
        assert check.passed is False
        assert "N/A" in check.current_value
        assert check.category == "encryption"
        assert check.severity == "high"

    def test_defender_realtime_non_windows(self, scanner):
        """Test Defender real-time check returns N/A on non-Windows."""
        check = scanner.check_defender_realtime()
        assert check.check_id == "WIN-AV-001"
        assert check.passed is False
        assert "N/A" in check.current_value

    def test_firewall_checks_non_windows(self, scanner):
        """Test firewall checks return N/A on non-Windows."""
        for check_func, check_id in [
            (scanner.check_firewall_domain, "WIN-FW-001"),
            (scanner.check_firewall_private, "WIN-FW-002"),
            (scanner.check_firewall_public, "WIN-FW-003"),
        ]:
            check = check_func()
            assert check.check_id == check_id
            assert check.passed is False
            assert "N/A" in check.current_value
            assert check.category == "firewall"

    def test_run_all_checks_non_windows(self, scanner):
        """Test run_all_checks returns 17 N/A checks on non-Windows."""
        result = scanner.run_all_checks()

        assert result.os_type == "windows"
        assert result.total_checks == 17
        assert result.passed == 0
        assert result.failed == 17
        assert result.compliance_percentage == 0.0

        # All checks should have N/A in current_value
        for check in result.checks:
            assert "N/A" in check.current_value

    def test_remediation_script_non_windows(self, scanner):
        """Test remediation script generation on non-Windows."""
        scanner.run_all_checks()
        script = scanner.get_remediation_script()

        assert "#Requires -RunAsAdministrator" in script
        assert "WIN-ENC-001" in script
        assert "BitLocker" in script


class TestWindowsHardeningScannerWindows:
    """Tests for scanner behavior on Windows systems (mocked)."""

    @pytest.fixture
    def mock_windows_scanner(self):
        """Create scanner with mocked Windows environment."""
        with patch("platform.system", return_value="Windows"):
            with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=1):
                from defensive_toolkit.hardening.windows.cis_benchmarks import (
                    WindowsHardeningScanner,
                )

                scanner = WindowsHardeningScanner()
                return scanner

    def test_run_powershell_not_windows(self):
        """Test _run_powershell returns error on non-Windows."""
        with patch("platform.system", return_value="Linux"):
            from defensive_toolkit.hardening.windows.cis_benchmarks import (
                WindowsHardeningScanner,
            )

            scanner = WindowsHardeningScanner()
            ret, out, err = scanner._run_powershell("Get-Process")

            assert ret == -1
            assert "Not running on Windows" in err

    def test_bitlocker_check_pass(self, mock_windows_scanner):
        """Test BitLocker check passes when protection is On."""
        with patch.object(
            mock_windows_scanner,
            "_run_powershell",
            return_value=(0, "On", ""),
        ):
            check = mock_windows_scanner.check_bitlocker_encryption()

            assert check.check_id == "WIN-ENC-001"
            assert check.passed is True
            assert "On" in check.current_value
            assert check.remediation is None

    def test_bitlocker_check_fail(self, mock_windows_scanner):
        """Test BitLocker check fails when protection is Off."""
        with patch.object(
            mock_windows_scanner,
            "_run_powershell",
            return_value=(0, "Off", ""),
        ):
            check = mock_windows_scanner.check_bitlocker_encryption()

            assert check.passed is False
            assert "Off" in check.current_value
            assert check.remediation is not None
            assert "manage-bde" in check.remediation

    def test_defender_realtime_pass(self, mock_windows_scanner):
        """Test Defender real-time check passes when enabled."""
        with patch.object(
            mock_windows_scanner,
            "_run_powershell",
            return_value=(0, "True", ""),
        ):
            check = mock_windows_scanner.check_defender_realtime()

            assert check.check_id == "WIN-AV-001"
            assert check.passed is True
            assert check.remediation is None

    def test_defender_realtime_fail(self, mock_windows_scanner):
        """Test Defender real-time check fails when disabled."""
        with patch.object(
            mock_windows_scanner,
            "_run_powershell",
            return_value=(0, "False", ""),
        ):
            check = mock_windows_scanner.check_defender_realtime()

            assert check.passed is False
            assert "Set-MpPreference" in check.remediation

    def test_firewall_domain_pass(self, mock_windows_scanner):
        """Test firewall domain profile check passes when enabled."""
        with patch.object(
            mock_windows_scanner,
            "_run_powershell",
            return_value=(0, "True", ""),
        ):
            check = mock_windows_scanner.check_firewall_domain()

            assert check.check_id == "WIN-FW-001"
            assert check.passed is True
            assert check.category == "firewall"

    def test_smbv1_disabled_pass(self, mock_windows_scanner):
        """Test SMBv1 check passes when disabled."""
        with patch.object(
            mock_windows_scanner,
            "_run_powershell",
            return_value=(0, "False", ""),
        ):
            check = mock_windows_scanner.check_smbv1_disabled()

            assert check.check_id == "WIN-NET-001"
            assert check.passed is True
            assert check.category == "network"

    def test_smbv1_disabled_fail(self, mock_windows_scanner):
        """Test SMBv1 check fails when enabled."""
        with patch.object(
            mock_windows_scanner,
            "_run_powershell",
            return_value=(0, "True", ""),
        ):
            check = mock_windows_scanner.check_smbv1_disabled()

            assert check.passed is False
            assert "Disable-WindowsOptionalFeature" in check.remediation

    def test_uac_consent_prompt_pass(self, mock_windows_scanner):
        """Test UAC consent prompt check passes with secure settings."""
        with patch.object(
            mock_windows_scanner,
            "_run_powershell",
            return_value=(0, "2", ""),
        ):
            check = mock_windows_scanner.check_uac_consent_prompt()

            assert check.check_id == "WIN-UAC-001"
            assert check.passed is True
            assert check.category == "uac"

    def test_guest_account_disabled_pass(self, mock_windows_scanner):
        """Test guest account check passes when disabled."""
        with patch.object(
            mock_windows_scanner,
            "_run_powershell",
            return_value=(0, "False", ""),
        ):
            check = mock_windows_scanner.check_guest_account_disabled()

            assert check.check_id == "WIN-ACC-001"
            assert check.passed is True

    def test_secure_boot_pass(self, mock_windows_scanner):
        """Test Secure Boot check passes when enabled."""
        with patch.object(
            mock_windows_scanner,
            "_run_powershell",
            return_value=(0, "True", ""),
        ):
            check = mock_windows_scanner.check_secure_boot()

            assert check.check_id == "WIN-BOOT-001"
            assert check.passed is True

    def test_run_all_checks_mixed_results(self, mock_windows_scanner):
        """Test run_all_checks aggregates results correctly."""
        # Mock different results for different checks
        def mock_powershell(cmd, timeout=30):
            if "BitLocker" in cmd:
                return (0, "On", "")
            elif "RealTimeProtectionEnabled" in cmd:
                return (0, "True", "")
            elif "MAPSReporting" in cmd:
                return (0, "2", "")
            elif "PUAProtection" in cmd:
                return (0, "1", "")
            elif "NetFirewallProfile" in cmd:
                return (0, "True", "")
            elif "ConsentPromptBehaviorAdmin" in cmd:
                return (0, "2", "")
            elif "EnableScriptBlockLogging" in cmd:
                return (0, "0", "")  # Fail this one
            elif "EnableSMB1Protocol" in cmd:
                return (0, "False", "")
            elif "EnableMulticast" in cmd:
                return (0, "0", "")
            elif "TcpipNetbiosOptions" in cmd:
                return (0, "2", "")
            elif "Guest" in cmd:
                return (0, "False", "")
            elif "Lockout threshold" in cmd:
                return (0, "5", "")
            elif "auditpol" in cmd:
                return (0, "  Logon                                      Success and Failure", "")
            elif "SecureBootUEFI" in cmd:
                return (0, "True", "")
            elif "EnableVirtualizationBasedSecurity" in cmd:
                return (0, "1", "")
            return (0, "", "")

        with patch.object(mock_windows_scanner, "_run_powershell", side_effect=mock_powershell):
            result = mock_windows_scanner.run_all_checks()

            assert result.total_checks == 17
            # PowerShell logging should fail, rest should pass
            assert result.passed == 16
            assert result.failed == 1
            assert result.compliance_percentage == 94.12

            # Check categories are populated
            assert "encryption" in result.categories
            assert "antivirus" in result.categories
            assert "firewall" in result.categories
            assert result.categories["encryption"]["passed"] == 1

    def test_remediation_script_generation(self, mock_windows_scanner):
        """Test remediation script is generated for failed checks."""
        # All checks fail
        with patch.object(
            mock_windows_scanner,
            "_run_powershell",
            return_value=(0, "False", ""),
        ):
            mock_windows_scanner.run_all_checks()
            script = mock_windows_scanner.get_remediation_script()

            assert "#Requires -RunAsAdministrator" in script
            assert "Windows Hardening Remediation Script" in script
            assert "try {" in script
            assert "catch {" in script

    def test_remediation_script_empty_when_all_pass(self, mock_windows_scanner):
        """Test remediation script indicates no action needed when all pass."""
        # Make all checks pass by returning appropriate values for each command
        def mock_pass(cmd, timeout=30):
            # BitLocker
            if "BitLocker" in cmd:
                return (0, "On", "")
            # Defender
            elif "RealTimeProtectionEnabled" in cmd:
                return (0, "True", "")
            elif "MAPSReporting" in cmd:
                return (0, "2", "")
            elif "PUAProtection" in cmd:
                return (0, "1", "")
            # Firewall
            elif "NetFirewallProfile" in cmd:
                return (0, "True", "")
            # UAC
            elif "ConsentPromptBehaviorAdmin" in cmd:
                return (0, "2", "")
            # PowerShell logging
            elif "EnableScriptBlockLogging" in cmd:
                return (0, "1", "")
            # Network
            elif "EnableSMB1Protocol" in cmd:
                return (0, "False", "")
            elif "EnableMulticast" in cmd:
                return (0, "0", "")
            elif "Win32_NetworkAdapterConfiguration" in cmd:
                return (0, "2", "")
            # Account
            elif "Get-LocalUser" in cmd:
                return (0, "False", "")
            elif "net accounts" in cmd:
                return (0, "5", "")
            # Audit
            elif "auditpol" in cmd:
                return (0, "  Logon                      Success and Failure", "")
            # Boot
            elif "SecureBootUEFI" in cmd:
                return (0, "True", "")
            # Credential Guard
            elif "EnableVirtualizationBasedSecurity" in cmd:
                return (0, "1", "")
            return (0, "True", "")

        with patch.object(mock_windows_scanner, "_run_powershell", side_effect=mock_pass):
            mock_windows_scanner.run_all_checks()
            script = mock_windows_scanner.get_remediation_script()

            assert "no remediation needed" in script.lower()


class TestWindowsHardeningScannerDataclasses:
    """Tests for dataclass imports and usage."""

    def test_imports_shared_dataclasses(self):
        """Test that scanner imports HardeningCheck and HardeningScanResult from Linux module."""
        from defensive_toolkit.hardening.windows.cis_benchmarks import (
            HardeningCheck,
            HardeningScanResult,
        )
        from defensive_toolkit.hardening.linux.cis_benchmarks import (
            HardeningCheck as LinuxHardeningCheck,
            HardeningScanResult as LinuxHardeningScanResult,
        )

        # Should be the same classes
        assert HardeningCheck is LinuxHardeningCheck
        assert HardeningScanResult is LinuxHardeningScanResult

    def test_check_result_structure(self):
        """Test that check results have correct structure."""
        with patch("platform.system", return_value="Linux"):
            from defensive_toolkit.hardening.windows.cis_benchmarks import (
                WindowsHardeningScanner,
            )

            scanner = WindowsHardeningScanner()
            check = scanner.check_bitlocker_encryption()

            # Verify all required fields exist
            assert hasattr(check, "check_id")
            assert hasattr(check, "title")
            assert hasattr(check, "description")
            assert hasattr(check, "category")
            assert hasattr(check, "severity")
            assert hasattr(check, "passed")
            assert hasattr(check, "current_value")
            assert hasattr(check, "expected_value")
            assert hasattr(check, "remediation")
            assert hasattr(check, "cis_reference")

    def test_scan_result_structure(self):
        """Test that scan results have correct structure."""
        with patch("platform.system", return_value="Linux"):
            from defensive_toolkit.hardening.windows.cis_benchmarks import (
                WindowsHardeningScanner,
            )

            scanner = WindowsHardeningScanner()
            result = scanner.run_all_checks()

            # Verify all required fields exist
            assert hasattr(result, "target")
            assert hasattr(result, "os_type")
            assert hasattr(result, "cis_level")
            assert hasattr(result, "total_checks")
            assert hasattr(result, "passed")
            assert hasattr(result, "failed")
            assert hasattr(result, "skipped")
            assert hasattr(result, "compliance_percentage")
            assert hasattr(result, "checks")
            assert hasattr(result, "categories")


class TestWindowsHardeningScannerCheckIDs:
    """Tests for consistent check ID patterns."""

    def test_all_check_ids_start_with_win(self):
        """Test all check IDs start with WIN- prefix."""
        with patch("platform.system", return_value="Linux"):
            from defensive_toolkit.hardening.windows.cis_benchmarks import (
                WindowsHardeningScanner,
            )

            scanner = WindowsHardeningScanner()
            result = scanner.run_all_checks()

            for check in result.checks:
                assert check.check_id.startswith("WIN-"), f"Invalid check ID: {check.check_id}"

    def test_unique_check_ids(self):
        """Test all check IDs are unique."""
        with patch("platform.system", return_value="Linux"):
            from defensive_toolkit.hardening.windows.cis_benchmarks import (
                WindowsHardeningScanner,
            )

            scanner = WindowsHardeningScanner()
            result = scanner.run_all_checks()

            check_ids = [check.check_id for check in result.checks]
            assert len(check_ids) == len(set(check_ids)), "Duplicate check IDs found"

    def test_expected_categories(self):
        """Test all expected categories are present."""
        with patch("platform.system", return_value="Linux"):
            from defensive_toolkit.hardening.windows.cis_benchmarks import (
                WindowsHardeningScanner,
            )

            scanner = WindowsHardeningScanner()
            result = scanner.run_all_checks()

            expected_categories = {
                "encryption",
                "antivirus",
                "firewall",
                "uac",
                "registry",
                "network",
                "account",
                "audit_logging",
                "boot",
                "credential",
            }

            actual_categories = set(result.categories.keys())
            assert expected_categories == actual_categories
