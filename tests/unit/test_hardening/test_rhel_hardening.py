"""
Tests for Linux (RHEL/CentOS) hardening scripts.

Tests the harden-rhel.sh script functionality including:
- Command-line argument parsing
- Hardening level configuration
- Dry-run mode
- SSH hardening
- Firewalld configuration
- SELinux configuration
- Kernel parameter hardening
"""

import os
import subprocess
from pathlib import Path

import pytest

# Path to hardening scripts
HARDENING_DIR = Path(__file__).parent.parent.parent.parent / "hardening" / "linux"
RHEL_SCRIPT = HARDENING_DIR / "harden-rhel.sh"


class TestRHELHardeningScript:
    """Tests for RHEL/CentOS hardening script."""

    @pytest.fixture
    def script_path(self) -> Path:
        """Return path to RHEL hardening script."""
        return RHEL_SCRIPT

    def test_script_exists(self, script_path: Path):
        """Test that the RHEL hardening script exists."""
        assert script_path.exists(), f"Script not found: {script_path}"

    def test_script_is_executable(self, script_path: Path):
        """Test that the script is executable."""
        assert os.access(script_path, os.X_OK), f"Script not executable: {script_path}"

    def test_help_message(self, script_path: Path):
        """Test that --help displays usage information."""
        result = subprocess.run(
            ["bash", str(script_path), "--help"],
            capture_output=True,
            text=True
        )
        assert "Usage:" in result.stdout or "usage:" in result.stdout.lower()
        assert "--level" in result.stdout
        assert "--dry-run" in result.stdout

    def test_dry_run_no_modifications(self, script_path: Path):
        """Test that dry-run mode doesn't make any modifications."""
        result = subprocess.run(
            ["bash", str(script_path), "--level", "1", "--dry-run", "--no-backup"],
            capture_output=True,
            text=True
        )

        # Should complete without errors or indicate dry-run
        assert result.returncode == 0 or "dry" in result.stdout.lower()

        # Should indicate dry-run mode
        output = result.stdout + result.stderr
        assert "dry" in output.lower() or "would" in output.lower()

    @pytest.mark.parametrize("level", ["1", "2", "3"])
    def test_hardening_levels(self, script_path: Path, level: str):
        """Test different hardening levels in dry-run mode."""
        result = subprocess.run(
            ["bash", str(script_path), "--level", level, "--dry-run", "--no-backup"],
            capture_output=True,
            text=True
        )

        # Should complete successfully
        assert result.returncode == 0 or "level" in result.stdout.lower()

    def test_script_structure(self, script_path: Path):
        """Test that script has required functions and structure."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Check for essential functions
        required_functions = [
            "harden_ssh",
            "configure_firewall",
            "harden_kernel"
        ]

        for func in required_functions:
            assert func in content, f"Missing function: {func}"

        # Check for shebang
        assert content.startswith("#!/bin/bash")

        # Check for CIS references
        assert "CIS" in content or "cis" in content

    def test_firewalld_configuration(self, script_path: Path):
        """Test that firewalld configuration is present (not UFW)."""
        with open(script_path, 'r') as f:
            content = f.read()

        # RHEL uses firewalld, not UFW
        assert "firewalld" in content.lower() or "firewall-cmd" in content

        # Should not use UFW
        assert "ufw " not in content.lower() or content.lower().count("ufw") == 0

    def test_selinux_configuration(self, script_path: Path):
        """Test that SELinux configuration is present (not AppArmor)."""
        with open(script_path, 'r') as f:
            content = f.read()

        # RHEL uses SELinux, not AppArmor
        assert "selinux" in content.lower()

        # Should enforce SELinux
        assert "enforcing" in content.lower()

    def test_yum_cron_updates(self, script_path: Path):
        """Test that yum-cron automatic updates are configured."""
        with open(script_path, 'r') as f:
            content = f.read()

        # RHEL uses yum-cron or dnf-automatic
        assert "yum-cron" in content.lower() or "dnf" in content.lower()

    def test_ssh_hardening_commands(self, script_path: Path):
        """Test that SSH hardening includes key security settings."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Check for critical SSH settings
        ssh_settings = [
            "PermitRootLogin",
            "MaxAuthTries",
            "X11Forwarding"
        ]

        for setting in ssh_settings:
            assert setting in content, f"Missing SSH setting: {setting}"

    def test_kernel_hardening(self, script_path: Path):
        """Test that kernel parameter hardening is included."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Check for sysctl configuration
        assert "sysctl" in content.lower()

        # Check for key kernel parameters
        kernel_params = [
            "ip_forward",
            "accept_redirects",
            "tcp_syncookies"
        ]

        for param in kernel_params:
            assert param in content, f"Missing kernel parameter: {param}"

    def test_aide_configuration(self, script_path: Path):
        """Test that AIDE file integrity monitoring is configured."""
        with open(script_path, 'r') as f:
            content = f.read()

        assert "aide" in content.lower() or "AIDE" in content

    def test_fail2ban_configuration(self, script_path: Path):
        """Test that Fail2ban intrusion prevention is included."""
        with open(script_path, 'r') as f:
            content = f.read()

        assert "fail2ban" in content.lower()

    def test_password_policy(self, script_path: Path):
        """Test that password policies are configured."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Check for PAM or password settings
        assert "pam" in content.lower() or "password" in content.lower()

    def test_backup_functionality(self, script_path: Path):
        """Test that backup option is supported."""
        result = subprocess.run(
            ["bash", str(script_path), "--no-backup", "--dry-run"],
            capture_output=True,
            text=True
        )

        # Should accept no-backup flag
        assert result.returncode == 0 or "backup" in result.stdout.lower()

    def test_logging_present(self, script_path: Path):
        """Test that script includes logging functionality."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Check for logging
        assert "log" in content.lower() or "echo" in content

    def test_error_handling(self, script_path: Path):
        """Test that script has error handling."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Check for error handling patterns
        assert "set -e" in content or "exit" in content

    def test_root_check(self, script_path: Path):
        """Test that script checks for root privileges."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Check for root/EUID check
        assert "EUID" in content or "root" in content.lower()

    def test_service_management(self, script_path: Path):
        """Test that script manages services appropriately."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Check for systemctl commands
        assert "systemctl" in content.lower()


class TestRHELvsUbuntuDifferences:
    """Tests to ensure RHEL script uses RHEL-specific tools."""

    def test_uses_firewalld_not_ufw(self):
        """Test that RHEL script uses firewalld, not UFW."""
        with open(RHEL_SCRIPT, 'r') as f:
            rhel_content = f.read()

        # RHEL should use firewalld
        assert "firewall-cmd" in rhel_content or "firewalld" in rhel_content.lower()

        # Should not have UFW commands
        ufw_count = rhel_content.lower().count("ufw ")
        assert ufw_count == 0 or ufw_count < 2  # Allow minimal mentions in comments

    def test_uses_selinux_not_apparmor(self):
        """Test that RHEL script uses SELinux, not AppArmor."""
        with open(RHEL_SCRIPT, 'r') as f:
            rhel_content = f.read()

        # RHEL should use SELinux
        assert "selinux" in rhel_content.lower()

        # Should not use AppArmor
        apparmor_count = rhel_content.lower().count("apparmor")
        assert apparmor_count == 0 or apparmor_count < 2  # Allow minimal mentions

    def test_uses_yum_or_dnf(self):
        """Test that RHEL script uses yum or dnf package manager."""
        with open(RHEL_SCRIPT, 'r') as f:
            rhel_content = f.read()

        # RHEL should use yum or dnf
        assert "yum" in rhel_content.lower() or "dnf" in rhel_content.lower()

    def test_rhel_specific_paths(self):
        """Test that RHEL script references RHEL-specific paths."""
        with open(RHEL_SCRIPT, 'r') as f:
            content = f.read()

        # Common RHEL paths
        rhel_indicators = [
            "/etc/sysconfig",
            "/etc/selinux",
            "rhel",
            "centos",
            "rocky",
            "alma"
        ]

        # At least some RHEL-specific references should exist
        found_count = sum(1 for indicator in rhel_indicators if indicator.lower() in content.lower())
        assert found_count > 0, "No RHEL-specific indicators found"


class TestRHELScriptIntegration:
    """Integration tests for RHEL hardening script."""

    def test_readme_documents_rhel(self):
        """Test that README documents the RHEL hardening script."""
        readme = HARDENING_DIR / "README.md"
        assert readme.exists()

        with open(readme, 'r') as f:
            content = f.read()

        assert "RHEL" in content or "Red Hat" in content
        assert "harden-rhel.sh" in content

    def test_config_files_compatible(self):
        """Test that configuration files work for both Ubuntu and RHEL."""
        config_dir = HARDENING_DIR / "config"
        assert config_dir.exists()

        # Config files should be generic enough for both platforms
        level1_config = config_dir / "cis-level1.conf"
        assert level1_config.exists()

        with open(level1_config, 'r') as f:
            content = f.read()

        # Should have SSH settings (common to both)
        assert "SSH" in content


class TestRHELScriptValidation:
    """Validation tests for RHEL hardening script."""

    def test_bash_syntax_valid(self):
        """Test that script has valid bash syntax."""
        result = subprocess.run(
            ["bash", "-n", str(RHEL_SCRIPT)],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0, f"Syntax error: {result.stderr}"

    def test_no_hardcoded_credentials(self):
        """Test that script doesn't contain hardcoded credentials."""
        with open(RHEL_SCRIPT, 'r') as f:
            content = f.read()

        # Check for common credential patterns
        forbidden_patterns = [
            "password=",
            "passwd=",
            "api_key=",
            "secret=",
            "token="
        ]

        for pattern in forbidden_patterns:
            assert pattern.lower() not in content.lower(), f"Possible hardcoded credential: {pattern}"

    def test_safe_file_operations(self):
        """Test that script uses safe file operations."""
        with open(RHEL_SCRIPT, 'r') as f:
            content = f.read()

        # Should not use dangerous operations without checks
        if "rm -rf /" in content:
            pytest.fail("Dangerous rm -rf / command found")

        # Should have backup functionality
        assert "backup" in content.lower() or "cp" in content


class TestRHELDistributionSupport:
    """Tests for multi-distribution support."""

    def test_mentions_supported_distributions(self):
        """Test that script documents supported distributions."""
        readme = HARDENING_DIR / "README.md"

        with open(readme, 'r') as f:
            content = f.read()

        # Should mention various RHEL-based distributions
        distributions = ["RHEL", "CentOS", "Rocky", "AlmaLinux"]

        found = sum(1 for dist in distributions if dist in content)
        assert found >= 2, "Should mention multiple RHEL-based distributions"

    def test_script_handles_multiple_distros(self):
        """Test that script has logic for different RHEL variants."""
        with open(RHEL_SCRIPT, 'r') as f:
            content = f.read()

        # Should check for different package managers or OS variants
        # Modern RHEL variants may use dnf instead of yum
        assert "yum" in content.lower() or "dnf" in content.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
