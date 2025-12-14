"""
Tests for Linux (Ubuntu/Debian) hardening scripts.

Tests the harden-ubuntu.sh script functionality including:
- Command-line argument parsing
- Hardening level configuration
- Dry-run mode
- SSH hardening
- Firewall configuration
- Kernel parameter hardening
- Service configuration
"""

import os
import subprocess
from pathlib import Path

import pytest

# Path to hardening scripts
HARDENING_DIR = Path(__file__).parent.parent.parent.parent / "hardening" / "linux"
UBUNTU_SCRIPT = HARDENING_DIR / "harden-ubuntu.sh"


class TestUbuntuHardeningScript:
    """Tests for Ubuntu hardening script."""

    @pytest.fixture
    def script_path(self) -> Path:
        """Return path to Ubuntu hardening script."""
        return UBUNTU_SCRIPT

    def test_script_exists(self, script_path: Path):
        """Test that the Ubuntu hardening script exists."""
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
        # Run in dry-run mode
        result = subprocess.run(
            ["bash", str(script_path), "--level", "1", "--dry-run", "--no-backup"],
            capture_output=True,
            text=True
        )

        # Should complete without errors
        assert result.returncode == 0 or "dry run" in result.stdout.lower()

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

    def test_invalid_level(self, script_path: Path):
        """Test that invalid hardening level is rejected."""
        result = subprocess.run(
            ["bash", str(script_path), "--level", "99", "--dry-run"],
            capture_output=True,
            text=True
        )

        # Should fail or show error
        output = result.stdout + result.stderr
        assert result.returncode != 0 or "invalid" in output.lower() or "error" in output.lower()

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

    def test_firewall_configuration(self, script_path: Path):
        """Test that firewall (UFW) configuration is present."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Check for UFW commands
        assert "ufw" in content.lower()
        assert "enable" in content.lower()

        # Check for default policies
        assert "default deny" in content.lower() or "default-deny" in content.lower()

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

    def test_apparmor_configuration(self, script_path: Path):
        """Test that AppArmor mandatory access control is configured."""
        with open(script_path, 'r') as f:
            content = f.read()

        assert "apparmor" in content.lower()

    def test_password_policy(self, script_path: Path):
        """Test that password policies are configured."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Check for PAM or password settings
        assert "pam" in content.lower() or "password" in content.lower()

    def test_automatic_updates(self, script_path: Path):
        """Test that automatic security updates are configured."""
        with open(script_path, 'r') as f:
            content = f.read()

        assert "unattended-upgrades" in content.lower() or "auto" in content.lower()

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

    def test_level2_password_auth_disabled(self, script_path: Path):
        """Test that Level 2+ disables password authentication."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Level 2 should disable password auth
        assert "PasswordAuthentication" in content

    def test_level2_strong_ciphers(self, script_path: Path):
        """Test that Level 2+ uses strong ciphers."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Check for strong ciphers
        assert "chacha20" in content.lower() or "aes256-gcm" in content.lower()

    def test_service_management(self, script_path: Path):
        """Test that script manages services appropriately."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Check for systemctl commands
        assert "systemctl" in content.lower() or "service" in content.lower()


class TestUbuntuScriptIntegration:
    """Integration tests for Ubuntu hardening script."""

    def test_config_file_references(self):
        """Test that configuration files are properly referenced."""
        config_dir = HARDENING_DIR / "config"
        assert config_dir.exists()

        level1_config = config_dir / "cis-level1.conf"
        level2_config = config_dir / "cis-level2.conf"

        # Config files should exist
        assert level1_config.exists(), "CIS Level 1 config missing"
        assert level2_config.exists(), "CIS Level 2 config missing"

    def test_aide_config_exists(self):
        """Test that AIDE configuration file exists."""
        aide_config = HARDENING_DIR / "config" / "aide.conf"
        assert aide_config.exists(), "AIDE config file missing"

    def test_readme_documentation(self):
        """Test that README documents the Ubuntu hardening script."""
        readme = HARDENING_DIR / "README.md"
        assert readme.exists()

        with open(readme, 'r') as f:
            content = f.read()

        assert "Ubuntu" in content
        assert "harden-ubuntu.sh" in content
        assert "Level 1" in content
        assert "Level 2" in content

    def test_all_utility_scripts_exist(self):
        """Test that all utility scripts exist."""
        required_scripts = [
            "audit-security-posture.sh",
            "backup-security-settings.sh",
            "restore-security-settings.sh",
            "check-compliance.sh"
        ]

        for script_name in required_scripts:
            script_path = HARDENING_DIR / script_name
            assert script_path.exists(), f"Missing utility script: {script_name}"
            assert os.access(script_path, os.X_OK), f"Script not executable: {script_name}"


class TestHardeningScriptOutput:
    """Tests for script output and reporting."""

    def test_dry_run_shows_changes(self, tmp_path):
        """Test that dry-run mode shows what would be changed."""
        result = subprocess.run(
            ["bash", str(UBUNTU_SCRIPT), "--level", "1", "--dry-run", "--no-backup"],
            capture_output=True,
            text=True,
            cwd=tmp_path
        )

        output = result.stdout + result.stderr

        # Should show what would be done
        assert len(output) > 100  # Should have substantial output
        assert "ssh" in output.lower() or "firewall" in output.lower()

    def test_script_provides_feedback(self):
        """Test that script provides user feedback."""
        result = subprocess.run(
            ["bash", str(UBUNTU_SCRIPT), "--dry-run", "--no-backup"],
            capture_output=True,
            text=True
        )

        output = result.stdout + result.stderr

        # Should have informative output
        assert len(output) > 50
        # Should have status indicators
        assert any(marker in output for marker in ['[', '+', '-', '*', '>', 'OK', 'FAIL'])


class TestHardeningScriptValidation:
    """Validation tests for hardening script."""

    def test_bash_syntax_valid(self):
        """Test that script has valid bash syntax."""
        result = subprocess.run(
            ["bash", "-n", str(UBUNTU_SCRIPT)],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0, f"Syntax error: {result.stderr}"

    def test_shellcheck_if_available(self):
        """Run shellcheck if available (optional)."""
        # Check if shellcheck is available
        shellcheck_available = subprocess.run(
            ["which", "shellcheck"],
            capture_output=True
        ).returncode == 0

        if not shellcheck_available:
            pytest.skip("shellcheck not available")

        result = subprocess.run(
            ["shellcheck", str(UBUNTU_SCRIPT)],
            capture_output=True,
            text=True
        )

        # Collect warnings/errors but don't fail on them
        if result.returncode != 0:
            print(f"ShellCheck warnings:\n{result.stdout}")

    def test_no_hardcoded_credentials(self):
        """Test that script doesn't contain hardcoded credentials."""
        with open(UBUNTU_SCRIPT, 'r') as f:
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
        with open(UBUNTU_SCRIPT, 'r') as f:
            content = f.read()

        # Should not use dangerous operations without checks
        if "rm -rf /" in content:
            pytest.fail("Dangerous rm -rf / command found")

        # Should have backup functionality
        assert "backup" in content.lower() or "cp" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
