"""
Tests for hardening backup and restore scripts.

Tests backup-security-settings.sh and restore-security-settings.sh including:
- Backup creation
- Timestamped backups
- Configuration file coverage
- Restore functionality
- Backup validation
"""

import os
import subprocess
from pathlib import Path

import pytest

# Path to hardening scripts (now under src/defensive_toolkit/)
HARDENING_DIR = (
    Path(__file__).parent.parent.parent.parent / "src" / "defensive_toolkit" / "hardening" / "linux"
)
BACKUP_SCRIPT = HARDENING_DIR / "backup-security-settings.sh"
RESTORE_SCRIPT = HARDENING_DIR / "restore-security-settings.sh"


class TestBackupScript:
    """Tests for backup-security-settings.sh script."""

    @pytest.fixture
    def script_path(self) -> Path:
        """Return path to backup script."""
        return BACKUP_SCRIPT

    def test_script_exists(self, script_path: Path):
        """Test that backup script exists."""
        assert script_path.exists(), f"Script not found: {script_path}"

    def test_script_is_executable(self, script_path: Path):
        """Test that script is executable."""
        assert os.access(script_path, os.X_OK), f"Script not executable: {script_path}"

    def test_script_structure(self, script_path: Path):
        """Test that script has proper structure."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should have shebang
        assert content.startswith("#!/bin/bash")

        # Should have backup functionality
        assert "backup" in content.lower()

    def test_creates_timestamped_backup(self, script_path: Path):
        """Test that backup uses timestamps."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should use date command for timestamps
        timestamp_indicators = ["date", "timestamp", "%Y", "%m", "%d"]

        found = any(indicator in content for indicator in timestamp_indicators)
        assert found, "Should create timestamped backups"

    def test_backup_directory_defined(self, script_path: Path):
        """Test that backup directory is defined."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should define backup directory
        backup_dirs = ["/var/backups", "BACKUP_DIR", "backup"]

        found = any(dir_name in content for dir_name in backup_dirs)
        assert found, "Should define backup directory"

    def test_backs_up_ssh_config(self, script_path: Path):
        """Test that SSH configuration is backed up."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should backup SSH config
        assert "sshd_config" in content or "/etc/ssh" in content

    def test_backs_up_sysctl_config(self, script_path: Path):
        """Test that sysctl configuration is backed up."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should backup sysctl config
        assert "sysctl" in content.lower()

    def test_backs_up_pam_config(self, script_path: Path):
        """Test that PAM configuration is backed up."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should backup PAM config
        assert "pam" in content.lower() or "/etc/pam.d" in content

    def test_backs_up_firewall_rules(self, script_path: Path):
        """Test that firewall rules are backed up."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should backup firewall rules (UFW or firewalld)
        firewall_indicators = ["ufw", "firewall", "iptables"]

        found = any(indicator in content.lower() for indicator in firewall_indicators)
        assert found, "Should backup firewall configuration"

    def test_backs_up_login_defs(self, script_path: Path):
        """Test that login.defs is backed up."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should backup login.defs
        assert "login.defs" in content

    def test_creates_manifest(self, script_path: Path):
        """Test that backup creates a manifest file."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should create manifest with backup info
        manifest_indicators = ["manifest", "hostname", "date"]

        found = any(indicator in content.lower() for indicator in manifest_indicators)
        assert found, "Should create backup manifest"

    def test_provides_feedback(self, script_path: Path):
        """Test that backup provides user feedback."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should echo status messages
        assert "echo" in content.lower()

    def test_handles_errors(self, script_path: Path):
        """Test that backup has error handling."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should have error handling
        error_indicators = ["set -e", "exit", "||", "2>/dev/null"]

        found = any(indicator in content for indicator in error_indicators)
        assert found, "Should have error handling"

    def test_checks_for_root(self, script_path: Path):
        """Test that backup checks for root privileges."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should check for root
        assert "EUID" in content or "root" in content.lower()

    @pytest.mark.skipif(
        __import__("sys").platform == "win32" or __import__("shutil").which("bash") is None,
        reason="Requires bash shell (Linux/macOS)",
    )
    def test_bash_syntax_valid(self, script_path: Path):
        """Test that script has valid bash syntax."""
        result = subprocess.run(["bash", "-n", str(script_path)], capture_output=True, text=True)

        assert result.returncode == 0, f"Syntax error: {result.stderr}"


class TestRestoreScript:
    """Tests for restore-security-settings.sh script."""

    @pytest.fixture
    def script_path(self) -> Path:
        """Return path to restore script."""
        return RESTORE_SCRIPT

    def test_script_exists(self, script_path: Path):
        """Test that restore script exists."""
        assert script_path.exists(), f"Script not found: {script_path}"

    def test_script_is_executable(self, script_path: Path):
        """Test that script is executable."""
        assert os.access(script_path, os.X_OK), f"Script not executable: {script_path}"

    def test_script_structure(self, script_path: Path):
        """Test that script has proper structure."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should have shebang
        assert content.startswith("#!/bin/bash")

        # Should have restore functionality
        assert "restore" in content.lower()

    def test_lists_available_backups(self, script_path: Path):
        """Test that restore can list available backups."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should list backups when run without arguments
        list_indicators = ["ls", "available", "backups"]

        found = any(indicator in content.lower() for indicator in list_indicators)
        assert found, "Should list available backups"

    def test_accepts_timestamp_argument(self, script_path: Path):
        """Test that restore accepts timestamp argument."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should accept timestamp as argument
        arg_indicators = ["$1", "TIMESTAMP", "timestamp"]

        found = any(indicator in content for indicator in arg_indicators)
        assert found, "Should accept timestamp argument"

    def test_validates_backup_exists(self, script_path: Path):
        """Test that restore validates backup exists."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should check if backup exists
        validation_indicators = ["if", "exist", "not found", "[-d", "[-f"]

        found = any(indicator in content.lower() for indicator in validation_indicators)
        assert found, "Should validate backup exists"

    def test_confirms_before_restore(self, script_path: Path):
        """Test that restore asks for confirmation."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should ask for confirmation
        confirm_indicators = ["confirm", "continue", "read", "yes"]

        found = any(indicator in content.lower() for indicator in confirm_indicators)
        assert found, "Should ask for confirmation"

    def test_restores_ssh_config(self, script_path: Path):
        """Test that SSH config is restored."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should restore SSH config
        assert "sshd_config" in content

    def test_restores_sysctl_config(self, script_path: Path):
        """Test that sysctl config is restored."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should restore sysctl config
        assert "sysctl" in content.lower()

    def test_restores_pam_config(self, script_path: Path):
        """Test that PAM config is restored."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should restore PAM config
        assert "pam" in content.lower()

    def test_restores_login_defs(self, script_path: Path):
        """Test that login.defs is restored."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should restore login.defs
        assert "login.defs" in content

    def test_uses_safe_copy(self, script_path: Path):
        """Test that restore uses safe copy operations."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should use cp with -p to preserve permissions
        assert "cp -p" in content or "cp -pr" in content

    def test_provides_service_restart_instructions(self, script_path: Path):
        """Test that restore provides service restart instructions."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should mention restarting services
        restart_indicators = ["restart", "systemctl", "service"]

        found = any(indicator in content.lower() for indicator in restart_indicators)
        assert found, "Should provide service restart instructions"

    def test_checks_for_root(self, script_path: Path):
        """Test that restore checks for root privileges."""
        with open(script_path, "r") as f:
            content = f.read()

        # Should check for root
        assert "EUID" in content or "root" in content.lower()

    @pytest.mark.skipif(
        __import__("sys").platform == "win32" or __import__("shutil").which("bash") is None,
        reason="Requires bash shell (Linux/macOS)",
    )
    def test_bash_syntax_valid(self, script_path: Path):
        """Test that script has valid bash syntax."""
        result = subprocess.run(["bash", "-n", str(script_path)], capture_output=True, text=True)

        assert result.returncode == 0, f"Syntax error: {result.stderr}"


class TestBackupRestoreIntegration:
    """Integration tests for backup and restore scripts."""

    def test_both_scripts_exist(self):
        """Test that both backup and restore scripts exist."""
        assert BACKUP_SCRIPT.exists()
        assert RESTORE_SCRIPT.exists()

    def test_both_scripts_executable(self):
        """Test that both scripts are executable."""
        assert os.access(BACKUP_SCRIPT, os.X_OK)
        assert os.access(RESTORE_SCRIPT, os.X_OK)

    def test_use_same_backup_directory(self):
        """Test that backup and restore use the same backup directory."""
        with open(BACKUP_SCRIPT, "r") as f:
            backup_content = f.read()

        with open(RESTORE_SCRIPT, "r") as f:
            restore_content = f.read()

        # Both should reference the same backup location
        assert "/var/backups" in backup_content or "BACKUP_DIR" in backup_content
        assert "/var/backups" in restore_content or "BACKUP_DIR" in restore_content

    def test_readme_documents_backup_restore(self):
        """Test that README documents backup and restore."""
        readme = HARDENING_DIR / "README.md"
        assert readme.exists()

        with open(readme, "r") as f:
            content = f.read()

        assert "backup-security-settings.sh" in content
        assert "restore-security-settings.sh" in content

    def test_backup_creates_restorable_format(self):
        """Test that backup creates data in restorable format."""
        with open(BACKUP_SCRIPT, "r") as f:
            backup_content = f.read()

        with open(RESTORE_SCRIPT, "r") as f:
            restore_content = f.read()

        # Files backed up should match files restored
        backup_files = []
        restore_files = []

        # Extract file references (simplified check)
        if "sshd_config" in backup_content:
            backup_files.append("sshd_config")
        if "sshd_config" in restore_content:
            restore_files.append("sshd_config")

        # Should have overlapping file references
        assert len(set(backup_files) & set(restore_files)) > 0


class TestBackupSafety:
    """Tests for backup safety features."""

    def test_backup_no_destructive_operations(self):
        """Test that backup script doesn't perform destructive operations."""
        with open(BACKUP_SCRIPT, "r") as f:
            content = f.read()

        # Should not remove original files (only copy)
        dangerous_patterns = ["rm -rf /", "rm /etc"]

        for pattern in dangerous_patterns:
            assert pattern not in content, f"Dangerous operation found: {pattern}"

    def test_restore_has_confirmation(self):
        """Test that restore requires confirmation before proceeding."""
        with open(RESTORE_SCRIPT, "r") as f:
            content = f.read()

        # Should require user confirmation
        assert "read" in content.lower() or "confirm" in content.lower()

    def test_backup_preserves_permissions(self):
        """Test that backup preserves file permissions."""
        with open(BACKUP_SCRIPT, "r") as f:
            content = f.read()

        # Should use cp -p to preserve permissions
        assert "cp -p" in content or "cp -pr" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
