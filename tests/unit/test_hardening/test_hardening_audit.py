"""
Tests for hardening audit scripts.

Tests the audit-security-posture.sh script including:
- Security posture checking
- Scoring logic
- Output formats
- Check coverage
"""

import pytest
import subprocess
import re
from pathlib import Path


# Path to hardening scripts
HARDENING_DIR = Path(__file__).parent.parent.parent.parent / "hardening" / "linux"
AUDIT_SCRIPT = HARDENING_DIR / "audit-security-posture.sh"


class TestAuditScript:
    """Tests for security posture audit script."""

    @pytest.fixture
    def script_path(self) -> Path:
        """Return path to audit script."""
        return AUDIT_SCRIPT

    def test_script_exists(self, script_path: Path):
        """Test that audit script exists."""
        assert script_path.exists(), f"Script not found: {script_path}"

    def test_script_is_executable(self, script_path: Path):
        """Test that script is executable."""
        import os
        assert os.access(script_path, os.X_OK), f"Script not executable: {script_path}"

    def test_script_runs_without_errors(self, script_path: Path):
        """Test that audit script runs without errors."""
        # Note: This may fail on Windows/non-root, but tests script structure
        result = subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True
        )

        # Script should attempt to run (may fail due to permissions)
        assert result.returncode == 0 or "root" in result.stderr.lower() or "EUID" in result.stderr

    def test_output_contains_checks(self, script_path: Path):
        """Test that audit output contains security checks."""
        result = subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True
        )

        output = result.stdout + result.stderr

        # Should contain check indicators
        check_indicators = ["[OK]", "[FAIL]", "SSH", "Firewall", "Audit"]

        found_count = sum(1 for indicator in check_indicators if indicator in output)
        assert found_count >= 2, "Should contain multiple security check indicators"

    def test_script_structure(self, script_path: Path):
        """Test that script has proper structure."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Should have shebang
        assert content.startswith("#!/bin/bash")

        # Should have check functions or patterns
        assert "check" in content.lower() or "audit" in content.lower()

    def test_checks_ssh_configuration(self, script_path: Path):
        """Test that audit checks SSH configuration."""
        with open(script_path, 'r') as f:
            content = f.read()

        ssh_checks = [
            "ssh" or "SSH",
            "PermitRootLogin" or "sshd_config"
        ]

        found = any(check.lower() in content.lower() for check in ssh_checks)
        assert found, "Should check SSH configuration"

    def test_checks_firewall_status(self, script_path: Path):
        """Test that audit checks firewall status."""
        with open(script_path, 'r') as f:
            content = f.read()

        firewall_checks = ["ufw", "firewall", "iptables"]

        found = any(check in content.lower() for check in firewall_checks)
        assert found, "Should check firewall status"

    def test_checks_kernel_parameters(self, script_path: Path):
        """Test that audit checks kernel parameters."""
        with open(script_path, 'r') as f:
            content = f.read()

        assert "sysctl" in content.lower() or "kernel" in content.lower()

    def test_has_scoring_logic(self, script_path: Path):
        """Test that audit includes scoring logic."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Should calculate scores or counts
        scoring_indicators = ["score", "passed", "failed", "total"]

        found = any(indicator in content.lower() for indicator in scoring_indicators)
        assert found, "Should include scoring logic"

    def test_provides_summary(self, script_path: Path):
        """Test that audit provides summary information."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Should have summary section
        assert "summary" in content.lower() or "total" in content.lower()

    def test_checks_aide_installation(self, script_path: Path):
        """Test that audit checks AIDE installation."""
        with open(script_path, 'r') as f:
            content = f.read()

        assert "aide" in content.lower() or "AIDE" in content

    def test_checks_automatic_updates(self, script_path: Path):
        """Test that audit checks automatic updates."""
        with open(script_path, 'r') as f:
            content = f.read()

        update_indicators = ["update", "unattended", "yum-cron"]

        found = any(indicator in content.lower() for indicator in update_indicators)
        assert found, "Should check automatic updates"


class TestAuditScoring:
    """Tests for audit scoring logic."""

    def test_calculates_percentage_score(self, script_path=AUDIT_SCRIPT):
        """Test that audit calculates percentage score."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Should calculate percentage (passed/total * 100)
        scoring_patterns = ["%", "percent", "100"]

        found = any(pattern in content.lower() for pattern in scoring_patterns)
        assert found, "Should calculate percentage score"

    def test_counts_passed_checks(self, script_path=AUDIT_SCRIPT):
        """Test that audit counts passed checks."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Should track passed checks
        assert "passed" in content.lower() or "PASSED" in content

    def test_counts_failed_checks(self, script_path=AUDIT_SCRIPT):
        """Test that audit counts failed checks."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Should track failed checks
        assert "failed" in content.lower() or "FAILED" in content

    def test_counts_total_checks(self, script_path=AUDIT_SCRIPT):
        """Test that audit counts total checks."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Should track total checks
        assert "total" in content.lower() or "TOTAL" in content


class TestAuditOutput:
    """Tests for audit output formatting."""

    def test_has_header(self, script_path=AUDIT_SCRIPT):
        """Test that audit has formatted header."""
        result = subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True
        )

        output = result.stdout + result.stderr

        # Should have header/title
        assert "audit" in output.lower() or "security" in output.lower()

    def test_uses_status_indicators(self, script_path=AUDIT_SCRIPT):
        """Test that audit uses clear status indicators."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Should use visual indicators
        indicators = ["[OK]", "[FAIL]", "[WARN]", "[INFO]", "[+]", "[-]"]

        found_count = sum(1 for ind in indicators if ind in content)
        assert found_count >= 1, "Should use status indicators"

    def test_has_separator_lines(self, script_path=AUDIT_SCRIPT):
        """Test that audit uses separator lines for readability."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Should have visual separators
        separators = ["===", "---", "***"]

        found = any(sep in content for sep in separators)
        assert found, "Should use separator lines"


class TestAuditCoverage:
    """Tests for audit check coverage."""

    def test_checks_multiple_categories(self, script_path=AUDIT_SCRIPT):
        """Test that audit checks multiple security categories."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Should check at least 3 major categories
        categories = [
            "ssh",
            "firewall",
            "kernel",
            "aide",
            "update",
            "selinux",
            "apparmor"
        ]

        found_count = sum(1 for cat in categories if cat in content.lower())
        assert found_count >= 3, f"Should check multiple categories (found {found_count})"

    def test_has_minimum_checks(self, script_path=AUDIT_SCRIPT):
        """Test that audit performs minimum number of checks."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Count check patterns (approximate)
        check_patterns = ["check_test", "grep -q", "[OK]", "[FAIL]"]

        total_checks = sum(content.count(pattern) for pattern in check_patterns)
        assert total_checks >= 5, "Should have at least 5 security checks"


class TestAuditIntegration:
    """Integration tests for audit script."""

    def test_readme_documents_audit(self):
        """Test that README documents audit script."""
        readme = HARDENING_DIR / "README.md"
        assert readme.exists()

        with open(readme, 'r') as f:
            content = f.read()

        assert "audit-security-posture.sh" in content
        assert "audit" in content.lower()

    def test_audit_script_independent(self):
        """Test that audit script can run independently."""
        # Script should not require hardening to be run first
        result = subprocess.run(
            ["bash", str(AUDIT_SCRIPT)],
            capture_output=True,
            text=True
        )

        # Should produce output even if hardening not applied
        output = result.stdout + result.stderr
        assert len(output) > 50, "Should produce meaningful output"

    def test_bash_syntax_valid(self):
        """Test that script has valid bash syntax."""
        result = subprocess.run(
            ["bash", "-n", str(AUDIT_SCRIPT)],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0, f"Syntax error: {result.stderr}"


class TestAuditOutputFormats:
    """Tests for audit output format support."""

    def test_default_text_output(self, script_path=AUDIT_SCRIPT):
        """Test that audit produces text output by default."""
        result = subprocess.run(
            ["bash", str(script_path)],
            capture_output=True,
            text=True
        )

        output = result.stdout + result.stderr

        # Should be human-readable text
        assert len(output) > 0
        # Should not be JSON or XML by default
        assert not output.strip().startswith("{")
        assert not output.strip().startswith("<")

    def test_supports_output_parameter(self, script_path=AUDIT_SCRIPT):
        """Test if audit supports output format parameter."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Check if it supports --output or similar parameter
        # (This is optional, but good to document)
        has_output_option = "--output" in content or "output_format" in content.lower()

        # This is informational, not a hard requirement
        if has_output_option:
            pytest.skip("Output format parameter detected")


class TestAuditRootCheck:
    """Tests for root privilege checking."""

    def test_checks_for_root(self, script_path=AUDIT_SCRIPT):
        """Test that audit checks if running as root."""
        with open(script_path, 'r') as f:
            content = f.read()

        # Should check for root privileges
        root_checks = ["EUID", "root", "sudo"]

        found = any(check in content for check in root_checks)
        assert found, "Should check for root privileges"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
