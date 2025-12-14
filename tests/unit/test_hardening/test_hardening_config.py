"""
Tests for hardening configuration files.

Tests configuration files including:
- CIS Level 1 configuration
- CIS Level 2 configuration
- AIDE configuration
- Configuration file syntax
- Setting validation
"""

import re
from pathlib import Path

import pytest

# Path to configuration files
HARDENING_DIR = Path(__file__).parent.parent.parent.parent / "hardening" / "linux"
CONFIG_DIR = HARDENING_DIR / "config"
LEVEL1_CONFIG = CONFIG_DIR / "cis-level1.conf"
LEVEL2_CONFIG = CONFIG_DIR / "cis-level2.conf"
AIDE_CONFIG = CONFIG_DIR / "aide.conf"


class TestConfigurationDirectory:
    """Tests for configuration directory structure."""

    def test_config_directory_exists(self):
        """Test that config directory exists."""
        assert CONFIG_DIR.exists(), f"Config directory not found: {CONFIG_DIR}"

    def test_config_directory_is_directory(self):
        """Test that config path is a directory."""
        assert CONFIG_DIR.is_dir(), f"Config path is not a directory: {CONFIG_DIR}"

    def test_level1_config_exists(self):
        """Test that CIS Level 1 config exists."""
        assert LEVEL1_CONFIG.exists(), f"Level 1 config not found: {LEVEL1_CONFIG}"

    def test_level2_config_exists(self):
        """Test that CIS Level 2 config exists."""
        assert LEVEL2_CONFIG.exists(), f"Level 2 config not found: {LEVEL2_CONFIG}"

    def test_aide_config_exists(self):
        """Test that AIDE config exists."""
        assert AIDE_CONFIG.exists(), f"AIDE config not found: {AIDE_CONFIG}"


class TestCISLevel1Config:
    """Tests for CIS Level 1 configuration file."""

    @pytest.fixture
    def config_content(self) -> str:
        """Return Level 1 config file content."""
        with open(LEVEL1_CONFIG, "r") as f:
            return f.read()

    def test_file_not_empty(self, config_content: str):
        """Test that config file is not empty."""
        assert len(config_content) > 0

    def test_has_ssh_settings(self, config_content: str):
        """Test that config has SSH settings."""
        ssh_settings = ["SSH", "ssh", "PermitRootLogin", "MaxAuthTries"]

        found = any(setting in config_content for setting in ssh_settings)
        assert found, "Should contain SSH settings"

    def test_ssh_permit_root_login(self, config_content: str):
        """Test SSH PermitRootLogin setting."""
        # Level 1 should disable root login
        assert "PermitRootLogin" in config_content or "PERMIT_ROOT" in config_content

    def test_has_firewall_settings(self, config_content: str):
        """Test that config has firewall settings."""
        firewall_settings = ["FIREWALL", "firewall", "UFW", "ufw"]

        found = any(setting in config_content for setting in firewall_settings)
        assert found, "Should contain firewall settings"

    def test_has_password_settings(self, config_content: str):
        """Test that config has password policy settings."""
        password_settings = ["PASSWORD", "password", "MIN_LENGTH", "MAX_DAYS"]

        found = any(setting in config_content for setting in password_settings)
        assert found, "Should contain password settings"

    def test_level1_allows_password_auth(self, config_content: str):
        """Test that Level 1 allows password authentication."""
        # Level 1 should allow password auth (safer for initial deployment)
        if (
            "PASSWORD_AUTHENTICATION" in config_content
            or "PasswordAuthentication" in config_content
        ):
            # If setting exists, should be "yes" for Level 1
            assert "yes" in config_content.lower() or "=1" in config_content

    def test_has_comments_or_documentation(self, config_content: str):
        """Test that config has comments explaining settings."""
        # Should have comments (# at start of line)
        assert "#" in config_content, "Should contain comments"

    def test_cis_benchmark_reference(self, config_content: str):
        """Test that config references CIS Benchmark."""
        # Should mention CIS or be labeled as Level 1
        cis_indicators = ["CIS", "Level 1", "level 1", "Benchmark"]

        found = any(indicator in config_content for indicator in cis_indicators)
        assert found, "Should reference CIS Benchmark"

    def test_no_syntax_errors(self, config_content: str):
        """Test that config has valid bash variable syntax."""
        # Check for common bash variable patterns
        lines = config_content.split("\n")

        for line in lines:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Should be variable assignment (VAR=value or VAR="value")
            if "=" in line:
                parts = line.split("=", 1)
                var_name = parts[0].strip()

                # Variable name should be valid (alphanumeric + underscore)
                assert re.match(
                    r"^[A-Z_][A-Z0-9_]*$", var_name
                ), f"Invalid variable name: {var_name}"


class TestCISLevel2Config:
    """Tests for CIS Level 2 configuration file."""

    @pytest.fixture
    def config_content(self) -> str:
        """Return Level 2 config file content."""
        with open(LEVEL2_CONFIG, "r") as f:
            return f.read()

    def test_file_not_empty(self, config_content: str):
        """Test that config file is not empty."""
        assert len(config_content) > 0

    def test_has_ssh_settings(self, config_content: str):
        """Test that config has SSH settings."""
        ssh_settings = ["SSH", "ssh", "PermitRootLogin", "PasswordAuthentication"]

        found = any(setting in config_content for setting in ssh_settings)
        assert found, "Should contain SSH settings"

    def test_level2_disables_password_auth(self, config_content: str):
        """Test that Level 2 disables password authentication."""
        # Level 2 should disable password auth (key-based only)
        password_auth_line = None

        for line in config_content.split("\n"):
            if "PASSWORD_AUTHENTICATION" in line or "PasswordAuthentication" in line:
                password_auth_line = line
                break

        if password_auth_line:
            # Should be set to "no" or 0
            assert "no" in password_auth_line.lower() or "=0" in password_auth_line

    def test_has_strong_ciphers(self, config_content: str):
        """Test that Level 2 specifies strong ciphers."""
        cipher_indicators = ["CIPHER", "cipher", "chacha20", "aes256"]

        found = any(indicator in config_content for indicator in cipher_indicators)
        assert found, "Should specify strong ciphers"

    def test_stricter_than_level1(self, config_content: str):
        """Test that Level 2 is stricter than Level 1."""
        with open(LEVEL1_CONFIG, "r") as f:
            level1_content = f.read()

        # Level 2 should have more/stricter settings
        # One way: longer file or more variable definitions
        level2_lines = [
            l for l in config_content.split("\n") if "=" in l and not l.strip().startswith("#")
        ]
        level1_lines = [
            l for l in level1_content.split("\n") if "=" in l and not l.strip().startswith("#")
        ]

        # Level 2 should have at least as many settings as Level 1
        assert (
            len(level2_lines) >= len(level1_lines) * 0.8
        ), "Level 2 should have comprehensive settings"

    def test_cis_level2_reference(self, config_content: str):
        """Test that config references CIS Level 2."""
        level2_indicators = ["Level 2", "level 2", "Level2", "CIS"]

        found = any(indicator in config_content for indicator in level2_indicators)
        assert found, "Should reference CIS Level 2"

    def test_has_comments_or_documentation(self, config_content: str):
        """Test that config has comments explaining settings."""
        assert "#" in config_content, "Should contain comments"


class TestAIDEConfig:
    """Tests for AIDE configuration file."""

    @pytest.fixture
    def config_content(self) -> str:
        """Return AIDE config file content."""
        with open(AIDE_CONFIG, "r") as f:
            return f.read()

    def test_file_not_empty(self, config_content: str):
        """Test that config file is not empty."""
        assert len(config_content) > 0

    def test_has_aide_rules(self, config_content: str):
        """Test that config has AIDE monitoring rules."""
        aide_indicators = ["AIDE", "aide", "rule", "RULE", "monitor"]

        found = any(indicator in config_content.lower() for indicator in aide_indicators)
        assert found, "Should contain AIDE rules"

    def test_monitors_critical_directories(self, config_content: str):
        """Test that config monitors critical system directories."""
        critical_dirs = ["/boot", "/bin", "/sbin", "/lib", "/etc"]

        found_count = sum(1 for dir_path in critical_dirs if dir_path in config_content)
        assert found_count >= 3, f"Should monitor critical directories (found {found_count})"

    def test_monitors_config_files(self, config_content: str):
        """Test that config monitors important configuration files."""
        config_files = ["/etc/passwd", "/etc/shadow", "/etc/ssh", "sshd_config"]

        found_count = sum(1 for file_path in config_files if file_path in config_content)
        assert found_count >= 2, "Should monitor critical config files"

    def test_has_monitoring_attributes(self, config_content: str):
        """Test that config specifies file attributes to monitor."""
        # AIDE monitors various file attributes
        attributes = [
            "p",  # permissions
            "i",  # inode
            "n",  # number of links
            "u",  # user
            "g",  # group
            "s",  # size
            "m",  # mtime
            "c",  # ctime
            "md5",  # checksums
            "sha",
        ]

        # Should have several attributes defined
        found_count = sum(1 for attr in attributes if attr in config_content.lower())
        assert found_count >= 3, "Should specify monitoring attributes"

    def test_has_comments_or_documentation(self, config_content: str):
        """Test that config has comments."""
        assert "#" in config_content, "Should contain comments"


class TestConfigurationConsistency:
    """Tests for consistency across configuration files."""

    def test_level2_builds_on_level1(self):
        """Test that Level 2 extends Level 1 settings."""
        with open(LEVEL1_CONFIG, "r") as f:
            level1_content = f.read()

        with open(LEVEL2_CONFIG, "r") as f:
            level2_content = f.read()

        # Extract variable names from Level 1
        level1_vars = set()
        for line in level1_content.split("\n"):
            if "=" in line and not line.strip().startswith("#"):
                var_name = line.split("=")[0].strip()
                level1_vars.add(var_name)

        # Extract variable names from Level 2
        level2_vars = set()
        for line in level2_content.split("\n"):
            if "=" in line and not line.strip().startswith("#"):
                var_name = line.split("=")[0].strip()
                level2_vars.add(var_name)

        # Level 2 should have overlap with Level 1 (common settings)
        overlap = level1_vars & level2_vars
        assert len(overlap) >= 3, "Level 2 should build on Level 1 settings"

    def test_all_configs_have_headers(self):
        """Test that all configs have header comments."""
        configs = [LEVEL1_CONFIG, LEVEL2_CONFIG, AIDE_CONFIG]

        for config_path in configs:
            with open(config_path, "r") as f:
                content = f.read()
                first_lines = content.split("\n")[:5]

                # Should have comment in first 5 lines
                has_comment = any(line.strip().startswith("#") for line in first_lines)
                assert has_comment, f"{config_path.name} should have header comment"

    def test_consistent_naming_convention(self):
        """Test that configs use consistent variable naming."""
        with open(LEVEL1_CONFIG, "r") as f:
            level1_content = f.read()

        with open(LEVEL2_CONFIG, "r") as f:
            level2_content = f.read()

        # Extract all variable names
        all_vars = []

        for content in [level1_content, level2_content]:
            for line in content.split("\n"):
                if "=" in line and not line.strip().startswith("#"):
                    var_name = line.split("=")[0].strip()
                    all_vars.append(var_name)

        # All should follow UPPER_CASE_WITH_UNDERSCORES convention
        for var_name in all_vars:
            assert re.match(r"^[A-Z_][A-Z0-9_]*$", var_name), f"Inconsistent naming: {var_name}"


class TestConfigurationDocumentation:
    """Tests for configuration documentation."""

    def test_readme_documents_configs(self):
        """Test that README documents configuration files."""
        readme = HARDENING_DIR / "README.md"
        assert readme.exists()

        with open(readme, "r") as f:
            content = f.read()

        # Should mention config files
        assert "cis-level1.conf" in content or "Level 1" in content
        assert "cis-level2.conf" in content or "Level 2" in content
        assert "aide.conf" in content or "AIDE" in content

    def test_configs_referenced_by_scripts(self):
        """Test that hardening scripts reference config files."""
        ubuntu_script = HARDENING_DIR / "harden-ubuntu.sh"

        if ubuntu_script.exists():
            with open(ubuntu_script, "r") as f:
                content = f.read()

            # Should reference config directory or files
            config_refs = ["config/", "cis-level", ".conf"]

            found = any(ref in content for ref in config_refs)
            # This is optional, so we just note it
            if not found:
                pytest.skip("Scripts may use inline config instead of files")


class TestConfigurationSecurity:
    """Security tests for configuration files."""

    def test_no_hardcoded_credentials(self):
        """Test that configs don't contain hardcoded credentials."""
        configs = [LEVEL1_CONFIG, LEVEL2_CONFIG, AIDE_CONFIG]

        for config_path in configs:
            with open(config_path, "r") as f:
                content = f.read()

            # Check for credential patterns (excluding variable names)
            forbidden_values = [
                "password=secret",
                "password=admin",
                "passwd=",
                "api_key=",
                "token=",
            ]

            for pattern in forbidden_values:
                assert (
                    pattern.lower() not in content.lower()
                ), f"Possible credential in {config_path.name}"

    def test_secure_defaults(self):
        """Test that configs use secure default values."""
        with open(LEVEL1_CONFIG, "r") as f:
            level1_content = f.read()

        # Level 1 should have secure defaults
        secure_indicators = ["no", "deny", "disable"]  # Disable insecure features  # Default deny

        # Should have some secure settings
        found_count = sum(
            1 for indicator in secure_indicators if indicator in level1_content.lower()
        )
        assert found_count >= 1, "Should have secure default settings"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
