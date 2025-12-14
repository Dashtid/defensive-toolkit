"""
Unit tests for YARA detection rules.

Tests validate rule syntax, metadata, and structure for quality assurance
and portfolio demonstration.

Author: Defensive Toolkit
Date: 2025-11-26
"""

import re
from pathlib import Path

import pytest


def get_detection_rules_path() -> Path:
    """Get path to detection rules directory."""
    # Try relative to test file
    test_dir = Path(__file__).parent
    rules_path = test_dir.parent.parent.parent / "rules"
    if rules_path.exists():
        return rules_path

    # Try from current working directory
    rules_path = Path("rules")
    if rules_path.exists():
        return rules_path

    pytest.skip("Detection rules directory not found")


def get_yara_files() -> list[Path]:
    """Get all YARA rule files."""
    rules_path = get_detection_rules_path()
    yara_path = rules_path / "yara"
    if not yara_path.exists():
        return []
    return list(yara_path.rglob("*.yar"))


def load_yara_content(file_path: Path) -> str:
    """Load YARA file content."""
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def extract_rules(content: str) -> list[str]:
    """Extract rule names from YARA content."""
    pattern = r"rule\s+(\w+)"
    return re.findall(pattern, content)


def extract_rule_content(content: str, rule_name: str) -> str:
    """Extract content of a specific rule using brace matching."""
    # Find the rule start
    pattern = rf"rule\s+{rule_name}\s*(?::\s*\w+(?:\s+\w+)*)?\s*\{{"
    match = re.search(pattern, content)
    if not match:
        return ""

    # Find matching closing brace using brace counting
    start_pos = match.end()
    brace_count = 1
    pos = start_pos

    while pos < len(content) and brace_count > 0:
        if content[pos] == "{":
            brace_count += 1
        elif content[pos] == "}":
            brace_count -= 1
        pos += 1

    if brace_count == 0:
        return content[start_pos : pos - 1]
    return ""


# Parametrize tests with all YARA files
yara_files = get_yara_files()


class TestYaraFileSyntax:
    """Test YARA file syntax."""

    @pytest.mark.parametrize("yara_file", yara_files, ids=lambda x: x.name)
    def test_file_readable(self, yara_file: Path):
        """Test that YARA files are readable."""
        try:
            content = load_yara_content(yara_file)
            assert len(content) > 0, f"Empty file: {yara_file}"
        except Exception as e:
            pytest.fail(f"Failed to read {yara_file}: {e}")

    @pytest.mark.parametrize("yara_file", yara_files, ids=lambda x: x.name)
    def test_has_rules(self, yara_file: Path):
        """Test that files contain at least one rule."""
        content = load_yara_content(yara_file)
        rules = extract_rules(content)
        assert len(rules) > 0, f"No rules found in {yara_file}"

    @pytest.mark.parametrize("yara_file", yara_files, ids=lambda x: x.name)
    def test_yara_compilation(self, yara_file: Path):
        """Test that YARA rules compile successfully."""
        try:
            import yara

            content = load_yara_content(yara_file)
            yara.compile(source=content)
        except ImportError:
            pytest.skip("yara-python not installed")
        except yara.SyntaxError as e:
            pytest.fail(f"YARA syntax error in {yara_file}: {e}")
        except Exception as e:
            pytest.fail(f"YARA compilation error in {yara_file}: {e}")


class TestYaraRuleStructure:
    """Test YARA rule structure."""

    @pytest.mark.parametrize("yara_file", yara_files, ids=lambda x: x.name)
    def test_rules_have_meta(self, yara_file: Path):
        """Test that rules have meta sections."""
        content = load_yara_content(yara_file)
        rules = extract_rules(content)
        for rule_name in rules:
            rule_content = extract_rule_content(content, rule_name)
            assert "meta:" in rule_content, (
                f"Rule '{rule_name}' in {yara_file.name} missing meta section"
            )

    @pytest.mark.parametrize("yara_file", yara_files, ids=lambda x: x.name)
    def test_rules_have_condition(self, yara_file: Path):
        """Test that rules have condition sections."""
        content = load_yara_content(yara_file)
        rules = extract_rules(content)
        for rule_name in rules:
            rule_content = extract_rule_content(content, rule_name)
            assert "condition:" in rule_content, (
                f"Rule '{rule_name}' in {yara_file.name} missing condition"
            )

    @pytest.mark.parametrize("yara_file", yara_files, ids=lambda x: x.name)
    def test_rules_have_strings_or_condition(self, yara_file: Path):
        """Test that rules have either strings section or condition."""
        content = load_yara_content(yara_file)
        rules = extract_rules(content)
        for rule_name in rules:
            rule_content = extract_rule_content(content, rule_name)
            has_strings = "strings:" in rule_content
            has_condition = "condition:" in rule_content
            assert has_strings or has_condition, (
                f"Rule '{rule_name}' in {yara_file.name} needs strings or condition"
            )


class TestYaraMetadata:
    """Test YARA rule metadata quality."""

    REQUIRED_META = ["description", "author"]
    RECOMMENDED_META = ["date", "severity", "reference"]

    @pytest.mark.parametrize("yara_file", yara_files, ids=lambda x: x.name)
    def test_has_description(self, yara_file: Path):
        """Test that rules have descriptions."""
        content = load_yara_content(yara_file)
        rules = extract_rules(content)
        for rule_name in rules:
            rule_content = extract_rule_content(content, rule_name)
            assert "description" in rule_content.lower(), (
                f"Rule '{rule_name}' in {yara_file.name} missing description"
            )

    @pytest.mark.parametrize("yara_file", yara_files, ids=lambda x: x.name)
    def test_has_author(self, yara_file: Path):
        """Test that rules have author."""
        content = load_yara_content(yara_file)
        rules = extract_rules(content)
        for rule_name in rules:
            rule_content = extract_rule_content(content, rule_name)
            assert "author" in rule_content.lower(), (
                f"Rule '{rule_name}' in {yara_file.name} missing author"
            )

    @pytest.mark.parametrize("yara_file", yara_files, ids=lambda x: x.name)
    def test_has_date(self, yara_file: Path):
        """Test that rules have date."""
        content = load_yara_content(yara_file)
        rules = extract_rules(content)
        for rule_name in rules:
            rule_content = extract_rule_content(content, rule_name)
            assert "date" in rule_content.lower(), (
                f"Rule '{rule_name}' in {yara_file.name} missing date"
            )


class TestYaraRuleNaming:
    """Test YARA rule naming conventions."""

    @pytest.mark.parametrize("yara_file", yara_files, ids=lambda x: x.name)
    def test_valid_rule_names(self, yara_file: Path):
        """Test that rule names are valid identifiers."""
        content = load_yara_content(yara_file)
        rules = extract_rules(content)
        for rule_name in rules:
            # YARA rule names must be valid identifiers
            assert re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", rule_name), (
                f"Invalid rule name '{rule_name}' in {yara_file.name}"
            )

    @pytest.mark.parametrize("yara_file", yara_files, ids=lambda x: x.name)
    def test_no_reserved_words(self, yara_file: Path):
        """Test that rule names don't use reserved words."""
        reserved = [
            "all", "and", "any", "ascii", "at", "base64", "condition",
            "contains", "entrypoint", "false", "filesize", "for", "global",
            "import", "in", "include", "int16", "int32", "int8", "matches",
            "meta", "nocase", "not", "of", "or", "private", "rule", "strings",
            "them", "true", "uint16", "uint32", "uint8", "wide", "xor",
        ]
        content = load_yara_content(yara_file)
        rules = extract_rules(content)
        for rule_name in rules:
            assert rule_name.lower() not in reserved, (
                f"Rule name '{rule_name}' is a reserved word in {yara_file.name}"
            )


class TestYaraStringPatterns:
    """Test YARA string pattern quality."""

    @pytest.mark.parametrize("yara_file", yara_files, ids=lambda x: x.name)
    def test_no_empty_strings(self, yara_file: Path):
        """Test that there are no empty string patterns."""
        content = load_yara_content(yara_file)
        # Check for empty string definitions
        empty_pattern = r'\$\w+\s*=\s*""'
        matches = re.findall(empty_pattern, content)
        assert len(matches) == 0, (
            f"Empty string patterns found in {yara_file.name}: {matches}"
        )

    @pytest.mark.parametrize("yara_file", yara_files, ids=lambda x: x.name)
    def test_string_variable_naming(self, yara_file: Path):
        """Test that string variables have valid names."""
        content = load_yara_content(yara_file)
        # Find all string variable definitions
        string_vars = re.findall(r"\$(\w+)\s*=", content)
        for var in string_vars:
            assert re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", var), (
                f"Invalid string variable name '${var}' in {yara_file.name}"
            )


class TestYaraCoverage:
    """Test overall YARA rule coverage."""

    def test_minimum_yara_files(self):
        """Test that we have minimum YARA files."""
        rules_path = get_detection_rules_path()
        yara_path = rules_path / "yara"
        if not yara_path.exists():
            pytest.skip("YARA directory not found")

        files = list(yara_path.rglob("*.yar"))
        assert len(files) >= 5, f"Expected at least 5 YARA files, found {len(files)}"

    def test_minimum_yara_rules(self):
        """Test that we have minimum number of YARA rules."""
        rules_path = get_detection_rules_path()
        yara_path = rules_path / "yara"
        if not yara_path.exists():
            pytest.skip("YARA directory not found")

        total_rules = 0
        for yara_file in yara_path.rglob("*.yar"):
            content = load_yara_content(yara_file)
            rules = extract_rules(content)
            total_rules += len(rules)

        assert total_rules >= 15, (
            f"Expected at least 15 YARA rules, found {total_rules}"
        )

    def test_threat_category_coverage(self):
        """Test coverage of major threat categories."""
        rules_path = get_detection_rules_path()
        yara_path = rules_path / "yara"
        if not yara_path.exists():
            pytest.skip("YARA directory not found")

        # Expected threat categories based on our implementation
        expected_files = [
            "webshells.yar",
            "ransomware.yar",
            "suspicious_scripts.yar",
            "infostealers.yar",
            "ransomware_2025.yar",
            "loaders.yar",
            "c2_frameworks.yar",
        ]

        existing_files = [f.name for f in yara_path.rglob("*.yar")]
        for expected in expected_files:
            assert expected in existing_files, (
                f"Expected YARA file '{expected}' not found"
            )


class TestYaraSeverity:
    """Test YARA rule severity levels."""

    VALID_SEVERITIES = ["informational", "low", "medium", "high", "critical"]

    @pytest.mark.parametrize("yara_file", yara_files, ids=lambda x: x.name)
    def test_valid_severity_values(self, yara_file: Path):
        """Test that severity values are valid."""
        content = load_yara_content(yara_file)
        # Find severity definitions
        severity_matches = re.findall(
            r'severity\s*=\s*["\']?(\w+)["\']?', content, re.IGNORECASE
        )
        for severity in severity_matches:
            assert severity.lower() in self.VALID_SEVERITIES, (
                f"Invalid severity '{severity}' in {yara_file.name}"
            )
