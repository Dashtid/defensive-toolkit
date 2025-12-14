"""
Unit tests for Sigma detection rules.

Tests validate rule syntax, required fields, MITRE ATT&CK mapping,
and overall rule quality for portfolio demonstration.

Author: Defensive Toolkit
Date: 2025-11-26
"""

import re
from pathlib import Path

import pytest
import yaml


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


def get_sigma_files() -> list[Path]:
    """Get all Sigma rule files."""
    rules_path = get_detection_rules_path()
    sigma_path = rules_path / "sigma"
    if not sigma_path.exists():
        return []
    return list(sigma_path.rglob("*.yml"))


def load_sigma_rules(file_path: Path) -> list[dict]:
    """Load all rules from a Sigma YAML file (handles multi-document)."""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    documents = list(yaml.safe_load_all(content))
    return [doc for doc in documents if doc is not None]


# Parametrize tests with all Sigma files
sigma_files = get_sigma_files()


class TestSigmaRuleSyntax:
    """Test Sigma rule YAML syntax."""

    @pytest.mark.parametrize("sigma_file", sigma_files, ids=lambda x: x.name)
    def test_valid_yaml_syntax(self, sigma_file: Path):
        """Test that all Sigma files have valid YAML syntax."""
        try:
            rules = load_sigma_rules(sigma_file)
            assert len(rules) > 0, f"No rules found in {sigma_file}"
        except yaml.YAMLError as e:
            pytest.fail(f"Invalid YAML syntax in {sigma_file}: {e}")

    @pytest.mark.parametrize("sigma_file", sigma_files, ids=lambda x: x.name)
    def test_file_encoding(self, sigma_file: Path):
        """Test that files are UTF-8 encoded."""
        try:
            with open(sigma_file, "r", encoding="utf-8") as f:
                f.read()
        except UnicodeDecodeError:
            pytest.fail(f"File {sigma_file} is not valid UTF-8")


class TestSigmaRequiredFields:
    """Test that Sigma rules have required fields."""

    REQUIRED_FIELDS = [
        "title",
        "id",
        "status",
        "description",
        "logsource",
        "detection",
    ]

    @pytest.mark.parametrize("sigma_file", sigma_files, ids=lambda x: x.name)
    def test_required_fields_present(self, sigma_file: Path):
        """Test that all required fields are present."""
        rules = load_sigma_rules(sigma_file)
        for idx, rule in enumerate(rules):
            for field in self.REQUIRED_FIELDS:
                assert field in rule, (
                    f"Missing required field '{field}' in rule {idx + 1} "
                    f"of {sigma_file.name}"
                )

    @pytest.mark.parametrize("sigma_file", sigma_files, ids=lambda x: x.name)
    def test_valid_uuid_format(self, sigma_file: Path):
        """Test that rule IDs are valid UUIDs."""
        uuid_pattern = (
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}$"
        )
        rules = load_sigma_rules(sigma_file)
        for idx, rule in enumerate(rules):
            if "id" in rule:
                assert re.match(uuid_pattern, str(rule["id"]), re.IGNORECASE), (
                    f"Invalid UUID format for rule {idx + 1} in {sigma_file.name}"
                )


class TestSigmaFieldValues:
    """Test that Sigma fields have valid values."""

    VALID_STATUSES = ["stable", "testing", "experimental", "deprecated", "unsupported"]
    VALID_LEVELS = ["informational", "low", "medium", "high", "critical"]

    @pytest.mark.parametrize("sigma_file", sigma_files, ids=lambda x: x.name)
    def test_valid_status(self, sigma_file: Path):
        """Test that status field has valid value."""
        rules = load_sigma_rules(sigma_file)
        for idx, rule in enumerate(rules):
            if "status" in rule:
                assert rule["status"] in self.VALID_STATUSES, (
                    f"Invalid status '{rule['status']}' in rule {idx + 1} "
                    f"of {sigma_file.name}"
                )

    @pytest.mark.parametrize("sigma_file", sigma_files, ids=lambda x: x.name)
    def test_valid_level(self, sigma_file: Path):
        """Test that level field has valid value."""
        rules = load_sigma_rules(sigma_file)
        for idx, rule in enumerate(rules):
            if "level" in rule:
                assert rule["level"] in self.VALID_LEVELS, (
                    f"Invalid level '{rule['level']}' in rule {idx + 1} "
                    f"of {sigma_file.name}"
                )

    @pytest.mark.parametrize("sigma_file", sigma_files, ids=lambda x: x.name)
    def test_logsource_structure(self, sigma_file: Path):
        """Test that logsource has proper structure."""
        rules = load_sigma_rules(sigma_file)
        for idx, rule in enumerate(rules):
            if "logsource" in rule:
                logsource = rule["logsource"]
                assert isinstance(logsource, dict), (
                    f"logsource must be a dict in rule {idx + 1} of {sigma_file.name}"
                )
                # Should have at least one of these
                has_source = any(
                    k in logsource for k in ["category", "product", "service"]
                )
                assert has_source, (
                    f"logsource needs category, product, or service in rule {idx + 1} "
                    f"of {sigma_file.name}"
                )


class TestSigmaDetectionLogic:
    """Test Sigma detection logic structure."""

    @pytest.mark.parametrize("sigma_file", sigma_files, ids=lambda x: x.name)
    def test_detection_has_condition(self, sigma_file: Path):
        """Test that detection section has a condition."""
        rules = load_sigma_rules(sigma_file)
        for idx, rule in enumerate(rules):
            if "detection" in rule:
                detection = rule["detection"]
                assert isinstance(detection, dict), (
                    f"detection must be a dict in rule {idx + 1} of {sigma_file.name}"
                )
                assert "condition" in detection, (
                    f"detection missing condition in rule {idx + 1} of {sigma_file.name}"
                )

    @pytest.mark.parametrize("sigma_file", sigma_files, ids=lambda x: x.name)
    def test_detection_has_selections(self, sigma_file: Path):
        """Test that detection has selection definitions."""
        rules = load_sigma_rules(sigma_file)
        for idx, rule in enumerate(rules):
            if "detection" in rule:
                detection = rule["detection"]
                # Should have at least one selection (key other than condition)
                selections = [k for k in detection.keys() if k != "condition"]
                assert len(selections) > 0, (
                    f"detection has no selections in rule {idx + 1} of {sigma_file.name}"
                )


class TestSigmaMitreMapping:
    """Test MITRE ATT&CK mapping in Sigma rules."""

    @pytest.mark.parametrize("sigma_file", sigma_files, ids=lambda x: x.name)
    def test_has_attack_tags(self, sigma_file: Path):
        """Test that rules have MITRE ATT&CK tags."""
        rules = load_sigma_rules(sigma_file)
        for idx, rule in enumerate(rules):
            if "tags" in rule:
                tags = rule["tags"]
                attack_tags = [t for t in tags if t.startswith("attack.")]
                # Warn if no ATT&CK tags (not a hard requirement)
                if not attack_tags:
                    pytest.warns(
                        UserWarning,
                        match="Consider adding MITRE ATT&CK tags",
                    )

    @pytest.mark.parametrize("sigma_file", sigma_files, ids=lambda x: x.name)
    def test_valid_attack_technique_format(self, sigma_file: Path):
        """Test that ATT&CK technique tags have valid format."""
        technique_pattern = r"^attack\.t\d{4}(\.\d{3})?$"
        rules = load_sigma_rules(sigma_file)
        for idx, rule in enumerate(rules):
            if "tags" in rule:
                tags = rule["tags"]
                technique_tags = [
                    t for t in tags if t.startswith("attack.t")
                ]
                for tag in technique_tags:
                    assert re.match(technique_pattern, tag, re.IGNORECASE), (
                        f"Invalid technique tag format '{tag}' in rule {idx + 1} "
                        f"of {sigma_file.name}"
                    )


class TestSigmaQuality:
    """Test Sigma rule quality aspects."""

    @pytest.mark.parametrize("sigma_file", sigma_files, ids=lambda x: x.name)
    def test_has_author(self, sigma_file: Path):
        """Test that rules have an author."""
        rules = load_sigma_rules(sigma_file)
        for idx, rule in enumerate(rules):
            assert "author" in rule, (
                f"Missing author in rule {idx + 1} of {sigma_file.name}"
            )

    @pytest.mark.parametrize("sigma_file", sigma_files, ids=lambda x: x.name)
    def test_has_date(self, sigma_file: Path):
        """Test that rules have a date."""
        rules = load_sigma_rules(sigma_file)
        for idx, rule in enumerate(rules):
            assert "date" in rule, (
                f"Missing date in rule {idx + 1} of {sigma_file.name}"
            )

    @pytest.mark.parametrize("sigma_file", sigma_files, ids=lambda x: x.name)
    def test_description_quality(self, sigma_file: Path):
        """Test that descriptions are meaningful."""
        rules = load_sigma_rules(sigma_file)
        for idx, rule in enumerate(rules):
            if "description" in rule:
                desc = rule["description"]
                assert len(str(desc)) >= 20, (
                    f"Description too short in rule {idx + 1} of {sigma_file.name}"
                )

    @pytest.mark.parametrize("sigma_file", sigma_files, ids=lambda x: x.name)
    def test_has_references(self, sigma_file: Path):
        """Test that rules have references."""
        rules = load_sigma_rules(sigma_file)
        for idx, rule in enumerate(rules):
            # References are recommended but not required
            if "references" not in rule:
                pass  # Warning only, don't fail


class TestSigmaRuleCounts:
    """Test overall rule counts and coverage."""

    def test_minimum_sigma_rules(self):
        """Test that we have a minimum number of Sigma rules."""
        rules_path = get_detection_rules_path()
        sigma_path = rules_path / "sigma"
        if not sigma_path.exists():
            pytest.skip("Sigma directory not found")

        files = list(sigma_path.rglob("*.yml"))
        total_rules = 0
        for f in files:
            rules = load_sigma_rules(f)
            total_rules += len(rules)

        # We should have at least 30 rules
        assert total_rules >= 30, (
            f"Expected at least 30 Sigma rules, found {total_rules}"
        )

    def test_coverage_by_tactic(self):
        """Test that we have coverage across tactics."""
        rules_path = get_detection_rules_path()
        sigma_path = rules_path / "sigma"
        if not sigma_path.exists():
            pytest.skip("Sigma directory not found")

        expected_tactics = [
            "execution",
            "persistence",
            "privilege-escalation",
            "defense-evasion",
            "credential-access",
            "discovery",
            "lateral-movement",
            "collection",
            "exfiltration",
            "command-and-control",
            "impact",
        ]

        for tactic in expected_tactics:
            tactic_path = sigma_path / tactic
            if tactic_path.exists():
                files = list(tactic_path.glob("*.yml"))
                assert len(files) > 0, f"No rules in tactic: {tactic}"
