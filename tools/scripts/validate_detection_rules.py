#!/usr/bin/env python3
"""
Detection Rule Validation Script

Validates Sigma and YARA rules for syntax, required fields, and quality.
Designed for CI/CD integration and portfolio demonstration.

Author: Defensive Toolkit
Date: 2025-11-26
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class ValidationResult:
    """Result of a rule validation check."""

    rule_file: str
    rule_type: str
    valid: bool
    errors: list[str]
    warnings: list[str]
    rule_count: int = 1


class SigmaValidator:
    """Validates Sigma detection rules."""

    REQUIRED_FIELDS = ["title", "id", "status", "description", "logsource", "detection"]
    RECOMMENDED_FIELDS = ["references", "author", "date", "tags", "falsepositives", "level"]
    VALID_STATUSES = ["stable", "testing", "experimental", "deprecated", "unsupported"]
    VALID_LEVELS = ["informational", "low", "medium", "high", "critical"]

    def validate_file(self, file_path: Path) -> ValidationResult:
        """Validate a Sigma YAML file."""
        errors = []
        warnings = []
        rule_count = 0

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Handle multi-document YAML
            documents = list(yaml.safe_load_all(content))
            rule_count = len([d for d in documents if d])

            for idx, doc in enumerate(documents):
                if doc is None:
                    continue

                doc_errors, doc_warnings = self._validate_document(doc, idx + 1)
                errors.extend(doc_errors)
                warnings.extend(doc_warnings)

        except yaml.YAMLError as e:
            errors.append(f"YAML syntax error: {e}")
        except Exception as e:
            errors.append(f"Failed to read file: {e}")

        return ValidationResult(
            rule_file=str(file_path),
            rule_type="sigma",
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            rule_count=rule_count,
        )

    def _validate_document(
        self, doc: dict, doc_num: int
    ) -> tuple[list[str], list[str]]:
        """Validate a single Sigma rule document."""
        errors = []
        warnings = []
        prefix = f"[Rule {doc_num}] " if doc_num > 1 else ""

        # Check required fields
        for field in self.REQUIRED_FIELDS:
            if field not in doc:
                errors.append(f"{prefix}Missing required field: {field}")

        # Check recommended fields
        for field in self.RECOMMENDED_FIELDS:
            if field not in doc:
                warnings.append(f"{prefix}Missing recommended field: {field}")

        # Validate status
        if "status" in doc and doc["status"] not in self.VALID_STATUSES:
            errors.append(
                f"{prefix}Invalid status '{doc['status']}'. "
                f"Valid values: {', '.join(self.VALID_STATUSES)}"
            )

        # Validate level
        if "level" in doc and doc["level"] not in self.VALID_LEVELS:
            errors.append(
                f"{prefix}Invalid level '{doc['level']}'. "
                f"Valid values: {', '.join(self.VALID_LEVELS)}"
            )

        # Validate ID format (UUID)
        if "id" in doc:
            uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
            if not re.match(uuid_pattern, str(doc["id"]), re.IGNORECASE):
                errors.append(f"{prefix}ID should be a valid UUID format")

        # Validate logsource
        if "logsource" in doc:
            logsource = doc["logsource"]
            if not isinstance(logsource, dict):
                errors.append(f"{prefix}logsource must be a dictionary")
            elif not any(
                k in logsource for k in ["category", "product", "service"]
            ):
                warnings.append(
                    f"{prefix}logsource should have category, product, or service"
                )

        # Validate detection
        if "detection" in doc:
            detection = doc["detection"]
            if not isinstance(detection, dict):
                errors.append(f"{prefix}detection must be a dictionary")
            elif "condition" not in detection:
                errors.append(f"{prefix}detection must have a condition")

        # Validate tags (MITRE ATT&CK)
        if "tags" in doc:
            tags = doc["tags"]
            if isinstance(tags, list):
                attack_tags = [t for t in tags if t.startswith("attack.")]
                if not attack_tags:
                    warnings.append(
                        f"{prefix}Consider adding MITRE ATT&CK tags (attack.tXXXX)"
                    )

        return errors, warnings


class YaraValidator:
    """Validates YARA detection rules."""

    REQUIRED_META = ["description", "author", "date"]
    RECOMMENDED_META = ["severity", "reference", "mitre_attack"]

    def validate_file(self, file_path: Path) -> ValidationResult:
        """Validate a YARA rule file."""
        errors = []
        warnings = []
        rule_count = 0

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Try to compile with yara-python if available
            try:
                import yara

                yara.compile(source=content)
            except ImportError:
                warnings.append(
                    "yara-python not installed - syntax check skipped"
                )
            except yara.SyntaxError as e:
                errors.append(f"YARA syntax error: {e}")
            except Exception as e:
                errors.append(f"YARA compilation error: {e}")

            # Parse rules manually for metadata validation
            rule_errors, rule_warnings, count = self._validate_rules(content)
            errors.extend(rule_errors)
            warnings.extend(rule_warnings)
            rule_count = count

        except Exception as e:
            errors.append(f"Failed to read file: {e}")

        return ValidationResult(
            rule_file=str(file_path),
            rule_type="yara",
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            rule_count=rule_count,
        )

    def _validate_rules(
        self, content: str
    ) -> tuple[list[str], list[str], int]:
        """Validate YARA rules from content."""
        errors = []
        warnings = []

        # Find all rule definitions
        rule_pattern = r"rule\s+(\w+)\s*(?::\s*\w+(?:\s+\w+)*)?\s*\{"
        rules = re.findall(rule_pattern, content)
        rule_count = len(rules)

        if rule_count == 0:
            errors.append("No valid YARA rules found in file")
            return errors, warnings, 0

        # Check each rule for metadata
        for rule_name in rules:
            rule_content = self._extract_rule_content(content, rule_name)
            if rule_content:
                rule_errors, rule_warnings = self._validate_rule_metadata(
                    rule_name, rule_content
                )
                errors.extend(rule_errors)
                warnings.extend(rule_warnings)

        return errors, warnings, rule_count

    def _extract_rule_content(
        self, content: str, rule_name: str
    ) -> Optional[str]:
        """Extract content of a specific YARA rule using brace matching."""
        # Find the rule start
        pattern = rf"rule\s+{rule_name}\s*(?::\s*\w+(?:\s+\w+)*)?\s*\{{"
        match = re.search(pattern, content)
        if not match:
            return None

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
        return None

    def _validate_rule_metadata(
        self, rule_name: str, rule_content: str
    ) -> tuple[list[str], list[str]]:
        """Validate metadata section of a YARA rule."""
        errors = []
        warnings = []

        # Check for meta section
        if "meta:" not in rule_content:
            warnings.append(f"[{rule_name}] Missing meta section")
            return errors, warnings

        # Extract meta section
        meta_match = re.search(
            r"meta:\s*(.*?)(?=strings:|condition:)", rule_content, re.DOTALL
        )
        if not meta_match:
            return errors, warnings

        meta_content = meta_match.group(1)

        # Check required metadata
        for field in self.REQUIRED_META:
            if f"{field}" not in meta_content.lower():
                warnings.append(f"[{rule_name}] Missing recommended meta: {field}")

        # Check for strings section
        if "strings:" not in rule_content:
            warnings.append(f"[{rule_name}] No strings section (condition-only rule)")

        # Check for condition section
        if "condition:" not in rule_content:
            errors.append(f"[{rule_name}] Missing condition section")

        return errors, warnings


class RuleValidator:
    """Main validator orchestrating Sigma and YARA validation."""

    def __init__(self, rules_path: Path):
        self.rules_path = rules_path
        self.sigma_validator = SigmaValidator()
        self.yara_validator = YaraValidator()

    def validate_all(self) -> list[ValidationResult]:
        """Validate all detection rules."""
        results = []

        # Validate Sigma rules
        sigma_path = self.rules_path / "sigma"
        if sigma_path.exists():
            for yml_file in sigma_path.rglob("*.yml"):
                result = self.sigma_validator.validate_file(yml_file)
                results.append(result)

        # Validate YARA rules
        yara_path = self.rules_path / "yara"
        if yara_path.exists():
            for yar_file in yara_path.rglob("*.yar"):
                result = self.yara_validator.validate_file(yar_file)
                results.append(result)

        return results

    def print_results(self, results: list[ValidationResult]) -> bool:
        """Print validation results and return success status."""
        total_rules = sum(r.rule_count for r in results)
        valid_files = sum(1 for r in results if r.valid)
        invalid_files = sum(1 for r in results if not r.valid)
        total_errors = sum(len(r.errors) for r in results)
        total_warnings = sum(len(r.warnings) for r in results)

        print("\n" + "=" * 70)
        print("DETECTION RULE VALIDATION REPORT")
        print("=" * 70)

        # Print issues
        for result in results:
            if result.errors or result.warnings:
                print(f"\n[{'FAIL' if result.errors else 'WARN'}] {result.rule_file}")
                for error in result.errors:
                    print(f"  [X] ERROR: {error}")
                for warning in result.warnings:
                    print(f"  [!] WARNING: {warning}")

        # Print summary
        print("\n" + "-" * 70)
        print("SUMMARY")
        print("-" * 70)
        print(f"Files Validated:  {len(results)}")
        print(f"Total Rules:      {total_rules}")
        print(f"Valid Files:      {valid_files}")
        print(f"Invalid Files:    {invalid_files}")
        print(f"Total Errors:     {total_errors}")
        print(f"Total Warnings:   {total_warnings}")

        if invalid_files == 0:
            print("\n[OK] All detection rules passed validation!")
            return True
        else:
            print(f"\n[FAIL] {invalid_files} file(s) have validation errors")
            return False

    def export_json(self, results: list[ValidationResult], output_file: Path):
        """Export results to JSON."""
        data = {
            "summary": {
                "total_files": len(results),
                "total_rules": sum(r.rule_count for r in results),
                "valid_files": sum(1 for r in results if r.valid),
                "invalid_files": sum(1 for r in results if not r.valid),
                "total_errors": sum(len(r.errors) for r in results),
                "total_warnings": sum(len(r.warnings) for r in results),
            },
            "results": [
                {
                    "file": r.rule_file,
                    "type": r.rule_type,
                    "valid": r.valid,
                    "rule_count": r.rule_count,
                    "errors": r.errors,
                    "warnings": r.warnings,
                }
                for r in results
            ],
        }

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\nResults exported to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Validate Sigma and YARA detection rules"
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path("rules"),
        help="Path to detection rules directory",
    )
    parser.add_argument(
        "--json",
        type=Path,
        help="Export results to JSON file",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors",
    )
    args = parser.parse_args()

    # Find rules directory
    rules_path = args.path
    if not rules_path.exists():
        # Try relative to script location
        script_dir = Path(__file__).parent.parent
        rules_path = script_dir / "rules"

    if not rules_path.exists():
        print(f"[X] Detection rules directory not found: {rules_path}")
        sys.exit(1)

    print(f"Validating rules in: {rules_path}")

    validator = RuleValidator(rules_path)
    results = validator.validate_all()

    if args.json:
        validator.export_json(results, args.json)

    success = validator.print_results(results)

    # In strict mode, warnings also cause failure
    if args.strict and any(r.warnings for r in results):
        print("\n[!] Strict mode: warnings treated as errors")
        success = False

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
