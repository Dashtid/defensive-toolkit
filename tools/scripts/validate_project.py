#!/usr/bin/env python3
"""
Project Structure Validator for Defensive Toolkit

Validates project structure, imports, tests, and documentation.

Usage:
    python scripts/validate_project.py
    python scripts/validate_project.py --check-structure
    python scripts/validate_project.py --check-imports
    python scripts/validate_project.py --verbose
"""

import argparse
import ast
import sys
from pathlib import Path


class ProjectValidator:
    """Validates defensive-toolkit project structure and configuration"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.root = Path(__file__).parent.parent
        self.errors = []
        self.warnings = []

    def log(self, message: str, level: str = "INFO"):
        """Log messages based on verbosity"""
        if level == "ERROR":
            self.errors.append(message)
            print(f"[-] {message}")
        elif level == "WARN":
            self.warnings.append(message)
            print(f"[!] {message}")
        elif self.verbose:
            print(f"[*] {message}")

    def validate_directory_structure(self) -> bool:
        """Validate expected directory structure exists"""
        print("[+] Validating directory structure...")

        required_dirs = [
            "automation",
            "automation/actions",
            "automation/integrations",
            "automation/playbooks",
            "compliance",
            "compliance/frameworks",
            "compliance/policy",
            "compliance/reporting",
            "rules",
            "rules/sigma",
            "rules/yara",
            "docs",
            "examples",
            "forensics",
            "forensics/artifacts",
            "forensics/disk",
            "forensics/memory",
            "forensics/timeline",
            "hardening",
            "hardening/windows-security",
            "incident-response",
            "incident-response/playbooks",
            "incident-response/scripts",
            "log-analysis",
            "log-analysis/analysis",
            "log-analysis/parsers",
            "monitoring",
            "scripts",
            "tests",
            "tests/unit",
            "tests/integration",
            "tests/fixtures",
            "threat-hunting",
            "threat-hunting/queries",
            "vulnerability-mgmt",
            "vulnerability-mgmt/prioritization",
            "vulnerability-mgmt/remediation",
            "vulnerability-mgmt/reporting",
            "vulnerability-mgmt/scanners",
        ]

        missing_dirs = []
        for dir_path in required_dirs:
            full_path = self.root / dir_path
            if not full_path.exists():
                missing_dirs.append(dir_path)
                self.log(f"Missing directory: {dir_path}", "ERROR")
            else:
                self.log(f"Found: {dir_path}", "INFO")

        if not missing_dirs:
            print("[OK] All required directories exist\n")
            return True
        else:
            print(f"[-] Missing {len(missing_dirs)} required directories\n")
            return False

    def validate_init_files(self) -> bool:
        """Validate __init__.py files exist in Python packages"""
        print("[+] Validating __init__.py files...")

        python_dirs = [
            "automation",
            "automation/actions",
            "automation/integrations",
            "automation/playbooks",
            "compliance",
            "compliance/frameworks",
            "compliance/policy",
            "compliance/reporting",
            "forensics",
            "forensics/artifacts",
            "forensics/artifacts/browser",
            "forensics/disk",
            "forensics/memory",
            "forensics/timeline",
            "log-analysis",
            "log-analysis/analysis",
            "log-analysis/parsers",
            "scripts",
            "tests",
            "tests/unit",
            "tests/integration",
            "tests/fixtures",
            "vulnerability-mgmt",
            "vulnerability-mgmt/prioritization",
            "vulnerability-mgmt/remediation",
            "vulnerability-mgmt/reporting",
            "vulnerability-mgmt/scanners",
        ]

        missing_init = []
        for dir_path in python_dirs:
            init_file = self.root / dir_path / "__init__.py"
            if not init_file.exists():
                missing_init.append(dir_path)
                self.log(f"Missing __init__.py in: {dir_path}", "ERROR")
            else:
                self.log(f"Found __init__.py in: {dir_path}", "INFO")

        if not missing_init:
            print("[OK] All __init__.py files exist\n")
            return True
        else:
            print(f"[-] Missing {len(missing_init)} __init__.py files\n")
            return False

    def validate_required_files(self) -> bool:
        """Validate required configuration and documentation files exist"""
        print("[+] Validating required files...")

        required_files = [
            "README.md",
            "LICENSE",
            "CONTRIBUTING.md",
            "SECURITY.md",
            "pyproject.toml",
            "requirements.txt",
            ".gitignore",
            ".coveragerc",
            "docs/GETTING_STARTED.md",
            "tests/README.md",
            "tests/conftest.py",
        ]

        missing_files = []
        for file_path in required_files:
            full_path = self.root / file_path
            if not full_path.exists():
                missing_files.append(file_path)
                self.log(f"Missing file: {file_path}", "ERROR")
            else:
                self.log(f"Found: {file_path}", "INFO")

        if not missing_files:
            print("[OK] All required files exist\n")
            return True
        else:
            print(f"[-] Missing {len(missing_files)} required files\n")
            return False

    def validate_python_syntax(self) -> bool:
        """Validate Python files have correct syntax"""
        print("[+] Validating Python syntax...")

        python_files = list(self.root.rglob("*.py"))
        syntax_errors = []

        for py_file in python_files:
            # Skip virtual environments and git directories
            if ".venv" in str(py_file) or ".git" in str(py_file):
                continue

            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    code = f.read()
                    ast.parse(code)
                self.log(f"Valid syntax: {py_file.relative_to(self.root)}", "INFO")
            except SyntaxError as e:
                syntax_errors.append((py_file, str(e)))
                self.log(
                    f"Syntax error in {py_file.relative_to(self.root)}: {e}", "ERROR"
                )
            except Exception as e:
                self.log(
                    f"Error reading {py_file.relative_to(self.root)}: {e}", "WARN"
                )

        if not syntax_errors:
            print(f"[OK] All {len(python_files)} Python files have valid syntax\n")
            return True
        else:
            print(f"[-] {len(syntax_errors)} files have syntax errors\n")
            return False

    def validate_documentation_structure(self) -> bool:
        """Validate documentation structure"""
        print("[+] Validating documentation structure...")

        expected_docs = [
            "docs/GETTING_STARTED.md",
            "docs/ARCHITECTURE.md",
            "docs/TESTING.md",
            "docs/DEPLOYMENT.md",
            "docs/API_REFERENCE.md",
            "docs/TROUBLESHOOTING.md",
            "docs/CHANGELOG.md",
        ]

        missing_docs = []
        for doc_path in expected_docs:
            full_path = self.root / doc_path
            if not full_path.exists():
                missing_docs.append(doc_path)
                self.log(f"Missing documentation: {doc_path}", "WARN")
            else:
                self.log(f"Found: {doc_path}", "INFO")

        category_readmes = [
            "rules/README.md",
            "hardening/windows-security/README.md",
            "automation/README.md",
            "compliance/README.md",
            "forensics/README.md",
            "log-analysis/README.md",
            "monitoring/README.md",
            "vulnerability-mgmt/README.md",
            "threat-hunting/README.md",
            "tests/README.md",
            "scripts/README.md",
        ]

        for readme_path in category_readmes:
            full_path = self.root / readme_path
            if not full_path.exists():
                missing_docs.append(readme_path)
                self.log(f"Missing README: {readme_path}", "WARN")
            else:
                self.log(f"Found: {readme_path}", "INFO")

        if not missing_docs:
            print("[OK] All documentation files exist\n")
            return True
        else:
            print(f"[!] {len(missing_docs)} documentation files missing (warnings)\n")
            return True  # Don't fail on missing docs, just warn

    def validate_test_structure(self) -> bool:
        """Validate test structure"""
        print("[+] Validating test structure...")

        test_dirs = ["tests/unit", "tests/integration", "tests/fixtures"]

        test_files_found = 0
        for test_dir in test_dirs:
            test_path = self.root / test_dir
            if test_path.exists():
                test_files = list(test_path.rglob("test_*.py"))
                test_files_found += len(test_files)
                self.log(
                    f"Found {len(test_files)} test files in {test_dir}", "INFO"
                )

        if test_files_found > 0:
            print(f"[OK] Found {test_files_found} test files\n")
            return True
        else:
            print("[-] No test files found\n")
            return False

    def validate_all(self) -> bool:
        """Run all validations"""
        print("=" * 70)
        print("Defensive Toolkit - Project Validation")
        print("=" * 70 + "\n")

        results = [
            self.validate_directory_structure(),
            self.validate_init_files(),
            self.validate_required_files(),
            self.validate_python_syntax(),
            self.validate_documentation_structure(),
            self.validate_test_structure(),
        ]

        print("=" * 70)
        if all(results):
            print("[OK] All validations passed!")
            print("=" * 70)
            return True
        else:
            print(f"[-] {len([r for r in results if not r])} validation(s) failed")
            print(f"[!] {len(self.errors)} error(s), {len(self.warnings)} warning(s)")
            print("=" * 70)
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Validate defensive-toolkit project structure"
    )
    parser.add_argument(
        "--check-structure",
        action="store_true",
        help="Only check directory structure",
    )
    parser.add_argument(
        "--check-imports", action="store_true", help="Only check Python imports"
    )
    parser.add_argument(
        "--check-tests", action="store_true", help="Only check test structure"
    )
    parser.add_argument(
        "--check-docs", action="store_true", help="Only check documentation"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )

    args = parser.parse_args()

    validator = ProjectValidator(verbose=args.verbose)

    # Run specific checks if requested
    if args.check_structure:
        success = validator.validate_directory_structure()
    elif args.check_imports:
        success = validator.validate_python_syntax()
    elif args.check_tests:
        success = validator.validate_test_structure()
    elif args.check_docs:
        success = validator.validate_documentation_structure()
    else:
        # Run all validations
        success = validator.validate_all()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
