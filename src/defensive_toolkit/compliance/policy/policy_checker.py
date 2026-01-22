#!/usr/bin/env python3
"""
Security Policy Checker
Validates system configuration against defined security policies
Supports YAML policy definitions with automated checks
"""

import argparse
import json
import logging
import platform
import re
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import yaml

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class PolicyChecker:
    """Security policy validation engine"""

    def __init__(self, policy_file: Path):
        self.policy_file = policy_file
        self.os_type = platform.system().lower()
        self.policy = self._load_policy()
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "policy_file": str(policy_file),
            "os": self.os_type,
            "checks_performed": [],
            "summary": {"total": 0, "passed": 0, "failed": 0, "warnings": 0, "skipped": 0},
        }

    def _load_policy(self) -> Dict:
        """Load policy definition from YAML file"""
        try:
            with open(self.policy_file, "r") as f:
                policy = yaml.safe_load(f)
            logger.info(f"Loaded policy: {policy.get('name', 'Unnamed')}")
            return policy
        except Exception as e:
            logger.error(f"Failed to load policy file: {e}")
            sys.exit(1)

    def check_all_policies(self) -> Dict:
        """Execute all policy checks"""
        logger.info("Starting policy validation")

        for check in self.policy.get("checks", []):
            check_id = check.get("id", "unknown")
            check_type = check.get("type", "")

            logger.debug(f"Running check {check_id}: {check.get('description', '')}")

            try:
                if check_type == "command":
                    result = self._check_command(check)
                elif check_type == "file_exists":
                    result = self._check_file_exists(check)
                elif check_type == "file_content":
                    result = self._check_file_content(check)
                elif check_type == "registry":
                    result = self._check_registry(check)
                elif check_type == "service_status":
                    result = self._check_service_status(check)
                elif check_type == "port_status":
                    result = self._check_port_status(check)
                elif check_type == "user_exists":
                    result = self._check_user_exists(check)
                elif check_type == "permission":
                    result = self._check_permission(check)
                else:
                    result = {
                        "id": check_id,
                        "status": "SKIPPED",
                        "message": f"Unknown check type: {check_type}",
                    }

                self.results["checks_performed"].append(result)

                # Update summary
                status = result["status"]
                self.results["summary"]["total"] += 1
                if status == "PASS":
                    self.results["summary"]["passed"] += 1
                elif status == "FAIL":
                    self.results["summary"]["failed"] += 1
                elif status == "WARN":
                    self.results["summary"]["warnings"] += 1
                elif status == "SKIPPED":
                    self.results["summary"]["skipped"] += 1

            except Exception as e:
                logger.error(f"Check {check_id} failed with exception: {e}")
                self.results["checks_performed"].append(
                    {"id": check_id, "type": check_type, "status": "ERROR", "message": str(e)}
                )
                self.results["summary"]["total"] += 1
                self.results["summary"]["failed"] += 1

        return self.results

    def _check_command(self, check: Dict) -> Dict:
        """Execute command and validate output"""
        check_id = check["id"]
        command = check.get("command", "")
        expected_output = check.get("expected_output", "")
        expected_return_code = check.get("expected_return_code", 0)
        match_type = check.get("match_type", "exact")  # exact, contains, regex

        # Handle OS-specific commands
        if "command_windows" in check and self.os_type == "windows":
            command = check["command_windows"]
        elif "command_linux" in check and self.os_type == "linux":
            command = check["command_linux"]

        result = {
            "id": check_id,
            "type": "command",
            "description": check.get("description", ""),
            "severity": check.get("severity", "medium"),
        }

        try:
            # Execute command with security validation
            if isinstance(command, str):
                # Validate command doesn't contain dangerous injection patterns
                dangerous_patterns = ["$(", "`", "&&", "||", ";", "|&", "\n", "\r"]
                for pattern in dangerous_patterns:
                    if pattern in command:
                        result["status"] = "ERROR"
                        result["message"] = f"Command blocked: contains unsafe pattern '{pattern}'"
                        return result

                # Use shlex.split to safely parse the command, avoiding shell=True
                try:
                    cmd_parts = shlex.split(command)
                    proc = subprocess.run(
                        cmd_parts, capture_output=True, text=True, timeout=30
                    )
                except ValueError as e:
                    # If shlex fails (complex shell syntax), log warning and skip
                    result["status"] = "ERROR"
                    result["message"] = f"Command parse error: {e}"
                    return result
            else:
                proc = subprocess.run(command, capture_output=True, text=True, timeout=30)

            # Check return code
            if proc.returncode != expected_return_code:
                result["status"] = "FAIL"
                result["message"] = (
                    f"Command returned {proc.returncode}, expected {expected_return_code}"
                )
                result["output"] = proc.stdout + proc.stderr
                return result

            # Validate output if specified
            if expected_output:
                output = proc.stdout.strip()

                if match_type == "exact":
                    if output == expected_output:
                        result["status"] = "PASS"
                        result["message"] = "Command output matches expected value"
                    else:
                        result["status"] = "FAIL"
                        result["message"] = (
                            f"Output mismatch. Expected: {expected_output}, Got: {output}"
                        )

                elif match_type == "contains":
                    if expected_output in output:
                        result["status"] = "PASS"
                        result["message"] = "Command output contains expected string"
                    else:
                        result["status"] = "FAIL"
                        result["message"] = f"Output does not contain: {expected_output}"

                elif match_type == "regex":
                    if re.search(expected_output, output):
                        result["status"] = "PASS"
                        result["message"] = "Command output matches regex pattern"
                    else:
                        result["status"] = "FAIL"
                        result["message"] = f"Output does not match regex: {expected_output}"

            else:
                # No output validation, just check return code
                result["status"] = "PASS"
                result["message"] = "Command executed successfully"

        except subprocess.TimeoutExpired:
            result["status"] = "FAIL"
            result["message"] = "Command execution timeout"
        except Exception as e:
            result["status"] = "ERROR"
            result["message"] = str(e)

        return result

    def _check_file_exists(self, check: Dict) -> Dict:
        """Check if file/directory exists"""
        check_id = check["id"]
        file_path = Path(check.get("path", ""))
        should_exist = check.get("should_exist", True)

        result = {
            "id": check_id,
            "type": "file_exists",
            "description": check.get("description", ""),
            "severity": check.get("severity", "medium"),
            "path": str(file_path),
        }

        exists = file_path.exists()

        if (exists and should_exist) or (not exists and not should_exist):
            result["status"] = "PASS"
            result["message"] = "File existence check passed"
        else:
            result["status"] = "FAIL"
            if should_exist:
                result["message"] = f"File does not exist: {file_path}"
            else:
                result["message"] = f"File should not exist but found: {file_path}"

        return result

    def _check_file_content(self, check: Dict) -> Dict:
        """Check file content for expected patterns"""
        check_id = check["id"]
        file_path = Path(check.get("path", ""))
        expected_content = check.get("content", "")
        match_type = check.get("match_type", "contains")  # contains, regex, not_contains

        result = {
            "id": check_id,
            "type": "file_content",
            "description": check.get("description", ""),
            "severity": check.get("severity", "medium"),
            "path": str(file_path),
        }

        if not file_path.exists():
            result["status"] = "FAIL"
            result["message"] = f"File not found: {file_path}"
            return result

        try:
            with open(file_path, "r") as f:
                content = f.read()

            if match_type == "contains":
                if expected_content in content:
                    result["status"] = "PASS"
                    result["message"] = "File contains expected content"
                else:
                    result["status"] = "FAIL"
                    result["message"] = f"File does not contain: {expected_content}"

            elif match_type == "not_contains":
                if expected_content not in content:
                    result["status"] = "PASS"
                    result["message"] = "File does not contain forbidden content"
                else:
                    result["status"] = "FAIL"
                    result["message"] = f"File contains forbidden content: {expected_content}"

            elif match_type == "regex":
                if re.search(expected_content, content, re.MULTILINE):
                    result["status"] = "PASS"
                    result["message"] = "File content matches regex pattern"
                else:
                    result["status"] = "FAIL"
                    result["message"] = f"File content does not match regex: {expected_content}"

        except Exception as e:
            result["status"] = "ERROR"
            result["message"] = f"Error reading file: {e}"

        return result

    def _check_registry(self, check: Dict) -> Dict:
        """Check Windows registry value (Windows only)"""
        check_id = check["id"]

        result = {
            "id": check_id,
            "type": "registry",
            "description": check.get("description", ""),
            "severity": check.get("severity", "medium"),
        }

        if self.os_type != "windows":
            result["status"] = "SKIPPED"
            result["message"] = "Registry checks only available on Windows"
            return result

        reg_path = check.get("path", "")
        reg_value = check.get("value", "")
        expected_data = check.get("expected_data", "")

        try:
            cmd = ["reg", "query", reg_path, "/v", reg_value]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if proc.returncode != 0:
                result["status"] = "FAIL"
                result["message"] = f"Registry key/value not found: {reg_path}\\{reg_value}"
                return result

            # Parse registry output
            if expected_data in proc.stdout:
                result["status"] = "PASS"
                result["message"] = "Registry value matches expected data"
            else:
                result["status"] = "FAIL"
                result["message"] = f"Registry value mismatch. Expected: {expected_data}"
                result["output"] = proc.stdout

        except Exception as e:
            result["status"] = "ERROR"
            result["message"] = str(e)

        return result

    def _check_service_status(self, check: Dict) -> Dict:
        """Check if service is running/stopped"""
        check_id = check["id"]
        service_name = check.get("service", "")
        expected_status = check.get("expected_status", "running")  # running, stopped

        result = {
            "id": check_id,
            "type": "service_status",
            "description": check.get("description", ""),
            "severity": check.get("severity", "medium"),
            "service": service_name,
        }

        try:
            if self.os_type == "windows":
                cmd = ["sc", "query", service_name]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                is_running = "RUNNING" in proc.stdout
            else:
                cmd = ["systemctl", "is-active", service_name]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                is_running = proc.returncode == 0 and "active" in proc.stdout

            if (expected_status == "running" and is_running) or (
                expected_status == "stopped" and not is_running
            ):
                result["status"] = "PASS"
                result["message"] = f"Service {service_name} is {expected_status}"
            else:
                result["status"] = "FAIL"
                actual = "running" if is_running else "stopped"
                result["message"] = (
                    f"Service {service_name} is {actual}, expected {expected_status}"
                )

        except Exception as e:
            result["status"] = "ERROR"
            result["message"] = str(e)

        return result

    def _check_port_status(self, check: Dict) -> Dict:
        """Check if port is open/closed"""
        check_id = check["id"]
        port = check.get("port", 0)
        expected_status = check.get("expected_status", "closed")  # open, closed

        result = {
            "id": check_id,
            "type": "port_status",
            "description": check.get("description", ""),
            "severity": check.get("severity", "medium"),
            "port": port,
        }

        try:
            if self.os_type == "windows":
                cmd = ["netstat", "-an"]
            else:
                cmd = ["ss", "-tuln"]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            is_open = f":{port} " in proc.stdout or f":{port}\n" in proc.stdout

            if (expected_status == "open" and is_open) or (
                expected_status == "closed" and not is_open
            ):
                result["status"] = "PASS"
                result["message"] = f"Port {port} is {expected_status}"
            else:
                result["status"] = "FAIL"
                actual = "open" if is_open else "closed"
                result["message"] = f"Port {port} is {actual}, expected {expected_status}"

        except Exception as e:
            result["status"] = "ERROR"
            result["message"] = str(e)

        return result

    def _check_user_exists(self, check: Dict) -> Dict:
        """Check if user account exists"""
        check_id = check["id"]
        username = check.get("username", "")
        should_exist = check.get("should_exist", True)

        result = {
            "id": check_id,
            "type": "user_exists",
            "description": check.get("description", ""),
            "severity": check.get("severity", "medium"),
            "username": username,
        }

        try:
            if self.os_type == "windows":
                cmd = ["net", "user", username]
            else:
                cmd = ["id", username]

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            exists = proc.returncode == 0

            if (exists and should_exist) or (not exists and not should_exist):
                result["status"] = "PASS"
                result["message"] = "User existence check passed"
            else:
                result["status"] = "FAIL"
                if should_exist:
                    result["message"] = f"User does not exist: {username}"
                else:
                    result["message"] = f"User should not exist but found: {username}"

        except Exception as e:
            result["status"] = "ERROR"
            result["message"] = str(e)

        return result

    def _check_permission(self, check: Dict) -> Dict:
        """Check file/directory permissions"""
        check_id = check["id"]
        file_path = Path(check.get("path", ""))
        expected_mode = check.get("mode", "")  # e.g., '0600', 'rwxr-xr-x'

        result = {
            "id": check_id,
            "type": "permission",
            "description": check.get("description", ""),
            "severity": check.get("severity", "medium"),
            "path": str(file_path),
        }

        if not file_path.exists():
            result["status"] = "FAIL"
            result["message"] = f"File not found: {file_path}"
            return result

        try:
            if self.os_type == "windows":
                # Windows permission check (simplified)
                result["status"] = "SKIPPED"
                result["message"] = "Windows permission checks not yet implemented"
            else:
                # Linux permission check
                st = file_path.stat()
                actual_mode = oct(st.st_mode)[-4:]

                if expected_mode.startswith("0"):
                    # Octal format
                    if actual_mode == expected_mode:
                        result["status"] = "PASS"
                        result["message"] = f"Permissions match: {expected_mode}"
                    else:
                        result["status"] = "FAIL"
                        result["message"] = (
                            f"Permission mismatch. Expected: {expected_mode}, Got: {actual_mode}"
                        )
                else:
                    result["status"] = "SKIPPED"
                    result["message"] = "Symbolic permission format not yet supported"

        except Exception as e:
            result["status"] = "ERROR"
            result["message"] = str(e)

        return result

    def generate_report(
        self, output_format: str = "json", output_file: Optional[Path] = None
    ) -> str:
        """Generate policy compliance report"""
        if output_format == "json":
            return self._generate_json_report(output_file)
        else:
            return self._generate_text_report(output_file)

    def _generate_json_report(self, output_file: Optional[Path] = None) -> str:
        """Generate JSON report"""
        json_output = json.dumps(self.results, indent=2)

        if output_file:
            with open(output_file, "w") as f:
                f.write(json_output)
            logger.info(f"JSON report saved to {output_file}")

        return json_output

    def _generate_text_report(self, output_file: Optional[Path] = None) -> str:
        """Generate plain text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("Security Policy Compliance Report")
        lines.append("=" * 80)
        lines.append(f"Policy: {self.policy.get('name', 'Unnamed')}")
        lines.append(f"Description: {self.policy.get('description', 'N/A')}")
        lines.append(f"Timestamp: {self.results['timestamp']}")
        lines.append(f"Operating System: {self.results['os']}")
        lines.append("")
        lines.append("SUMMARY")
        lines.append("-" * 80)
        summary = self.results["summary"]
        lines.append(f"Total Checks: {summary['total']}")
        lines.append(f"Passed: {summary['passed']}")
        lines.append(f"Failed: {summary['failed']}")
        lines.append(f"Warnings: {summary['warnings']}")
        lines.append(f"Skipped: {summary['skipped']}")
        compliance_rate = (
            (summary["passed"] / summary["total"] * 100) if summary["total"] > 0 else 0
        )
        lines.append(f"Compliance Rate: {compliance_rate:.1f}%")
        lines.append("")

        # Detailed results
        lines.append("DETAILED RESULTS")
        lines.append("-" * 80)
        for check in self.results["checks_performed"]:
            status_symbol = (
                "[v]"
                if check["status"] == "PASS"
                else (
                    "[X]"
                    if check["status"] == "FAIL"
                    else "[!]" if check["status"] == "WARN" else "[i]"
                )
            )
            lines.append(
                f"\n{status_symbol} {check['id']}: {check.get('description', 'No description')}"
            )
            lines.append(f"    Type: {check['type']}")
            lines.append(f"    Severity: {check.get('severity', 'medium')}")
            lines.append(f"    Status: {check['status']}")
            lines.append(f"    Message: {check.get('message', 'N/A')}")

        lines.append("\n" + "=" * 80)

        report = "\n".join(lines)

        if output_file:
            with open(output_file, "w") as f:
                f.write(report)
            logger.info(f"Text report saved to {output_file}")

        return report


def main():
    parser = argparse.ArgumentParser(
        description="Security Policy Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check policy compliance
  python policy-checker.py --policy baseline-security.yaml

  # Generate JSON report
  python policy-checker.py --policy baseline-security.yaml --output-format json --output report.json

  # Verbose output
  python policy-checker.py --policy baseline-security.yaml --verbose
        """,
    )

    parser.add_argument(
        "--policy", "-p", type=Path, required=True, help="Policy definition file (YAML)"
    )
    parser.add_argument(
        "--output-format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument("--output", "-o", type=Path, help="Output file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Create checker instance
    checker = PolicyChecker(policy_file=args.policy)

    # Run all checks
    results = checker.check_all_policies()

    # Generate report
    report = checker.generate_report(output_format=args.output_format, output_file=args.output)

    # Print to console if no output file specified
    if not args.output:
        print(report)

    # Exit with appropriate code
    if results["summary"]["failed"] > 0:
        logger.warning(f"{results['summary']['failed']} policy checks failed")
        sys.exit(1)
    else:
        logger.info("All policy checks passed")
        sys.exit(0)


if __name__ == "__main__":
    main()
