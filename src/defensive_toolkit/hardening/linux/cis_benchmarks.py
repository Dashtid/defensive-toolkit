#!/usr/bin/env python3
"""
Linux CIS Benchmark Hardening Checks
Author: Defensive Toolkit
Date: 2025-12-28

Description:
    Implements CIS Benchmark checks for Linux systems including:
    - SSH hardening
    - File permissions
    - Service configuration
    - Kernel parameters
    - Audit logging

Reference: CIS Ubuntu Linux 22.04 LTS Benchmark v1.0.0
"""

import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class HardeningCheck:
    """Single hardening check result."""

    check_id: str
    title: str
    description: str
    category: str
    severity: str  # critical, high, medium, low
    passed: bool
    current_value: Optional[str] = None
    expected_value: Optional[str] = None
    remediation: Optional[str] = None
    cis_reference: Optional[str] = None


@dataclass
class HardeningScanResult:
    """Complete hardening scan result."""

    target: str
    os_type: str
    cis_level: int
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    compliance_percentage: float = 0.0
    checks: List[HardeningCheck] = field(default_factory=list)
    categories: Dict[str, Dict[str, int]] = field(default_factory=dict)


class LinuxHardeningScanner:
    """Linux CIS Benchmark compliance scanner."""

    def __init__(self, target: str = "localhost", cis_level: int = 1):
        """
        Initialize scanner.

        Args:
            target: Target hostname (localhost for local system)
            cis_level: CIS benchmark level (1 or 2)
        """
        self.target = target
        self.cis_level = cis_level
        self.checks: List[HardeningCheck] = []
        self.is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False

    def _run_command(self, cmd: str, timeout: int = 30) -> tuple[int, str, str]:
        """Run shell command and return (returncode, stdout, stderr).

        Security note: shell=True is intentionally used here because CIS benchmark
        checks require shell features (pipes, redirects, globbing). All commands
        are hardcoded in this module, not user-provided. Do not pass untrusted
        input to this method.
        """
        # Basic command validation - reject obviously dangerous patterns
        dangerous_patterns = ["$(", "`", "&&", "||", ";", "|&"]
        # Allow pipes (|) as they're needed for CIS checks, but not command chaining
        for pattern in dangerous_patterns:
            if pattern in cmd and pattern != "|":
                logger.warning(f"[!] Blocked potentially dangerous command pattern: {pattern}")
                return -1, "", f"Command contains blocked pattern: {pattern}"

        try:
            result = subprocess.run(
                cmd,
                shell=True,  # nosec B602 - required for CIS benchmark checks with pipes
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def _file_exists(self, path: str) -> bool:
        """Check if file exists."""
        return Path(path).exists()

    def _read_file(self, path: str) -> Optional[str]:
        """Read file contents."""
        try:
            return Path(path).read_text()
        except Exception:
            return None

    def _get_file_permissions(self, path: str) -> Optional[str]:
        """Get file permissions in octal format."""
        try:
            return oct(os.stat(path).st_mode)[-4:]
        except Exception:
            return None

    # =========================================================================
    # SSH Hardening Checks (CIS 5.2)
    # =========================================================================

    def check_ssh_protocol(self) -> HardeningCheck:
        """Check SSH protocol version (CIS 5.2.4)."""
        config = self._read_file("/etc/ssh/sshd_config")

        # SSH2 is default in modern OpenSSH, Protocol line is deprecated
        passed = True
        current = "SSH2 (default)"

        if config and "Protocol 1" in config:
            passed = False
            current = "Protocol 1 enabled"

        return HardeningCheck(
            check_id="SSH-001",
            title="SSH Protocol Version",
            description="Ensure SSH Protocol 2 is used",
            category="ssh",
            severity="high",
            passed=passed,
            current_value=current,
            expected_value="Protocol 2 only",
            remediation="Remove 'Protocol 1' from /etc/ssh/sshd_config",
            cis_reference="5.2.4",
        )

    def check_ssh_root_login(self) -> HardeningCheck:
        """Check SSH root login is disabled (CIS 5.2.10)."""
        config = self._read_file("/etc/ssh/sshd_config")
        passed = False
        current = "Unknown"

        if config:
            for line in config.splitlines():
                line = line.strip()
                if line.startswith("PermitRootLogin"):
                    value = line.split()[-1].lower()
                    current = value
                    passed = value in ("no", "prohibit-password")
                    break

        return HardeningCheck(
            check_id="SSH-002",
            title="SSH Root Login",
            description="Ensure SSH root login is disabled",
            category="ssh",
            severity="high",
            passed=passed,
            current_value=current,
            expected_value="no or prohibit-password",
            remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
            cis_reference="5.2.10",
        )

    def check_ssh_password_auth(self) -> HardeningCheck:
        """Check SSH password authentication (CIS 5.2.15)."""
        config = self._read_file("/etc/ssh/sshd_config")
        passed = False
        current = "yes (default)"

        if config:
            for line in config.splitlines():
                line = line.strip()
                if line.startswith("PasswordAuthentication"):
                    current = line.split()[-1].lower()
                    passed = current == "no"
                    break

        return HardeningCheck(
            check_id="SSH-003",
            title="SSH Password Authentication",
            description="Ensure SSH password authentication is disabled",
            category="ssh",
            severity="medium",
            passed=passed,
            current_value=current,
            expected_value="no (use key-based auth)",
            remediation="Set 'PasswordAuthentication no' in /etc/ssh/sshd_config",
            cis_reference="5.2.15",
        )

    def check_ssh_empty_passwords(self) -> HardeningCheck:
        """Check SSH permits empty passwords (CIS 5.2.11)."""
        config = self._read_file("/etc/ssh/sshd_config")
        passed = True  # Default is no
        current = "no (default)"

        if config:
            for line in config.splitlines():
                line = line.strip()
                if line.startswith("PermitEmptyPasswords"):
                    current = line.split()[-1].lower()
                    passed = current == "no"
                    break

        return HardeningCheck(
            check_id="SSH-004",
            title="SSH Empty Passwords",
            description="Ensure SSH does not allow empty passwords",
            category="ssh",
            severity="critical",
            passed=passed,
            current_value=current,
            expected_value="no",
            remediation="Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config",
            cis_reference="5.2.11",
        )

    def check_ssh_max_auth_tries(self) -> HardeningCheck:
        """Check SSH MaxAuthTries (CIS 5.2.7)."""
        config = self._read_file("/etc/ssh/sshd_config")
        passed = False
        current = "6 (default)"

        if config:
            for line in config.splitlines():
                line = line.strip()
                if line.startswith("MaxAuthTries"):
                    try:
                        value = int(line.split()[-1])
                        current = str(value)
                        passed = value <= 4
                    except ValueError:
                        pass
                    break

        return HardeningCheck(
            check_id="SSH-005",
            title="SSH Max Auth Tries",
            description="Ensure SSH MaxAuthTries is set to 4 or less",
            category="ssh",
            severity="medium",
            passed=passed,
            current_value=current,
            expected_value="<= 4",
            remediation="Set 'MaxAuthTries 4' in /etc/ssh/sshd_config",
            cis_reference="5.2.7",
        )

    # =========================================================================
    # File Permission Checks (CIS 6.1)
    # =========================================================================

    def check_passwd_permissions(self) -> HardeningCheck:
        """Check /etc/passwd permissions (CIS 6.1.2)."""
        perms = self._get_file_permissions("/etc/passwd")
        passed = perms == "0644" if perms else False

        return HardeningCheck(
            check_id="FILE-001",
            title="/etc/passwd Permissions",
            description="Ensure permissions on /etc/passwd are configured",
            category="file_permissions",
            severity="high",
            passed=passed,
            current_value=perms or "N/A",
            expected_value="0644",
            remediation="chmod 644 /etc/passwd",
            cis_reference="6.1.2",
        )

    def check_shadow_permissions(self) -> HardeningCheck:
        """Check /etc/shadow permissions (CIS 6.1.3)."""
        perms = self._get_file_permissions("/etc/shadow")
        # Should be 0640 or 0600 or 0400
        passed = perms in ("0640", "0600", "0400", "0000") if perms else False

        return HardeningCheck(
            check_id="FILE-002",
            title="/etc/shadow Permissions",
            description="Ensure permissions on /etc/shadow are configured",
            category="file_permissions",
            severity="critical",
            passed=passed,
            current_value=perms or "N/A",
            expected_value="0640 or more restrictive",
            remediation="chmod 640 /etc/shadow",
            cis_reference="6.1.3",
        )

    def check_gshadow_permissions(self) -> HardeningCheck:
        """Check /etc/gshadow permissions (CIS 6.1.5)."""
        perms = self._get_file_permissions("/etc/gshadow")
        passed = perms in ("0640", "0600", "0400", "0000") if perms else False

        return HardeningCheck(
            check_id="FILE-003",
            title="/etc/gshadow Permissions",
            description="Ensure permissions on /etc/gshadow are configured",
            category="file_permissions",
            severity="high",
            passed=passed,
            current_value=perms or "N/A",
            expected_value="0640 or more restrictive",
            remediation="chmod 640 /etc/gshadow",
            cis_reference="6.1.5",
        )

    def check_group_permissions(self) -> HardeningCheck:
        """Check /etc/group permissions (CIS 6.1.4)."""
        perms = self._get_file_permissions("/etc/group")
        passed = perms == "0644" if perms else False

        return HardeningCheck(
            check_id="FILE-004",
            title="/etc/group Permissions",
            description="Ensure permissions on /etc/group are configured",
            category="file_permissions",
            severity="high",
            passed=passed,
            current_value=perms or "N/A",
            expected_value="0644",
            remediation="chmod 644 /etc/group",
            cis_reference="6.1.4",
        )

    # =========================================================================
    # Service Checks (CIS 2.2)
    # =========================================================================

    def check_service_disabled(self, service: str, check_id: str, cis_ref: str) -> HardeningCheck:
        """Check if a service is disabled."""
        ret, out, _ = self._run_command(f"systemctl is-enabled {service} 2>/dev/null")
        current = out if out else "not installed"
        passed = current in ("disabled", "masked", "not installed", "not-found")

        return HardeningCheck(
            check_id=check_id,
            title=f"{service.title()} Service",
            description=f"Ensure {service} service is disabled",
            category="services",
            severity="medium",
            passed=passed,
            current_value=current,
            expected_value="disabled or not installed",
            remediation=f"systemctl --now disable {service}",
            cis_reference=cis_ref,
        )

    def check_telnet_disabled(self) -> HardeningCheck:
        """Check telnet is disabled (CIS 2.2.18)."""
        return self.check_service_disabled("telnet", "SVC-001", "2.2.18")

    def check_rsh_disabled(self) -> HardeningCheck:
        """Check rsh is disabled (CIS 2.2.17)."""
        return self.check_service_disabled("rsh.socket", "SVC-002", "2.2.17")

    def check_tftp_disabled(self) -> HardeningCheck:
        """Check TFTP is disabled (CIS 2.2.19)."""
        return self.check_service_disabled("tftp.socket", "SVC-003", "2.2.19")

    # =========================================================================
    # Kernel Parameters (CIS 3.2, 3.3)
    # =========================================================================

    def check_sysctl_param(
        self, param: str, expected: str, check_id: str, title: str, cis_ref: str, severity: str = "medium"
    ) -> HardeningCheck:
        """Check sysctl parameter value."""
        ret, out, _ = self._run_command(f"sysctl {param} 2>/dev/null")

        current = "N/A"
        passed = False

        if out and "=" in out:
            current = out.split("=")[-1].strip()
            passed = current == expected

        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=f"Ensure {param} is set to {expected}",
            category="kernel",
            severity=severity,
            passed=passed,
            current_value=current,
            expected_value=expected,
            remediation=f'sysctl -w {param}="{expected}"',
            cis_reference=cis_ref,
        )

    def check_ip_forwarding(self) -> HardeningCheck:
        """Check IP forwarding is disabled (CIS 3.2.1)."""
        return self.check_sysctl_param(
            "net.ipv4.ip_forward", "0", "KERN-001", "IP Forwarding", "3.2.1", "high"
        )

    def check_icmp_redirects(self) -> HardeningCheck:
        """Check ICMP redirects are disabled (CIS 3.2.2)."""
        return self.check_sysctl_param(
            "net.ipv4.conf.all.accept_redirects", "0", "KERN-002", "ICMP Redirects", "3.2.2"
        )

    def check_source_routing(self) -> HardeningCheck:
        """Check source routing is disabled (CIS 3.2.1)."""
        return self.check_sysctl_param(
            "net.ipv4.conf.all.accept_source_route",
            "0",
            "KERN-003",
            "Source Routing",
            "3.2.1",
        )

    def check_tcp_syncookies(self) -> HardeningCheck:
        """Check TCP SYN cookies are enabled (CIS 3.3.8)."""
        return self.check_sysctl_param(
            "net.ipv4.tcp_syncookies", "1", "KERN-004", "TCP SYN Cookies", "3.3.8", "high"
        )

    # =========================================================================
    # Audit Checks (CIS 4.1)
    # =========================================================================

    def check_auditd_installed(self) -> HardeningCheck:
        """Check auditd is installed (CIS 4.1.1.1)."""
        ret, out, _ = self._run_command("which auditd 2>/dev/null")
        passed = ret == 0 and bool(out)

        return HardeningCheck(
            check_id="AUDIT-001",
            title="Auditd Installed",
            description="Ensure auditd is installed",
            category="audit",
            severity="high",
            passed=passed,
            current_value="installed" if passed else "not installed",
            expected_value="installed",
            remediation="apt install auditd audispd-plugins",
            cis_reference="4.1.1.1",
        )

    def check_auditd_enabled(self) -> HardeningCheck:
        """Check auditd is enabled (CIS 4.1.1.2)."""
        ret, out, _ = self._run_command("systemctl is-enabled auditd 2>/dev/null")
        passed = out == "enabled"

        return HardeningCheck(
            check_id="AUDIT-002",
            title="Auditd Enabled",
            description="Ensure auditd service is enabled",
            category="audit",
            severity="high",
            passed=passed,
            current_value=out or "not enabled",
            expected_value="enabled",
            remediation="systemctl --now enable auditd",
            cis_reference="4.1.1.2",
        )

    # =========================================================================
    # Main Scan Methods
    # =========================================================================

    def run_all_checks(self) -> HardeningScanResult:
        """Run all hardening checks."""
        logger.info(f"[+] Starting Linux hardening scan (CIS Level {self.cis_level})")

        # SSH checks
        self.checks.append(self.check_ssh_protocol())
        self.checks.append(self.check_ssh_root_login())
        self.checks.append(self.check_ssh_password_auth())
        self.checks.append(self.check_ssh_empty_passwords())
        self.checks.append(self.check_ssh_max_auth_tries())

        # File permission checks
        self.checks.append(self.check_passwd_permissions())
        self.checks.append(self.check_shadow_permissions())
        self.checks.append(self.check_gshadow_permissions())
        self.checks.append(self.check_group_permissions())

        # Service checks
        self.checks.append(self.check_telnet_disabled())
        self.checks.append(self.check_rsh_disabled())
        self.checks.append(self.check_tftp_disabled())

        # Kernel parameter checks
        self.checks.append(self.check_ip_forwarding())
        self.checks.append(self.check_icmp_redirects())
        self.checks.append(self.check_source_routing())
        self.checks.append(self.check_tcp_syncookies())

        # Audit checks
        self.checks.append(self.check_auditd_installed())
        self.checks.append(self.check_auditd_enabled())

        # Calculate results
        total = len(self.checks)
        passed = sum(1 for c in self.checks if c.passed)
        failed = total - passed
        compliance = (passed / total * 100) if total > 0 else 0

        # Group by category
        categories: Dict[str, Dict[str, int]] = {}
        for check in self.checks:
            if check.category not in categories:
                categories[check.category] = {"passed": 0, "failed": 0}
            if check.passed:
                categories[check.category]["passed"] += 1
            else:
                categories[check.category]["failed"] += 1

        logger.info(f"[+] Scan complete: {passed}/{total} checks passed ({compliance:.1f}%)")

        return HardeningScanResult(
            target=self.target,
            os_type="linux",
            cis_level=self.cis_level,
            total_checks=total,
            passed=passed,
            failed=failed,
            skipped=0,
            compliance_percentage=round(compliance, 2),
            checks=self.checks,
            categories=categories,
        )

    def get_remediation_script(self) -> str:
        """Generate remediation script for failed checks."""
        lines = [
            "#!/bin/bash",
            "# Linux Hardening Remediation Script",
            "# Generated by Defensive Toolkit",
            "",
            "set -e",
            "",
        ]

        for check in self.checks:
            if not check.passed and check.remediation:
                lines.append(f"# {check.check_id}: {check.title}")
                lines.append(f"echo '[+] Applying: {check.title}'")
                lines.append(check.remediation)
                lines.append("")

        lines.append("echo '[OK] Remediation complete'")
        return "\n".join(lines)


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Linux CIS Benchmark Scanner")
    parser.add_argument("--level", type=int, default=1, choices=[1, 2], help="CIS level")
    parser.add_argument("--remediate", action="store_true", help="Generate remediation script")

    args = parser.parse_args()

    scanner = LinuxHardeningScanner(cis_level=args.level)
    result = scanner.run_all_checks()

    # Print summary
    print(f"\nCompliance: {result.compliance_percentage}%")
    print(f"Passed: {result.passed}/{result.total_checks}")
    print(f"Failed: {result.failed}")

    # Print failed checks
    if result.failed > 0:
        print("\nFailed Checks:")
        for check in result.checks:
            if not check.passed:
                print(f"  [{check.severity.upper()}] {check.check_id}: {check.title}")
                print(f"    Current: {check.current_value}")
                print(f"    Expected: {check.expected_value}")

    if args.remediate:
        script = scanner.get_remediation_script()
        print("\n# Remediation Script:")
        print(script)


if __name__ == "__main__":
    main()
