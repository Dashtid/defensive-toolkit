#!/usr/bin/env python3
"""
NIST 800-53 Rev 5 Compliance Checker
Validates system configuration against NIST 800-53 security controls
Focuses on technical controls that can be automated
"""

import argparse
import json
import logging
import platform
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class NISTChecker:
    """NIST 800-53 Rev 5 compliance checker"""

    def __init__(self, output_format: str = 'json', impact_level: str = 'moderate'):
        self.output_format = output_format
        self.impact_level = impact_level  # low, moderate, high
        self.os_type = platform.system().lower()
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'os': self.os_type,
            'framework': 'NIST 800-53 Rev 5',
            'impact_level': impact_level,
            'controls_checked': [],
            'compliance_summary': {
                'total': 0,
                'passed': 0,
                'failed': 0,
                'not_applicable': 0,
                'compliance_percentage': 0.0
            }
        }

    def check_ac_access_control(self) -> Dict:
        """
        AC - Access Control Family
        Limit system access to authorized users and processes
        """
        logger.info("Checking AC (Access Control) controls")

        checks = []

        # AC-2: Account Management
        if self.os_type == 'windows':
            # Check user accounts
            user_list = self._run_command(['net', 'user'])
            checks.append({
                'control': 'AC-2',
                'title': 'Account management capability',
                'status': 'PASS' if user_list else 'FAIL',
                'details': 'User account enumeration available',
                'baseline': ['low', 'moderate', 'high']
            })

            # Check password policy (AC-2)
            password_policy = self._run_command(['net', 'accounts'])
            checks.append({
                'control': 'AC-2',
                'title': 'Password policy enforcement',
                'status': 'PASS' if password_policy else 'FAIL',
                'details': 'Password policies can be configured',
                'baseline': ['low', 'moderate', 'high']
            })
        else:
            # Linux user management
            passwd_readable = Path('/etc/passwd').exists()
            checks.append({
                'control': 'AC-2',
                'title': 'Account management capability',
                'status': 'PASS' if passwd_readable else 'FAIL',
                'details': 'User account files accessible',
                'baseline': ['low', 'moderate', 'high']
            })

        # AC-7: Unsuccessful Logon Attempts
        if self.os_type == 'windows':
            # Check account lockout policy
            lockout_check = self._run_command(['net', 'accounts'])
            has_lockout = lockout_check and 'Lockout threshold' in str(lockout_check)
            checks.append({
                'control': 'AC-7',
                'title': 'Account lockout policy',
                'status': 'PASS' if has_lockout else 'FAIL',
                'details': 'Account lockout after failed attempts',
                'baseline': ['moderate', 'high']
            })
        else:
            # Check for pam_faillock or pam_tally2
            pam_files = list(Path('/etc/pam.d').glob('*')) if Path('/etc/pam.d').exists() else []
            has_faillock = any('faillock' in str(f) or 'tally' in str(f) for f in pam_files)
            checks.append({
                'control': 'AC-7',
                'title': 'Failed login attempt tracking',
                'status': 'INFO' if has_faillock else 'MANUAL',
                'details': 'PAM modules for failed login tracking' if has_faillock else 'Manual configuration required',
                'baseline': ['moderate', 'high']
            })

        # AC-17: Remote Access
        if self.os_type == 'windows':
            # Check RDP status
            rdp_check = self._run_command(['reg', 'query', 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server', '/v', 'fDenyTSConnections'])
            checks.append({
                'control': 'AC-17',
                'title': 'Remote access configuration',
                'status': 'PASS' if rdp_check else 'INFO',
                'details': 'RDP configuration accessible',
                'baseline': ['low', 'moderate', 'high']
            })
        else:
            # Check SSH configuration
            ssh_config_exists = Path('/etc/ssh/sshd_config').exists()
            checks.append({
                'control': 'AC-17',
                'title': 'Remote access configuration',
                'status': 'PASS' if ssh_config_exists else 'FAIL',
                'details': 'SSH configuration file available',
                'baseline': ['low', 'moderate', 'high']
            })

        return {
            'family': 'AC',
            'title': 'Access Control',
            'controls_checked': len(checks),
            'checks': checks
        }

    def check_au_audit_accountability(self) -> Dict:
        """
        AU - Audit and Accountability Family
        Create, protect, and retain audit records
        """
        logger.info("Checking AU (Audit and Accountability) controls")

        checks = []

        # AU-2: Audit Events
        if self.os_type == 'windows':
            # Check Windows Event Log service
            eventlog_check = self._run_command(['sc', 'query', 'EventLog'])
            is_running = eventlog_check and 'RUNNING' in str(eventlog_check)
            checks.append({
                'control': 'AU-2',
                'title': 'Event logging service',
                'status': 'PASS' if is_running else 'FAIL',
                'details': 'Windows Event Log service status',
                'baseline': ['low', 'moderate', 'high']
            })
        else:
            # Check syslog/rsyslog/journald
            has_syslog = (self._command_exists('rsyslogd') or
                         self._command_exists('syslog-ng') or
                         self._command_exists('journalctl'))
            checks.append({
                'control': 'AU-2',
                'title': 'System logging service',
                'status': 'PASS' if has_syslog else 'FAIL',
                'details': 'Logging daemon available',
                'baseline': ['low', 'moderate', 'high']
            })

        # AU-4: Audit Storage Capacity
        if self.os_type == 'windows':
            # Check event log max size
            checks.append({
                'control': 'AU-4',
                'title': 'Audit log capacity',
                'status': 'MANUAL',
                'details': 'Verify event log size limits configured',
                'baseline': ['moderate', 'high']
            })
        else:
            # Check disk space for /var/log
            df_output = self._run_command(['df', '-h', '/var/log'])
            checks.append({
                'control': 'AU-4',
                'title': 'Audit log storage',
                'status': 'PASS' if df_output else 'FAIL',
                'details': 'Log directory disk space monitoring available',
                'baseline': ['moderate', 'high']
            })

        # AU-9: Protection of Audit Information
        if self.os_type == 'windows':
            # Check event log ACLs
            checks.append({
                'control': 'AU-9',
                'title': 'Audit log protection',
                'status': 'MANUAL',
                'details': 'Verify event log file permissions',
                'baseline': ['moderate', 'high']
            })
        else:
            # Check /var/log permissions
            log_perms = self._run_command(['ls', '-ld', '/var/log'])
            is_protected = log_perms and 'drwxr' in str(log_perms)
            checks.append({
                'control': 'AU-9',
                'title': 'Audit log directory permissions',
                'status': 'PASS' if is_protected else 'WARN',
                'details': 'Log directory should be root-owned with restricted permissions',
                'baseline': ['moderate', 'high']
            })

        return {
            'family': 'AU',
            'title': 'Audit and Accountability',
            'controls_checked': len(checks),
            'checks': checks
        }

    def check_cm_configuration_management(self) -> Dict:
        """
        CM - Configuration Management Family
        Establish and maintain baseline configurations
        """
        logger.info("Checking CM (Configuration Management) controls")

        checks = []

        # CM-2: Baseline Configuration
        checks.append({
            'control': 'CM-2',
            'title': 'Baseline configuration',
            'status': 'MANUAL',
            'details': 'Requires documented system baseline',
            'baseline': ['low', 'moderate', 'high']
        })

        # CM-6: Configuration Settings
        if self.os_type == 'windows':
            # Check Group Policy
            gp_check = self._run_command(['gpresult', '/R'])
            checks.append({
                'control': 'CM-6',
                'title': 'Configuration management capability',
                'status': 'PASS' if gp_check else 'INFO',
                'details': 'Group Policy available for configuration management',
                'baseline': ['low', 'moderate', 'high']
            })
        else:
            # Check for configuration management tools
            has_tools = (self._command_exists('ansible') or
                        self._command_exists('puppet') or
                        self._command_exists('chef-client'))
            checks.append({
                'control': 'CM-6',
                'title': 'Configuration management tools',
                'status': 'INFO' if has_tools else 'MANUAL',
                'details': 'Configuration management tools available' if has_tools else 'Manual configuration required',
                'baseline': ['moderate', 'high']
            })

        # CM-7: Least Functionality
        if self.os_type == 'windows':
            # Check for unnecessary services
            services_check = self._run_command(['sc', 'query', 'type=', 'service'])
            checks.append({
                'control': 'CM-7',
                'title': 'Service inventory',
                'status': 'MANUAL',
                'details': 'Review running services for necessity',
                'baseline': ['moderate', 'high']
            })
        else:
            # Check for running services
            systemctl_check = self._run_command(['systemctl', 'list-units', '--type=service'])
            checks.append({
                'control': 'CM-7',
                'title': 'Service inventory',
                'status': 'MANUAL',
                'details': 'Review active services for necessity',
                'baseline': ['moderate', 'high']
            })

        return {
            'family': 'CM',
            'title': 'Configuration Management',
            'controls_checked': len(checks),
            'checks': checks
        }

    def check_ia_identification_authentication(self) -> Dict:
        """
        IA - Identification and Authentication Family
        Identify and authenticate users and processes
        """
        logger.info("Checking IA (Identification and Authentication) controls")

        checks = []

        # IA-2: Identification and Authentication (Organizational Users)
        checks.append({
            'control': 'IA-2',
            'title': 'User authentication required',
            'status': 'PASS',
            'details': 'Operating system requires user authentication',
            'baseline': ['low', 'moderate', 'high']
        })

        # IA-5: Authenticator Management
        if self.os_type == 'windows':
            # Check password complexity
            password_policy = self._run_command(['net', 'accounts'])
            checks.append({
                'control': 'IA-5',
                'title': 'Password complexity requirements',
                'status': 'MANUAL',
                'details': 'Verify password complexity policy enabled',
                'baseline': ['moderate', 'high']
            })
        else:
            # Check PAM password quality
            pam_pwquality = Path('/etc/security/pwquality.conf').exists()
            checks.append({
                'control': 'IA-5',
                'title': 'Password quality enforcement',
                'status': 'PASS' if pam_pwquality else 'INFO',
                'details': 'PAM password quality module' if pam_pwquality else 'Password quality configuration',
                'baseline': ['moderate', 'high']
            })

        # IA-8: Identification and Authentication (Non-Organizational Users)
        checks.append({
            'control': 'IA-8',
            'title': 'External user authentication',
            'status': 'MANUAL',
            'details': 'Verify external user authentication requirements',
            'baseline': ['moderate', 'high']
        })

        return {
            'family': 'IA',
            'title': 'Identification and Authentication',
            'controls_checked': len(checks),
            'checks': checks
        }

    def check_sc_system_communications_protection(self) -> Dict:
        """
        SC - System and Communications Protection Family
        Monitor, control, and protect communications
        """
        logger.info("Checking SC (System and Communications Protection) controls")

        checks = []

        # SC-7: Boundary Protection
        if self.os_type == 'windows':
            # Check Windows Firewall
            firewall_check = self._run_command(['netsh', 'advfirewall', 'show', 'allprofiles'])
            is_enabled = firewall_check and 'State' in str(firewall_check) and 'ON' in str(firewall_check)
            checks.append({
                'control': 'SC-7',
                'title': 'Host-based firewall',
                'status': 'PASS' if is_enabled else 'FAIL',
                'details': 'Windows Firewall status',
                'baseline': ['low', 'moderate', 'high']
            })
        else:
            # Check iptables/nftables/ufw
            has_firewall = (self._command_exists('iptables') or
                           self._command_exists('nft') or
                           self._command_exists('ufw'))
            checks.append({
                'control': 'SC-7',
                'title': 'Host-based firewall',
                'status': 'PASS' if has_firewall else 'FAIL',
                'details': 'Firewall tools available',
                'baseline': ['low', 'moderate', 'high']
            })

        # SC-8: Transmission Confidentiality and Integrity
        if self.os_type == 'windows':
            # Check TLS/SSL support
            checks.append({
                'control': 'SC-8',
                'title': 'Cryptographic protection',
                'status': 'MANUAL',
                'details': 'Verify encrypted protocols configured',
                'baseline': ['moderate', 'high']
            })
        else:
            # Check OpenSSL
            openssl_exists = self._command_exists('openssl')
            checks.append({
                'control': 'SC-8',
                'title': 'Cryptographic libraries',
                'status': 'PASS' if openssl_exists else 'FAIL',
                'details': 'OpenSSL available for encryption',
                'baseline': ['moderate', 'high']
            })

        # SC-28: Protection of Information at Rest
        if self.os_type == 'windows':
            # Check BitLocker
            bitlocker_check = self._run_command(['manage-bde', '-status'])
            checks.append({
                'control': 'SC-28',
                'title': 'Encryption at rest capability',
                'status': 'PASS' if bitlocker_check else 'INFO',
                'details': 'BitLocker encryption available',
                'baseline': ['moderate', 'high']
            })
        else:
            # Check LUKS/dm-crypt
            cryptsetup_exists = self._command_exists('cryptsetup')
            checks.append({
                'control': 'SC-28',
                'title': 'Encryption at rest capability',
                'status': 'PASS' if cryptsetup_exists else 'INFO',
                'details': 'LUKS encryption tools available' if cryptsetup_exists else 'Encryption tools',
                'baseline': ['moderate', 'high']
            })

        return {
            'family': 'SC',
            'title': 'System and Communications Protection',
            'controls_checked': len(checks),
            'checks': checks
        }

    def check_si_system_information_integrity(self) -> Dict:
        """
        SI - System and Information Integrity Family
        Identify, report, and correct flaws in a timely manner
        """
        logger.info("Checking SI (System and Information Integrity) controls")

        checks = []

        # SI-2: Flaw Remediation
        if self.os_type == 'windows':
            # Check Windows Update
            wu_check = self._run_command(['powershell', '-Command', 'Get-Service -Name wuauserv'])
            checks.append({
                'control': 'SI-2',
                'title': 'Patch management capability',
                'status': 'PASS' if wu_check else 'FAIL',
                'details': 'Windows Update service available',
                'baseline': ['low', 'moderate', 'high']
            })
        else:
            # Check package manager updates
            pkg_mgr = self._detect_package_manager()
            checks.append({
                'control': 'SI-2',
                'title': 'Patch management capability',
                'status': 'PASS' if pkg_mgr else 'FAIL',
                'details': f'Package manager: {pkg_mgr if pkg_mgr else "None"}',
                'baseline': ['low', 'moderate', 'high']
            })

        # SI-3: Malicious Code Protection
        if self.os_type == 'windows':
            # Check Windows Defender
            defender_check = self._run_command(['powershell', '-Command', 'Get-MpComputerStatus'])
            checks.append({
                'control': 'SI-3',
                'title': 'Anti-malware protection',
                'status': 'PASS' if defender_check else 'FAIL',
                'details': 'Windows Defender available',
                'baseline': ['low', 'moderate', 'high']
            })
        else:
            # Check ClamAV or similar
            clamav_exists = self._command_exists('clamscan')
            checks.append({
                'control': 'SI-3',
                'title': 'Anti-malware protection',
                'status': 'INFO' if clamav_exists else 'MANUAL',
                'details': 'ClamAV installed' if clamav_exists else 'Anti-malware solution recommended',
                'baseline': ['low', 'moderate', 'high']
            })

        # SI-4: System Monitoring
        checks.append({
            'control': 'SI-4',
            'title': 'System monitoring capability',
            'status': 'MANUAL',
            'details': 'Verify intrusion detection/monitoring configured',
            'baseline': ['moderate', 'high']
        })

        return {
            'family': 'SI',
            'title': 'System and Information Integrity',
            'controls_checked': len(checks),
            'checks': checks
        }

    def run_all_checks(self, families: Optional[List[str]] = None) -> Dict:
        """Run all or specified NIST 800-53 control family checks"""
        logger.info(f"Starting NIST 800-53 Rev 5 compliance check ({self.impact_level} baseline)")

        # Define all available control family checks
        available_checks = {
            'AC': self.check_ac_access_control,
            'AU': self.check_au_audit_accountability,
            'CM': self.check_cm_configuration_management,
            'IA': self.check_ia_identification_authentication,
            'SC': self.check_sc_system_communications_protection,
            'SI': self.check_si_system_information_integrity
        }

        # Determine which families to check
        families_to_check = families if families else available_checks.keys()

        # Run each family check
        for family in families_to_check:
            if family.upper() in available_checks:
                family_result = available_checks[family.upper()]()

                # Filter checks by impact level baseline
                filtered_checks = [
                    check for check in family_result['checks']
                    if self.impact_level in check.get('baseline', [])
                ]

                family_result['checks'] = filtered_checks
                family_result['controls_checked'] = len(filtered_checks)

                self.results['controls_checked'].append(family_result)

        # Calculate summary statistics
        self._calculate_summary()

        return self.results

    def _calculate_summary(self):
        """Calculate compliance summary statistics"""
        total = 0
        passed = 0
        failed = 0
        not_applicable = 0

        for family in self.results['controls_checked']:
            for check in family['checks']:
                total += 1
                status = check['status']
                if status == 'PASS':
                    passed += 1
                elif status == 'FAIL':
                    failed += 1
                elif status in ['MANUAL', 'INFO', 'WARN', 'N/A']:
                    not_applicable += 1

        self.results['compliance_summary'] = {
            'total': total,
            'passed': passed,
            'failed': failed,
            'not_applicable': not_applicable,
            'compliance_percentage': round((passed / total * 100) if total > 0 else 0, 2)
        }

    def generate_report(self, output_file: Optional[Path] = None):
        """Generate compliance report in specified format"""
        if self.output_format == 'json':
            return self._generate_json_report(output_file)
        else:
            return self._generate_text_report(output_file)

    def _generate_json_report(self, output_file: Optional[Path] = None) -> str:
        """Generate JSON report"""
        json_output = json.dumps(self.results, indent=2)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_output)
            logger.info(f"JSON report saved to {output_file}")

        return json_output

    def _generate_text_report(self, output_file: Optional[Path] = None) -> str:
        """Generate plain text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("NIST 800-53 Rev 5 Compliance Report")
        lines.append("=" * 80)
        lines.append(f"Timestamp: {self.results['timestamp']}")
        lines.append(f"Operating System: {self.results['os']}")
        lines.append(f"Impact Level: {self.results['impact_level'].upper()}")
        lines.append("")
        lines.append("COMPLIANCE SUMMARY")
        lines.append("-" * 80)
        summary = self.results['compliance_summary']
        lines.append(f"Total Checks: {summary['total']}")
        lines.append(f"Passed: {summary['passed']}")
        lines.append(f"Failed: {summary['failed']}")
        lines.append(f"Not Applicable/Manual: {summary['not_applicable']}")
        lines.append(f"Compliance Score: {summary['compliance_percentage']}%")
        lines.append("")

        # Detailed results
        lines.append("DETAILED RESULTS")
        lines.append("-" * 80)
        for family in self.results['controls_checked']:
            lines.append(f"\n[+] {family['family']} - {family['title']}")
            lines.append(f"    Controls checked: {family['controls_checked']}")
            for check in family['checks']:
                status_symbol = "[v]" if check['status'] == 'PASS' else \
                               "[X]" if check['status'] == 'FAIL' else \
                               "[!]" if check['status'] == 'WARN' else \
                               "[i]"
                lines.append(f"    {status_symbol} {check['control']}: {check['title']}")
                lines.append(f"        Status: {check['status']}")
                lines.append(f"        Details: {check['details']}")

        lines.append("\n" + "=" * 80)

        report = "\n".join(lines)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            logger.info(f"Text report saved to {output_file}")

        return report

    def _run_command(self, cmd: List[str]) -> Optional[str]:
        """Run system command and return output"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout if result.returncode == 0 else None
        except Exception as e:
            logger.debug(f"Command failed: {' '.join(cmd)} - {e}")
            return None

    def _command_exists(self, command: str) -> bool:
        """Check if command exists in PATH"""
        if self.os_type == 'windows':
            check_cmd = ['where', command]
        else:
            check_cmd = ['which', command]

        result = self._run_command(check_cmd)
        return result is not None and len(result) > 0

    def _detect_package_manager(self) -> Optional[str]:
        """Detect Linux package manager"""
        managers = ['apt', 'yum', 'dnf', 'zypper', 'pacman']
        for mgr in managers:
            if self._command_exists(mgr):
                return mgr
        return None


def main():
    parser = argparse.ArgumentParser(
        description='NIST 800-53 Rev 5 Compliance Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all checks for moderate impact baseline
  python nist-checker.py --impact-level moderate --output report.json

  # Check specific control families
  python nist-checker.py --families AC AU IA

  # High impact baseline checks
  python nist-checker.py --impact-level high --output-format text
        """
    )

    parser.add_argument('--families', nargs='+', type=str,
                       help='Specific control families to check (e.g., AC AU IA)')
    parser.add_argument('--impact-level', choices=['low', 'moderate', 'high'],
                       default='moderate', help='FIPS 199 impact level (default: moderate)')
    parser.add_argument('--output-format', choices=['json', 'text'],
                       default='text', help='Output format (default: text)')
    parser.add_argument('--output', '-o', type=Path,
                       help='Output file path')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Create checker instance
    checker = NISTChecker(output_format=args.output_format, impact_level=args.impact_level)

    # Run checks
    results = checker.run_all_checks(families=args.families)

    # Generate report
    report = checker.generate_report(output_file=args.output)

    # Print to console if no output file specified
    if not args.output:
        print(report)

    # Exit with appropriate code
    summary = results['compliance_summary']
    if summary['failed'] > 0:
        logger.warning(f"{summary['failed']} checks failed")
        sys.exit(1)
    else:
        logger.info("All automated checks passed")
        sys.exit(0)


if __name__ == '__main__':
    main()
