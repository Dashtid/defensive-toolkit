#!/usr/bin/env python3
"""
CIS Controls v8 Compliance Checker
Validates system configuration against CIS Controls v8 safeguards
Supports Windows and Linux systems
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


class CISChecker:
    """CIS Controls v8 compliance checker"""

    def __init__(self, output_format: str = 'json'):
        self.output_format = output_format
        self.os_type = platform.system().lower()
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'os': self.os_type,
            'cis_version': 'v8',
            'controls_checked': [],
            'compliance_summary': {
                'total': 0,
                'passed': 0,
                'failed': 0,
                'not_applicable': 0,
                'compliance_percentage': 0.0
            }
        }

    def check_control_1_inventory(self) -> Dict:
        """
        CIS Control 1: Inventory and Control of Enterprise Assets
        Actively manage all enterprise assets connected to the infrastructure
        """
        logger.info("Checking CIS Control 1: Asset Inventory")

        checks = []

        # 1.1: Establish and Maintain Detailed Enterprise Asset Inventory
        if self.os_type == 'windows':
            # Check Windows inventory tools
            wmi_check = self._run_command(['wmic', 'computersystem', 'get', 'name,manufacturer,model'])
            checks.append({
                'safeguard': '1.1',
                'title': 'Asset inventory available',
                'status': 'PASS' if wmi_check else 'FAIL',
                'details': 'System inventory accessible via WMI'
            })
        else:
            # Linux inventory
            dmidecode_check = self._command_exists('dmidecode')
            checks.append({
                'safeguard': '1.1',
                'title': 'Asset inventory tools available',
                'status': 'PASS' if dmidecode_check else 'FAIL',
                'details': 'dmidecode available for hardware inventory'
            })

        # 1.2: Address Unauthorized Assets
        if self.os_type == 'windows':
            # Check for network discovery
            netstat_output = self._run_command(['netstat', '-an'])
            checks.append({
                'safeguard': '1.2',
                'title': 'Network monitoring capability',
                'status': 'PASS' if netstat_output else 'FAIL',
                'details': 'Network connections can be monitored'
            })
        else:
            # Linux network monitoring
            ss_exists = self._command_exists('ss') or self._command_exists('netstat')
            checks.append({
                'safeguard': '1.2',
                'title': 'Network monitoring capability',
                'status': 'PASS' if ss_exists else 'FAIL',
                'details': 'Network monitoring tools available'
            })

        return {
            'control': '1',
            'title': 'Inventory and Control of Enterprise Assets',
            'safeguards_checked': len(checks),
            'checks': checks
        }

    def check_control_2_software_inventory(self) -> Dict:
        """
        CIS Control 2: Inventory and Control of Software Assets
        Actively manage all software on the network
        """
        logger.info("Checking CIS Control 2: Software Inventory")

        checks = []

        # 2.1: Establish and Maintain Software Inventory
        if self.os_type == 'windows':
            # Check installed software registry
            reg_check = self._run_command(['reg', 'query', 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall'])
            checks.append({
                'safeguard': '2.1',
                'title': 'Software inventory available',
                'status': 'PASS' if reg_check else 'FAIL',
                'details': 'Installed software can be enumerated'
            })
        else:
            # Linux package managers
            pkg_mgr = self._detect_package_manager()
            checks.append({
                'safeguard': '2.1',
                'title': 'Software inventory available',
                'status': 'PASS' if pkg_mgr else 'FAIL',
                'details': f'Package manager detected: {pkg_mgr if pkg_mgr else "None"}'
            })

        # 2.2: Ensure Authorized Software is Currently Supported
        checks.append({
            'safeguard': '2.2',
            'title': 'OS support status',
            'status': 'MANUAL',
            'details': 'Verify OS version is currently supported by vendor'
        })

        return {
            'control': '2',
            'title': 'Inventory and Control of Software Assets',
            'safeguards_checked': len(checks),
            'checks': checks
        }

    def check_control_3_data_protection(self) -> Dict:
        """
        CIS Control 3: Data Protection
        Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data
        """
        logger.info("Checking CIS Control 3: Data Protection")

        checks = []

        # 3.1: Establish and Maintain Data Management Process
        checks.append({
            'safeguard': '3.1',
            'title': 'Data classification process',
            'status': 'MANUAL',
            'details': 'Requires organizational policy review'
        })

        # 3.3: Configure Data Access Control Lists
        if self.os_type == 'windows':
            # Check if NTFS permissions are in use
            icacls_exists = self._command_exists('icacls')
            checks.append({
                'safeguard': '3.3',
                'title': 'File system ACLs available',
                'status': 'PASS' if icacls_exists else 'FAIL',
                'details': 'NTFS ACL management tools available'
            })
        else:
            # Linux file permissions
            checks.append({
                'safeguard': '3.3',
                'title': 'File system permissions available',
                'status': 'PASS',
                'details': 'POSIX permissions and ACLs supported'
            })

        # 3.11: Encrypt Sensitive Data at Rest
        if self.os_type == 'windows':
            # Check BitLocker status
            bitlocker_check = self._run_command(['manage-bde', '-status'])
            checks.append({
                'safeguard': '3.11',
                'title': 'Disk encryption capability',
                'status': 'PASS' if bitlocker_check else 'FAIL',
                'details': 'BitLocker encryption available'
            })
        else:
            # Linux encryption (LUKS)
            cryptsetup_exists = self._command_exists('cryptsetup')
            checks.append({
                'safeguard': '3.11',
                'title': 'Disk encryption capability',
                'status': 'PASS' if cryptsetup_exists else 'FAIL',
                'details': 'LUKS encryption tools available' if cryptsetup_exists else 'No encryption tools found'
            })

        return {
            'control': '3',
            'title': 'Data Protection',
            'safeguards_checked': len(checks),
            'checks': checks
        }

    def check_control_4_secure_configuration(self) -> Dict:
        """
        CIS Control 4: Secure Configuration of Enterprise Assets and Software
        Establish and maintain secure configurations for all assets
        """
        logger.info("Checking CIS Control 4: Secure Configuration")

        checks = []

        # 4.1: Establish and Maintain Secure Configuration Process
        checks.append({
            'safeguard': '4.1',
            'title': 'Configuration management process',
            'status': 'MANUAL',
            'details': 'Requires documented configuration baselines'
        })

        # 4.7: Manage Default Accounts
        if self.os_type == 'windows':
            # Check for disabled Guest account
            guest_check = self._run_command(['net', 'user', 'Guest'])
            guest_disabled = 'Account active' in str(guest_check) and 'No' in str(guest_check)
            checks.append({
                'safeguard': '4.7',
                'title': 'Default Guest account disabled',
                'status': 'PASS' if guest_disabled else 'FAIL',
                'details': 'Guest account should be disabled'
            })
        else:
            # Check for locked system accounts
            shadow_check = self._run_command(['cat', '/etc/shadow'])
            checks.append({
                'safeguard': '4.7',
                'title': 'System accounts locked',
                'status': 'MANUAL',
                'details': 'Verify system accounts have locked passwords'
            })

        return {
            'control': '4',
            'title': 'Secure Configuration of Enterprise Assets',
            'safeguards_checked': len(checks),
            'checks': checks
        }

    def check_control_5_account_management(self) -> Dict:
        """
        CIS Control 5: Account Management
        Use processes and tools to assign and manage authorization to credentials
        """
        logger.info("Checking CIS Control 5: Account Management")

        checks = []

        # 5.2: Use Unique Passwords
        if self.os_type == 'windows':
            # Check password policy
            net_accounts = self._run_command(['net', 'accounts'])
            checks.append({
                'safeguard': '5.2',
                'title': 'Password policy configured',
                'status': 'PASS' if net_accounts else 'FAIL',
                'details': 'Password policy can be enforced'
            })
        else:
            # Linux password policy
            pam_exists = Path('/etc/pam.d/common-password').exists() or Path('/etc/pam.d/system-auth').exists()
            checks.append({
                'safeguard': '5.2',
                'title': 'Password policy configured',
                'status': 'PASS' if pam_exists else 'FAIL',
                'details': 'PAM password policy available'
            })

        # 5.3: Disable Dormant Accounts
        checks.append({
            'safeguard': '5.3',
            'title': 'Dormant account management',
            'status': 'MANUAL',
            'details': 'Requires account activity audit'
        })

        return {
            'control': '5',
            'title': 'Account Management',
            'safeguards_checked': len(checks),
            'checks': checks
        }

    def check_control_6_access_control(self) -> Dict:
        """
        CIS Control 6: Access Control Management
        Use processes and tools to create, assign, manage, and revoke access credentials
        """
        logger.info("Checking CIS Control 6: Access Control")

        checks = []

        # 6.1: Establish an Access Granting Process
        checks.append({
            'safeguard': '6.1',
            'title': 'Access granting process',
            'status': 'MANUAL',
            'details': 'Requires documented access control policy'
        })

        # 6.5: Require MFA for Administrative Access
        if self.os_type == 'windows':
            # Check if Windows Hello or similar is configured
            checks.append({
                'safeguard': '6.5',
                'title': 'MFA for administrative access',
                'status': 'MANUAL',
                'details': 'Verify MFA configured for admin accounts'
            })
        else:
            # Check for PAM MFA modules
            pam_google_auth = Path('/etc/pam.d/google-authenticator').exists()
            checks.append({
                'safeguard': '6.5',
                'title': 'MFA capability available',
                'status': 'PASS' if pam_google_auth else 'INFO',
                'details': 'Google Authenticator PAM module' if pam_google_auth else 'No MFA module detected'
            })

        return {
            'control': '6',
            'title': 'Access Control Management',
            'safeguards_checked': len(checks),
            'checks': checks
        }

    def check_control_10_malware_defenses(self) -> Dict:
        """
        CIS Control 10: Malware Defenses
        Prevent or control installation, spread, and execution of malicious applications
        """
        logger.info("Checking CIS Control 10: Malware Defenses")

        checks = []

        # 10.1: Deploy and Maintain Anti-Malware Software
        if self.os_type == 'windows':
            # Check Windows Defender status
            defender_check = self._run_command(['powershell', '-Command', 'Get-MpComputerStatus'])
            checks.append({
                'safeguard': '10.1',
                'title': 'Anti-malware software present',
                'status': 'PASS' if defender_check else 'FAIL',
                'details': 'Windows Defender available'
            })
        else:
            # Check for ClamAV
            clamav_exists = self._command_exists('clamscan')
            checks.append({
                'safeguard': '10.1',
                'title': 'Anti-malware software present',
                'status': 'PASS' if clamav_exists else 'INFO',
                'details': 'ClamAV installed' if clamav_exists else 'No anti-malware detected'
            })

        return {
            'control': '10',
            'title': 'Malware Defenses',
            'safeguards_checked': len(checks),
            'checks': checks
        }

    def run_all_checks(self, controls: Optional[List[int]] = None) -> Dict:
        """Run all or specified CIS Control checks"""
        logger.info(f"Starting CIS Controls v8 compliance check on {self.os_type}")

        # Define all available control checks
        available_checks = {
            1: self.check_control_1_inventory,
            2: self.check_control_2_software_inventory,
            3: self.check_control_3_data_protection,
            4: self.check_control_4_secure_configuration,
            5: self.check_control_5_account_management,
            6: self.check_control_6_access_control,
            10: self.check_control_10_malware_defenses
        }

        # Determine which controls to check
        controls_to_check = controls if controls else available_checks.keys()

        # Run each control check
        for control_num in controls_to_check:
            if control_num in available_checks:
                control_result = available_checks[control_num]()
                self.results['controls_checked'].append(control_result)

        # Calculate summary statistics
        self._calculate_summary()

        return self.results

    def _calculate_summary(self):
        """Calculate compliance summary statistics"""
        total = 0
        passed = 0
        failed = 0
        not_applicable = 0

        for control in self.results['controls_checked']:
            for check in control['checks']:
                total += 1
                status = check['status']
                if status == 'PASS':
                    passed += 1
                elif status == 'FAIL':
                    failed += 1
                elif status in ['MANUAL', 'INFO', 'N/A']:
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
        elif self.output_format == 'html':
            return self._generate_html_report(output_file)
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
        lines.append("CIS Controls v8 Compliance Report")
        lines.append("=" * 80)
        lines.append(f"Timestamp: {self.results['timestamp']}")
        lines.append(f"Operating System: {self.results['os']}")
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
        for control in self.results['controls_checked']:
            lines.append(f"\n[+] Control {control['control']}: {control['title']}")
            lines.append(f"    Safeguards checked: {control['safeguards_checked']}")
            for check in control['checks']:
                status_symbol = "[v]" if check['status'] == 'PASS' else \
                               "[X]" if check['status'] == 'FAIL' else \
                               "[i]"
                lines.append(f"    {status_symbol} {check['safeguard']}: {check['title']}")
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
        description='CIS Controls v8 Compliance Checker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all checks and output JSON
  python cis-checker.py --output-format json --output report.json

  # Check specific controls
  python cis-checker.py --controls 1 2 3

  # Generate text report
  python cis-checker.py --output-format text --output report.txt
        """
    )

    parser.add_argument('--controls', nargs='+', type=int,
                       help='Specific control numbers to check (e.g., 1 2 3)')
    parser.add_argument('--output-format', choices=['json', 'text', 'html'],
                       default='text', help='Output format (default: text)')
    parser.add_argument('--output', '-o', type=Path,
                       help='Output file path')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Create checker instance
    checker = CISChecker(output_format=args.output_format)

    # Run checks
    results = checker.run_all_checks(controls=args.controls)

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
