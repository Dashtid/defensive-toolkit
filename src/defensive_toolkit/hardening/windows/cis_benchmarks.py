#!/usr/bin/env python3
"""
Windows CIS Benchmark Hardening Checks
Author: Defensive Toolkit
Date: 2026-01-22

Description:
    Implements CIS Benchmark and Microsoft Security Baseline checks for Windows systems:
    - BitLocker encryption
    - Windows Defender configuration
    - Firewall profiles
    - UAC settings
    - Network hardening (SMB, LLMNR, NetBIOS)
    - Account policies
    - Audit logging
    - Secure Boot
    - Credential Guard

References:
    - CIS Microsoft Windows 11 Enterprise Benchmark v4.0.0 (March 2025)
    - Microsoft Security Baseline v25H2
    - DISA Windows 11 STIG V2R2 (January 2025)
    - ACSC Essential Eight Guidance
"""

import logging
import platform
import subprocess
from typing import Dict, List, Optional

# Import shared dataclasses from Linux module (no duplication)
from defensive_toolkit.hardening.linux.cis_benchmarks import (
    HardeningCheck,
    HardeningScanResult,
)

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class WindowsHardeningScanner:
    """Windows CIS Benchmark and Security Baseline compliance scanner."""

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
        self.is_windows = platform.system() == "Windows"
        self.is_admin = self._check_admin() if self.is_windows else False

    def _check_admin(self) -> bool:
        """Check if running as administrator."""
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _run_powershell(self, cmd: str, timeout: int = 30) -> tuple[int, str, str]:
        """
        Run PowerShell command and return (returncode, stdout, stderr).

        Cross-platform safe: returns error on non-Windows systems.
        """
        if not self.is_windows:
            return -1, "", "Not running on Windows"

        try:
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    cmd,
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except FileNotFoundError:
            return -1, "", "PowerShell not found"
        except Exception as e:
            return -1, "", str(e)

    def _not_windows_check(
        self,
        check_id: str,
        title: str,
        description: str,
        category: str,
        severity: str,
        expected_value: str,
        remediation: str,
        cis_reference: Optional[str] = None,
    ) -> HardeningCheck:
        """Return a N/A check result for non-Windows systems."""
        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=False,
            current_value="N/A (not Windows)",
            expected_value=expected_value,
            remediation=remediation,
            cis_reference=cis_reference,
        )

    # =========================================================================
    # Encryption Checks (CIS 18.10.9)
    # =========================================================================

    def check_bitlocker_encryption(self) -> HardeningCheck:
        """Check BitLocker encryption status (CIS 18.10.9.1)."""
        check_id = "WIN-ENC-001"
        title = "BitLocker System Drive Encryption"
        description = "Ensure BitLocker Drive Encryption is enabled on the system drive"
        category = "encryption"
        severity = "high"
        expected = "ProtectionStatus: On"
        remediation = "Enable BitLocker: manage-bde -on C: -RecoveryPassword"
        cis_ref = "18.10.9.1"

        if not self.is_windows:
            return self._not_windows_check(
                check_id, title, description, category, severity, expected, remediation, cis_ref
            )

        ret, out, err = self._run_powershell(
            "(Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue).ProtectionStatus"
        )

        if ret != 0 or not out:
            return HardeningCheck(
                check_id=check_id,
                title=title,
                description=description,
                category=category,
                severity=severity,
                passed=False,
                current_value="Unable to check (BitLocker may not be available)",
                expected_value=expected,
                remediation=remediation,
                cis_reference=cis_ref,
            )

        passed = out.lower() == "on"
        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=passed,
            current_value=f"ProtectionStatus: {out}",
            expected_value=expected,
            remediation=remediation if not passed else None,
            cis_reference=cis_ref,
        )

    # =========================================================================
    # Antivirus Checks (Microsoft Security Baseline)
    # =========================================================================

    def check_defender_realtime(self) -> HardeningCheck:
        """Check Windows Defender real-time protection (MS Baseline)."""
        check_id = "WIN-AV-001"
        title = "Windows Defender Real-time Protection"
        description = "Ensure Windows Defender real-time protection is enabled"
        category = "antivirus"
        severity = "high"
        expected = "RealTimeProtectionEnabled: True"
        remediation = "Set-MpPreference -DisableRealtimeMonitoring $false"
        cis_ref = None

        if not self.is_windows:
            return self._not_windows_check(
                check_id, title, description, category, severity, expected, remediation, cis_ref
            )

        ret, out, err = self._run_powershell(
            "(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled"
        )

        if ret != 0 or not out:
            return HardeningCheck(
                check_id=check_id,
                title=title,
                description=description,
                category=category,
                severity=severity,
                passed=False,
                current_value="Unable to check (Defender may not be available)",
                expected_value=expected,
                remediation=remediation,
                cis_reference=cis_ref,
            )

        passed = out.lower() == "true"
        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=passed,
            current_value=f"RealTimeProtectionEnabled: {out}",
            expected_value=expected,
            remediation=remediation if not passed else None,
            cis_reference=cis_ref,
        )

    def check_defender_cloud(self) -> HardeningCheck:
        """Check Windows Defender cloud protection (CIS 18.9.45.4.1)."""
        check_id = "WIN-AV-002"
        title = "Windows Defender Cloud Protection"
        description = "Ensure cloud-delivered protection (MAPS) is enabled"
        category = "antivirus"
        severity = "medium"
        expected = "MAPSReporting: 2 (Advanced)"
        remediation = "Set-MpPreference -MAPSReporting Advanced"
        cis_ref = "18.9.45.4.1"

        if not self.is_windows:
            return self._not_windows_check(
                check_id, title, description, category, severity, expected, remediation, cis_ref
            )

        ret, out, err = self._run_powershell(
            "(Get-MpPreference -ErrorAction SilentlyContinue).MAPSReporting"
        )

        if ret != 0:
            return HardeningCheck(
                check_id=check_id,
                title=title,
                description=description,
                category=category,
                severity=severity,
                passed=False,
                current_value="Unable to check",
                expected_value=expected,
                remediation=remediation,
                cis_reference=cis_ref,
            )

        try:
            maps_value = int(out) if out else 0
        except ValueError:
            maps_value = 0

        passed = maps_value >= 1  # 1=Basic, 2=Advanced
        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=passed,
            current_value=f"MAPSReporting: {maps_value}",
            expected_value=expected,
            remediation=remediation if not passed else None,
            cis_reference=cis_ref,
        )

    def check_defender_pua(self) -> HardeningCheck:
        """Check Windows Defender PUA protection (MS Recommended)."""
        check_id = "WIN-AV-003"
        title = "Windows Defender PUA Protection"
        description = "Ensure potentially unwanted application (PUA) protection is enabled"
        category = "antivirus"
        severity = "low"
        expected = "PUAProtection: Enabled (1)"
        remediation = "Set-MpPreference -PUAProtection Enabled"
        cis_ref = None

        if not self.is_windows:
            return self._not_windows_check(
                check_id, title, description, category, severity, expected, remediation, cis_ref
            )

        ret, out, err = self._run_powershell(
            "(Get-MpPreference -ErrorAction SilentlyContinue).PUAProtection"
        )

        if ret != 0:
            return HardeningCheck(
                check_id=check_id,
                title=title,
                description=description,
                category=category,
                severity=severity,
                passed=False,
                current_value="Unable to check",
                expected_value=expected,
                remediation=remediation,
                cis_reference=cis_ref,
            )

        try:
            pua_value = int(out) if out else 0
        except ValueError:
            pua_value = 0

        passed = pua_value == 1
        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=passed,
            current_value=f"PUAProtection: {pua_value}",
            expected_value=expected,
            remediation=remediation if not passed else None,
            cis_reference=cis_ref,
        )

    # =========================================================================
    # Firewall Checks (CIS 9.1)
    # =========================================================================

    def _check_firewall_profile(
        self, profile: str, check_id: str
    ) -> HardeningCheck:
        """Check a specific firewall profile status."""
        title = f"Windows Firewall ({profile} Profile)"
        description = f"Ensure Windows Firewall is enabled for {profile} profile"
        category = "firewall"
        severity = "high"
        expected = "Enabled: True"
        remediation = f"Set-NetFirewallProfile -Profile {profile} -Enabled True"
        cis_ref = "9.1"

        if not self.is_windows:
            return self._not_windows_check(
                check_id, title, description, category, severity, expected, remediation, cis_ref
            )

        ret, out, err = self._run_powershell(
            f"(Get-NetFirewallProfile -Name {profile} -ErrorAction SilentlyContinue).Enabled"
        )

        if ret != 0 or not out:
            return HardeningCheck(
                check_id=check_id,
                title=title,
                description=description,
                category=category,
                severity=severity,
                passed=False,
                current_value="Unable to check",
                expected_value=expected,
                remediation=remediation,
                cis_reference=cis_ref,
            )

        passed = out.lower() == "true"
        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=passed,
            current_value=f"Enabled: {out}",
            expected_value=expected,
            remediation=remediation if not passed else None,
            cis_reference=cis_ref,
        )

    def check_firewall_domain(self) -> HardeningCheck:
        """Check Windows Firewall Domain profile (CIS 9.1.1)."""
        return self._check_firewall_profile("Domain", "WIN-FW-001")

    def check_firewall_private(self) -> HardeningCheck:
        """Check Windows Firewall Private profile (CIS 9.1.2)."""
        return self._check_firewall_profile("Private", "WIN-FW-002")

    def check_firewall_public(self) -> HardeningCheck:
        """Check Windows Firewall Public profile (CIS 9.1.3)."""
        return self._check_firewall_profile("Public", "WIN-FW-003")

    # =========================================================================
    # UAC Checks (CIS 2.3.17)
    # =========================================================================

    def check_uac_consent_prompt(self) -> HardeningCheck:
        """Check UAC consent prompt for admins (CIS 2.3.17.1)."""
        check_id = "WIN-UAC-001"
        title = "UAC Admin Consent Prompt"
        description = "Ensure UAC prompts administrators on the secure desktop"
        category = "uac"
        severity = "high"
        expected = "ConsentPromptBehaviorAdmin: 2 (Prompt on secure desktop)"
        remediation = (
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
            "-Name ConsentPromptBehaviorAdmin -Value 2"
        )
        cis_ref = "2.3.17.1"

        if not self.is_windows:
            return self._not_windows_check(
                check_id, title, description, category, severity, expected, remediation, cis_ref
            )

        ret, out, err = self._run_powershell(
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
            "-Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin"
        )

        if ret != 0:
            return HardeningCheck(
                check_id=check_id,
                title=title,
                description=description,
                category=category,
                severity=severity,
                passed=False,
                current_value="Unable to check",
                expected_value=expected,
                remediation=remediation,
                cis_reference=cis_ref,
            )

        try:
            value = int(out) if out else -1
        except ValueError:
            value = -1

        # 2 = Prompt for consent on secure desktop (recommended)
        # 1 = Prompt for credentials on secure desktop
        # 5 = Prompt for consent for non-Windows binaries
        passed = value in [1, 2]
        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=passed,
            current_value=f"ConsentPromptBehaviorAdmin: {value}",
            expected_value=expected,
            remediation=remediation if not passed else None,
            cis_reference=cis_ref,
        )

    # =========================================================================
    # Registry/Policy Checks (CIS 18.9.95)
    # =========================================================================

    def check_powershell_logging(self) -> HardeningCheck:
        """Check PowerShell script block logging (CIS 18.9.95.1)."""
        check_id = "WIN-REG-001"
        title = "PowerShell Script Block Logging"
        description = "Ensure PowerShell script block logging is enabled"
        category = "registry"
        severity = "medium"
        expected = "EnableScriptBlockLogging: 1"
        remediation = (
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' "
            "-Name EnableScriptBlockLogging -Value 1"
        )
        cis_ref = "18.9.95.1"

        if not self.is_windows:
            return self._not_windows_check(
                check_id, title, description, category, severity, expected, remediation, cis_ref
            )

        ret, out, err = self._run_powershell(
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' "
            "-Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging"
        )

        # Key may not exist if not configured
        try:
            value = int(out) if out else 0
        except ValueError:
            value = 0

        passed = value == 1
        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=passed,
            current_value=f"EnableScriptBlockLogging: {value}",
            expected_value=expected,
            remediation=remediation if not passed else None,
            cis_reference=cis_ref,
        )

    # =========================================================================
    # Network Checks (CIS 18.5, MS Baseline)
    # =========================================================================

    def check_smbv1_disabled(self) -> HardeningCheck:
        """Check SMBv1 is disabled (MS Baseline)."""
        check_id = "WIN-NET-001"
        title = "SMBv1 Protocol Disabled"
        description = "Ensure SMBv1 protocol is disabled"
        category = "network"
        severity = "high"
        expected = "SMB1Protocol: False"
        remediation = "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
        cis_ref = None

        if not self.is_windows:
            return self._not_windows_check(
                check_id, title, description, category, severity, expected, remediation, cis_ref
            )

        ret, out, err = self._run_powershell(
            "(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol"
        )

        if ret != 0 or not out:
            return HardeningCheck(
                check_id=check_id,
                title=title,
                description=description,
                category=category,
                severity=severity,
                passed=False,
                current_value="Unable to check",
                expected_value=expected,
                remediation=remediation,
                cis_reference=cis_ref,
            )

        passed = out.lower() == "false"
        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=passed,
            current_value=f"EnableSMB1Protocol: {out}",
            expected_value=expected,
            remediation=remediation if not passed else None,
            cis_reference=cis_ref,
        )

    def check_llmnr_disabled(self) -> HardeningCheck:
        """Check LLMNR is disabled (CIS 18.5.8)."""
        check_id = "WIN-NET-002"
        title = "LLMNR Protocol Disabled"
        description = "Ensure Link-Local Multicast Name Resolution is disabled"
        category = "network"
        severity = "medium"
        expected = "EnableMulticast: 0 (Disabled)"
        remediation = (
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' "
            "-Name EnableMulticast -Value 0"
        )
        cis_ref = "18.5.8"

        if not self.is_windows:
            return self._not_windows_check(
                check_id, title, description, category, severity, expected, remediation, cis_ref
            )

        ret, out, err = self._run_powershell(
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' "
            "-Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast"
        )

        # Key may not exist (defaults to enabled)
        try:
            value = int(out) if out else 1
        except ValueError:
            value = 1

        passed = value == 0
        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=passed,
            current_value=f"EnableMulticast: {value}",
            expected_value=expected,
            remediation=remediation if not passed else None,
            cis_reference=cis_ref,
        )

    def check_netbios_disabled(self) -> HardeningCheck:
        """Check NetBIOS over TCP/IP is disabled (MS Baseline)."""
        check_id = "WIN-NET-003"
        title = "NetBIOS over TCP/IP Disabled"
        description = "Ensure NetBIOS over TCP/IP is disabled on all network adapters"
        category = "network"
        severity = "high"
        expected = "NetbiosOptions: 2 (Disabled)"
        remediation = "Run: .\\fix-netbios.ps1 or disable via adapter properties"
        cis_ref = None

        if not self.is_windows:
            return self._not_windows_check(
                check_id, title, description, category, severity, expected, remediation, cis_ref
            )

        # Check NetBIOS setting on all adapters
        ret, out, err = self._run_powershell(
            "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | "
            "Select-Object -ExpandProperty TcpipNetbiosOptions | Sort-Object -Unique"
        )

        if ret != 0 or not out:
            return HardeningCheck(
                check_id=check_id,
                title=title,
                description=description,
                category=category,
                severity=severity,
                passed=False,
                current_value="Unable to check",
                expected_value=expected,
                remediation=remediation,
                cis_reference=cis_ref,
            )

        # 0=Default, 1=Enabled, 2=Disabled
        # All adapters should return 2
        values = [v.strip() for v in out.split("\n") if v.strip()]
        passed = all(v == "2" for v in values)
        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=passed,
            current_value=f"NetbiosOptions: {', '.join(values)}",
            expected_value=expected,
            remediation=remediation if not passed else None,
            cis_reference=cis_ref,
        )

    # =========================================================================
    # Account Checks (CIS 2.3.1, 1.2.1)
    # =========================================================================

    def check_guest_account_disabled(self) -> HardeningCheck:
        """Check Guest account is disabled (CIS 2.3.1)."""
        check_id = "WIN-ACC-001"
        title = "Guest Account Disabled"
        description = "Ensure the built-in Guest account is disabled"
        category = "account"
        severity = "medium"
        expected = "Guest Enabled: False"
        remediation = "Disable-LocalUser -Name Guest"
        cis_ref = "2.3.1"

        if not self.is_windows:
            return self._not_windows_check(
                check_id, title, description, category, severity, expected, remediation, cis_ref
            )

        ret, out, err = self._run_powershell(
            "(Get-LocalUser -Name Guest -ErrorAction SilentlyContinue).Enabled"
        )

        if ret != 0 or not out:
            return HardeningCheck(
                check_id=check_id,
                title=title,
                description=description,
                category=category,
                severity=severity,
                passed=False,
                current_value="Unable to check",
                expected_value=expected,
                remediation=remediation,
                cis_reference=cis_ref,
            )

        passed = out.lower() == "false"
        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=passed,
            current_value=f"Guest Enabled: {out}",
            expected_value=expected,
            remediation=remediation if not passed else None,
            cis_reference=cis_ref,
        )

    def check_account_lockout(self) -> HardeningCheck:
        """Check account lockout threshold (CIS 1.2.1)."""
        check_id = "WIN-ACC-002"
        title = "Account Lockout Threshold"
        description = "Ensure account lockout threshold is configured"
        category = "account"
        severity = "medium"
        expected = "LockoutThreshold: <= 5"
        remediation = "net accounts /lockoutthreshold:5"
        cis_ref = "1.2.1"

        if not self.is_windows:
            return self._not_windows_check(
                check_id, title, description, category, severity, expected, remediation, cis_ref
            )

        ret, out, err = self._run_powershell(
            "(net accounts | Select-String 'Lockout threshold').ToString() -replace '.*:\\s*', ''"
        )

        if ret != 0 or not out:
            return HardeningCheck(
                check_id=check_id,
                title=title,
                description=description,
                category=category,
                severity=severity,
                passed=False,
                current_value="Unable to check",
                expected_value=expected,
                remediation=remediation,
                cis_reference=cis_ref,
            )

        try:
            if "never" in out.lower():
                threshold = 0
            else:
                threshold = int(out.strip())
        except ValueError:
            threshold = 0

        # 0 means no lockout (bad), 1-5 is good
        passed = 1 <= threshold <= 5
        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=passed,
            current_value=f"LockoutThreshold: {threshold}",
            expected_value=expected,
            remediation=remediation if not passed else None,
            cis_reference=cis_ref,
        )

    # =========================================================================
    # Audit Logging Checks (STIG V-220737)
    # =========================================================================

    def check_audit_policy(self) -> HardeningCheck:
        """Check audit policy is configured (STIG V-220737)."""
        check_id = "WIN-AUD-001"
        title = "Security Audit Policy"
        description = "Ensure security audit policy is configured for logon events"
        category = "audit_logging"
        severity = "medium"
        expected = "Logon/Logoff auditing: Success,Failure"
        remediation = "auditpol /set /subcategory:Logon /success:enable /failure:enable"
        cis_ref = None

        if not self.is_windows:
            return self._not_windows_check(
                check_id, title, description, category, severity, expected, remediation, cis_ref
            )

        ret, out, err = self._run_powershell(
            "auditpol /get /subcategory:Logon 2>$null | Select-String 'Logon'"
        )

        if ret != 0 or not out:
            return HardeningCheck(
                check_id=check_id,
                title=title,
                description=description,
                category=category,
                severity=severity,
                passed=False,
                current_value="Unable to check (requires admin)",
                expected_value=expected,
                remediation=remediation,
                cis_reference=cis_ref,
            )

        # Check for "Success and Failure" or both individually
        has_success = "success" in out.lower()
        has_failure = "failure" in out.lower()
        passed = has_success and has_failure

        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=passed,
            current_value=out.strip(),
            expected_value=expected,
            remediation=remediation if not passed else None,
            cis_reference=cis_ref,
        )

    # =========================================================================
    # Boot Security Checks (ACSC)
    # =========================================================================

    def check_secure_boot(self) -> HardeningCheck:
        """Check Secure Boot is enabled (ACSC Essential Eight)."""
        check_id = "WIN-BOOT-001"
        title = "Secure Boot Enabled"
        description = "Ensure UEFI Secure Boot is enabled"
        category = "boot"
        severity = "high"
        expected = "SecureBootEnabled: True"
        remediation = "Enable Secure Boot in UEFI/BIOS settings"
        cis_ref = None

        if not self.is_windows:
            return self._not_windows_check(
                check_id, title, description, category, severity, expected, remediation, cis_ref
            )

        ret, out, err = self._run_powershell("Confirm-SecureBootUEFI")

        if ret != 0 or err:
            return HardeningCheck(
                check_id=check_id,
                title=title,
                description=description,
                category=category,
                severity=severity,
                passed=False,
                current_value="Unable to check (may not be supported)",
                expected_value=expected,
                remediation=remediation,
                cis_reference=cis_ref,
            )

        passed = out.lower() == "true"
        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=passed,
            current_value=f"SecureBootEnabled: {out}",
            expected_value=expected,
            remediation=remediation if not passed else None,
            cis_reference=cis_ref,
        )

    # =========================================================================
    # Credential Protection Checks (MS Baseline)
    # =========================================================================

    def check_credential_guard(self) -> HardeningCheck:
        """Check Credential Guard is enabled (MS Baseline)."""
        check_id = "WIN-CRED-001"
        title = "Credential Guard"
        description = "Ensure Credential Guard is configured"
        category = "credential"
        severity = "medium"
        expected = "LsaCfgFlags: 1 or 2 (Enabled)"
        remediation = (
            "Enable via Group Policy: Computer Configuration > Administrative Templates > "
            "System > Device Guard > Turn On Virtualization Based Security"
        )
        cis_ref = None

        if not self.is_windows:
            return self._not_windows_check(
                check_id, title, description, category, severity, expected, remediation, cis_ref
            )

        ret, out, err = self._run_powershell(
            "(Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' "
            "-Name EnableVirtualizationBasedSecurity -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity"
        )

        try:
            value = int(out) if out else 0
        except ValueError:
            value = 0

        # 1 = Enabled with UEFI lock, 2 = Enabled without lock
        passed = value in [1, 2]
        return HardeningCheck(
            check_id=check_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            passed=passed,
            current_value=f"EnableVirtualizationBasedSecurity: {value}",
            expected_value=expected,
            remediation=remediation if not passed else None,
            cis_reference=cis_ref,
        )

    # =========================================================================
    # Main Scan Method
    # =========================================================================

    def run_all_checks(self) -> HardeningScanResult:
        """Run all Windows hardening checks."""
        self.checks = []

        # Run all checks
        self.checks.append(self.check_bitlocker_encryption())
        self.checks.append(self.check_defender_realtime())
        self.checks.append(self.check_defender_cloud())
        self.checks.append(self.check_defender_pua())
        self.checks.append(self.check_firewall_domain())
        self.checks.append(self.check_firewall_private())
        self.checks.append(self.check_firewall_public())
        self.checks.append(self.check_uac_consent_prompt())
        self.checks.append(self.check_powershell_logging())
        self.checks.append(self.check_smbv1_disabled())
        self.checks.append(self.check_llmnr_disabled())
        self.checks.append(self.check_netbios_disabled())
        self.checks.append(self.check_guest_account_disabled())
        self.checks.append(self.check_account_lockout())
        self.checks.append(self.check_audit_policy())
        self.checks.append(self.check_secure_boot())
        self.checks.append(self.check_credential_guard())

        # Calculate metrics
        total = len(self.checks)
        passed = sum(1 for c in self.checks if c.passed)
        failed = total - passed
        compliance = (passed / total * 100) if total > 0 else 0.0

        # Group by category
        categories: Dict[str, Dict[str, int]] = {}
        for check in self.checks:
            if check.category not in categories:
                categories[check.category] = {"passed": 0, "failed": 0}
            if check.passed:
                categories[check.category]["passed"] += 1
            else:
                categories[check.category]["failed"] += 1

        return HardeningScanResult(
            target=self.target,
            os_type="windows",
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
        """Generate PowerShell remediation script for failed checks."""
        if not self.checks:
            return "# No checks run yet. Run run_all_checks() first."

        failed_checks = [c for c in self.checks if not c.passed and c.remediation]

        if not failed_checks:
            return "# All checks passed - no remediation needed."

        lines = [
            "#Requires -RunAsAdministrator",
            "# Windows Hardening Remediation Script",
            "# Generated by Defensive Toolkit",
            f"# Target: {self.target}",
            f"# CIS Level: {self.cis_level}",
            "",
            "Write-Host '[+] Starting Windows hardening remediation...' -ForegroundColor Cyan",
            "",
        ]

        for check in failed_checks:
            lines.append(f"# {check.check_id}: {check.title}")
            lines.append(f"Write-Host '[*] Remediating: {check.title}' -ForegroundColor Yellow")
            lines.append(f"try {{")
            lines.append(f"    {check.remediation}")
            lines.append(f"    Write-Host '[+] {check.check_id} remediated' -ForegroundColor Green")
            lines.append(f"}} catch {{")
            lines.append(f"    Write-Host '[-] Failed to remediate {check.check_id}: $_' -ForegroundColor Red")
            lines.append(f"}}")
            lines.append("")

        lines.append("Write-Host '[+] Remediation complete. Re-run audit to verify.' -ForegroundColor Cyan")

        return "\n".join(lines)
