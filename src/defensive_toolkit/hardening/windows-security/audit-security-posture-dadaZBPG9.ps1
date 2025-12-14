# Windows 11 Security Posture Audit Script
# Checks current security configuration against CIS Benchmark and Microsoft Baseline recommendations
# Author: David Dashti
# Date: November 2025
# Version: 2.0.0
#
# USAGE:
#   Run as Administrator: .\audit-security-posture.ps1
#   Generate HTML report: .\audit-security-posture.ps1 -OutputFormat HTML
#   Export to JSON: .\audit-security-posture.ps1 -OutputFormat JSON
#
# FEATURES:
#   - 30+ security checks across CIS Benchmark and Microsoft Baselines
#   - Detailed explanations for each check (why it matters)
#   - Remediation commands for failed checks
#   - HTML report with remediation guidance
#   - Risk prioritization (High/Medium/Low)
#
# REFERENCES:
#   - CIS Microsoft Windows 11 Enterprise Benchmark v4.0.0 (March 2025)
#   - Microsoft Security Baseline for Windows 11
#   - Australian Cyber Security Centre (ACSC) Windows 11 Hardening Guide (September 2025)
#   - NIST SP 800-53 Security Controls

#Requires -Version 7.0
#Requires -RunAsAdministrator

param(
    [Parameter()]
    [ValidateSet('Console', 'JSON', 'HTML', 'CSV')]
    [string]$OutputFormat = 'Console',

    [Parameter()]
    [string]$OutputPath = ""
)

# Handle long paths - use temp directory if script path is too long
# Windows MAX_PATH is 260 chars; we need room for extension (.html = 5 chars) plus safety margin
if (-not $OutputPath) {
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $defaultPath = "$PSScriptRoot\audit-results-$timestamp"
    # Check if full path with extension would exceed 250 chars (leaving margin before 260 limit)
    # Also detect OneDrive paths which tend to be very long
    if (($defaultPath.Length -gt 150) -or ($PSScriptRoot -match 'OneDrive')) {
        # Path too long for Windows or in OneDrive - use temp directory
        $OutputPath = "$env:TEMP\security-audit-$timestamp"
        Write-Host "[i] Using temp directory for output (long path detected): $OutputPath" -ForegroundColor Blue
    } else {
        $OutputPath = $defaultPath
    }
}

# Colors for console output
$Colors = @{
    Red    = 'Red'
    Green  = 'Green'
    Yellow = 'Yellow'
    Blue   = 'Blue'
    Cyan   = 'Cyan'
}

# Audit results collection
$AuditResults = @{
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
    WindowsVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
    WindowsBuild = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
    Checks = @()
    Summary = @{
        Total = 0
        Passed = 0
        Failed = 0
        Warning = 0
        NotApplicable = 0
    }
}

function Write-Info { param([string]$Message) Write-Host "[i] $Message" -ForegroundColor $Colors.Blue }
function Write-Success { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor $Colors.Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor $Colors.Yellow }
function Write-Error { param([string]$Message) Write-Host "[-] $Message" -ForegroundColor $Colors.Red }
function Write-Header { param([string]$Message) Write-Host "`n=== $Message ===" -ForegroundColor $Colors.Cyan }

function Add-AuditCheck {
    param(
        [string]$Category,
        [string]$CheckName,
        [string]$Status,  # Pass, Fail, Warning, N/A
        [string]$CurrentValue,
        [string]$RecommendedValue,
        [string]$Risk,    # High, Medium, Low
        [string]$Impact,  # High, Medium, Low
        [string]$Reference,
        [string]$Description = "",      # Why this check matters
        [string]$Remediation = ""       # Command/steps to fix
    )

    $check = [PSCustomObject]@{
        Category = $Category
        CheckName = $CheckName
        Status = $Status
        CurrentValue = $CurrentValue
        RecommendedValue = $RecommendedValue
        Risk = $Risk
        Impact = $Impact
        Reference = $Reference
        Description = $Description
        Remediation = $Remediation
    }

    $AuditResults.Checks += $check
    $AuditResults.Summary.Total++

    switch ($Status) {
        'Pass' {
            $AuditResults.Summary.Passed++
            Write-Success "$CheckName - PASS"
        }
        'Fail' {
            $AuditResults.Summary.Failed++
            Write-Error "$CheckName - FAIL"
            if ($Description) { Write-Host "    Why: $Description" -ForegroundColor Gray }
            if ($Remediation) { Write-Host "    Fix: $Remediation" -ForegroundColor Yellow }
        }
        'Warning' {
            $AuditResults.Summary.Warning++
            Write-Warning "$CheckName - WARNING"
            if ($Description) { Write-Host "    Why: $Description" -ForegroundColor Gray }
        }
        'N/A' { $AuditResults.Summary.NotApplicable++ }
    }
}

function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$ExpectedValue
    )

    try {
        if (Test-Path $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $value) {
                $currentValue = $value.$Name
                if ($currentValue -eq $ExpectedValue) {
                    return @{ Result = 'Pass'; Value = $currentValue }
                } else {
                    return @{ Result = 'Fail'; Value = $currentValue }
                }
            }
        }
        return @{ Result = 'Fail'; Value = 'Not Set' }
    }
    catch {
        return @{ Result = 'Fail'; Value = 'Error checking' }
    }
}

function Test-ServiceStatus {
    param(
        [string]$ServiceName,
        [string]$ExpectedStatus
    )

    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            if ($service.Status -eq $ExpectedStatus) {
                return @{ Result = 'Pass'; Value = $service.Status }
            } else {
                return @{ Result = 'Fail'; Value = $service.Status }
            }
        }
        return @{ Result = 'N/A'; Value = 'Service not found' }
    }
    catch {
        return @{ Result = 'N/A'; Value = 'Error checking' }
    }
}

# ===== HIGH PRIORITY CHECKS =====

Write-Header "HIGH PRIORITY SECURITY CHECKS"

# Check 1: BitLocker Encryption
Write-Info "Checking BitLocker encryption status..."
try {
    $bitlocker = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
    if ($null -ne $bitlocker) {
        $status = if ($bitlocker.ProtectionStatus -eq 'On') { 'Pass' } else { 'Fail' }
        Add-AuditCheck -Category "Encryption" -CheckName "BitLocker System Drive Encryption" `
            -Status $status -CurrentValue $bitlocker.ProtectionStatus `
            -RecommendedValue "On" -Risk "High" -Impact "Low" `
            -Reference "CIS 18.10.9.1" `
            -Description "Full disk encryption protects data if device is lost or stolen. Required for compliance (ISO 27001, HIPAA)." `
            -Remediation "manage-bde -on C: -RecoveryPassword"
    } else {
        Add-AuditCheck -Category "Encryption" -CheckName "BitLocker System Drive Encryption" `
            -Status "N/A" -CurrentValue "BitLocker not available" `
            -RecommendedValue "On" -Risk "High" -Impact "Low" `
            -Reference "CIS 18.10.9.1" `
            -Description "Full disk encryption protects data if device is lost or stolen." `
            -Remediation "BitLocker requires Windows Pro/Enterprise and TPM 1.2+"
    }
}
catch {
    Add-AuditCheck -Category "Encryption" -CheckName "BitLocker System Drive Encryption" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "On" -Risk "High" -Impact "Low" `
        -Reference "CIS 18.10.9.1" `
        -Description "Full disk encryption protects data if device is lost or stolen." `
        -Remediation "Run Get-BitLockerVolume manually to diagnose"
}

# Check 2: Windows Defender Real-time Protection
Write-Info "Checking Windows Defender status..."
try {
    $defender = Get-MpPreference
    $defenderStatus = Get-MpComputerStatus

    $realtimeStatus = if ($defenderStatus.RealTimeProtectionEnabled) { 'Pass' } else { 'Fail' }
    Add-AuditCheck -Category "Antivirus" -CheckName "Windows Defender Real-time Protection" `
        -Status $realtimeStatus -CurrentValue $defenderStatus.RealTimeProtectionEnabled `
        -RecommendedValue "True" -Risk "High" -Impact "Low" `
        -Reference "MS Baseline" `
        -Description "Real-time protection scans files as they are accessed, blocking malware before execution." `
        -Remediation "Set-MpPreference -DisableRealtimeMonitoring `$false"

    $cloudStatus = if ($defender.MAPSReporting -gt 0) { 'Pass' } else { 'Warning' }
    Add-AuditCheck -Category "Antivirus" -CheckName "Windows Defender Cloud Protection" `
        -Status $cloudStatus -CurrentValue $defender.MAPSReporting `
        -RecommendedValue "2 (Advanced)" -Risk "Medium" -Impact "Low" `
        -Reference "MS Baseline" `
        -Description "Cloud protection provides faster detection of new threats using Microsoft's cloud intelligence." `
        -Remediation "Set-MpPreference -MAPSReporting Advanced"
}
catch {
    Add-AuditCheck -Category "Antivirus" -CheckName "Windows Defender Status" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "Enabled" -Risk "High" -Impact "Low" `
        -Reference "MS Baseline" `
        -Description "Windows Defender is the primary antimalware protection for Windows." `
        -Remediation "Check if third-party AV is installed, or run Get-MpComputerStatus"
}

# Check 3: Windows Firewall Status
Write-Info "Checking Windows Firewall status..."
foreach ($fwProfileName in @('Domain', 'Public', 'Private')) {
    try {
        $fwProfile = Get-NetFirewallProfile -Name $fwProfileName
        $status = if ($fwProfile.Enabled) { 'Pass' } else { 'Fail' }
        Add-AuditCheck -Category "Firewall" -CheckName "Windows Firewall ($fwProfileName Profile)" `
            -Status $status -CurrentValue $fwProfile.Enabled `
            -RecommendedValue "True" -Risk "High" -Impact "Low" `
            -Reference "CIS 9.1" `
            -Description "Firewall blocks unauthorized network connections. Each profile (Domain/Private/Public) should be enabled." `
            -Remediation "Set-NetFirewallProfile -Name $fwProfileName -Enabled True"
    }
    catch {
        Add-AuditCheck -Category "Firewall" -CheckName "Windows Firewall ($fwProfileName Profile)" `
            -Status "Warning" -CurrentValue "Unable to check" `
            -RecommendedValue "True" -Risk "High" -Impact "Low" `
            -Reference "CIS 9.1" `
            -Description "Firewall blocks unauthorized network connections." `
            -Remediation "Run Get-NetFirewallProfile to diagnose"
    }
}

# Check 4: UAC Settings
Write-Info "Checking User Account Control (UAC) settings..."
$uacCheck = Test-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorAdmin" -ExpectedValue 2
$status = if ($uacCheck.Value -ge 1) { 'Pass' } else { 'Fail' }
Add-AuditCheck -Category "Access Control" -CheckName "UAC Admin Consent Prompt" `
    -Status $status -CurrentValue $uacCheck.Value `
    -RecommendedValue "2 (Prompt for consent)" -Risk "High" -Impact "Medium" `
    -Reference "CIS 2.3.17.1" `
    -Description "UAC prevents unauthorized changes by prompting for admin credentials. Disabling it allows malware to run with elevated privileges silently." `
    -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2"

# Check 5: Secure Boot
Write-Info "Checking Secure Boot status..."
try {
    $secureBootEnabled = Confirm-SecureBootUEFI
    $status = if ($secureBootEnabled) { 'Pass' } else { 'Fail' }
    Add-AuditCheck -Category "Boot Security" -CheckName "Secure Boot" `
        -Status $status -CurrentValue $secureBootEnabled `
        -RecommendedValue "True" -Risk "High" -Impact "Low" `
        -Reference "ACSC High Priority" `
        -Description "Secure Boot prevents bootkits and rootkits by only allowing signed bootloaders. Essential for protecting against firmware-level attacks." `
        -Remediation "Enable in UEFI/BIOS settings. Requires UEFI mode (not legacy BIOS)."
}
catch {
    Add-AuditCheck -Category "Boot Security" -CheckName "Secure Boot" `
        -Status "N/A" -CurrentValue "Not supported or unable to check" `
        -RecommendedValue "True" -Risk "High" -Impact "Low" `
        -Reference "ACSC High Priority" `
        -Description "Secure Boot prevents bootkits and rootkits by only allowing signed bootloaders." `
        -Remediation "Check UEFI/BIOS settings. System may be in legacy BIOS mode."
}

# Check 6: SMBv1 Protocol
Write-Info "Checking SMBv1 protocol status..."
try {
    $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($null -ne $smbv1) {
        $status = if ($smbv1.State -eq 'Disabled') { 'Pass' } else { 'Fail' }
        Add-AuditCheck -Category "Network Security" -CheckName "SMBv1 Protocol Disabled" `
            -Status $status -CurrentValue $smbv1.State `
            -RecommendedValue "Disabled" -Risk "High" -Impact "Low" `
            -Reference "MS Baseline" `
            -Description "SMBv1 has critical vulnerabilities (EternalBlue/WannaCry). Microsoft deprecated it in 2014. Must be disabled." `
            -Remediation "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
    }
}
catch {
    Add-AuditCheck -Category "Network Security" -CheckName "SMBv1 Protocol Disabled" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "Disabled" -Risk "High" -Impact "Low" `
        -Reference "MS Baseline" `
        -Description "SMBv1 has critical vulnerabilities (EternalBlue/WannaCry). Must be disabled." `
        -Remediation "Run Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
}

# Check 6b: SMB Signing (NEW - 2025 requirement)
Write-Info "Checking SMB Signing configuration..."
try {
    $smbServerConfig = Get-SmbServerConfiguration
    $smbClientConfig = Get-SmbClientConfiguration

    # Server-side signing
    $serverSigningStatus = if ($smbServerConfig.RequireSecuritySignature) { 'Pass' } else { 'Warning' }
    Add-AuditCheck -Category "Network Security" -CheckName "SMB Server Signing Required" `
        -Status $serverSigningStatus -CurrentValue $smbServerConfig.RequireSecuritySignature `
        -RecommendedValue "True" -Risk "High" -Impact "Low" `
        -Reference "CIS 2.3.9.2" `
        -Description "SMB signing prevents man-in-the-middle attacks. Required by default in Windows 11 24H2." `
        -Remediation "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"

    # Client-side signing
    $clientSigningStatus = if ($smbClientConfig.RequireSecuritySignature) { 'Pass' } else { 'Warning' }
    Add-AuditCheck -Category "Network Security" -CheckName "SMB Client Signing Required" `
        -Status $clientSigningStatus -CurrentValue $smbClientConfig.RequireSecuritySignature `
        -RecommendedValue "True" -Risk "High" -Impact "Low" `
        -Reference "CIS 2.3.9.1" `
        -Description "SMB client signing ensures server authenticity and prevents relay attacks." `
        -Remediation "Set-SmbClientConfiguration -RequireSecuritySignature `$true -Force"
}
catch {
    Add-AuditCheck -Category "Network Security" -CheckName "SMB Signing Configuration" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "Required" -Risk "High" -Impact "Low" `
        -Reference "CIS 2.3.9" `
        -Description "SMB signing prevents man-in-the-middle and relay attacks." `
        -Remediation "Run Get-SmbServerConfiguration and Get-SmbClientConfiguration"
}

# Check 6c: LSA Protection (NEW)
Write-Info "Checking LSA Protection status..."
$lsaCheck = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" -ExpectedValue 1
# Value 1 = Enabled, Value 2 = Enabled with UEFI lock (stronger)
$lsaStatus = if ($lsaCheck.Value -ge 1) { 'Pass' } else { 'Fail' }
$lsaDesc = if ($lsaCheck.Value -eq 2) { "2 (Enabled + UEFI Lock)" } elseif ($lsaCheck.Value -eq 1) { "1 (Enabled)" } else { $lsaCheck.Value }
Add-AuditCheck -Category "Credential Protection" -CheckName "LSA Protection (RunAsPPL)" `
    -Status $lsaStatus -CurrentValue $lsaDesc `
    -RecommendedValue "1+ (Enabled)" -Risk "High" -Impact "Low" `
    -Reference "MS Baseline" `
    -Description "LSA Protection prevents credential theft tools like Mimikatz from accessing LSASS memory." `
    -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord"

# Check 6d: Attack Surface Reduction (ASR) Rules (NEW)
Write-Info "Checking Attack Surface Reduction (ASR) rules..."
try {
    $asrRules = (Get-MpPreference).AttackSurfaceReductionRules_Ids
    if ($null -ne $asrRules -and $asrRules.Count -gt 0) {
        Add-AuditCheck -Category "Exploit Protection" -CheckName "Attack Surface Reduction (ASR) Rules" `
            -Status "Pass" -CurrentValue "$($asrRules.Count) rules configured" `
            -RecommendedValue "Multiple rules enabled" -Risk "High" -Impact "Medium" `
            -Reference "ACSC" `
            -Description "ASR rules block common attack techniques like Office macro abuse, script execution, and credential theft." `
            -Remediation "Configure via Group Policy or: Add-MpPreference -AttackSurfaceReductionRules_Ids <GUID> -AttackSurfaceReductionRules_Actions Enabled"
    } else {
        Add-AuditCheck -Category "Exploit Protection" -CheckName "Attack Surface Reduction (ASR) Rules" `
            -Status "Warning" -CurrentValue "No rules configured" `
            -RecommendedValue "Multiple rules enabled" -Risk "High" -Impact "Medium" `
            -Reference "ACSC" `
            -Description "ASR rules block common attack techniques. Recommended by ACSC and Microsoft for all enterprise systems." `
            -Remediation "See: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference"
    }
}
catch {
    Add-AuditCheck -Category "Exploit Protection" -CheckName "Attack Surface Reduction (ASR) Rules" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "Multiple rules enabled" -Risk "High" -Impact "Medium" `
        -Reference "ACSC" `
        -Description "ASR rules block common attack techniques like Office macro abuse and script execution." `
        -Remediation "Run Get-MpPreference to check ASR configuration"
}

# ===== MEDIUM PRIORITY CHECKS =====

Write-Header "MEDIUM PRIORITY SECURITY CHECKS"

# Check 7: Account Lockout Policy
Write-Info "Checking account lockout policies..."
try {
    $lockoutThreshold = (net accounts | Select-String "Lockout threshold").ToString().Split(':')[1].Trim()
    $status = if ($lockoutThreshold -ne "Never" -and [int]$lockoutThreshold -le 10) { 'Pass' } else { 'Fail' }
    Add-AuditCheck -Category "Account Policy" -CheckName "Account Lockout Threshold" `
        -Status $status -CurrentValue $lockoutThreshold `
        -RecommendedValue "5-10 attempts" -Risk "Medium" -Impact "Low" `
        -Reference "CIS 1.2.1" `
        -Description "Account lockout prevents brute-force password attacks. Domain-joined systems inherit this from Group Policy." `
        -Remediation "net accounts /lockoutthreshold:5 (or configure via Group Policy for domain systems)"
}
catch {
    Add-AuditCheck -Category "Account Policy" -CheckName "Account Lockout Threshold" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "5-10 attempts" -Risk "Medium" -Impact "Low" `
        -Reference "CIS 1.2.1" `
        -Description "Account lockout prevents brute-force password attacks." `
        -Remediation "Run 'net accounts' to view current settings"
}

# Check 8: Password Policy
Write-Info "Checking password complexity requirements..."
$passwordCheck = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
    -Name "RequireStrongKey" -ExpectedValue 1
Add-AuditCheck -Category "Account Policy" -CheckName "Password Complexity" `
    -Status $passwordCheck.Result -CurrentValue $passwordCheck.Value `
    -RecommendedValue "1 (Enabled)" -Risk "Medium" -Impact "Low" `
    -Reference "CIS 1.1" `
    -Description "Strong password keys ensure secure authentication between domain members. Weak keys can be exploited." `
    -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireStrongKey' -Value 1"

# Check 9: Remote Desktop
Write-Info "Checking Remote Desktop configuration..."
$rdpCheck = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections" -ExpectedValue 1
$status = if ($rdpCheck.Value -eq 1) { 'Pass' } else { 'Warning' }
Add-AuditCheck -Category "Remote Access" -CheckName "Remote Desktop Disabled" `
    -Status $status -CurrentValue $(if($rdpCheck.Value -eq 1){"Disabled"}else{"Enabled"}) `
    -RecommendedValue "Disabled (unless needed)" -Risk "Medium" -Impact "Medium" `
    -Reference "CIS 18.9.62" `
    -Description "RDP is a common attack vector for ransomware. Disable if not required, or restrict with Network Level Authentication (NLA)." `
    -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1"

# Check 10: Guest Account
Write-Info "Checking Guest account status..."
try {
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($null -ne $guestAccount) {
        $status = if (-not $guestAccount.Enabled) { 'Pass' } else { 'Fail' }
        Add-AuditCheck -Category "Account Security" -CheckName "Guest Account Disabled" `
            -Status $status -CurrentValue $guestAccount.Enabled `
            -RecommendedValue "False (Disabled)" -Risk "Medium" -Impact "Low" `
            -Reference "CIS 2.3.1" `
            -Description "Guest account allows anonymous access. Should always be disabled to prevent unauthorized access." `
            -Remediation "Disable-LocalUser -Name 'Guest'"
    }
}
catch {
    Add-AuditCheck -Category "Account Security" -CheckName "Guest Account Disabled" `
        -Status "N/A" -CurrentValue "Unable to check" `
        -RecommendedValue "False (Disabled)" -Risk "Medium" -Impact "Low" `
        -Reference "CIS 2.3.1" `
        -Description "Guest account allows anonymous access." `
        -Remediation "Run Get-LocalUser -Name Guest"
}

# Check 11: Windows Update Settings
Write-Info "Checking Windows Update configuration..."
$updateCheck = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "NoAutoUpdate" -ExpectedValue 0
$status = if ($updateCheck.Value -eq 0 -or $updateCheck.Value -eq 'Not Set') { 'Pass' } else { 'Fail' }
Add-AuditCheck -Category "Update Management" -CheckName "Automatic Windows Updates" `
    -Status $status -CurrentValue $updateCheck.Value `
    -RecommendedValue "0 (Enabled)" -Risk "Medium" -Impact "Low" `
    -Reference "CIS 18.9.108" `
    -Description "Automatic updates ensure security patches are applied promptly. Delayed patching is a top cause of breaches." `
    -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Value 0"

# Check 12: PowerShell Script Block Logging
Write-Info "Checking PowerShell Script Block logging configuration..."
$psLogging = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -ExpectedValue 1
Add-AuditCheck -Category "Auditing" -CheckName "PowerShell Script Block Logging" `
    -Status $psLogging.Result -CurrentValue $psLogging.Value `
    -RecommendedValue "1 (Enabled)" -Risk "Medium" -Impact "Low" `
    -Reference "MS Baseline" `
    -Description "Script Block Logging records all PowerShell code execution (Event ID 4104), including de-obfuscated malicious scripts." `
    -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1"

# Check 12b: PowerShell Module Logging (NEW)
Write-Info "Checking PowerShell Module logging configuration..."
$psModuleLogging = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
    -Name "EnableModuleLogging" -ExpectedValue 1
Add-AuditCheck -Category "Auditing" -CheckName "PowerShell Module Logging" `
    -Status $psModuleLogging.Result -CurrentValue $psModuleLogging.Value `
    -RecommendedValue "1 (Enabled)" -Risk "Medium" -Impact "Low" `
    -Reference "Mandiant" `
    -Description "Module Logging records pipeline execution details (Event ID 4103). Complements Script Block Logging for full visibility." `
    -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 1"

# Check 12c: PowerShell Transcription (NEW)
Write-Info "Checking PowerShell Transcription configuration..."
$psTranscription = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
    -Name "EnableTranscripting" -ExpectedValue 1
Add-AuditCheck -Category "Auditing" -CheckName "PowerShell Transcription" `
    -Status $psTranscription.Result -CurrentValue $psTranscription.Value `
    -RecommendedValue "1 (Enabled)" -Risk "Medium" -Impact "Low" `
    -Reference "Mandiant" `
    -Description "Transcription creates text files of all PowerShell sessions. Provides forensic evidence of attacker commands." `
    -Remediation "New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Force; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Value 1"

# Check 12d: NTLM Restrictions (NEW)
Write-Info "Checking NTLM restrictions..."
$ntlmCheck = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "RestrictSendingNTLMTraffic" -ExpectedValue 2
$ntlmStatus = if ($ntlmCheck.Value -ge 1) { 'Pass' } elseif ($ntlmCheck.Value -eq 'Not Set') { 'Warning' } else { 'Fail' }
Add-AuditCheck -Category "Authentication" -CheckName "NTLM Traffic Restrictions" `
    -Status $ntlmStatus -CurrentValue $ntlmCheck.Value `
    -RecommendedValue "2 (Deny all)" -Risk "Medium" -Impact "Medium" `
    -Reference "CIS 2.3.11" `
    -Description "NTLM is vulnerable to relay attacks. Microsoft is deprecating NTLM in 2025. Restrict or disable where possible." `
    -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic' -Value 2"

# ===== LOW PRIORITY / INFORMATIONAL CHECKS =====

Write-Header "LOW PRIORITY / INFORMATIONAL CHECKS"

# Check 13: Controlled Folder Access (NEW - Ransomware Protection)
Write-Info "Checking Controlled Folder Access (Ransomware Protection)..."
try {
    $cfa = (Get-MpPreference).EnableControlledFolderAccess
    $status = if ($cfa -eq 1) { 'Pass' } else { 'Warning' }
    Add-AuditCheck -Category "Ransomware Protection" -CheckName "Controlled Folder Access" `
        -Status $status -CurrentValue $(if($cfa -eq 1){"Enabled"}elseif($cfa -eq 2){"Audit Mode"}else{"Disabled"}) `
        -RecommendedValue "Enabled" -Risk "Medium" -Impact "Medium" `
        -Reference "MS Baseline" `
        -Description "Controlled Folder Access blocks unauthorized apps from modifying protected folders (Documents, Pictures, etc.). Key ransomware defense." `
        -Remediation "Set-MpPreference -EnableControlledFolderAccess Enabled"
}
catch {
    Add-AuditCheck -Category "Ransomware Protection" -CheckName "Controlled Folder Access" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "Enabled" -Risk "Medium" -Impact "Medium" `
        -Reference "MS Baseline" `
        -Description "Controlled Folder Access blocks ransomware from encrypting user files." `
        -Remediation "Run Get-MpPreference to check EnableControlledFolderAccess"
}

# Check 13b: Windows Defender PUA Protection
Write-Info "Checking Potentially Unwanted Application (PUA) protection..."
try {
    $pua = (Get-MpPreference).PUAProtection
    $status = if ($pua -eq 1) { 'Pass' } else { 'Warning' }
    Add-AuditCheck -Category "Antivirus" -CheckName "PUA Protection" `
        -Status $status -CurrentValue $pua `
        -RecommendedValue "1 (Enabled)" -Risk "Low" -Impact "Low" `
        -Reference "MS Recommended" `
        -Description "PUA protection blocks adware, bundleware, and other unwanted software that degrades system performance." `
        -Remediation "Set-MpPreference -PUAProtection Enabled"
}
catch {
    Add-AuditCheck -Category "Antivirus" -CheckName "PUA Protection" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "1 (Enabled)" -Risk "Low" -Impact "Low" `
        -Reference "MS Recommended" `
        -Description "PUA protection blocks adware and bundleware." `
        -Remediation "Run Get-MpPreference"
}

# Check 14: File Extension Visibility
Write-Info "Checking file extension visibility..."
$extensionCheck = Test-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
    -Name "HideFileExt" -ExpectedValue 0
Add-AuditCheck -Category "User Experience" -CheckName "Show File Extensions" `
    -Status $extensionCheck.Result -CurrentValue $extensionCheck.Value `
    -RecommendedValue "0 (Show extensions)" -Risk "Low" -Impact "Low" `
    -Reference "ACSC Low Priority" `
    -Description "Hidden extensions help attackers disguise malware (e.g., 'invoice.pdf.exe' appears as 'invoice.pdf')." `
    -Remediation "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Value 0"

# Check 15: Telemetry Level
Write-Info "Checking telemetry/diagnostic data settings..."
$telemetryCheck = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
    -Name "AllowTelemetry" -ExpectedValue 1
$status = if ($telemetryCheck.Value -le 1) { 'Pass' } elseif ($telemetryCheck.Value -le 2) { 'Warning' } else { 'Fail' }
Add-AuditCheck -Category "Privacy" -CheckName "Telemetry Level" `
    -Status $status -CurrentValue $telemetryCheck.Value `
    -RecommendedValue "0-1 (Security/Basic)" -Risk "Low" -Impact "Low" `
    -Reference "Privacy" `
    -Description "Higher telemetry levels send more data to Microsoft. Security (0) or Basic (1) recommended for enterprise." `
    -Remediation "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 1"

# Check 16: Credential Guard
Write-Info "Checking Credential Guard status..."
try {
    $credGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($null -ne $credGuard) {
        $status = if ($credGuard.SecurityServicesRunning -contains 1) { 'Pass' } else { 'Warning' }
        Add-AuditCheck -Category "Credential Protection" -CheckName "Credential Guard" `
            -Status $status -CurrentValue $credGuard.SecurityServicesRunning `
            -RecommendedValue "Running (if hardware supports)" -Risk "Medium" -Impact "Low" `
            -Reference "MS Baseline" `
            -Description "Credential Guard uses virtualization to protect NTLM hashes and Kerberos tickets from theft (Pass-the-Hash attacks)." `
            -Remediation "Enable via Group Policy: Computer Config > Admin Templates > System > Device Guard > Turn On Virtualization Based Security"
    } else {
        Add-AuditCheck -Category "Credential Protection" -CheckName "Credential Guard" `
            -Status "N/A" -CurrentValue "Not supported" `
            -RecommendedValue "Running (if hardware supports)" -Risk "Medium" -Impact "Low" `
            -Reference "MS Baseline" `
            -Description "Credential Guard requires UEFI, Secure Boot, and virtualization support (VT-x/AMD-V)." `
            -Remediation "Check hardware compatibility: Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"
    }
}
catch {
    Add-AuditCheck -Category "Credential Protection" -CheckName "Credential Guard" `
        -Status "N/A" -CurrentValue "Unable to check" `
        -RecommendedValue "Running (if hardware supports)" -Risk "Medium" -Impact "Low" `
        -Reference "MS Baseline" `
        -Description "Credential Guard protects credentials using virtualization-based security." `
        -Remediation "Requires Windows Enterprise/Education edition and compatible hardware"
}

# Check 17: Memory Integrity (Core Isolation)
Write-Info "Checking Memory Integrity/Core Isolation..."
$memIntegrityCheck = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" `
    -Name "Enabled" -ExpectedValue 1
Add-AuditCheck -Category "System Security" -CheckName "Memory Integrity (HVCI)" `
    -Status $memIntegrityCheck.Result -CurrentValue $memIntegrityCheck.Value `
    -RecommendedValue "1 (Enabled)" -Risk "Medium" -Impact "Low" `
    -Reference "MS Baseline" `
    -Description "Memory Integrity (HVCI) prevents malicious code injection into kernel-mode drivers. Blocks kernel exploits." `
    -Remediation "Settings > Privacy & Security > Windows Security > Device Security > Core isolation > Memory integrity: On"

# Check 18: Admin Account Usage
Write-Info "Checking if running as standard user (best practice)..."
try {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name

    # This script requires admin, so we check if the user's account is in Administrators group
    $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    $userIsAdmin = $adminGroup | Where-Object { $_.Name -eq $currentUser }

    $status = if ($null -eq $userIsAdmin) { 'Pass' } else { 'Warning' }
    Add-AuditCheck -Category "User Account" -CheckName "Using Standard User Account for Daily Work" `
        -Status $status -CurrentValue $(if($userIsAdmin){"Admin"}else{"Standard"}) `
        -RecommendedValue "Standard User (Non-Admin)" -Risk "High" -Impact "High" `
        -Reference "Best Practice" `
        -Description "Running as admin daily increases attack surface. Malware inherits admin privileges. Use standard account and elevate only when needed." `
        -Remediation "Create a separate admin account. Remove daily-use account from Administrators group."
}
catch {
    Add-AuditCheck -Category "User Account" -CheckName "Using Standard User Account" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "Standard User (Non-Admin)" -Risk "High" -Impact "High" `
        -Reference "Best Practice" `
        -Description "Running as admin daily increases attack surface." `
        -Remediation "Check group membership: Get-LocalGroupMember -Group Administrators"
}

# Check 19: Windows Hello / PIN (NEW)
Write-Info "Checking Windows Hello configuration..."
try {
    $helloPath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions"
    if (Test-Path $helloPath) {
        Add-AuditCheck -Category "Authentication" -CheckName "Windows Hello Available" `
            -Status "Pass" -CurrentValue "Configured" `
            -RecommendedValue "Enabled" -Risk "Low" -Impact "Low" `
            -Reference "MS Baseline" `
            -Description "Windows Hello provides phishing-resistant authentication using biometrics or PIN tied to device hardware." `
            -Remediation "Settings > Accounts > Sign-in options > Set up Windows Hello PIN/Face/Fingerprint"
    } else {
        Add-AuditCheck -Category "Authentication" -CheckName "Windows Hello Available" `
            -Status "Warning" -CurrentValue "Not configured" `
            -RecommendedValue "Enabled" -Risk "Low" -Impact "Low" `
            -Reference "MS Baseline" `
            -Description "Windows Hello is recommended by NIST for phishing-resistant MFA." `
            -Remediation "Settings > Accounts > Sign-in options > Set up Windows Hello"
    }
}
catch {
    Add-AuditCheck -Category "Authentication" -CheckName "Windows Hello Available" `
        -Status "N/A" -CurrentValue "Unable to check" `
        -RecommendedValue "Enabled" -Risk "Low" -Impact "Low" `
        -Reference "MS Baseline" `
        -Description "Windows Hello provides phishing-resistant authentication." `
        -Remediation "Check Settings > Accounts > Sign-in options"
}

# Check 20: Print Spooler Service (NEW - PrintNightmare)
Write-Info "Checking Print Spooler service status..."
try {
    $spooler = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
    if ($null -ne $spooler) {
        # If not needed for printing, should be disabled (PrintNightmare CVEs)
        $status = if ($spooler.Status -eq 'Stopped' -and $spooler.StartType -eq 'Disabled') { 'Pass' } else { 'Warning' }
        Add-AuditCheck -Category "Service Security" -CheckName "Print Spooler Service" `
            -Status $status -CurrentValue "$($spooler.Status) ($($spooler.StartType))" `
            -RecommendedValue "Disabled (if not printing)" -Risk "Medium" -Impact "Medium" `
            -Reference "CVE-2021-34527" `
            -Description "Print Spooler has critical vulnerabilities (PrintNightmare). Disable on systems that don't need printing, especially servers." `
            -Remediation "Stop-Service -Name Spooler -Force; Set-Service -Name Spooler -StartupType Disabled"
    }
}
catch {
    Add-AuditCheck -Category "Service Security" -CheckName "Print Spooler Service" `
        -Status "N/A" -CurrentValue "Unable to check" `
        -RecommendedValue "Disabled (if not printing)" -Risk "Medium" -Impact "Medium" `
        -Reference "CVE-2021-34527" `
        -Description "Print Spooler has been exploited in multiple critical vulnerabilities." `
        -Remediation "Run Get-Service -Name Spooler"
}

# Check 21: Administrative Shares (NEW)
Write-Info "Checking administrative shares..."
try {
    $adminShares = Get-SmbShare | Where-Object { $_.Name -match '^\w\$$|^ADMIN\$$|^IPC\$$' }
    $shareCount = ($adminShares | Measure-Object).Count
    $status = if ($shareCount -eq 0) { 'Pass' } else { 'Warning' }
    Add-AuditCheck -Category "Network Security" -CheckName "Administrative Shares" `
        -Status $status -CurrentValue "$shareCount admin shares (C$, ADMIN$, etc.)" `
        -RecommendedValue "Disabled (if not needed)" -Risk "Low" -Impact "Medium" `
        -Reference "CIS 2.3.10" `
        -Description "Admin shares (C$, ADMIN$) allow remote access. Used by lateral movement tools like PsExec. Disable if not required." `
        -Remediation "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks' -Value 0"
}
catch {
    Add-AuditCheck -Category "Network Security" -CheckName "Administrative Shares" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "Disabled (if not needed)" -Risk "Low" -Impact "Medium" `
        -Reference "CIS 2.3.10" `
        -Description "Admin shares allow remote access for system administration." `
        -Remediation "Run Get-SmbShare to view shares"
}

# ===== GENERATE REPORT =====

Write-Header "AUDIT SUMMARY"

Write-Host "`nSystem Information:" -ForegroundColor Cyan
Write-Host "  Computer Name: $($AuditResults.ComputerName)"
Write-Host "  Windows Version: $($AuditResults.WindowsVersion)"
Write-Host "  Windows Build: $($AuditResults.WindowsBuild)"
Write-Host "  Audit Date: $($AuditResults.Timestamp)"

Write-Host "`nSecurity Posture Summary:" -ForegroundColor Cyan
Write-Host "  Total Checks: $($AuditResults.Summary.Total)"
Write-Success "  Passed: $($AuditResults.Summary.Passed)"
Write-Error "  Failed: $($AuditResults.Summary.Failed)"
Write-Warning "  Warnings: $($AuditResults.Summary.Warning)"
Write-Host "  Not Applicable: $($AuditResults.Summary.NotApplicable)" -ForegroundColor Gray

$passRate = [math]::Round(($AuditResults.Summary.Passed / $AuditResults.Summary.Total) * 100, 1)
Write-Host "`n  Overall Pass Rate: $passRate%" -ForegroundColor $(if($passRate -ge 80){'Green'}elseif($passRate -ge 60){'Yellow'}else{'Red'})

# High risk failures
$highRiskFails = $AuditResults.Checks | Where-Object { $_.Risk -eq 'High' -and $_.Status -eq 'Fail' }
if ($highRiskFails.Count -gt 0) {
    Write-Host "`n[!] HIGH RISK ITEMS REQUIRING ATTENTION:" -ForegroundColor Red
    $highRiskFails | ForEach-Object {
        Write-Host "  - $($_.CheckName): Current=$($_.CurrentValue), Recommended=$($_.RecommendedValue)" -ForegroundColor Red
    }
}

# Export results
switch ($OutputFormat) {
    'JSON' {
        $jsonPath = "$OutputPath.json"
        $AuditResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Info "`nJSON report saved to: $jsonPath"
    }
    'CSV' {
        $csvPath = "$OutputPath.csv"
        $AuditResults.Checks | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Info "`nCSV report saved to: $csvPath"
    }
    'HTML' {
        $htmlPath = "$OutputPath.html"
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows 11 Security Audit - $($AuditResults.ComputerName)</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #0078d4; }
        h2 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
        .summary { background: white; padding: 20px; border-radius: 5px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stats { display: flex; gap: 20px; flex-wrap: wrap; }
        .stat { padding: 15px; border-radius: 5px; min-width: 120px; text-align: center; }
        .pass { background: #d4edda; color: #155724; }
        .fail { background: #f8d7da; color: #721c24; }
        .warning { background: #fff3cd; color: #856404; }
        .na { background: #e9ecef; color: #6c757d; }
        table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 30px; }
        th { background: #0078d4; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; vertical-align: top; }
        tr:hover { background: #f0f7ff; }
        .status-pass { color: #28a745; font-weight: bold; }
        .status-fail { color: #dc3545; font-weight: bold; }
        .status-warning { color: #ff8c00; font-weight: bold; }
        .status-na { color: #6c757d; }
        .risk-high { color: #dc3545; font-weight: bold; }
        .risk-medium { color: #ff8c00; }
        .risk-low { color: #6c757d; }
        .description { font-size: 0.9em; color: #666; margin-top: 5px; }
        .remediation { font-size: 0.85em; background: #f8f9fa; padding: 8px; border-radius: 4px; margin-top: 8px; font-family: 'Consolas', 'Courier New', monospace; border-left: 3px solid #0078d4; }
        .remediation-section { background: white; padding: 20px; border-radius: 5px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .remediation-item { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .remediation-item.high { border-left: 4px solid #dc3545; }
        .remediation-item.medium { border-left: 4px solid #ff8c00; }
        .remediation-item h4 { margin: 0 0 10px 0; color: #333; }
        .remediation-item code { background: #f4f4f4; padding: 10px; display: block; border-radius: 4px; overflow-x: auto; }
        .toc { background: white; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .toc a { color: #0078d4; text-decoration: none; }
        .toc a:hover { text-decoration: underline; }
        .version { font-size: 0.8em; color: #666; }
    </style>
</head>
<body>
    <h1>Windows 11 Security Audit Report</h1>
    <p class="version">Generated by Defensive Toolkit v2.0.0 | CIS Benchmark v4.0.0 | ACSC Guidelines (September 2025)</p>

    <div class="toc">
        <strong>Quick Navigation:</strong>
        <a href="#summary">Summary</a> |
        <a href="#results">Detailed Results</a> |
        <a href="#remediation">Remediation Guide</a>
    </div>

    <div class="summary" id="summary">
        <h2>System Information</h2>
        <p><strong>Computer:</strong> $($AuditResults.ComputerName)</p>
        <p><strong>Windows Version:</strong> $($AuditResults.WindowsVersion)</p>
        <p><strong>Build:</strong> $($AuditResults.WindowsBuild)</p>
        <p><strong>Audit Date:</strong> $($AuditResults.Timestamp)</p>

        <h2>Summary</h2>
        <div class="stats">
            <div class="stat pass"><h3>$($AuditResults.Summary.Passed)</h3><p>Passed</p></div>
            <div class="stat fail"><h3>$($AuditResults.Summary.Failed)</h3><p>Failed</p></div>
            <div class="stat warning"><h3>$($AuditResults.Summary.Warning)</h3><p>Warnings</p></div>
            <div class="stat na"><h3>$($AuditResults.Summary.NotApplicable)</h3><p>N/A</p></div>
        </div>
        <p><strong>Overall Pass Rate:</strong> <span style="font-size: 1.5em; color: $(if($passRate -ge 80){'#28a745'}elseif($passRate -ge 60){'#ff8c00'}else{'#dc3545'});">$passRate%</span></p>
    </div>

    <h2 id="results">Detailed Results</h2>
    <table>
        <tr>
            <th style="width: 12%;">Category</th>
            <th style="width: 25%;">Check Name</th>
            <th style="width: 8%;">Status</th>
            <th style="width: 15%;">Current</th>
            <th style="width: 15%;">Recommended</th>
            <th style="width: 8%;">Risk</th>
            <th style="width: 17%;">Why It Matters</th>
        </tr>
"@
        foreach ($check in $AuditResults.Checks) {
            $statusClass = switch ($check.Status) {
                'Pass' { 'status-pass' }
                'Fail' { 'status-fail' }
                'Warning' { 'status-warning' }
                default { 'status-na' }
            }
            $riskClass = "risk-$($check.Risk.ToLower())"
            $descText = if ($check.Description) { $check.Description } else { "-" }
            $html += @"
        <tr>
            <td>$($check.Category)</td>
            <td><strong>$($check.CheckName)</strong><br><small style="color:#666;">$($check.Reference)</small></td>
            <td class="$statusClass">$($check.Status)</td>
            <td><code>$($check.CurrentValue)</code></td>
            <td><code>$($check.RecommendedValue)</code></td>
            <td class="$riskClass">$($check.Risk)</td>
            <td style="font-size: 0.9em;">$descText</td>
        </tr>
"@
        }
        $html += @"
    </table>

    <div class="remediation-section" id="remediation">
        <h2>Remediation Guide</h2>
        <p>The following items require attention. Commands are provided for PowerShell (run as Administrator).</p>
"@
        # Add remediation items for failed/warning checks
        $needsRemediation = $AuditResults.Checks | Where-Object { $_.Status -in @('Fail', 'Warning') -and $_.Remediation }
        foreach ($check in $needsRemediation) {
            $priorityClass = $check.Risk.ToLower()
            $html += @"
        <div class="remediation-item $priorityClass">
            <h4>[$($check.Risk.ToUpper())] $($check.CheckName)</h4>
            <p><strong>Current:</strong> $($check.CurrentValue) | <strong>Recommended:</strong> $($check.RecommendedValue)</p>
            <p>$($check.Description)</p>
            <code>$($check.Remediation)</code>
        </div>
"@
        }
        $html += @"
    </div>

    <div class="summary">
        <h2>Next Steps</h2>
        <ol>
            <li>Review the remediation guide above and prioritize HIGH risk items</li>
            <li>Run <code>backup-security-settings.ps1</code> before making changes</li>
            <li>Apply remediations starting with HIGH priority items</li>
            <li>Re-run this audit to verify improvements</li>
        </ol>
        <p><strong>References:</strong></p>
        <ul>
            <li><a href="https://www.cisecurity.org/cis-benchmarks" target="_blank">CIS Benchmarks</a></li>
            <li><a href="https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines" target="_blank">Microsoft Security Baselines</a></li>
            <li><a href="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/small-business-cyber-security/small-business-cloud-security-guides/technical-example-hardening-microsoft-windows-11-workstations" target="_blank">ACSC Windows 11 Hardening Guide</a></li>
        </ul>
    </div>
</body>
</html>
"@
        $html | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Info "`nHTML report saved to: $htmlPath"
    }
    'Console' {
        Write-Info "`nDetailed results displayed above. Use -OutputFormat JSON/CSV/HTML to export."
    }
}

Write-Host "`n[i] Next steps:" -ForegroundColor Cyan
Write-Host "  1. Review failed checks and warnings above"
Write-Host "  2. Run backup-security-settings.ps1 before making changes"
Write-Host "  3. Apply hardening: harden-level1-safe.ps1 (coming soon)"
Write-Host "  4. Re-run this audit to verify improvements`n"
