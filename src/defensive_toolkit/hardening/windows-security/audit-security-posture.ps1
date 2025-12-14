# Windows 11 Security Posture Audit Script
# Checks current security configuration against CIS Benchmark and Microsoft Baseline recommendations
# Author: David Dashti
# Date: October 2025
#
# USAGE:
#   Run as Administrator: .\audit-security-posture.ps1
#   Generate HTML report: .\audit-security-posture.ps1 -OutputFormat HTML
#   Export to JSON: .\audit-security-posture.ps1 -OutputFormat JSON

#Requires -Version 7.0
#Requires -RunAsAdministrator

param(
    [Parameter()]
    [ValidateSet('Console', 'JSON', 'HTML', 'CSV')]
    [string]$OutputFormat = 'Console',

    [Parameter()]
    [string]$OutputPath = "$PSScriptRoot\audit-results-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
)

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
        [string]$Reference
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
    }

    $AuditResults.Checks += $check
    $AuditResults.Summary.Total++

    switch ($Status) {
        'Pass' { $AuditResults.Summary.Passed++; Write-Success "$CheckName - PASS" }
        'Fail' { $AuditResults.Summary.Failed++; Write-Error "$CheckName - FAIL" }
        'Warning' { $AuditResults.Summary.Warning++; Write-Warning "$CheckName - WARNING" }
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
            -Reference "CIS 18.10.9.1"
    } else {
        Add-AuditCheck -Category "Encryption" -CheckName "BitLocker System Drive Encryption" `
            -Status "N/A" -CurrentValue "BitLocker not available" `
            -RecommendedValue "On" -Risk "High" -Impact "Low" `
            -Reference "CIS 18.10.9.1"
    }
}
catch {
    Add-AuditCheck -Category "Encryption" -CheckName "BitLocker System Drive Encryption" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "On" -Risk "High" -Impact "Low" `
        -Reference "CIS 18.10.9.1"
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
        -Reference "MS Baseline"

    $cloudStatus = if ($defender.MAPSReporting -gt 0) { 'Pass' } else { 'Warning' }
    Add-AuditCheck -Category "Antivirus" -CheckName "Windows Defender Cloud Protection" `
        -Status $cloudStatus -CurrentValue $defender.MAPSReporting `
        -RecommendedValue "2 (Advanced)" -Risk "Medium" -Impact "Low" `
        -Reference "MS Baseline"
}
catch {
    Add-AuditCheck -Category "Antivirus" -CheckName "Windows Defender Status" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "Enabled" -Risk "High" -Impact "Low" `
        -Reference "MS Baseline"
}

# Check 3: Windows Firewall Status
Write-Info "Checking Windows Firewall status..."
foreach ($profile in @('Domain', 'Public', 'Private')) {
    try {
        $fwProfile = Get-NetFirewallProfile -Name $profile
        $status = if ($fwProfile.Enabled) { 'Pass' } else { 'Fail' }
        Add-AuditCheck -Category "Firewall" -CheckName "Windows Firewall ($profile Profile)" `
            -Status $status -CurrentValue $fwProfile.Enabled `
            -RecommendedValue "True" -Risk "High" -Impact "Low" `
            -Reference "CIS 9.1"
    }
    catch {
        Add-AuditCheck -Category "Firewall" -CheckName "Windows Firewall ($profile Profile)" `
            -Status "Warning" -CurrentValue "Unable to check" `
            -RecommendedValue "True" -Risk "High" -Impact "Low" `
            -Reference "CIS 9.1"
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
    -Reference "CIS 2.3.17.1"

# Check 5: Secure Boot
Write-Info "Checking Secure Boot status..."
try {
    $secureBootEnabled = Confirm-SecureBootUEFI
    $status = if ($secureBootEnabled) { 'Pass' } else { 'Fail' }
    Add-AuditCheck -Category "Boot Security" -CheckName "Secure Boot" `
        -Status $status -CurrentValue $secureBootEnabled `
        -RecommendedValue "True" -Risk "High" -Impact "Low" `
        -Reference "ACSC High Priority"
}
catch {
    Add-AuditCheck -Category "Boot Security" -CheckName "Secure Boot" `
        -Status "N/A" -CurrentValue "Not supported or unable to check" `
        -RecommendedValue "True" -Risk "High" -Impact "Low" `
        -Reference "ACSC High Priority"
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
            -Reference "MS Baseline"
    }
}
catch {
    Add-AuditCheck -Category "Network Security" -CheckName "SMBv1 Protocol Disabled" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "Disabled" -Risk "High" -Impact "Low" `
        -Reference "MS Baseline"
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
        -Reference "CIS 1.2.1"
}
catch {
    Add-AuditCheck -Category "Account Policy" -CheckName "Account Lockout Threshold" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "5-10 attempts" -Risk "Medium" -Impact "Low" `
        -Reference "CIS 1.2.1"
}

# Check 8: Password Policy
Write-Info "Checking password complexity requirements..."
$passwordCheck = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
    -Name "RequireStrongKey" -ExpectedValue 1
Add-AuditCheck -Category "Account Policy" -CheckName "Password Complexity" `
    -Status $passwordCheck.Result -CurrentValue $passwordCheck.Value `
    -RecommendedValue "1 (Enabled)" -Risk "Medium" -Impact "Low" `
    -Reference "CIS 1.1"

# Check 9: Remote Desktop
Write-Info "Checking Remote Desktop configuration..."
$rdpCheck = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections" -ExpectedValue 1
$status = if ($rdpCheck.Value -eq 1) { 'Pass' } else { 'Warning' }
Add-AuditCheck -Category "Remote Access" -CheckName "Remote Desktop Disabled" `
    -Status $status -CurrentValue $(if($rdpCheck.Value -eq 1){"Disabled"}else{"Enabled"}) `
    -RecommendedValue "Disabled (unless needed)" -Risk "Medium" -Impact "Medium" `
    -Reference "CIS 18.9.62"

# Check 10: Guest Account
Write-Info "Checking Guest account status..."
try {
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($null -ne $guestAccount) {
        $status = if (-not $guestAccount.Enabled) { 'Pass' } else { 'Fail' }
        Add-AuditCheck -Category "Account Security" -CheckName "Guest Account Disabled" `
            -Status $status -CurrentValue $guestAccount.Enabled `
            -RecommendedValue "False (Disabled)" -Risk "Medium" -Impact "Low" `
            -Reference "CIS 2.3.1"
    }
}
catch {
    Add-AuditCheck -Category "Account Security" -CheckName "Guest Account Disabled" `
        -Status "N/A" -CurrentValue "Unable to check" `
        -RecommendedValue "False (Disabled)" -Risk "Medium" -Impact "Low" `
        -Reference "CIS 2.3.1"
}

# Check 11: Windows Update Settings
Write-Info "Checking Windows Update configuration..."
$updateCheck = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "NoAutoUpdate" -ExpectedValue 0
$status = if ($updateCheck.Value -eq 0 -or $updateCheck.Value -eq 'Not Set') { 'Pass' } else { 'Fail' }
Add-AuditCheck -Category "Update Management" -CheckName "Automatic Windows Updates" `
    -Status $status -CurrentValue $updateCheck.Value `
    -RecommendedValue "0 (Enabled)" -Risk "Medium" -Impact "Low" `
    -Reference "CIS 18.9.108"

# Check 12: PowerShell Logging
Write-Info "Checking PowerShell logging configuration..."
$psLogging = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -ExpectedValue 1
Add-AuditCheck -Category "Auditing" -CheckName "PowerShell Script Block Logging" `
    -Status $psLogging.Result -CurrentValue $psLogging.Value `
    -RecommendedValue "1 (Enabled)" -Risk "Medium" -Impact "Low" `
    -Reference "MS Baseline"

# ===== LOW PRIORITY / INFORMATIONAL CHECKS =====

Write-Header "LOW PRIORITY / INFORMATIONAL CHECKS"

# Check 13: Windows Defender PUA Protection
Write-Info "Checking Potentially Unwanted Application (PUA) protection..."
try {
    $pua = (Get-MpPreference).PUAProtection
    $status = if ($pua -eq 1) { 'Pass' } else { 'Warning' }
    Add-AuditCheck -Category "Antivirus" -CheckName "PUA Protection" `
        -Status $status -CurrentValue $pua `
        -RecommendedValue "1 (Enabled)" -Risk "Low" -Impact "Low" `
        -Reference "MS Recommended"
}
catch {
    Add-AuditCheck -Category "Antivirus" -CheckName "PUA Protection" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "1 (Enabled)" -Risk "Low" -Impact "Low" `
        -Reference "MS Recommended"
}

# Check 14: File Extension Visibility
Write-Info "Checking file extension visibility..."
$extensionCheck = Test-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
    -Name "HideFileExt" -ExpectedValue 0
Add-AuditCheck -Category "User Experience" -CheckName "Show File Extensions" `
    -Status $extensionCheck.Result -CurrentValue $extensionCheck.Value `
    -RecommendedValue "0 (Show extensions)" -Risk "Low" -Impact "Low" `
    -Reference "ACSC Low Priority"

# Check 15: Telemetry Level
Write-Info "Checking telemetry/diagnostic data settings..."
$telemetryCheck = Test-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
    -Name "AllowTelemetry" -ExpectedValue 1
$status = if ($telemetryCheck.Value -le 1) { 'Pass' } elseif ($telemetryCheck.Value -le 2) { 'Warning' } else { 'Fail' }
Add-AuditCheck -Category "Privacy" -CheckName "Telemetry Level" `
    -Status $status -CurrentValue $telemetryCheck.Value `
    -RecommendedValue "0-1 (Security/Basic)" -Risk "Low" -Impact "Low" `
    -Reference "Privacy"

# Check 16: Credential Guard
Write-Info "Checking Credential Guard status..."
try {
    $credGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($null -ne $credGuard) {
        $status = if ($credGuard.SecurityServicesRunning -contains 1) { 'Pass' } else { 'Warning' }
        Add-AuditCheck -Category "Credential Protection" -CheckName "Credential Guard" `
            -Status $status -CurrentValue $credGuard.SecurityServicesRunning `
            -RecommendedValue "Running (if hardware supports)" -Risk "Medium" -Impact "Low" `
            -Reference "MS Baseline"
    } else {
        Add-AuditCheck -Category "Credential Protection" -CheckName "Credential Guard" `
            -Status "N/A" -CurrentValue "Not supported" `
            -RecommendedValue "Running (if hardware supports)" -Risk "Medium" -Impact "Low" `
            -Reference "MS Baseline"
    }
}
catch {
    Add-AuditCheck -Category "Credential Protection" -CheckName "Credential Guard" `
        -Status "N/A" -CurrentValue "Unable to check" `
        -RecommendedValue "Running (if hardware supports)" -Risk "Medium" -Impact "Low" `
        -Reference "MS Baseline"
}

# Check 17: Memory Integrity (Core Isolation)
Write-Info "Checking Memory Integrity/Core Isolation..."
$memIntegrityCheck = Test-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" `
    -Name "Enabled" -ExpectedValue 1
Add-AuditCheck -Category "System Security" -CheckName "Memory Integrity (HVCI)" `
    -Status $memIntegrityCheck.Result -CurrentValue $memIntegrityCheck.Value `
    -RecommendedValue "1 (Enabled)" -Risk "Medium" -Impact "Low" `
    -Reference "MS Baseline"

# Check 18: Admin Account Usage
Write-Info "Checking if running as standard user (best practice)..."
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name

    # This script requires admin, so we check if the user's account is in Administrators group
    $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    $userIsAdmin = $adminGroup | Where-Object { $_.Name -eq $currentUser }

    $status = if ($null -eq $userIsAdmin) { 'Pass' } else { 'Warning' }
    Add-AuditCheck -Category "User Account" -CheckName "Using Standard User Account for Daily Work" `
        -Status $status -CurrentValue $(if($userIsAdmin){"Admin"}else{"Standard"}) `
        -RecommendedValue "Standard User (Non-Admin)" -Risk "High" -Impact "High" `
        -Reference "Best Practice"
}
catch {
    Add-AuditCheck -Category "User Account" -CheckName "Using Standard User Account" `
        -Status "Warning" -CurrentValue "Unable to check" `
        -RecommendedValue "Standard User (Non-Admin)" -Risk "High" -Impact "High" `
        -Reference "Best Practice"
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
        .summary { background: white; padding: 20px; border-radius: 5px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stats { display: flex; gap: 20px; }
        .stat { padding: 15px; border-radius: 5px; min-width: 120px; text-align: center; }
        .pass { background: #d4edda; color: #155724; }
        .fail { background: #f8d7da; color: #721c24; }
        .warning { background: #fff3cd; color: #856404; }
        table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background: #0078d4; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .status-pass { color: #28a745; font-weight: bold; }
        .status-fail { color: #dc3545; font-weight: bold; }
        .status-warning { color: #ffc107; font-weight: bold; }
        .risk-high { color: #dc3545; }
        .risk-medium { color: #ff8c00; }
        .risk-low { color: #6c757d; }
    </style>
</head>
<body>
    <h1>Windows 11 Security Audit Report</h1>
    <div class="summary">
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
        </div>
        <p><strong>Overall Pass Rate:</strong> $passRate%</p>
    </div>

    <h2>Detailed Results</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Check Name</th>
            <th>Status</th>
            <th>Current Value</th>
            <th>Recommended</th>
            <th>Risk</th>
            <th>Reference</th>
        </tr>
"@
        foreach ($check in $AuditResults.Checks) {
            $statusClass = switch ($check.Status) {
                'Pass' { 'status-pass' }
                'Fail' { 'status-fail' }
                'Warning' { 'status-warning' }
                default { '' }
            }
            $riskClass = "risk-$($check.Risk.ToLower())"
            $html += @"
        <tr>
            <td>$($check.Category)</td>
            <td>$($check.CheckName)</td>
            <td class="$statusClass">$($check.Status)</td>
            <td>$($check.CurrentValue)</td>
            <td>$($check.RecommendedValue)</td>
            <td class="$riskClass">$($check.Risk)</td>
            <td>$($check.Reference)</td>
        </tr>
"@
        }
        $html += @"
    </table>
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
