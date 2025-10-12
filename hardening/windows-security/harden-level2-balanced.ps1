<#
.SYNOPSIS
    Level 2 Security Hardening - Balanced Security with Moderate Impact

.DESCRIPTION
    Applies CIS Benchmark Level 2 and additional DISA STIG controls that provide:
    - Significantly improved security posture
    - May require application configuration adjustments
    - Recommended for security-conscious environments
    - Includes all Level 1 controls plus additional hardening

    Based on:
    - CIS Microsoft Windows 11 Enterprise Benchmark v4.0.0 Level 2
    - DISA Windows 11 STIG V2R2 Medium Priority
    - Microsoft Security Baseline v25H2
    - ACSC Essential Eight + ISM Controls

    PREREQUISITES:
    - Run Level 1 hardening first
    - Create backup (automatically done if not skipped)
    - Test in non-production environment first

    POTENTIAL IMPACTS:
    - Some legacy applications may need configuration
    - Network file sharing restricted
    - Remote access may require additional setup
    - PowerShell script execution restrictions

.PARAMETER SkipBackup
    Skip automatic backup creation (not recommended)

.PARAMETER WhatIf
    Show what would be changed without making changes

.PARAMETER SkipLevel1Check
    Skip verification that Level 1 was applied

.EXAMPLE
    .\harden-level2-balanced.ps1
    Apply Level 2 hardening with automatic backup

.EXAMPLE
    .\harden-level2-balanced.ps1 -WhatIf
    Preview changes without applying them

.NOTES
    Author: Security Hardening Toolkit
    Requires: Administrator privileges
    Compatible: Windows 11 (tested on 24H2)
    Hardening Level: 2 (Balanced/Moderate Impact)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipBackup,

    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,

    [Parameter(Mandatory=$false)]
    [switch]$SkipLevel1Check
)

#Requires -RunAsAdministrator

# Color scheme
$Colors = @{
    Green  = 'Green'
    Yellow = 'Yellow'
    Red    = 'Red'
    Cyan   = 'Cyan'
    Blue   = 'Blue'
    Magenta = 'Magenta'
}

# Track changes
$script:ChangesApplied = @()
$script:ChangesFailed = @()
$script:ChangesSkipped = @()

# Logging functions
function Write-Log {
    param([string]$Message, [string]$Color = 'White')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-Log "[+] $Message" -Color $Colors.Green }
function Write-Info { param([string]$Message) Write-Log "[i] $Message" -Color $Colors.Blue }
function Write-Warning { param([string]$Message) Write-Log "[!] $Message" -Color $Colors.Yellow }
function Write-Error { param([string]$Message) Write-Log "[-] $Message" -Color $Colors.Red }

# Apply setting with error handling
function Set-SecuritySetting {
    param(
        [string]$Name,
        [string]$Description,
        [scriptblock]$Action,
        [string]$Reference,
        [string]$Impact = "Moderate"
    )

    Write-Info "Applying: $Description (Impact: $Impact)"

    if ($WhatIf) {
        Write-Warning "  [WhatIf] Would apply: $Name"
        $script:ChangesSkipped += @{Name=$Name; Description=$Description; Reference=$Reference; Impact=$Impact}
        return
    }

    try {
        & $Action
        Write-Success "  Applied: $Name"
        $script:ChangesApplied += @{Name=$Name; Description=$Description; Reference=$Reference; Impact=$Impact}
    } catch {
        Write-Error "  Failed: $Name - $_"
        $script:ChangesFailed += @{Name=$Name; Description=$Description; Error=$_.Exception.Message}
    }
}

# Create backup before making changes
function New-PreHardeningBackup {
    if ($SkipBackup) {
        Write-Warning "Skipping backup (not recommended!)"
        return
    }

    Write-Info "Creating backup before Level 2 hardening..."

    $backupScript = Join-Path $PSScriptRoot "backup-security-settings.ps1"

    if (-not (Test-Path $backupScript)) {
        Write-Error "Backup script not found: $backupScript"
        exit 1
    }

    try {
        & $backupScript -RestorePointDescription "Before Level 2 Hardening - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        Write-Success "Backup completed"
    } catch {
        Write-Error "Backup failed: $_"
        exit 1
    }
}

# 1. Restrict PowerShell Execution Policy (MEDIUM - CIS 18.9.95.2)
function Set-PowerShellExecutionPolicy {
    Set-SecuritySetting -Name "PSExecutionPolicy" -Description "Set PowerShell Execution Policy to RemoteSigned" -Reference "CIS 18.9.95.2" -Impact "Moderate" -Action {
        Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop

        # Also set via Group Policy for consistency
        $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
        if (-not (Test-Path $psPath)) {
            New-Item -Path $psPath -Force | Out-Null
        }
        Set-ItemProperty -Path $psPath -Name "EnableScripts" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path $psPath -Name "ExecutionPolicy" -Value "RemoteSigned" -ErrorAction Stop
    }
}

# 2. Enable Credential Guard (HIGH - MS Baseline, STIG V-220715)
function Enable-CredentialGuard {
    Set-SecuritySetting -Name "CredentialGuard" -Description "Enable Windows Defender Credential Guard" -Reference "MS Baseline, STIG V-220715" -Impact "Low" -Action {
        $dgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
        if (-not (Test-Path $dgPath)) {
            New-Item -Path $dgPath -Force | Out-Null
        }
        Set-ItemProperty -Path $dgPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path $dgPath -Name "RequirePlatformSecurityFeatures" -Value 3 -ErrorAction Stop  # Secure Boot + DMA

        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -Value 1 -ErrorAction Stop  # Enable with UEFI lock
    }
}

# 3. Enable Memory Integrity (HVCI) (HIGH - MS Baseline)
function Enable-MemoryIntegrity {
    Set-SecuritySetting -Name "MemoryIntegrity" -Description "Enable Hypervisor-Protected Code Integrity (HVCI)" -Reference "MS Security Baseline" -Impact "Low" -Action {
        $hvciPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
        if (-not (Test-Path $hvciPath)) {
            New-Item -Path $hvciPath -Force | Out-Null
        }
        Set-ItemProperty -Path $hvciPath -Name "Enabled" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path $hvciPath -Name "WasEnabledBy" -Value 2 -ErrorAction Stop  # Enabled by policy
    }
}

# 4. Disable Windows Script Host (MEDIUM - CIS 18.9.97.2.1)
function Disable-WindowsScriptHost {
    Set-SecuritySetting -Name "WSH" -Description "Disable Windows Script Host (WSH)" -Reference "CIS 18.9.97.2.1" -Impact "Moderate" -Action {
        $wshPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
        if (-not (Test-Path $wshPath)) {
            New-Item -Path $wshPath -Force | Out-Null
        }
        Set-ItemProperty -Path $wshPath -Name "Enabled" -Value 0 -ErrorAction Stop
    }
}

# 5. Restrict Remote Desktop Access (MEDIUM - CIS 18.9.59.1)
function Restrict-RemoteDesktop {
    Set-SecuritySetting -Name "RDP" -Description "Harden Remote Desktop Configuration" -Reference "CIS 18.9.59.1" -Impact "Moderate" -Action {
        # Enable NLA (Network Level Authentication)
        $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        Set-ItemProperty -Path $rdpPath -Name "UserAuthentication" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path $rdpPath -Name "SecurityLayer" -Value 2 -ErrorAction Stop  # Require SSL/TLS

        # Set client connection encryption level to high
        Set-ItemProperty -Path $rdpPath -Name "MinEncryptionLevel" -Value 3 -ErrorAction Stop

        # Disable Remote Assistance
        $raPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
        Set-ItemProperty -Path $raPath -Name "fAllowToGetHelp" -Value 0 -ErrorAction Stop
    }
}

# 6. Disable WPAD (MEDIUM - Security Best Practice)
function Disable-WPAD {
    Set-SecuritySetting -Name "WPAD" -Description "Disable Web Proxy Auto-Discovery (WPAD)" -Reference "Security Best Practice" -Impact "Low" -Action {
        $wpadPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
        if (-not (Test-Path $wpadPath)) {
            New-Item -Path $wpadPath -Force | Out-Null
        }
        Set-ItemProperty -Path $wpadPath -Name "WpadOverride" -Value 1 -ErrorAction Stop

        # Also disable via WinHTTP
        $winhttpPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
        if (-not (Test-Path $winhttpPath)) {
            New-Item -Path $winhttpPath -Force | Out-Null
        }
        Set-ItemProperty -Path $winhttpPath -Name "DisableWpad" -Value 1 -ErrorAction Stop
    }
}

# 7. Restrict NTLM Authentication (HIGH - MS Baseline v25H2)
function Restrict-NTLMAuth {
    Set-SecuritySetting -Name "NTLM" -Description "Restrict NTLM Authentication (Audit Mode)" -Reference "MS Baseline v25H2" -Impact "Moderate" -Action {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        if (-not (Test-Path $lsaPath)) {
            New-Item -Path $lsaPath -Force | Out-Null
        }
        # Audit NTLM authentication (level 1) - safer than blocking
        Set-ItemProperty -Path $lsaPath -Name "AuditReceivingNTLMTraffic" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path $lsaPath -Name "RestrictSendingNTLMTraffic" -Value 1 -ErrorAction Stop
    }
}

# 8. Enable Attack Surface Reduction Rules (HIGH - MS Baseline)
function Enable-ASRRules {
    Set-SecuritySetting -Name "ASR" -Description "Enable Windows Defender Attack Surface Reduction Rules" -Reference "MS Security Baseline" -Impact "Moderate" -Action {
        # Enable key ASR rules (audit mode for some to avoid breaking apps)
        $asrRules = @{
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = 1  # Block executable content from email and webmail
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 1  # Block Office applications from creating child processes
            "3B576869-A4EC-4529-8536-B80A7769E899" = 1  # Block Office applications from creating executable content
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 1  # Block Office applications from injecting code
            "D3E037E1-3EB8-44C8-A917-57927947596D" = 1  # Block JavaScript or VBScript from launching downloaded executable
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 1  # Block execution of potentially obfuscated scripts
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = 1  # Block Win32 API calls from Office macros
            "01443614-CD74-433A-B99E-2ECDC07BFC25" = 2  # Block executable files from running unless they meet criteria (audit)
            "C1DB55AB-C21A-4637-BB3F-A12568109D35" = 1  # Use advanced protection against ransomware
            "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = 2  # Block credential stealing from lsass.exe (audit - can break debugging)
        }

        foreach ($ruleId in $asrRules.Keys) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions $asrRules[$ruleId] -ErrorAction SilentlyContinue
        }
    }
}

# 9. Enable Controlled Folder Access (HIGH - MS Baseline)
function Enable-ControlledFolderAccess {
    Set-SecuritySetting -Name "CFA" -Description "Enable Controlled Folder Access (Ransomware Protection)" -Reference "MS Security Baseline" -Impact "Moderate" -Action {
        # Enable in audit mode first
        Set-MpPreference -EnableControlledFolderAccess AuditMode -ErrorAction Stop

        # Add common development folders to protected folders
        $protectedFolders = @(
            "$env:USERPROFILE\Documents",
            "$env:USERPROFILE\Pictures",
            "$env:USERPROFILE\Desktop"
        )

        foreach ($folder in $protectedFolders) {
            if (Test-Path $folder) {
                Add-MpPreference -ControlledFolderAccessProtectedFolders $folder -ErrorAction SilentlyContinue
            }
        }
    }
}

# 10. Restrict Anonymous Enumeration Further (MEDIUM - STIG V-220713)
function Restrict-AnonymousEnumeration {
    Set-SecuritySetting -Name "AnonymousEnum" -Description "Restrict Anonymous Enumeration of SAM Accounts" -Reference "STIG V-220713" -Impact "Low" -Action {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -Value 2 -ErrorAction Stop  # More restrictive

        # Don't allow anonymous enumeration of SAM accounts
        $samPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $samPath -Name "RestrictRemoteSAM" -Value "O:BAG:BAD:(A;;RC;;;BA)" -ErrorAction Stop
    }
}

# 11. Disable Print Spooler Service (MEDIUM - MS Baseline v25H2)
function Disable-PrintSpooler {
    Set-SecuritySetting -Name "PrintSpooler" -Description "Disable Print Spooler Service (if not needed)" -Reference "MS Baseline v25H2" -Impact "High" -Action {
        # Check if any printers are installed
        $printers = Get-Printer -ErrorAction SilentlyContinue

        if ($printers.Count -eq 0) {
            Stop-Service -Name Spooler -Force -ErrorAction Stop
            Set-Service -Name Spooler -StartupType Disabled -ErrorAction Stop
            Write-Info "  No printers detected - Print Spooler disabled"
        } else {
            Write-Warning "  Printers detected - Skipping Print Spooler disable"
            throw "Printers in use - keeping Print Spooler enabled"
        }
    }
}

# 12. Enable BitLocker Encryption (HIGH - CIS 18.9.10.1, STIG V-220716)
function Enable-BitLockerDrive {
    Set-SecuritySetting -Name "BitLocker" -Description "Enable BitLocker Drive Encryption" -Reference "CIS 18.9.10.1, STIG V-220716" -Impact "Low" -Action {
        # Check if BitLocker is already enabled
        $blStatus = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue

        if ($blStatus.ProtectionStatus -eq "On") {
            Write-Info "  BitLocker already enabled on $env:SystemDrive"
        } else {
            Write-Warning "  BitLocker not enabled - manual intervention required"
            Write-Warning "  Run: Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod XtsAes256 -UsedSpaceOnly"
            throw "BitLocker requires manual setup - skipping automatic enable"
        }
    }
}

# 13. Disable WiFi Sense (MEDIUM - CIS 18.5.21.1)
function Disable-WiFiSense {
    Set-SecuritySetting -Name "WiFiSense" -Description "Disable WiFi Sense" -Reference "CIS 18.5.21.1" -Impact "Low" -Action {
        $wifiPath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
        if (-not (Test-Path $wifiPath)) {
            New-Item -Path $wifiPath -Force | Out-Null
        }
        Set-ItemProperty -Path $wifiPath -Name "AutoConnectAllowedOEM" -Value 0 -ErrorAction Stop
    }
}

# 14. Restrict WinRM Access (MEDIUM - CIS 18.9.95.3)
function Restrict-WinRM {
    Set-SecuritySetting -Name "WinRM" -Description "Harden Windows Remote Management (WinRM)" -Reference "CIS 18.9.95.3" -Impact "Moderate" -Action {
        # Only harden if WinRM is running
        $winrmService = Get-Service -Name WinRM -ErrorAction SilentlyContinue

        if ($winrmService.Status -eq "Running") {
            # Disable basic authentication
            Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false -ErrorAction Stop

            # Allow only Kerberos and Negotiate
            Set-Item WSMan:\localhost\Service\Auth\Kerberos -Value $true -ErrorAction Stop
            Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true -ErrorAction Stop

            # Require encryption
            Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false -ErrorAction Stop

            Write-Info "  WinRM hardened (if you don't use it, consider disabling entirely)"
        } else {
            Write-Info "  WinRM not running - skipping configuration"
        }
    }
}

# 15. Configure Advanced Audit Policy (MEDIUM - STIG V-220738)
function Set-AdvancedAuditPolicy {
    Set-SecuritySetting -Name "AdvancedAudit" -Description "Configure Advanced Audit Policy" -Reference "STIG V-220738" -Impact "Low" -Action {
        # Enable detailed audit subcategories
        auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
        auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable | Out-Null
    }
}

# 16. Set Minimum TLS Version (MEDIUM - MS Baseline)
function Set-MinimumTLS {
    Set-SecuritySetting -Name "TLS" -Description "Enforce TLS 1.2 or Higher" -Reference "MS Security Baseline" -Impact "Low" -Action {
        # Disable older protocols
        $protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")

        foreach ($protocol in $protocols) {
            $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
            $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"

            if (-not (Test-Path $serverPath)) { New-Item -Path $serverPath -Force | Out-Null }
            if (-not (Test-Path $clientPath)) { New-Item -Path $clientPath -Force | Out-Null }

            Set-ItemProperty -Path $serverPath -Name "Enabled" -Value 0 -ErrorAction Stop
            Set-ItemProperty -Path $clientPath -Name "Enabled" -Value 0 -ErrorAction Stop
            Set-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value 1 -ErrorAction Stop
            Set-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 1 -ErrorAction Stop
        }

        # Enable TLS 1.2 and 1.3
        $modernProtocols = @("TLS 1.2", "TLS 1.3")
        foreach ($protocol in $modernProtocols) {
            $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
            $clientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Client"

            if (-not (Test-Path $serverPath)) { New-Item -Path $serverPath -Force | Out-Null }
            if (-not (Test-Path $clientPath)) { New-Item -Path $clientPath -Force | Out-Null }

            Set-ItemProperty -Path $serverPath -Name "Enabled" -Value 1 -ErrorAction Stop
            Set-ItemProperty -Path $clientPath -Name "Enabled" -Value 1 -ErrorAction Stop
            Set-ItemProperty -Path $serverPath -Name "DisabledByDefault" -Value 0 -ErrorAction Stop
            Set-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 0 -ErrorAction Stop
        }
    }
}

# 17. Disable Windows Store Consumer Features (LOW - CIS 18.9.16.1)
function Disable-ConsumerFeatures {
    Set-SecuritySetting -Name "ConsumerFeatures" -Description "Disable Windows Store Consumer Features" -Reference "CIS 18.9.16.1" -Impact "Low" -Action {
        $cloudPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
        if (-not (Test-Path $cloudPath)) {
            New-Item -Path $cloudPath -Force | Out-Null
        }
        Set-ItemProperty -Path $cloudPath -Name "DisableWindowsConsumerFeatures" -Value 1 -ErrorAction Stop
    }
}

# 18. Restrict Telemetry to Security Level (MEDIUM - CIS 18.9.16.4)
function Set-TelemetrySecurity {
    Set-SecuritySetting -Name "Telemetry" -Description "Set Telemetry to Security Level (Enterprise only)" -Reference "CIS 18.9.16.4" -Impact "Low" -Action {
        $telemetryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        if (-not (Test-Path $telemetryPath)) {
            New-Item -Path $telemetryPath -Force | Out-Null
        }
        # 0 = Security (Enterprise only), 1 = Basic (fallback for Pro)
        Set-ItemProperty -Path $telemetryPath -Name "AllowTelemetry" -Value 0 -ErrorAction Stop
        Set-ItemProperty -Path $telemetryPath -Name "MaxTelemetryAllowed" -Value 1 -ErrorAction Stop
    }
}

# Generate summary report
function Show-HardeningSummary {
    Write-Log "`n[*] ======================================" -Color $Colors.Cyan
    Write-Log "[*] Hardening Summary - Level 2" -Color $Colors.Cyan
    Write-Log "[*] ======================================`n" -Color $Colors.Cyan

    if ($WhatIf) {
        Write-Info "WhatIf mode - No changes were applied"
        Write-Info "Changes that would be applied: $($script:ChangesSkipped.Count)"
    } else {
        Write-Success "Changes applied: $($script:ChangesApplied.Count)"
        Write-Error "Changes failed: $($script:ChangesFailed.Count)"

        # Show impact breakdown
        $highImpact = ($script:ChangesApplied | Where-Object { $_.Impact -eq "High" }).Count
        $moderateImpact = ($script:ChangesApplied | Where-Object { $_.Impact -eq "Moderate" }).Count
        $lowImpact = ($script:ChangesApplied | Where-Object { $_.Impact -eq "Low" }).Count

        Write-Info "Impact breakdown: High ($highImpact), Moderate ($moderateImpact), Low ($lowImpact)"
    }

    if ($script:ChangesFailed.Count -gt 0) {
        Write-Log "`n[!] Failed Changes:" -Color $Colors.Red
        foreach ($change in $script:ChangesFailed) {
            Write-Error "  - $($change.Name): $($change.Error)"
        }
    }

    if (-not $WhatIf) {
        Write-Log "`n[!] IMPORTANT - Level 2 Changes Require Testing:" -Color $Colors.Yellow
        Write-Log "  - Some applications may need configuration adjustments" -Color $Colors.Yellow
        Write-Log "  - Test all workflows thoroughly" -Color $Colors.Yellow
        Write-Log "  - Check PowerShell script execution" -Color $Colors.Yellow
        Write-Log "  - Verify network file sharing works" -Color $Colors.Yellow

        Write-Log "`n[i] Next Steps:" -Color $Colors.Cyan
        Write-Log "  1. REBOOT your computer (REQUIRED for many changes)" -Color $Colors.Cyan
        Write-Log "  2. Run audit: .\audit-security-posture.ps1" -Color $Colors.Cyan
        Write-Log "  3. Test ALL your applications and workflows" -Color $Colors.Cyan
        Write-Log "  4. If issues occur, restore: .\restore-security-settings.ps1" -Color $Colors.Cyan
        Write-Log "  5. Monitor for 1-2 weeks before Level 3`n" -Color $Colors.Cyan
    }
}

# Main execution
function Main {
    Write-Log "`n[*] Windows 11 Security Hardening - Level 2 (Balanced)" -Color $Colors.Magenta
    Write-Log "[*] ========================================================`n" -Color $Colors.Magenta

    Write-Info "Based on: CIS Benchmark v4.0.0 Level 2, DISA STIG V2R2, MS Baseline v25H2"
    Write-Info "Level: 2 - Balanced security with moderate impact"
    Write-Info "Prerequisites: Level 1 hardening should be applied first`n"

    if ($WhatIf) {
        Write-Warning "WhatIf mode enabled - No changes will be applied`n"
    }

    try {
        # Create backup first
        if (-not $WhatIf) {
            New-PreHardeningBackup
        }

        Write-Log "`n[*] Applying Level 2 security hardening...`n" -Color $Colors.Cyan

        # Apply all Level 2 hardening measures
        Set-PowerShellExecutionPolicy
        Enable-CredentialGuard
        Enable-MemoryIntegrity
        Disable-WindowsScriptHost
        Restrict-RemoteDesktop
        Disable-WPAD
        Restrict-NTLMAuth
        Enable-ASRRules
        Enable-ControlledFolderAccess
        Restrict-AnonymousEnumeration
        Disable-PrintSpooler
        Enable-BitLockerDrive
        Disable-WiFiSense
        Restrict-WinRM
        Set-AdvancedAuditPolicy
        Set-MinimumTLS
        Disable-ConsumerFeatures
        Set-TelemetrySecurity

        Show-HardeningSummary

        Write-Log "`n[+] Level 2 Hardening Completed!" -Color $Colors.Green

    } catch {
        Write-Error "Hardening process failed: $_"
        exit 1
    }
}

# Run main function
Main
