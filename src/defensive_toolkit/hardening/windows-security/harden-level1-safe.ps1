<#
.SYNOPSIS
    Level 1 Security Hardening - Safe, Developer-Friendly Changes

.DESCRIPTION
    Applies CIS Benchmark Level 1 and DISA STIG High Priority controls that are:
    - Safe for developer workstations
    - Non-breaking for normal operations
    - Reversible via backup/restore
    - Focused on high-impact security improvements

    Based on:
    - CIS Microsoft Windows 11 Enterprise Benchmark v4.0.0 (March 2025)
    - DISA Windows 11 STIG V2R2 (January 2025)
    - Microsoft Security Baseline v25H2
    - ACSC Essential Eight Guidance

    This level will NOT break:
    - Development tools (Docker, WSL, VS Code)
    - Network connectivity
    - File sharing (for developers)
    - Remote desktop (if configured)

.PARAMETER SkipBackup
    Skip automatic backup creation (not recommended)

.PARAMETER WhatIf
    Show what would be changed without making changes

.EXAMPLE
    .\harden-level1-safe.ps1
    Apply Level 1 hardening with automatic backup

.EXAMPLE
    .\harden-level1-safe.ps1 -WhatIf
    Preview changes without applying them

.NOTES
    Author: Security Hardening Toolkit
    Requires: Administrator privileges
    Compatible: Windows 11 (tested on 24H2)
    Hardening Level: 1 (Safe/Non-Breaking)
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipBackup
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
        [string]$Reference
    )

    Write-Info "Applying: $Description"

    if ($WhatIfPreference) {
        Write-Warning "  [WhatIf] Would apply: $Name"
        $script:ChangesSkipped += @{Name=$Name; Description=$Description; Reference=$Reference}
        return
    }

    try {
        & $Action
        Write-Success "  Applied: $Name"
        $script:ChangesApplied += @{Name=$Name; Description=$Description; Reference=$Reference}
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

    Write-Info "Creating backup before hardening..."

    $backupScript = Join-Path $PSScriptRoot "backup-security-settings.ps1"

    if (-not (Test-Path $backupScript)) {
        Write-Error "Backup script not found: $backupScript"
        Write-Error "Cannot proceed without backup capability"
        exit 1
    }

    try {
        & $backupScript -RestorePointDescription "Before Level 1 Hardening - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        Write-Success "Backup completed"
    } catch {
        Write-Error "Backup failed: $_"
        Write-Error "Cannot proceed without successful backup"
        exit 1
    }
}

# 1. Disable SMBv1 Protocol (HIGH PRIORITY - CIS 18.3.1, STIG V-220726)
function Disable-SMBv1 {
    Set-SecuritySetting -Name "SMBv1" -Description "Disable SMBv1 Protocol" -Reference "CIS 18.3.1, STIG V-220726" -Action {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
    }
}

# 2. Enable Windows Defender Real-Time Protection (HIGH PRIORITY - CIS 18.9.45, STIG V-220778)
function Enable-DefenderRealTime {
    Set-SecuritySetting -Name "DefenderRealTime" -Description "Enable Windows Defender Real-Time Protection" -Reference "CIS 18.9.45, STIG V-220778" -Action {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop
        Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction Stop
        Set-MpPreference -DisableIOAVProtection $false -ErrorAction Stop
    }
}

# 3. Enable Windows Defender PUA Protection (MEDIUM PRIORITY - MS Baseline)
function Enable-DefenderPUA {
    Set-SecuritySetting -Name "DefenderPUA" -Description "Enable Potentially Unwanted Application Protection" -Reference "MS Security Baseline" -Action {
        Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
    }
}

# 4. Enable Windows Defender Cloud Protection (HIGH PRIORITY - CIS 18.9.45.4.1)
function Enable-DefenderCloud {
    Set-SecuritySetting -Name "DefenderCloud" -Description "Enable Cloud-Delivered Protection" -Reference "CIS 18.9.45.4.1" -Action {
        Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
        Set-MpPreference -SubmitSamplesConsent SendSafeSamples -ErrorAction Stop
    }
}

# 5. Enable Windows Firewall for All Profiles (HIGH PRIORITY - CIS 9.1.1, STIG V-220729)
function Enable-WindowsFirewall {
    Set-SecuritySetting -Name "WindowsFirewall" -Description "Enable Windows Firewall (All Profiles)" -Reference "CIS 9.1.1, STIG V-220729" -Action {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
    }
}

# 6. Configure Account Lockout Policy (MEDIUM PRIORITY - CIS 1.2.1, STIG V-220708)
function Set-AccountLockoutPolicy {
    Set-SecuritySetting -Name "AccountLockout" -Description "Configure Account Lockout Policy" -Reference "CIS 1.2.1, STIG V-220708" -Action {
        # Lockout after 5 invalid attempts, 15 minute duration
        net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 | Out-Null
    }
}

# 7. Set Minimum Password Length (MEDIUM PRIORITY - CIS 1.1.1, STIG V-220707)
function Set-PasswordPolicy {
    Set-SecuritySetting -Name "PasswordPolicy" -Description "Enforce Password Complexity" -Reference "CIS 1.1.1, STIG V-220707" -Action {
        # 14 characters minimum, complexity enabled
        net accounts /minpwlen:14 /maxpwage:60 /minpwage:1 /uniquepw:24 | Out-Null
        # Complexity is enforced via local security policy (requires secedit)
        $secpolConfig = @"
[Unicode]
Unicode=yes
[System Access]
PasswordComplexity = 1
MinimumPasswordLength = 14
PasswordHistorySize = 24
MinimumPasswordAge = 1
MaximumPasswordAge = 60
ClearTextPassword = 0
[Version]
signature="`$CHICAGO`$"
Revision=1
"@
        $tempFile = [System.IO.Path]::GetTempFileName()
        $secpolConfig | Set-Content $tempFile -Encoding Unicode
        secedit /configure /db secedit.sdb /cfg $tempFile /areas SECURITYPOLICY /quiet
        Remove-Item $tempFile -Force
    }
}

# 8. Disable Guest Account (HIGH PRIORITY - CIS 2.3.1.1, STIG V-220709)
function Disable-GuestAccount {
    Set-SecuritySetting -Name "GuestAccount" -Description "Disable Guest Account" -Reference "CIS 2.3.1.1, STIG V-220709" -Action {
        Disable-LocalUser -Name "Guest" -ErrorAction Stop
    }
}

# 9. Enable UAC (HIGH PRIORITY - CIS 2.3.17.1, STIG V-220711)
function Enable-UAC {
    Set-SecuritySetting -Name "UAC" -Description "Enable User Account Control" -Reference "CIS 2.3.17.1, STIG V-220711" -Action {
        $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -ErrorAction Stop  # Prompt for consent
        Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 1 -ErrorAction Stop
    }
}

# 10. Enable Windows Update Automatic Updates (MEDIUM PRIORITY - CIS 18.9.101.1)
function Enable-WindowsUpdate {
    Set-SecuritySetting -Name "WindowsUpdate" -Description "Enable Automatic Windows Updates" -Reference "CIS 18.9.101.1" -Action {
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (-not (Test-Path $wuPath)) {
            New-Item -Path $wuPath -Force | Out-Null
        }
        Set-ItemProperty -Path $wuPath -Name "NoAutoUpdate" -Value 0 -ErrorAction Stop
        Set-ItemProperty -Path $wuPath -Name "AUOptions" -Value 4 -ErrorAction Stop  # Auto download and schedule install
        Set-ItemProperty -Path $wuPath -Name "ScheduledInstallDay" -Value 0 -ErrorAction Stop  # Every day
        Set-ItemProperty -Path $wuPath -Name "ScheduledInstallTime" -Value 3 -ErrorAction Stop  # 3 AM
    }
}

# 11. Enable PowerShell Script Block Logging (MEDIUM PRIORITY - CIS 18.9.95.1, STIG V-220721)
function Enable-PowerShellLogging {
    Set-SecuritySetting -Name "PSScriptBlockLogging" -Description "Enable PowerShell Script Block Logging" -Reference "CIS 18.9.95.1, STIG V-220721" -Action {
        $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (-not (Test-Path $psPath)) {
            New-Item -Path $psPath -Force | Out-Null
        }
        Set-ItemProperty -Path $psPath -Name "EnableScriptBlockLogging" -Value 1 -ErrorAction Stop
    }
}

# 12. Enable PowerShell Transcription (MEDIUM PRIORITY - MS Baseline)
function Enable-PowerShellTranscription {
    Set-SecuritySetting -Name "PSTranscription" -Description "Enable PowerShell Transcription" -Reference "MS Security Baseline" -Action {
        $psPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        if (-not (Test-Path $psPath)) {
            New-Item -Path $psPath -Force | Out-Null
        }
        Set-ItemProperty -Path $psPath -Name "EnableTranscripting" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path $psPath -Name "OutputDirectory" -Value "$env:SystemDrive\PSTranscripts" -ErrorAction Stop
        Set-ItemProperty -Path $psPath -Name "EnableInvocationHeader" -Value 1 -ErrorAction Stop

        # Create transcript directory
        $transcriptDir = "$env:SystemDrive\PSTranscripts"
        if (-not (Test-Path $transcriptDir)) {
            New-Item -Path $transcriptDir -ItemType Directory -Force | Out-Null
        }
    }
}

# 13. Disable LLMNR (MEDIUM PRIORITY - CIS 18.5.8, STIG V-220730)
function Disable-LLMNR {
    Set-SecuritySetting -Name "LLMNR" -Description "Disable Link-Local Multicast Name Resolution" -Reference "CIS 18.5.8, STIG V-220730" -Action {
        $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (-not (Test-Path $llmnrPath)) {
            New-Item -Path $llmnrPath -Force | Out-Null
        }
        Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -ErrorAction Stop
    }
}

# 14. Disable NetBIOS over TCP/IP (HIGH PRIORITY - MS Baseline v25H2)
function Disable-NetBIOS {
    Set-SecuritySetting -Name "NetBIOS" -Description "Disable NetBIOS over TCP/IP" -Reference "MS Security Baseline v25H2" -Action {
        # Disable NetBIOS on all network adapters
        $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
        foreach ($adapter in $adapters) {
            $adapter.SetTcpipNetbios(2) | Out-Null  # 2 = Disable NetBIOS
        }
    }
}

# 15. Configure Screen Saver Lock (LOW PRIORITY - CIS 18.9.89.2)
function Set-ScreenSaverLock {
    Set-SecuritySetting -Name "ScreenSaverLock" -Description "Enable Screen Saver Lock (15 minutes)" -Reference "CIS 18.9.89.2" -Action {
        $ssPath = "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
        if (-not (Test-Path $ssPath)) {
            New-Item -Path $ssPath -Force | Out-Null
        }
        Set-ItemProperty -Path $ssPath -Name "ScreenSaveActive" -Value "1" -ErrorAction Stop
        Set-ItemProperty -Path $ssPath -Name "ScreenSaverIsSecure" -Value "1" -ErrorAction Stop
        Set-ItemProperty -Path $ssPath -Name "ScreenSaveTimeOut" -Value "900" -ErrorAction Stop  # 15 minutes
    }
}

# 16. Show File Extensions (LOW PRIORITY - Security Best Practice)
function Enable-FileExtensions {
    Set-SecuritySetting -Name "FileExtensions" -Description "Show File Extensions in Explorer" -Reference "Security Best Practice" -Action {
        $explorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Set-ItemProperty -Path $explorerPath -Name "HideFileExt" -Value 0 -ErrorAction Stop
    }
}

# 17. Disable AutoRun/AutoPlay (MEDIUM PRIORITY - CIS 18.9.8.1, STIG V-220727)
function Disable-AutoRun {
    Set-SecuritySetting -Name "AutoRun" -Description "Disable AutoRun/AutoPlay for All Drives" -Reference "CIS 18.9.8.1, STIG V-220727" -Action {
        $autorunPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $autorunPath)) {
            New-Item -Path $autorunPath -Force | Out-Null
        }
        Set-ItemProperty -Path $autorunPath -Name "NoDriveTypeAutoRun" -Value 255 -ErrorAction Stop  # Disable for all drives
        Set-ItemProperty -Path $autorunPath -Name "NoAutorun" -Value 1 -ErrorAction Stop
    }
}

# 18. Enable Windows Defender Exploit Protection (HIGH PRIORITY - MS Baseline)
function Enable-ExploitProtection {
    Set-SecuritySetting -Name "ExploitProtection" -Description "Enable Exploit Protection Defaults" -Reference "MS Security Baseline" -Action {
        # Apply Windows Defender Exploit Protection defaults
        Set-ProcessMitigation -System -Enable DEP,SEHOP,ForceRandomization,BottomUp -ErrorAction Stop
    }
}

# 19. Configure Audit Policy (MEDIUM PRIORITY - STIG V-220737)
function Set-AuditPolicy {
    Set-SecuritySetting -Name "AuditPolicy" -Description "Enable Security Audit Logging" -Reference "STIG V-220737" -Action {
        # Enable audit policy for key events
        auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Policy Change" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"Privilege Use" /success:enable /failure:enable | Out-Null
        auditpol /set /category:"System" /success:enable /failure:enable | Out-Null
    }
}

# 20. Restrict Anonymous Access (HIGH PRIORITY - CIS 2.3.11.3, STIG V-220712)
function Restrict-AnonymousAccess {
    Set-SecuritySetting -Name "AnonymousAccess" -Description "Restrict Anonymous Access to Named Pipes and Shares" -Reference "CIS 2.3.11.3, STIG V-220712" -Action {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path $lsaPath -Name "EveryoneIncludesAnonymous" -Value 0 -ErrorAction Stop
    }
}

# Generate summary report
function Show-HardeningSummary {
    Write-Log "`n[*] ======================================" -Color $Colors.Cyan
    Write-Log "[*] Hardening Summary - Level 1" -Color $Colors.Cyan
    Write-Log "[*] ======================================`n" -Color $Colors.Cyan

    if ($WhatIfPreference) {
        Write-Info "WhatIf mode - No changes were applied"
        Write-Info "Changes that would be applied: $($script:ChangesSkipped.Count)"
    } else {
        Write-Success "Changes applied: $($script:ChangesApplied.Count)"
        Write-Error "Changes failed: $($script:ChangesFailed.Count)"
    }

    if ($script:ChangesFailed.Count -gt 0) {
        Write-Log "`n[!] Failed Changes:" -Color $Colors.Red
        foreach ($change in $script:ChangesFailed) {
            Write-Error "  - $($change.Name): $($change.Error)"
        }
    }

    if (-not $WhatIfPreference) {
        Write-Log "`n[i] Next Steps:" -Color $Colors.Cyan
        Write-Log "  1. Restart your computer to apply all changes" -Color $Colors.Cyan
        Write-Log "  2. Run audit: .\audit-security-posture.ps1" -Color $Colors.Cyan
        Write-Log "  3. Test your applications and workflows" -Color $Colors.Cyan
        Write-Log "  4. If issues occur, restore: .\restore-security-settings.ps1" -Color $Colors.Cyan
        Write-Log "  5. Consider Level 2 hardening if all works well`n" -Color $Colors.Cyan
    }
}

# Main execution
function Main {
    Write-Log "`n[*] Windows 11 Security Hardening - Level 1 (Safe)" -Color $Colors.Magenta
    Write-Log "[*] =================================================`n" -Color $Colors.Magenta

    Write-Info "Based on: CIS Benchmark v4.0.0, DISA STIG V2R2, MS Baseline v25H2"
    Write-Info "Level: 1 - Safe for developer workstations"
    Write-Info "Changes: Non-breaking, high-impact security improvements`n"

    if ($WhatIfPreference) {
        Write-Warning "WhatIf mode enabled - No changes will be applied`n"
    }

    try {
        # Create backup first
        if (-not $WhatIfPreference) {
            New-PreHardeningBackup
        }

        Write-Log "`n[*] Applying security hardening...`n" -Color $Colors.Cyan

        # Apply all hardening measures
        Disable-SMBv1
        Enable-DefenderRealTime
        Enable-DefenderPUA
        Enable-DefenderCloud
        Enable-WindowsFirewall
        Set-AccountLockoutPolicy
        Set-PasswordPolicy
        Disable-GuestAccount
        Enable-UAC
        Enable-WindowsUpdate
        Enable-PowerShellLogging
        Enable-PowerShellTranscription
        Disable-LLMNR
        Disable-NetBIOS
        Set-ScreenSaverLock
        Enable-FileExtensions
        Disable-AutoRun
        Enable-ExploitProtection
        Set-AuditPolicy
        Restrict-AnonymousAccess

        Show-HardeningSummary

        Write-Log "`n[+] Level 1 Hardening Completed!" -Color $Colors.Green

    } catch {
        Write-Error "Hardening process failed: $_"
        exit 1
    }
}

# Run main function
Main
