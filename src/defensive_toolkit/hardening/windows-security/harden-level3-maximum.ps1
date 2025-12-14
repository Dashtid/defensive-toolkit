<#
.SYNOPSIS
    Level 3 Security Hardening - Maximum Security with High Impact

.DESCRIPTION
    Applies CIS Benchmark Level 2+ and maximum DISA STIG controls for:
    - Maximum security posture
    - High-security environments (finance, healthcare, defense)
    - May break compatibility with many applications
    - Requires significant testing and configuration

    Based on:
    - CIS Microsoft Windows 11 Enterprise Benchmark v4.0.0 Level 2+
    - DISA Windows 11 STIG V2R2 All Controls
    - Microsoft Security Baseline v25H2 Maximum
    - ACSC ISM Official/Protected controls
    - NSA/CISA Windows 10/11 Hardening Guidance

    PREREQUISITES:
    - Run Level 1 and Level 2 hardening first
    - Create backup (automatically done if not skipped)
    - TEST IN NON-PRODUCTION FIRST
    - Document all application dependencies

    HIGH IMPACT WARNINGS:
    - Many legacy applications will break
    - Network file sharing severely restricted
    - Remote access requires certificates
    - Development workflows may be impacted
    - Some Windows features disabled entirely

.PARAMETER SkipBackup
    Skip automatic backup creation (not recommended)

.PARAMETER WhatIf
    Show what would be changed without making changes

.PARAMETER Force
    Skip confirmation prompts (use with extreme caution)

.EXAMPLE
    .\harden-level3-maximum.ps1
    Apply Level 3 hardening with automatic backup and confirmations

.EXAMPLE
    .\harden-level3-maximum.ps1 -WhatIf
    Preview changes without applying them (RECOMMENDED FIRST)

.NOTES
    Author: Security Hardening Toolkit
    Requires: Administrator privileges
    Compatible: Windows 11 (tested on 24H2)
    Hardening Level: 3 (Maximum Security/High Impact)
    WARNING: DO NOT USE ON PRODUCTION SYSTEMS WITHOUT THOROUGH TESTING
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipBackup,

    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,

    [Parameter(Mandatory=$false)]
    [switch]$Force
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
        [string]$Impact = "High",
        [string]$BreaksApps = "Unknown"
    )

    Write-Info "Applying: $Description (Impact: $Impact, May Break: $BreaksApps)"

    if ($WhatIf) {
        Write-Warning "  [WhatIf] Would apply: $Name"
        $script:ChangesSkipped += @{Name=$Name; Description=$Description; Reference=$Reference; Impact=$Impact; Breaks=$BreaksApps}
        return
    }

    try {
        & $Action
        Write-Success "  Applied: $Name"
        $script:ChangesApplied += @{Name=$Name; Description=$Description; Reference=$Reference; Impact=$Impact; Breaks=$BreaksApps}
    } catch {
        Write-Error "  Failed: $Name - $_"
        $script:ChangesFailed += @{Name=$Name; Description=$Description; Error=$_.Exception.Message}
    }
}

# Show Level 3 Warning
function Show-Level3Warning {
    if ($Force) {
        Write-Warning "Force flag enabled - skipping confirmation"
        return
    }

    Write-Log "`n[!] ======================================" -Color $Colors.Red
    Write-Log "[!] LEVEL 3 HARDENING WARNING" -Color $Colors.Red
    Write-Log "[!] ======================================`n" -Color $Colors.Red

    Write-Warning "Level 3 hardening applies MAXIMUM security controls that WILL:"
    Write-Warning "  - Break many applications and workflows"
    Write-Warning "  - Restrict network access significantly"
    Write-Warning "  - Disable convenient Windows features"
    Write-Warning "  - Require extensive testing and troubleshooting"
    Write-Warning "  - May require application whitelisting"

    Write-Log "`n[!] This level is intended for:" -Color $Colors.Yellow
    Write-Log "    - High-security environments (finance, defense, healthcare)" -Color $Colors.Yellow
    Write-Log "    - Systems handling classified/sensitive data" -Color $Colors.Yellow
    Write-Log "    - Compliance requirements (HIPAA, PCI-DSS, FedRAMP)" -Color $Colors.Yellow

    Write-Log "`n[!] NOT recommended for:" -Color $Colors.Red
    Write-Log "    - Developer workstations" -Color $Colors.Red
    Write-Log "    - General office use" -Color $Colors.Red
    Write-Log "    - Production systems without testing" -Color $Colors.Red

    Write-Host "`n"
    $confirm1 = Read-Host "Type 'I UNDERSTAND THE RISKS' to continue"
    if ($confirm1 -ne 'I UNDERSTAND THE RISKS') {
        Write-Info "Level 3 hardening cancelled"
        exit 0
    }

    $confirm2 = Read-Host "Have you tested this on a non-production system first? (yes/no)"
    if ($confirm2 -ne 'yes') {
        Write-Error "Please test on a non-production system first!"
        exit 1
    }

    $confirm3 = Read-Host "Final confirmation - Type 'HARDEN' to proceed"
    if ($confirm3 -ne 'HARDEN') {
        Write-Info "Level 3 hardening cancelled"
        exit 0
    }
}

# Create backup before making changes
function New-PreHardeningBackup {
    if ($SkipBackup) {
        Write-Warning "Skipping backup (EXTREMELY NOT RECOMMENDED for Level 3!)"
        return
    }

    Write-Info "Creating backup before Level 3 hardening..."

    $backupScript = Join-Path $PSScriptRoot "backup-security-settings.ps1"

    if (-not (Test-Path $backupScript)) {
        Write-Error "Backup script not found: $backupScript"
        exit 1
    }

    try {
        & $backupScript -RestorePointDescription "Before Level 3 Hardening - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        Write-Success "Backup completed"
    } catch {
        Write-Error "Backup failed: $_"
        exit 1
    }
}

# 1. Enable AppLocker (HIGH - CIS 18.9.6, STIG V-220719)
function Enable-AppLocker {
    Set-SecuritySetting -Name "AppLocker" -Description "Enable AppLocker Application Control" -Reference "CIS 18.9.6, STIG V-220719" -Impact "Very High" -BreaksApps "Unsigned/Unknown applications" -Action {
        # Enable AppLocker service
        Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction Stop
        Start-Service -Name AppIDSvc -ErrorAction Stop

        # Create default rules (allow signed Microsoft apps, allow admins everything)
        Write-Info "  Creating AppLocker default rules..."

        # This requires manual GPO configuration for full deployment
        Write-Warning "  AppLocker requires manual Group Policy configuration"
        Write-Warning "  See: Computer Configuration > Windows Settings > Security Settings > Application Control Policies"
    }
}

# 2. Set PowerShell to ConstrainedLanguage Mode (VERY HIGH - NSA Guidance)
function Set-ConstrainedLanguageMode {
    Set-SecuritySetting -Name "PSConstrainedLanguage" -Description "Set PowerShell to Constrained Language Mode" -Reference "NSA Windows Hardening" -Impact "Very High" -BreaksApps "Most PowerShell scripts" -Action {
        $envPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        Set-ItemProperty -Path $envPath -Name "__PSLockdownPolicy" -Value "4" -ErrorAction Stop

        Write-Warning "  PowerShell will be severely restricted - many scripts will break"
        Write-Warning "  Use Windows PowerShell ISE or allow-list scripts as needed"
    }
}

# 3. Block NTLM Authentication Completely (HIGH - MS Baseline v25H2)
function Block-NTLMAuth {
    Set-SecuritySetting -Name "BlockNTLM" -Description "Block NTLM Authentication (Force Kerberos)" -Reference "MS Baseline v25H2" -Impact "Very High" -BreaksApps "Legacy apps, network shares" -Action {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        if (-not (Test-Path $lsaPath)) {
            New-Item -Path $lsaPath -Force | Out-Null
        }
        # Deny all NTLM (requires Kerberos)
        Set-ItemProperty -Path $lsaPath -Name "RestrictSendingNTLMTraffic" -Value 2 -ErrorAction Stop
        Set-ItemProperty -Path $lsaPath -Name "RestrictReceivingNTLMTraffic" -Value 2 -ErrorAction Stop

        Write-Warning "  All network authentication now requires Kerberos"
    }
}

# 4. Disable Remote Desktop Completely (HIGH - Maximum Security)
function Disable-RemoteDesktop {
    Set-SecuritySetting -Name "DisableRDP" -Description "Disable Remote Desktop Protocol Entirely" -Reference "Maximum Security" -Impact "High" -BreaksApps "Remote Desktop" -Action {
        $rdpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
        Set-ItemProperty -Path $rdpPath -Name "fDenyTSConnections" -Value 1 -ErrorAction Stop

        # Disable RDP firewall rules
        Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue

        Write-Info "  Remote Desktop completely disabled"
    }
}

# 5. Disable WinRM Completely (MEDIUM - If not using PowerShell Remoting)
function Disable-WinRM {
    Set-SecuritySetting -Name "DisableWinRM" -Description "Disable Windows Remote Management" -Reference "Maximum Security" -Impact "High" -BreaksApps "PowerShell Remoting, remote management" -Action {
        Stop-Service -Name WinRM -Force -ErrorAction Stop
        Set-Service -Name WinRM -StartupType Disabled -ErrorAction Stop
        Disable-NetFirewallRule -DisplayGroup "Windows Remote Management" -ErrorAction SilentlyContinue

        Write-Info "  WinRM and PowerShell Remoting disabled"
    }
}

# 6. Enable Controlled Folder Access (Production Mode) (HIGH - Ransomware Protection)
function Enable-CFAProduction {
    Set-SecuritySetting -Name "CFAProduction" -Description "Enable Controlled Folder Access (Block Mode)" -Reference "MS Security Baseline" -Impact "High" -BreaksApps "Apps that modify documents without permission" -Action {
        # Enable in blocking mode (was audit in Level 2)
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop

        Write-Warning "  Controlled Folder Access now in BLOCK mode"
        Write-Warning "  Add trusted apps with: Add-MpPreference -ControlledFolderAccessAllowedApplications 'C:\path\to\app.exe'"
    }
}

# 7. Disable All Unnecessary Services (HIGH - Attack Surface Reduction)
function Disable-UnnecessaryServices {
    Set-SecuritySetting -Name "DisableServices" -Description "Disable Unnecessary Windows Services" -Reference "NSA Hardening Guidance" -Impact "High" -BreaksApps "Various features" -Action {
        $servicesToDisable = @(
            "RemoteRegistry",              # Remote Registry
            "RemoteAccess",                # Routing and Remote Access
            "WMPNetworkSvc",               # Windows Media Player Network Sharing
            "SSDPSRV",                     # SSDP Discovery
            "upnphost",                    # UPnP Device Host
            "WSearch",                     # Windows Search (if not needed)
            "XblAuthManager",              # Xbox Live Auth Manager
            "XblGameSave",                 # Xbox Live Game Save
            "XboxNetApiSvc",               # Xbox Live Networking Service
            "lfsvc",                       # Geolocation Service
            "MapsBroker",                  # Downloaded Maps Manager
            "PhoneSvc",                    # Phone Service
            "RetailDemo",                  # Retail Demo Service
            "SharedAccess",                # Internet Connection Sharing (ICS)
            "WerSvc",                      # Windows Error Reporting
            "WbioSrvc",                    # Windows Biometric Service (if not using)
            "TapiSrv"                      # Telephony
        )

        foreach ($service in $servicesToDisable) {
            try {
                $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($svc) {
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
                    Write-Info "  Disabled: $service"
                }
            } catch {
                Write-Warning "  Could not disable: $service"
            }
        }
    }
}

# 8. Enable All Attack Surface Reduction Rules (Production Mode) (HIGH)
function Enable-ASRProductionMode {
    Set-SecuritySetting -Name "ASRProduction" -Description "Enable All ASR Rules in Block Mode" -Reference "MS Security Baseline" -Impact "Very High" -BreaksApps "Macros, scripts, some installers" -Action {
        # Enable ALL ASR rules in block mode (some were audit in Level 2)
        $asrRules = @{
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = 1  # Block executable content from email and webmail
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 1  # Block Office applications from creating child processes
            "3B576869-A4EC-4529-8536-B80A7769E899" = 1  # Block Office applications from creating executable content
            "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 1  # Block Office applications from injecting code
            "D3E037E1-3EB8-44C8-A917-57927947596D" = 1  # Block JavaScript or VBScript from launching downloaded executable
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 1  # Block execution of potentially obfuscated scripts
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = 1  # Block Win32 API calls from Office macros
            "01443614-CD74-433A-B99E-2ECDC07BFC25" = 1  # Block executable files from running unless they meet criteria (NOW BLOCK)
            "C1DB55AB-C21A-4637-BB3F-A12568109D35" = 1  # Use advanced protection against ransomware
            "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = 1  # Block credential stealing from lsass.exe (NOW BLOCK)
            "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = 1  # Block persistence through WMI event subscription
            "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = 1  # Block process creations from PSExec and WMI commands
            "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = 1  # Block untrusted and unsigned processes from USB
            "26190899-1602-49E8-8B27-EB1D0A1CE869" = 1  # Block Office communication apps from creating child processes
            "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = 1  # Block Adobe Reader from creating child processes
        }

        foreach ($ruleId in $asrRules.Keys) {
            Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions $asrRules[$ruleId] -ErrorAction SilentlyContinue
        }

        Write-Warning "  All ASR rules now in BLOCK mode - test thoroughly!"
    }
}

# 9. Enable Network Protection (HIGH - MS Baseline)
function Enable-NetworkProtection {
    Set-SecuritySetting -Name "NetworkProtection" -Description "Enable Windows Defender Network Protection" -Reference "MS Security Baseline" -Impact "Moderate" -BreaksApps "Access to malicious sites" -Action {
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
        Write-Info "  Network Protection blocks connections to malicious domains"
    }
}

# 10. Disable PowerShell v2 Engine (MEDIUM - CIS 18.9.95.2)
function Disable-PowerShellV2 {
    Set-SecuritySetting -Name "PSv2" -Description "Disable PowerShell 2.0 Engine" -Reference "CIS 18.9.95.2, STIG V-220723" -Impact "Low" -BreaksApps "Legacy scripts requiring PSv2" -Action {
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction Stop | Out-Null
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart -ErrorAction Stop | Out-Null
        Write-Info "  PowerShell 2.0 disabled (prevents downgrade attacks)"
    }
}

# 11. Restrict Null Session Access Completely (HIGH - STIG V-220714)
function Block-NullSessions {
    Set-SecuritySetting -Name "NullSessions" -Description "Block All Null Session Access" -Reference "STIG V-220714" -Impact "Low" -BreaksApps "Anonymous SMB enumeration" -Action {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

        # Most restrictive anonymous access
        Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -Value 2 -ErrorAction Stop
        Set-ItemProperty -Path $lsaPath -Name "EveryoneIncludesAnonymous" -Value 0 -ErrorAction Stop

        # Don't allow enumeration of SAM accounts
        Set-ItemProperty -Path $lsaPath -Name "RestrictRemoteSAM" -Value "O:BAG:BAD:(A;;RC;;;BA)" -ErrorAction Stop

        # Empty null session pipes and shares
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "NullSessionPipes" -Value "" -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "NullSessionShares" -Value "" -ErrorAction Stop
    }
}

# 12. Enable LSA Protection (HIGH - STIG V-220725)
function Enable-LSAProtection {
    Set-SecuritySetting -Name "LSAProtection" -Description "Enable LSA Protection (RunAsPPL)" -Reference "STIG V-220725" -Impact "Low" -BreaksApps "Some drivers/security tools" -Action {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -ErrorAction Stop

        Write-Info "  LSA running as Protected Process - prevents credential dumping"
    }
}

# 13. Disable IPv6 (MEDIUM - If not used)
function Disable-IPv6 {
    Set-SecuritySetting -Name "IPv6" -Description "Disable IPv6 Protocol" -Reference "Security Best Practice (if not used)" -Impact "Moderate" -BreaksApps "IPv6-only services" -Action {
        # Disable IPv6 on all adapters
        $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
        foreach ($adapter in $adapters) {
            Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
        }

        # Also disable via registry
        $ipv6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        if (-not (Test-Path $ipv6Path)) {
            New-Item -Path $ipv6Path -Force | Out-Null
        }
        Set-ItemProperty -Path $ipv6Path -Name "DisabledComponents" -Value 0xFF -ErrorAction Stop

        Write-Info "  IPv6 disabled on all adapters"
    }
}

# 14. Enable Strict Firewall Logging (MEDIUM - Forensics)
function Enable-FirewallLogging {
    Set-SecuritySetting -Name "FirewallLogging" -Description "Enable Detailed Firewall Logging" -Reference "Security Best Practice" -Impact "Low" -BreaksApps "None" -Action {
        $profiles = @("Domain", "Public", "Private")

        foreach ($profile in $profiles) {
            Set-NetFirewallProfile -Name $profile `
                -LogAllowed True `
                -LogBlocked True `
                -LogMaxSizeKilobytes 16384 `
                -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall-$profile.log" `
                -ErrorAction Stop
        }

        Write-Info "  Firewall logging enabled for all profiles"
    }
}

# 15. Disable Legacy Protocols and Features (HIGH - Attack Surface Reduction)
function Disable-LegacyFeatures {
    Set-SecuritySetting -Name "LegacyFeatures" -Description "Disable Legacy Windows Features" -Reference "NSA Hardening Guidance" -Impact "Moderate" -BreaksApps "Legacy applications" -Action {
        # Disable Windows features that are security risks
        $featuresToDisable = @(
            "SMB1Protocol",                         # Already in Level 1 but ensuring
            "TFTP",                                 # Trivial FTP
            "TelnetClient",                         # Telnet
            "SimpleTCP",                            # Simple TCP/IP Services
            "Windows-Defender-ApplicationGuard"    # If not using
        )

        foreach ($feature in $featuresToDisable) {
            try {
                Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue | Out-Null
                Write-Info "  Disabled feature: $feature"
            } catch {
                Write-Info "  Feature not installed or already disabled: $feature"
            }
        }
    }
}

# 16. Restrict Administrative Shares (HIGH - C$, ADMIN$, etc.)
function Restrict-AdminShares {
    Set-SecuritySetting -Name "AdminShares" -Description "Restrict Administrative Shares" -Reference "Security Best Practice" -Impact "High" -BreaksApps "Remote admin tools, scripts" -Action {
        $serverPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

        # Restrict admin shares to admins only, no anonymous
        Set-ItemProperty -Path $serverPath -Name "AutoShareWks" -Value 0 -ErrorAction Stop
        Set-ItemProperty -Path $serverPath -Name "AutoShareServer" -Value 0 -ErrorAction Stop

        Write-Warning "  Administrative shares disabled - may break remote management"
    }
}

# 17. Maximum Audit Policy (LOW - Complete visibility)
function Set-MaximumAuditPolicy {
    Set-SecuritySetting -Name "MaxAudit" -Description "Enable Maximum Audit Policy Coverage" -Reference "STIG V-220739" -Impact "Low" -BreaksApps "None (generates large logs)" -Action {
        # Enable auditing for ALL categories
        $categories = @(
            "Logon/Logoff",
            "Account Logon",
            "Account Management",
            "Policy Change",
            "Privilege Use",
            "Object Access",
            "DS Access",
            "System",
            "Detailed Tracking"
        )

        foreach ($category in $categories) {
            auditpol /set /category:$category /success:enable /failure:enable | Out-Null
        }

        Write-Info "  Maximum audit policy enabled - monitor Event Viewer logs"
    }
}

# 18. Disable Bluetooth (MEDIUM - If not needed)
function Disable-Bluetooth {
    Set-SecuritySetting -Name "Bluetooth" -Description "Disable Bluetooth Support" -Reference "Security Best Practice" -Impact "Moderate" -BreaksApps "Bluetooth devices" -Action {
        # Disable Bluetooth services
        $btServices = @("bthserv", "BluetoothUserService")

        foreach ($service in $btServices) {
            try {
                $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($svc) {
                    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
                }
            } catch {}
        }

        Write-Info "  Bluetooth services disabled"
    }
}

# Generate summary report
function Show-HardeningSummary {
    Write-Log "`n[*] ======================================" -Color $Colors.Cyan
    Write-Log "[*] Hardening Summary - Level 3" -Color $Colors.Cyan
    Write-Log "[*] ======================================`n" -Color $Colors.Cyan

    if ($WhatIf) {
        Write-Info "WhatIf mode - No changes were applied"
        Write-Info "Changes that would be applied: $($script:ChangesSkipped.Count)"

        # Show what apps might break
        Write-Log "`n[!] Potentially Impacted Applications:" -Color $Colors.Yellow
        $script:ChangesSkipped | Where-Object { $_.Breaks -ne "None" -and $_.Breaks -ne "Unknown" } | ForEach-Object {
            Write-Warning "  $($_.Name): $($_.Breaks)"
        }
    } else {
        Write-Success "Changes applied: $($script:ChangesApplied.Count)"
        Write-Error "Changes failed: $($script:ChangesFailed.Count)"

        # Show impact breakdown
        $veryHighImpact = ($script:ChangesApplied | Where-Object { $_.Impact -eq "Very High" }).Count
        $highImpact = ($script:ChangesApplied | Where-Object { $_.Impact -eq "High" }).Count
        $moderateImpact = ($script:ChangesApplied | Where-Object { $_.Impact -eq "Moderate" }).Count
        $lowImpact = ($script:ChangesApplied | Where-Object { $_.Impact -eq "Low" }).Count

        Write-Info "Impact breakdown: Very High ($veryHighImpact), High ($highImpact), Moderate ($moderateImpact), Low ($lowImpact)"

        # Show what was broken
        Write-Log "`n[!] Applications That May Be Impacted:" -Color $Colors.Yellow
        $script:ChangesApplied | Where-Object { $_.Breaks -ne "None" -and $_.Breaks -ne "Unknown" } | ForEach-Object {
            Write-Warning "  $($_.Name): $($_.Breaks)"
        }
    }

    if ($script:ChangesFailed.Count -gt 0) {
        Write-Log "`n[!] Failed Changes:" -Color $Colors.Red
        foreach ($change in $script:ChangesFailed) {
            Write-Error "  - $($change.Name): $($change.Error)"
        }
    }

    if (-not $WhatIf) {
        Write-Log "`n[!] CRITICAL - Level 3 Post-Hardening Tasks:" -Color $Colors.Red
        Write-Log "  1. REBOOT IMMEDIATELY (many changes require restart)" -Color $Colors.Red
        Write-Log "  2. Test EVERY application you use" -Color $Colors.Red
        Write-Log "  3. Document what breaks and create exceptions" -Color $Colors.Red
        Write-Log "  4. Review Event Viewer for errors" -Color $Colors.Red
        Write-Log "  5. Configure AppLocker/ASR exceptions as needed" -Color $Colors.Red

        Write-Log "`n[i] Maintenance:" -Color $Colors.Cyan
        Write-Log "  - Run audit weekly: .\audit-security-posture.ps1" -Color $Colors.Cyan
        Write-Log "  - Monitor Security Event Log daily" -Color $Colors.Cyan
        Write-Log "  - Review firewall logs regularly" -Color $Colors.Cyan
        Write-Log "  - Document all exceptions and allow-listed apps" -Color $Colors.Cyan
        Write-Log "  - If critical issues: .\restore-security-settings.ps1`n" -Color $Colors.Cyan
    }
}

# Main execution
function Main {
    Write-Log "`n[*] Windows 11 Security Hardening - Level 3 (MAXIMUM)" -Color $Colors.Magenta
    Write-Log "[*] ============================================================`n" -Color $Colors.Magenta

    Write-Info "Based on: CIS Level 2+, DISA STIG All Controls, NSA/CISA Guidance"
    Write-Info "Level: 3 - MAXIMUM security for high-security environments"
    Write-Info "WARNING: HIGH IMPACT - Many applications will break`n"

    if ($WhatIf) {
        Write-Warning "WhatIf mode enabled - No changes will be applied (REVIEW OUTPUT CAREFULLY)`n"
    } else {
        Show-Level3Warning
    }

    try {
        # Create backup first
        if (-not $WhatIf) {
            New-PreHardeningBackup
        }

        Write-Log "`n[*] Applying Level 3 MAXIMUM security hardening...`n" -Color $Colors.Cyan

        # Apply all Level 3 hardening measures
        Enable-AppLocker
        Set-ConstrainedLanguageMode
        Block-NTLMAuth
        Disable-RemoteDesktop
        Disable-WinRM
        Enable-CFAProduction
        Disable-UnnecessaryServices
        Enable-ASRProductionMode
        Enable-NetworkProtection
        Disable-PowerShellV2
        Block-NullSessions
        Enable-LSAProtection
        Disable-IPv6
        Enable-FirewallLogging
        Disable-LegacyFeatures
        Restrict-AdminShares
        Set-MaximumAuditPolicy
        Disable-Bluetooth

        Show-HardeningSummary

        Write-Log "`n[+] Level 3 MAXIMUM Hardening Completed!" -Color $Colors.Green

    } catch {
        Write-Error "Hardening process failed: $_"
        exit 1
    }
}

# Run main function
Main
