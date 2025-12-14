<#
.SYNOPSIS
    Backup security settings before applying hardening changes.

.DESCRIPTION
    Creates comprehensive backups of security-related settings including:
    - System Restore Point
    - Registry exports for security policies
    - Current group policy settings
    - Windows Defender configuration
    - Firewall rules
    - User Account Control settings

    This script MUST be run before applying any hardening changes to enable rollback.

.PARAMETER BackupPath
    Directory where backup files will be stored. Defaults to .\backups\[timestamp]

.PARAMETER SkipRestorePoint
    Skip creation of system restore point (not recommended)

.PARAMETER RestorePointDescription
    Custom description for the system restore point

.EXAMPLE
    .\backup-security-settings.ps1
    Creates backup with default settings

.EXAMPLE
    .\backup-security-settings.ps1 -BackupPath "C:\SecurityBackups\20250112"
    Creates backup in custom location

.NOTES
    Author: Security Hardening Toolkit
    Requires: Administrator privileges
    Compatible: Windows 11 (tested on 24H2)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$BackupPath,

    [Parameter(Mandatory=$false)]
    [switch]$SkipRestorePoint,

    [Parameter(Mandatory=$false)]
    [string]$RestorePointDescription = "Security Hardening Backup - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
)

#Requires -RunAsAdministrator

# Color scheme
$Colors = @{
    Green  = 'Green'
    Yellow = 'Yellow'
    Red    = 'Red'
    Cyan   = 'Cyan'
    Blue   = 'Blue'
}

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

# Setup backup directory
function Initialize-BackupDirectory {
    if (-not $script:BackupPath) {
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $script:BackupPath = Join-Path $PSScriptRoot "backups\$timestamp"
    }

    if (-not (Test-Path $script:BackupPath)) {
        New-Item -Path $script:BackupPath -ItemType Directory -Force | Out-Null
        Write-Success "Created backup directory: $script:BackupPath"
    }

    # Create backup manifest
    $manifest = @{
        BackupDate = Get-Date -Format 'o'
        ComputerName = $env:COMPUTERNAME
        UserName = $env:USERNAME
        WindowsVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
        BuildNumber = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
        BackupPath = $script:BackupPath
    }

    $manifest | ConvertTo-Json | Set-Content (Join-Path $script:BackupPath "backup-manifest.json")
    Write-Info "Backup manifest created"
}

# Create System Restore Point
function New-SystemRestorePoint {
    if ($SkipRestorePoint) {
        Write-Warning "Skipping System Restore Point creation (not recommended)"
        return
    }

    Write-Info "Creating System Restore Point..."

    try {
        # Enable System Restore if not already enabled
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue

        # Create restore point
        Checkpoint-Computer -Description $RestorePointDescription -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop

        Write-Success "System Restore Point created: $RestorePointDescription"

        # Save restore point info to manifest
        $restorePoints = Get-ComputerRestorePoint | Select-Object -First 1
        $restoreInfo = @{
            Description = $RestorePointDescription
            CreationTime = $restorePoints.CreationTime
            SequenceNumber = $restorePoints.SequenceNumber
        }

        $restoreInfo | ConvertTo-Json | Set-Content (Join-Path $script:BackupPath "restore-point-info.json")

    } catch {
        Write-Error "Failed to create System Restore Point: $_"
        Write-Warning "Continuing with other backups..."
    }
}

# Backup Registry Keys
function Backup-RegistryKeys {
    Write-Info "Backing up registry security settings..."

    $registryKeys = @(
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"; Name = "Policies"},
        @{Path = "HKLM:\SOFTWARE\Policies"; Name = "SoftwarePolicies"},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"; Name = "SMB"},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "LSA"},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows Defender"; Name = "Defender"},
        @{Path = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"; Name = "Firewall"},
        @{Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"; Name = "WindowsUpdate"},
        @{Path = "HKLM:\SOFTWARE\Microsoft\PowerShell"; Name = "PowerShell"},
        @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies"; Name = "UserPolicies"}
    )

    $backupCount = 0
    foreach ($key in $registryKeys) {
        if (Test-Path $key.Path) {
            $exportPath = Join-Path $script:BackupPath "registry_$($key.Name).reg"
            try {
                $null = reg export $key.Path $exportPath /y 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Success "Backed up registry: $($key.Name)"
                    $backupCount++
                } else {
                    Write-Warning "Failed to backup registry: $($key.Name)"
                }
            } catch {
                Write-Warning "Error backing up $($key.Name): $_"
            }
        } else {
            Write-Info "Registry key not found (will be skipped): $($key.Path)"
        }
    }

    Write-Success "Backed up $backupCount registry keys"
}

# Backup Group Policy Settings
function Backup-GroupPolicy {
    Write-Info "Backing up Group Policy settings..."

    try {
        $gpResultPath = Join-Path $script:BackupPath "group-policy-report.html"
        gpresult /H $gpResultPath /F | Out-Null

        if (Test-Path $gpResultPath) {
            Write-Success "Group Policy report saved"
        }

        # Export local security policy
        $secpolPath = Join-Path $script:BackupPath "security-policy.inf"
        secedit /export /cfg $secpolPath /quiet

        if (Test-Path $secpolPath) {
            Write-Success "Security policy exported"
        }

    } catch {
        Write-Warning "Failed to backup Group Policy: $_"
    }
}

# Backup Windows Defender Settings
function Backup-DefenderSettings {
    Write-Info "Backing up Windows Defender settings..."

    try {
        $defenderPrefs = Get-MpPreference | Select-Object * -ExcludeProperty Cim*
        $defenderStatus = Get-MpComputerStatus | Select-Object * -ExcludeProperty Cim*

        $defenderBackup = @{
            Preferences = $defenderPrefs
            Status = $defenderStatus
            BackupDate = Get-Date -Format 'o'
        }

        $defenderPath = Join-Path $script:BackupPath "defender-settings.json"
        $defenderBackup | ConvertTo-Json -Depth 10 | Set-Content $defenderPath

        Write-Success "Windows Defender settings backed up"

    } catch {
        Write-Warning "Failed to backup Defender settings: $_"
    }
}

# Backup Firewall Rules
function Backup-FirewallRules {
    Write-Info "Backing up Windows Firewall rules..."

    try {
        $firewallPath = Join-Path $script:BackupPath "firewall-rules.wfw"
        netsh advfirewall export $firewallPath | Out-Null

        if (Test-Path $firewallPath) {
            Write-Success "Firewall rules exported"
        }

        # Also save firewall profiles as JSON
        $profiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, LogAllowed, LogBlocked
        $profilesPath = Join-Path $script:BackupPath "firewall-profiles.json"
        $profiles | ConvertTo-Json | Set-Content $profilesPath

        Write-Success "Firewall profiles backed up"

    } catch {
        Write-Warning "Failed to backup firewall rules: $_"
    }
}

# Backup UAC Settings
function Backup-UACSettings {
    Write-Info "Backing up UAC settings..."

    try {
        $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $uacSettings = Get-ItemProperty -Path $uacPath -ErrorAction Stop

        $uacBackup = @{
            ConsentPromptBehaviorAdmin = $uacSettings.ConsentPromptBehaviorAdmin
            ConsentPromptBehaviorUser = $uacSettings.ConsentPromptBehaviorUser
            EnableLUA = $uacSettings.EnableLUA
            PromptOnSecureDesktop = $uacSettings.PromptOnSecureDesktop
            EnableInstallerDetection = $uacSettings.EnableInstallerDetection
        }

        $uacBackupPath = Join-Path $script:BackupPath "uac-settings.json"
        $uacBackup | ConvertTo-Json | Set-Content $uacBackupPath

        Write-Success "UAC settings backed up"

    } catch {
        Write-Warning "Failed to backup UAC settings: $_"
    }
}

# Backup BitLocker Configuration
function Backup-BitLockerConfig {
    Write-Info "Backing up BitLocker configuration..."

    try {
        $bitlockerVolumes = Get-BitLockerVolume -ErrorAction Stop
        $bitlockerBackup = $bitlockerVolumes | Select-Object MountPoint, VolumeStatus, EncryptionPercentage, KeyProtector, ProtectionStatus

        $bitlockerPath = Join-Path $script:BackupPath "bitlocker-config.json"
        $bitlockerBackup | ConvertTo-Json | Set-Content $bitlockerPath

        Write-Success "BitLocker configuration backed up"

    } catch {
        Write-Info "BitLocker not configured or not available"
    }
}

# Create README for restore
function New-RestoreReadme {
    $readmeContent = @"
# Security Settings Backup - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

## Backup Information
- Computer: $env:COMPUTERNAME
- User: $env:USERNAME
- Backup Path: $script:BackupPath
- Windows Version: $((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName)

## Restore Instructions

### Quick Restore (Recommended)
Run the restore script from the security directory:
``````powershell
.\restore-security-settings.ps1 -BackupPath "$script:BackupPath"
``````

### Manual System Restore
1. Open System Restore: ``rstrui.exe``
2. Select restore point: "$RestorePointDescription"
3. Follow wizard to complete restore

### Manual Registry Restore
WARNING: Only restore if you understand registry implications!
``````powershell
reg import "$script:BackupPath\registry_[KeyName].reg"
``````

### Manual Firewall Restore
``````powershell
netsh advfirewall import "$script:BackupPath\firewall-rules.wfw"
``````

### Manual Security Policy Restore
``````powershell
secedit /configure /cfg "$script:BackupPath\security-policy.inf" /db secedit.sdb /verbose
``````

## Backup Contents
- System Restore Point: $RestorePointDescription
- Registry exports (security-related keys)
- Group Policy settings
- Windows Defender configuration
- Firewall rules and profiles
- UAC settings
- BitLocker configuration (if enabled)

## Important Notes
- Keep this backup until you've verified hardening changes work correctly
- Test restore procedure before relying on it
- Store backups in multiple locations for disaster recovery
- Regular backups recommended before system changes

Generated by: backup-security-settings.ps1
"@

    $readmePath = Join-Path $script:BackupPath "README.md"
    $readmeContent | Set-Content $readmePath -Encoding UTF8
    Write-Success "Restore instructions saved"
}

# Main execution
function Main {
    Write-Log "`n[*] Starting Security Settings Backup..." -Color $Colors.Cyan
    Write-Log "[*] ======================================`n" -Color $Colors.Cyan

    try {
        Initialize-BackupDirectory
        New-SystemRestorePoint
        Backup-RegistryKeys
        Backup-GroupPolicy
        Backup-DefenderSettings
        Backup-FirewallRules
        Backup-UACSettings
        Backup-BitLockerConfig
        New-RestoreReadme

        Write-Log "`n[+] ======================================" -Color $Colors.Green
        Write-Log "[+] Backup completed successfully!" -Color $Colors.Green
        Write-Log "[+] ======================================`n" -Color $Colors.Green

        Write-Info "Backup location: $script:BackupPath"
        Write-Info "Files backed up: $((Get-ChildItem $script:BackupPath).Count)"

        $backupSize = (Get-ChildItem $script:BackupPath -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
        Write-Info "Total backup size: $([math]::Round($backupSize, 2)) MB"

        Write-Log "`n[i] Next steps:" -Color $Colors.Cyan
        Write-Log "    1. Verify backup files in: $script:BackupPath" -Color $Colors.Cyan
        Write-Log "    2. Run audit script: .\audit-security-posture.ps1" -Color $Colors.Cyan
        Write-Log "    3. Apply hardening: .\harden-level1-safe.ps1" -Color $Colors.Cyan
        Write-Log "    4. Keep backup until changes are verified`n" -Color $Colors.Cyan

    } catch {
        Write-Error "Backup failed: $_"
        exit 1
    }
}

# Run main function
Main
