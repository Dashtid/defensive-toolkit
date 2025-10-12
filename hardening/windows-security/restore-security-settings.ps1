<#
.SYNOPSIS
    Restore security settings from a previous backup.

.DESCRIPTION
    Restores security settings from a backup created by backup-security-settings.ps1.
    Can perform full restore or selective restore of specific components.

    Restore capabilities:
    - System Restore Point rollback
    - Registry keys
    - Group Policy settings
    - Windows Defender configuration
    - Firewall rules
    - UAC settings

.PARAMETER BackupPath
    Path to the backup directory containing the backup files

.PARAMETER RestoreComponents
    Specific components to restore. Options: Registry, GroupPolicy, Defender, Firewall, UAC
    If not specified, will prompt for each component

.PARAMETER Force
    Skip confirmation prompts (use with caution)

.PARAMETER UseSystemRestore
    Use System Restore instead of manual restoration (recommended for full rollback)

.EXAMPLE
    .\restore-security-settings.ps1 -BackupPath ".\backups\20250112_143000"
    Restore with interactive prompts

.EXAMPLE
    .\restore-security-settings.ps1 -BackupPath ".\backups\20250112_143000" -RestoreComponents Registry,Firewall
    Restore only registry and firewall settings

.EXAMPLE
    .\restore-security-settings.ps1 -BackupPath ".\backups\20250112_143000" -UseSystemRestore
    Use Windows System Restore to rollback all changes

.NOTES
    Author: Security Hardening Toolkit
    Requires: Administrator privileges
    Compatible: Windows 11 (tested on 24H2)
    WARNING: Restoring settings will overwrite current configuration
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$BackupPath,

    [Parameter(Mandatory=$false)]
    [ValidateSet('Registry', 'GroupPolicy', 'Defender', 'Firewall', 'UAC', 'All')]
    [string[]]$RestoreComponents,

    [Parameter(Mandatory=$false)]
    [switch]$Force,

    [Parameter(Mandatory=$false)]
    [switch]$UseSystemRestore
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

# Validate backup directory
function Test-BackupDirectory {
    if (-not (Test-Path $BackupPath)) {
        Write-Error "Backup directory not found: $BackupPath"
        exit 1
    }

    $manifestPath = Join-Path $BackupPath "backup-manifest.json"
    if (-not (Test-Path $manifestPath)) {
        Write-Error "Invalid backup directory: manifest file not found"
        exit 1
    }

    try {
        $script:manifest = Get-Content $manifestPath | ConvertFrom-Json
        Write-Info "Backup found:"
        Write-Info "  Date: $($script:manifest.BackupDate)"
        Write-Info "  Computer: $($script:manifest.ComputerName)"
        Write-Info "  User: $($script:manifest.UserName)"
        Write-Info "  Windows: $($script:manifest.WindowsVersion) (Build $($script:manifest.BuildNumber))"

        # Warn if restoring from different computer
        if ($script:manifest.ComputerName -ne $env:COMPUTERNAME) {
            Write-Warning "Backup was created on a different computer: $($script:manifest.ComputerName)"
            if (-not $Force) {
                $continue = Read-Host "Continue anyway? (yes/no)"
                if ($continue -ne 'yes') {
                    Write-Info "Restore cancelled"
                    exit 0
                }
            }
        }

    } catch {
        Write-Error "Failed to read backup manifest: $_"
        exit 1
    }
}

# Restore using System Restore
function Invoke-SystemRestore {
    Write-Info "Launching System Restore wizard..."

    $restoreInfoPath = Join-Path $BackupPath "restore-point-info.json"
    if (Test-Path $restoreInfoPath) {
        $restoreInfo = Get-Content $restoreInfoPath | ConvertFrom-Json
        Write-Info "Restore point: $($restoreInfo.Description)"
        Write-Info "Created: $($restoreInfo.CreationTime)"
        Write-Info "Sequence: $($restoreInfo.SequenceNumber)"
    }

    Write-Warning "`nSystem Restore will:"
    Write-Warning "  - Restart your computer"
    Write-Warning "  - Restore all system settings to backup date"
    Write-Warning "  - Keep personal files intact"

    if (-not $Force) {
        $confirm = Read-Host "`nProceed with System Restore? (yes/no)"
        if ($confirm -ne 'yes') {
            Write-Info "System Restore cancelled"
            return
        }
    }

    # Launch System Restore GUI
    Start-Process "rstrui.exe" -Wait
    Write-Info "System Restore completed (or cancelled by user)"
}

# Restore Registry Keys
function Restore-RegistryKeys {
    Write-Info "Restoring registry keys..."

    $regFiles = Get-ChildItem -Path $BackupPath -Filter "registry_*.reg"

    if ($regFiles.Count -eq 0) {
        Write-Warning "No registry backup files found"
        return
    }

    Write-Info "Found $($regFiles.Count) registry backup files"

    foreach ($regFile in $regFiles) {
        $keyName = $regFile.Name -replace 'registry_', '' -replace '\.reg', ''

        if (-not $Force) {
            $restore = Read-Host "Restore registry key: $keyName? (yes/no/all)"
            if ($restore -eq 'no') { continue }
            if ($restore -eq 'all') { $script:Force = $true }
        }

        try {
            Write-Info "Restoring: $keyName..."
            $result = reg import $regFile.FullName 2>&1

            if ($LASTEXITCODE -eq 0) {
                Write-Success "Restored: $keyName"
            } else {
                Write-Error "Failed to restore $keyName : $result"
            }
        } catch {
            Write-Error "Error restoring $keyName : $_"
        }
    }

    Write-Success "Registry restore completed"
}

# Restore Group Policy
function Restore-GroupPolicy {
    Write-Info "Restoring Group Policy settings..."

    $secpolPath = Join-Path $BackupPath "security-policy.inf"

    if (-not (Test-Path $secpolPath)) {
        Write-Warning "Security policy backup not found"
        return
    }

    try {
        Write-Info "Importing security policy..."
        $result = secedit /configure /cfg $secpolPath /db secedit.sdb /verbose 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Success "Security policy restored"

            # Force Group Policy update
            Write-Info "Updating Group Policy..."
            gpupdate /force | Out-Null
            Write-Success "Group Policy updated"
        } else {
            Write-Error "Failed to restore security policy: $result"
        }

    } catch {
        Write-Error "Error restoring Group Policy: $_"
    }
}

# Restore Windows Defender Settings
function Restore-DefenderSettings {
    Write-Info "Restoring Windows Defender settings..."

    $defenderPath = Join-Path $BackupPath "defender-settings.json"

    if (-not (Test-Path $defenderPath)) {
        Write-Warning "Defender settings backup not found"
        return
    }

    try {
        $defenderBackup = Get-Content $defenderPath | ConvertFrom-Json
        $prefs = $defenderBackup.Preferences

        Write-Info "Restoring Defender preferences..."

        # Restore key settings
        if ($null -ne $prefs.DisableRealtimeMonitoring) {
            Set-MpPreference -DisableRealtimeMonitoring $prefs.DisableRealtimeMonitoring
        }
        if ($null -ne $prefs.DisableBehaviorMonitoring) {
            Set-MpPreference -DisableBehaviorMonitoring $prefs.DisableBehaviorMonitoring
        }
        if ($null -ne $prefs.DisableBlockAtFirstSeen) {
            Set-MpPreference -DisableBlockAtFirstSeen $prefs.DisableBlockAtFirstSeen
        }
        if ($null -ne $prefs.DisableIOAVProtection) {
            Set-MpPreference -DisableIOAVProtection $prefs.DisableIOAVProtection
        }
        if ($null -ne $prefs.DisableScriptScanning) {
            Set-MpPreference -DisableScriptScanning $prefs.DisableScriptScanning
        }
        if ($null -ne $prefs.PUAProtection) {
            Set-MpPreference -PUAProtection $prefs.PUAProtection
        }

        Write-Success "Windows Defender settings restored"

    } catch {
        Write-Error "Failed to restore Defender settings: $_"
    }
}

# Restore Firewall Rules
function Restore-FirewallRules {
    Write-Info "Restoring Windows Firewall rules..."

    $firewallPath = Join-Path $BackupPath "firewall-rules.wfw"

    if (-not (Test-Path $firewallPath)) {
        Write-Warning "Firewall rules backup not found"
        return
    }

    try {
        Write-Info "Importing firewall rules..."
        netsh advfirewall import $firewallPath | Out-Null

        if ($LASTEXITCODE -eq 0) {
            Write-Success "Firewall rules restored"
        } else {
            Write-Error "Failed to restore firewall rules"
        }

        # Restore firewall profiles
        $profilesPath = Join-Path $BackupPath "firewall-profiles.json"
        if (Test-Path $profilesPath) {
            $profiles = Get-Content $profilesPath | ConvertFrom-Json

            foreach ($profile in $profiles) {
                Set-NetFirewallProfile -Name $profile.Name `
                    -Enabled $profile.Enabled `
                    -DefaultInboundAction $profile.DefaultInboundAction `
                    -DefaultOutboundAction $profile.DefaultOutboundAction `
                    -AllowInboundRules $profile.AllowInboundRules `
                    -LogAllowed $profile.LogAllowed `
                    -LogBlocked $profile.LogBlocked `
                    -ErrorAction SilentlyContinue
            }

            Write-Success "Firewall profiles restored"
        }

    } catch {
        Write-Error "Error restoring firewall rules: $_"
    }
}

# Restore UAC Settings
function Restore-UACSettings {
    Write-Info "Restoring UAC settings..."

    $uacPath = Join-Path $BackupPath "uac-settings.json"

    if (-not (Test-Path $uacPath)) {
        Write-Warning "UAC settings backup not found"
        return
    }

    try {
        $uacBackup = Get-Content $uacPath | ConvertFrom-Json
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

        Write-Info "Applying UAC settings..."

        Set-ItemProperty -Path $regPath -Name "ConsentPromptBehaviorAdmin" -Value $uacBackup.ConsentPromptBehaviorAdmin -ErrorAction Stop
        Set-ItemProperty -Path $regPath -Name "ConsentPromptBehaviorUser" -Value $uacBackup.ConsentPromptBehaviorUser -ErrorAction Stop
        Set-ItemProperty -Path $regPath -Name "EnableLUA" -Value $uacBackup.EnableLUA -ErrorAction Stop
        Set-ItemProperty -Path $regPath -Name "PromptOnSecureDesktop" -Value $uacBackup.PromptOnSecureDesktop -ErrorAction Stop

        if ($null -ne $uacBackup.EnableInstallerDetection) {
            Set-ItemProperty -Path $regPath -Name "EnableInstallerDetection" -Value $uacBackup.EnableInstallerDetection -ErrorAction Stop
        }

        Write-Success "UAC settings restored"
        Write-Warning "UAC changes require system restart to take effect"

    } catch {
        Write-Error "Failed to restore UAC settings: $_"
    }
}

# Confirm restore operation
function Confirm-RestoreOperation {
    Write-Log "`n[!] WARNING: RESTORE OPERATION" -Color $Colors.Yellow
    Write-Log "[!] ==========================================`n" -Color $Colors.Yellow

    Write-Warning "This will restore security settings from backup:"
    Write-Warning "  Backup Date: $($script:manifest.BackupDate)"
    Write-Warning "  Backup Path: $BackupPath"

    if ($RestoreComponents) {
        Write-Warning "  Components: $($RestoreComponents -join ', ')"
    } else {
        Write-Warning "  Components: All (with prompts)"
    }

    Write-Warning "`nCurrent settings will be OVERWRITTEN!"

    if (-not $Force) {
        Write-Host "`n"
        $confirm = Read-Host "Type 'RESTORE' to continue"
        if ($confirm -ne 'RESTORE') {
            Write-Info "Restore cancelled"
            exit 0
        }
    }
}

# Main execution
function Main {
    Write-Log "`n[*] Security Settings Restore Tool" -Color $Colors.Cyan
    Write-Log "[*] ======================================`n" -Color $Colors.Cyan

    try {
        Test-BackupDirectory

        # Use System Restore if requested
        if ($UseSystemRestore) {
            Invoke-SystemRestore
            exit 0
        }

        Confirm-RestoreOperation

        Write-Log "`n[*] Starting restore process...`n" -Color $Colors.Cyan

        # Determine which components to restore
        $componentsToRestore = if ($RestoreComponents -contains 'All') {
            @('Registry', 'GroupPolicy', 'Defender', 'Firewall', 'UAC')
        } elseif ($RestoreComponents) {
            $RestoreComponents
        } else {
            @('Registry', 'GroupPolicy', 'Defender', 'Firewall', 'UAC')
        }

        # Restore each component
        foreach ($component in $componentsToRestore) {
            switch ($component) {
                'Registry'    { Restore-RegistryKeys }
                'GroupPolicy' { Restore-GroupPolicy }
                'Defender'    { Restore-DefenderSettings }
                'Firewall'    { Restore-FirewallRules }
                'UAC'         { Restore-UACSettings }
            }
        }

        Write-Log "`n[+] ======================================" -Color $Colors.Green
        Write-Log "[+] Restore completed!" -Color $Colors.Green
        Write-Log "[+] ======================================`n" -Color $Colors.Green

        Write-Warning "IMPORTANT: Some changes may require a system restart"
        Write-Info "Verify settings with: .\audit-security-posture.ps1"

    } catch {
        Write-Error "Restore failed: $_"
        exit 1
    }
}

# Run main function
Main
