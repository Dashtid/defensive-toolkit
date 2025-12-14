#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows Incident Response Triage Script

.DESCRIPTION
    Collects volatile and non-volatile data from Windows systems for incident response.
    Gathers system information, running processes, network connections, registry artifacts,
    event logs, and other forensic data.

.PARAMETER OutputDir
    Directory to save collected artifacts (default: C:\IR\Triage)

.PARAMETER Quick
    Perform quick triage (volatile data only, faster)

.PARAMETER Full
    Perform full triage (all artifacts, slower)

.PARAMETER ComputerName
    Target computer name for remote collection (default: localhost)

.EXAMPLE
    .\windows-triage.ps1 -OutputDir C:\Evidence -Quick

.EXAMPLE
    .\windows-triage.ps1 -Full -OutputDir \\fileserver\IR\Case123

.NOTES
    Author: Defensive Toolkit
    Date: 2025-10-15
    Version: 1.0

    WARNING: This script collects sensitive system information.
    Ensure proper authorization before running.
    Follow chain of custody procedures for evidence handling.
#>

[CmdletBinding(DefaultParameterSetName = 'Standard')]
param(
    [Parameter()]
    [string]$OutputDir = "C:\IR\Triage",

    [Parameter(ParameterSetName = 'Quick')]
    [switch]$Quick,

    [Parameter(ParameterSetName = 'Full')]
    [switch]$Full,

    [Parameter()]
    [string]$ComputerName = $env:COMPUTERNAME
)

# Script configuration
$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$triageDir = Join-Path $OutputDir "$ComputerName`_$timestamp"

# Create output directory
Write-Host "[+] Creating triage directory: $triageDir"
New-Item -Path $triageDir -ItemType Directory -Force | Out-Null

# Logging function
function Write-Log {
    param([string]$Message, [string]$Type = "INFO")
    $logMessage = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Type, $Message
    Write-Host $logMessage
    Add-Content -Path (Join-Path $triageDir "triage.log") -Value $logMessage
}

Write-Log "Starting Windows IR triage collection" "INFO"
Write-Log "Target: $ComputerName" "INFO"
Write-Log "Mode: $(if($Quick){'Quick'}elseif($Full){'Full'}else{'Standard'})" "INFO"

# Create manifest file
$manifest = @{
    CollectionTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    ComputerName = $ComputerName
    Hostname = $env:COMPUTERNAME
    Username = $env:USERNAME
    Domain = $env:USERDOMAIN
    ScriptVersion = "1.0"
    CollectionMode = $(if($Quick){'Quick'}elseif($Full){'Full'}else{'Standard'})
    Artifacts = @()
}

#region Volatile Data Collection

Write-Log "Collecting volatile data..." "INFO"

# System information
try {
    Write-Log "Collecting system information"
    Get-ComputerInfo | ConvertTo-Json | Out-File (Join-Path $triageDir "system_info.json")
    $manifest.Artifacts += "system_info.json"
} catch {
    Write-Log "Error collecting system information: $_" "ERROR"
}

# Running processes
try {
    Write-Log "Collecting running processes"
    Get-Process | Select-Object Name, Id, Path, Company, ProductVersion, StartTime, CPU, WorkingSet, Threads |
        Export-Csv (Join-Path $triageDir "processes.csv") -NoTypeInformation

    # Detailed process information with command lines
    Get-WmiObject Win32_Process | Select-Object ProcessId, Name, CommandLine, CreationDate, ParentProcessId |
        Export-Csv (Join-Path $triageDir "processes_detailed.csv") -NoTypeInformation

    $manifest.Artifacts += @("processes.csv", "processes_detailed.csv")
} catch {
    Write-Log "Error collecting processes: $_" "ERROR"
}

# Network connections
try {
    Write-Log "Collecting network connections"
    Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, CreationTime |
        Export-Csv (Join-Path $triageDir "network_tcp_connections.csv") -NoTypeInformation

    Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess, CreationTime |
        Export-Csv (Join-Path $triageDir "network_udp_endpoints.csv") -NoTypeInformation

    $manifest.Artifacts += @("network_tcp_connections.csv", "network_udp_endpoints.csv")
} catch {
    Write-Log "Error collecting network connections: $_" "ERROR"
}

# DNS cache
try {
    Write-Log "Collecting DNS cache"
    Get-DnsClientCache | Select-Object Entry, RecordName, RecordType, Status, Data, TimeToLive |
        Export-Csv (Join-Path $triageDir "dns_cache.csv") -NoTypeInformation
    $manifest.Artifacts += "dns_cache.csv"
} catch {
    Write-Log "Error collecting DNS cache: $_" "ERROR"
}

# ARP cache
try {
    Write-Log "Collecting ARP cache"
    Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias |
        Export-Csv (Join-Path $triageDir "arp_cache.csv") -NoTypeInformation
    $manifest.Artifacts += "arp_cache.csv"
} catch {
    Write-Log "Error collecting ARP cache: $_" "ERROR"
}

# Logged on users
try {
    Write-Log "Collecting logged on users"
    query user 2>&1 | Out-File (Join-Path $triageDir "logged_on_users.txt")
    $manifest.Artifacts += "logged_on_users.txt"
} catch {
    Write-Log "Error collecting logged on users: $_" "ERROR"
}

# Loaded DLLs (top 20 processes by CPU)
try {
    Write-Log "Collecting loaded DLLs"
    Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 | ForEach-Object {
        try {
            $proc = $_
            $_.Modules | Select-Object @{N='ProcessName';E={$proc.Name}}, @{N='ProcessId';E={$proc.Id}}, ModuleName, FileName, Size |
                Export-Csv (Join-Path $triageDir "loaded_dlls.csv") -NoTypeInformation -Append
        } catch {}
    }
    $manifest.Artifacts += "loaded_dlls.csv"
} catch {
    Write-Log "Error collecting loaded DLLs: $_" "ERROR"
}

#endregion

#region Registry Artifacts

if (-not $Quick) {
    Write-Log "Collecting registry artifacts..." "INFO"

    # AutoRun locations
    try {
        Write-Log "Collecting AutoRun registry keys"
        $autorunPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        )

        $autoruns = @()
        foreach ($path in $autorunPaths) {
            if (Test-Path $path) {
                Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | ForEach-Object {
                    $props = $_ | Get-Member -MemberType NoteProperty | Where-Object {$_.Name -notlike 'PS*'}
                    foreach ($prop in $props) {
                        $autoruns += [PSCustomObject]@{
                            Location = $path
                            Name = $prop.Name
                            Value = $_."$($prop.Name)"
                        }
                    }
                }
            }
        }
        $autoruns | Export-Csv (Join-Path $triageDir "registry_autoruns.csv") -NoTypeInformation
        $manifest.Artifacts += "registry_autoruns.csv"
    } catch {
        Write-Log "Error collecting AutoRun keys: $_" "ERROR"
    }

    # Recently accessed files (MRU)
    try {
        Write-Log "Collecting recent file access (MRU)"
        $mruPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        if (Test-Path $mruPath) {
            Get-ChildItem -Path $mruPath -Recurse | ForEach-Object {
                Get-ItemProperty -Path $_.PSPath | Out-File (Join-Path $triageDir "registry_mru.txt") -Append
            }
            $manifest.Artifacts += "registry_mru.txt"
        }
    } catch {
        Write-Log "Error collecting MRU: $_" "ERROR"
    }
}

#endregion

#region System Artifacts

if (-not $Quick) {
    Write-Log "Collecting system artifacts..." "INFO"

    # Scheduled tasks
    try {
        Write-Log "Collecting scheduled tasks"
        Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} |
            Select-Object TaskName, TaskPath, State, @{N='Author';E={($_ | Get-ScheduledTaskInfo).Author}},
                         @{N='LastRunTime';E={($_ | Get-ScheduledTaskInfo).LastRunTime}},
                         @{N='NextRunTime';E={($_ | Get-ScheduledTaskInfo).NextRunTime}} |
            Export-Csv (Join-Path $triageDir "scheduled_tasks.csv") -NoTypeInformation
        $manifest.Artifacts += "scheduled_tasks.csv"
    } catch {
        Write-Log "Error collecting scheduled tasks: $_" "ERROR"
    }

    # Services
    try {
        Write-Log "Collecting services"
        Get-Service | Select-Object Name, DisplayName, Status, StartType, @{N='PathName';E={(Get-WmiObject Win32_Service -Filter "Name='$($_.Name)'").PathName}} |
            Export-Csv (Join-Path $triageDir "services.csv") -NoTypeInformation
        $manifest.Artifacts += "services.csv"
    } catch {
        Write-Log "Error collecting services: $_" "ERROR"
    }

    # Drivers
    try {
        Write-Log "Collecting drivers"
        Get-WindowsDriver -Online | Select-Object Driver, OriginalFileName, Inbox, ClassName, ProviderName, Date, Version |
            Export-Csv (Join-Path $triageDir "drivers.csv") -NoTypeInformation
        $manifest.Artifacts += "drivers.csv"
    } catch {
        Write-Log "Error collecting drivers: $_" "ERROR"
    }

    # Installed software
    try {
        Write-Log "Collecting installed software"
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation |
            Export-Csv (Join-Path $triageDir "installed_software.csv") -NoTypeInformation
        $manifest.Artifacts += "installed_software.csv"
    } catch {
        Write-Log "Error collecting installed software: $_" "ERROR"
    }

    # Firewall rules
    try {
        Write-Log "Collecting firewall rules"
        Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true} |
            Select-Object Name, DisplayName, Direction, Action, Profile, Enabled |
            Export-Csv (Join-Path $triageDir "firewall_rules.csv") -NoTypeInformation
        $manifest.Artifacts += "firewall_rules.csv"
    } catch {
        Write-Log "Error collecting firewall rules: $_" "ERROR"
    }
}

#endregion

#region Event Logs

if ($Full) {
    Write-Log "Collecting event logs..." "INFO"

    $logs = @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational',
              'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-Windows Defender/Operational')

    foreach ($log in $logs) {
        try {
            $logName = $log -replace '[/\\]', '_'
            Write-Log "Collecting $log event log"

            $events = Get-WinEvent -LogName $log -MaxEvents 1000 -ErrorAction SilentlyContinue
            if ($events) {
                $events | Select-Object TimeCreated, Id, LevelDisplayName, Message |
                    Export-Csv (Join-Path $triageDir "eventlog_$logName.csv") -NoTypeInformation
                $manifest.Artifacts += "eventlog_$logName.csv"
            }
        } catch {
            Write-Log "Error collecting $log event log: $_" "WARN"
        }
    }
}

#endregion

#region File System Artifacts

if ($Full) {
    Write-Log "Collecting file system artifacts..." "INFO"

    # Recent file modifications
    try {
        Write-Log "Collecting recent file modifications"
        Get-ChildItem -Path "C:\Users" -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} |
            Select-Object FullName, CreationTime, LastWriteTime, LastAccessTime, Length |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 500 |
            Export-Csv (Join-Path $triageDir "recent_file_modifications.csv") -NoTypeInformation
        $manifest.Artifacts += "recent_file_modifications.csv"
    } catch {
        Write-Log "Error collecting recent file modifications: $_" "ERROR"
    }

    # Prefetch files (if accessible)
    try {
        Write-Log "Listing prefetch files"
        if (Test-Path "C:\Windows\Prefetch") {
            Get-ChildItem -Path "C:\Windows\Prefetch\*.pf" -ErrorAction SilentlyContinue |
                Select-Object Name, CreationTime, LastWriteTime, LastAccessTime, Length |
                Export-Csv (Join-Path $triageDir "prefetch_files.csv") -NoTypeInformation
            $manifest.Artifacts += "prefetch_files.csv"
        }
    } catch {
        Write-Log "Error collecting prefetch files: $_" "ERROR"
    }
}

#endregion

# Save manifest
$manifest | ConvertTo-Json -Depth 3 | Out-File (Join-Path $triageDir "triage_manifest.json")

# Create collection summary
$summary = @"
Windows IR Triage Collection Summary
=====================================
Collection Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Computer Name: $ComputerName
Collection Mode: $(if($Quick){'Quick'}elseif($Full){'Full'}else{'Standard'})
Output Directory: $triageDir
Artifacts Collected: $($manifest.Artifacts.Count)

Artifacts:
$($manifest.Artifacts | ForEach-Object { "  - $_" } | Out-String)

Collection completed successfully.
"@

$summary | Out-File (Join-Path $triageDir "COLLECTION_SUMMARY.txt")
Write-Host $summary

Write-Log "Triage collection completed" "INFO"
Write-Log "Output directory: $triageDir" "INFO"
Write-Host "`n[OK] Triage collection completed successfully."
Write-Host "[OK] Review artifacts in: $triageDir"
Write-Host "`n[!] IMPORTANT: Maintain proper chain of custody for all collected evidence."
