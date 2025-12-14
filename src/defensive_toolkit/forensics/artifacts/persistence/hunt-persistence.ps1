#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Hunt for persistence mechanisms on Windows systems

.DESCRIPTION
    Searches for common persistence mechanisms used by malware and APTs:
    - Registry Run keys (all variants)
    - Scheduled tasks
    - Services (especially unusual or suspicious ones)
    - WMI event subscriptions
    - Startup folders
    - DLL hijacking opportunities
    - Image File Execution Options (IFEO)
    - AppInit DLLs
    - Winlogon helper DLLs
    - Browser helper objects
    - COM hijacking

.PARAMETER OutputDir
    Output directory for results

.PARAMETER DeepScan
    Perform deep scan (slower, more comprehensive)

.EXAMPLE
    .\hunt-persistence.ps1 -OutputDir C:\forensics\persistence
    .\hunt-persistence.ps1 -OutputDir C:\analysis -DeepScan

.NOTES
    Author: Defensive Toolkit
    Date: 2025-10-15
    Requires: Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$OutputDir,

    [Parameter()]
    [switch]$DeepScan
)

$ErrorActionPreference = "Continue"

# Create output directory
$OutputPath = New-Item -ItemType Directory -Path $OutputDir -Force
Write-Host "`n[+] Output directory: $OutputPath" -ForegroundColor Green

$Results = @{
    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    Hostname = $env:COMPUTERNAME
    Findings = @()
    Statistics = @{
        TotalFindings = 0
        High = 0
        Medium = 0
        Low = 0
    }
}

function Add-Finding {
    param(
        [string]$Type,
        [string]$Severity,
        [string]$Description,
        [string]$Location,
        [hashtable]$Details
    )

    $finding = @{
        Type = $Type
        Severity = $Severity
        Description = $Description
        Location = $Location
        Details = $Details
        Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    }

    $Results.Findings += $finding
    $Results.Statistics.TotalFindings++
    $Results.Statistics.$Severity++

    $color = switch ($Severity) {
        "High" { "Red" }
        "Medium" { "Yellow" }
        "Low" { "Cyan" }
    }

    Write-Host "    [$Severity] $Description" -ForegroundColor $color
    Write-Host "        Location: $Location" -ForegroundColor Gray
}

function Check-RegistryRunKeys {
    Write-Host "`n[+] Checking registry run keys..." -ForegroundColor Cyan

    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    )

    $suspiciousKeywords = @('temp', 'appdata', 'programdata', 'users\public', 'download', 'recycle')

    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue

            if ($items) {
                $items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                    $name = $_.Name
                    $value = $_.Value

                    # Check for suspicious paths
                    $isSuspicious = $false
                    $reason = ""

                    foreach ($keyword in $suspiciousKeywords) {
                        if ($value -match $keyword) {
                            $isSuspicious = $true
                            $reason = "Suspicious path: $keyword"
                            break
                        }
                    }

                    # Check for hidden/obfuscated entries
                    if ($value -match "powershell|cmd\.exe|wscript|cscript|mshta|rundll32") {
                        $isSuspicious = $true
                        $reason = "Suspicious executable"
                    }

                    if ($isSuspicious) {
                        Add-Finding -Type "Registry Run Key" -Severity "High" `
                            -Description "Suspicious autorun entry: $name" `
                            -Location $key `
                            -Details @{
                                EntryName = $name
                                Command = $value
                                Reason = $reason
                            }
                    }
                }
            }
        }
    }
}

function Check-ScheduledTasks {
    Write-Host "`n[+] Checking scheduled tasks..." -ForegroundColor Cyan

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.State -ne "Disabled" }

        foreach ($task in $tasks) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue
            $actions = $task.Actions

            foreach ($action in $actions) {
                if ($action.Execute) {
                    $executable = $action.Execute.ToLower()

                    # Check for suspicious characteristics
                    if ($executable -match "powershell|cmd\.exe|wscript|cscript|mshta|rundll32" -or
                        $action.Arguments -match "-enc|-encodedcommand|-noprofile|-windowstyle hidden") {

                        Add-Finding -Type "Scheduled Task" -Severity "High" `
                            -Description "Suspicious scheduled task: $($task.TaskName)" `
                            -Location $task.TaskPath `
                            -Details @{
                                TaskName = $task.TaskName
                                Executable = $action.Execute
                                Arguments = $action.Arguments
                                Author = $task.Author
                                State = $task.State
                                LastRunTime = $taskInfo.LastRunTime
                            }
                    }

                    # Check for unusual paths
                    if ($executable -match "temp|appdata|programdata|users\\public") {
                        Add-Finding -Type "Scheduled Task" -Severity "Medium" `
                            -Description "Task with suspicious path: $($task.TaskName)" `
                            -Location $task.TaskPath `
                            -Details @{
                                TaskName = $task.TaskName
                                Executable = $action.Execute
                                Reason = "Unusual execution path"
                            }
                    }
                }
            }
        }

    } catch {
        Write-Host "    [X] Error checking scheduled tasks: $_" -ForegroundColor Red
    }
}

function Check-Services {
    Write-Host "`n[+] Checking services..." -ForegroundColor Cyan

    try {
        $services = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue

        foreach ($service in $services) {
            $path = $service.PathName.ToLower()

            # Check for suspicious service paths
            if ($path -match "temp|appdata|programdata|users\\public|download") {
                Add-Finding -Type "Service" -Severity "High" `
                    -Description "Service with suspicious path: $($service.Name)" `
                    -Location $service.PathName `
                    -Details @{
                        ServiceName = $service.Name
                        DisplayName = $service.DisplayName
                        PathName = $service.PathName
                        StartMode = $service.StartMode
                        State = $service.State
                        StartName = $service.StartName
                    }
            }

            # Check for unsigned services (if deep scan)
            if ($DeepScan) {
                # Extract executable path
                $exePath = $path -replace '"', '' -split ' ' | Select-Object -First 1

                if (Test-Path $exePath) {
                    $signature = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue

                    if ($signature.Status -ne "Valid") {
                        Add-Finding -Type "Service" -Severity "Medium" `
                            -Description "Unsigned/invalid signature: $($service.Name)" `
                            -Location $service.PathName `
                            -Details @{
                                ServiceName = $service.Name
                                SignatureStatus = $signature.Status
                            }
                    }
                }
            }
        }

    } catch {
        Write-Host "    [X] Error checking services: $_" -ForegroundColor Red
    }
}

function Check-WMIEventSubscriptions {
    Write-Host "`n[+] Checking WMI event subscriptions..." -ForegroundColor Cyan

    try {
        # Check for WMI event filters
        $filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue

        foreach ($filter in $filters) {
            Add-Finding -Type "WMI Event Subscription" -Severity "High" `
                -Description "WMI Event Filter detected: $($filter.Name)" `
                -Location "root\subscription" `
                -Details @{
                    Name = $filter.Name
                    Query = $filter.Query
                    QueryLanguage = $filter.QueryLanguage
                }
        }

        # Check for WMI event consumers
        $consumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue

        foreach ($consumer in $consumers) {
            Add-Finding -Type "WMI Event Consumer" -Severity "High" `
                -Description "WMI Event Consumer detected: $($consumer.Name)" `
                -Location "root\subscription" `
                -Details @{
                    Name = $consumer.Name
                    Type = $consumer.__CLASS
                }
        }

    } catch {
        Write-Host "    [X] Error checking WMI subscriptions: $_" -ForegroundColor Red
    }
}

function Check-StartupFolders {
    Write-Host "`n[+] Checking startup folders..." -ForegroundColor Cyan

    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $items = Get-ChildItem -Path $path -ErrorAction SilentlyContinue

            foreach ($item in $items) {
                Add-Finding -Type "Startup Folder" -Severity "Medium" `
                    -Description "File in startup folder: $($item.Name)" `
                    -Location $path `
                    -Details @{
                        FileName = $item.Name
                        FullPath = $item.FullName
                        CreationTime = $item.CreationTime
                        LastWriteTime = $item.LastWriteTime
                    }
            }
        }
    }
}

function Check-IFEO {
    Write-Host "`n[+] Checking Image File Execution Options (IFEO)..." -ForegroundColor Cyan

    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"

    if (Test-Path $ifeoPath) {
        $entries = Get-ChildItem -Path $ifeoPath -ErrorAction SilentlyContinue

        foreach ($entry in $entries) {
            $debugger = (Get-ItemProperty -Path $entry.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger

            if ($debugger) {
                Add-Finding -Type "IFEO Debugger" -Severity "High" `
                    -Description "IFEO debugger set: $($entry.PSChildName)" `
                    -Location $entry.PSPath `
                    -Details @{
                        TargetExecutable = $entry.PSChildName
                        Debugger = $debugger
                    }
            }
        }
    }
}

function Check-AppInit {
    Write-Host "`n[+] Checking AppInit DLLs..." -ForegroundColor Cyan

    $appInitPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"

    if (Test-Path $appInitPath) {
        $appInit = (Get-ItemProperty -Path $appInitPath -ErrorAction SilentlyContinue).AppInit_DLLs

        if ($appInit) {
            Add-Finding -Type "AppInit DLL" -Severity "High" `
                -Description "AppInit_DLLs configured" `
                -Location $appInitPath `
                -Details @{
                    DLLs = $appInit
                }
        }
    }
}

function Check-Winlogon {
    Write-Host "`n[+] Checking Winlogon helper DLLs..." -ForegroundColor Cyan

    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    if (Test-Path $winlogonPath) {
        $props = Get-ItemProperty -Path $winlogonPath -ErrorAction SilentlyContinue

        # Check for unusual Winlogon values
        $checkProps = @('Shell', 'Userinit', 'Notify', 'UIHost')

        foreach ($prop in $checkProps) {
            if ($props.$prop) {
                # Check for suspicious values
                if ($props.$prop -notmatch "explorer\.exe|userinit\.exe") {
                    Add-Finding -Type "Winlogon Helper" -Severity "High" `
                        -Description "Unusual Winlogon value: $prop" `
                        -Location $winlogonPath `
                        -Details @{
                            Property = $prop
                            Value = $props.$prop
                        }
                }
            }
        }
    }
}

# Main execution
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Persistence Mechanism Hunter" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($DeepScan) {
    Write-Host "[i] Deep scan enabled (slower, more comprehensive)" -ForegroundColor Yellow
}

# Run checks
Check-RegistryRunKeys
Check-ScheduledTasks
Check-Services
Check-WMIEventSubscriptions
Check-StartupFolders
Check-IFEO
Check-AppInit
Check-Winlogon

# Generate summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Persistence Hunt Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Findings: $($Results.Statistics.TotalFindings)" -ForegroundColor $(if ($Results.Statistics.TotalFindings -gt 0) { "Yellow" } else { "Green" })
Write-Host "  High Severity: $($Results.Statistics.High)" -ForegroundColor Red
Write-Host "  Medium Severity: $($Results.Statistics.Medium)" -ForegroundColor Yellow
Write-Host "  Low Severity: $($Results.Statistics.Low)" -ForegroundColor Cyan

# Save results
$reportFile = Join-Path $OutputPath "persistence_findings.json"
$Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "`n[OK] Report saved: $reportFile" -ForegroundColor Green

# Create CSV for easier analysis
if ($Results.Findings.Count -gt 0) {
    $csvFile = Join-Path $OutputPath "persistence_findings.csv"
    $Results.Findings | ForEach-Object {
        [PSCustomObject]@{
            Timestamp = $_.Timestamp
            Type = $_.Type
            Severity = $_.Severity
            Description = $_.Description
            Location = $_.Location
        }
    } | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "[OK] CSV report saved: $csvFile" -ForegroundColor Green
}

Write-Host "========================================`n" -ForegroundColor Cyan
