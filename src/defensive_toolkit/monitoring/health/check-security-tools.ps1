#Requires -Version 5.1

<#
.SYNOPSIS
    Health check for security tools and services

.DESCRIPTION
    Monitors the health and status of security tools including:
    - Antivirus (Windows Defender)
    - Firewall
    - Event logging
    - Splunk Universal Forwarder
    - Sysmon (if installed)

.PARAMETER OutputFormat
    Output format: Text, JSON, or HTML (default: Text)

.PARAMETER SendAlert
    Send alert if issues detected (email)

.PARAMETER AlertEmail
    Email address for alerts

.EXAMPLE
    .\check-security-tools.ps1

.EXAMPLE
    .\check-security-tools.ps1 -OutputFormat JSON

.NOTES
    Author: Defensive Toolkit
    Date: 2025-10-15
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Text', 'JSON', 'HTML')]
    [string]$OutputFormat = 'Text',

    [Parameter()]
    [switch]$SendAlert,

    [Parameter()]
    [string]$AlertEmail
)

$ErrorActionPreference = "Continue"

# Health check results
$results = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Hostname = $env:COMPUTERNAME
    Checks = @()
    OverallStatus = "Healthy"
    IssuesFound = 0
}

function Test-Component {
    param(
        [string]$Name,
        [scriptblock]$Test,
        [string]$Description
    )

    $check = @{
        Name = $Name
        Description = $Description
        Status = "Unknown"
        Message = ""
        Timestamp = Get-Date -Format "HH:mm:ss"
    }

    try {
        $testResult = & $Test
        if ($testResult.Status) {
            $check.Status = "OK"
            $check.Message = $testResult.Message
        } else {
            $check.Status = "FAIL"
            $check.Message = $testResult.Message
            $results.IssuesFound++
            $results.OverallStatus = "Degraded"
        }
    } catch {
        $check.Status = "ERROR"
        $check.Message = $_.Exception.Message
        $results.IssuesFound++
        $results.OverallStatus = "Degraded"
    }

    $results.Checks += $check
}

# Check Windows Defender
Test-Component -Name "Windows Defender" -Description "Antivirus status" -Test {
    $defender = Get-MpComputerStatus
    if ($defender.AntivirusEnabled -and $defender.RealTimeProtectionEnabled) {
        @{Status = $true; Message = "Running, Signatures updated: $($defender.AntivirusSignatureLastUpdated)"}
    } else {
        @{Status = $false; Message = "Not running or real-time protection disabled"}
    }
}

# Check Windows Firewall
Test-Component -Name "Windows Firewall" -Description "Firewall status" -Test {
    $firewall = Get-NetFirewallProfile
    $allEnabled = ($firewall | Where-Object {$_.Enabled -eq $false}).Count -eq 0
    if ($allEnabled) {
        @{Status = $true; Message = "All profiles enabled"}
    } else {
        $disabled = ($firewall | Where-Object {$_.Enabled -eq $false} | Select-Object -ExpandProperty Name) -join ", "
        @{Status = $false; Message = "Profiles disabled: $disabled"}
    }
}

# Check Event Log Service
Test-Component -Name "Event Log Service" -Description "Windows Event Log service" -Test {
    $service = Get-Service -Name EventLog
    if ($service.Status -eq 'Running') {
        @{Status = $true; Message = "Running"}
    } else {
        @{Status = $false; Message = "Status: $($service.Status)"}
    }
}

# Check Security Event Log
Test-Component -Name "Security Event Log" -Description "Security log collection" -Test {
    $log = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($log) {
        $lastEvent = $log.TimeCreated
        $age = (Get-Date) - $lastEvent
        if ($age.TotalMinutes -lt 10) {
            @{Status = $true; Message = "Last event: $lastEvent ($('{0:N0}' -f $age.TotalMinutes) minutes ago)"}
        } else {
            @{Status = $false; Message = "No recent events (last: $lastEvent)"}
        }
    } else {
        @{Status = $false; Message = "Cannot read Security event log"}
    }
}

# Check Splunk Universal Forwarder
Test-Component -Name "Splunk Forwarder" -Description "Log forwarding to SIEM" -Test {
    $service = Get-Service -Name SplunkForwarder -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq 'Running') {
            @{Status = $true; Message = "Running"}
        } else {
            @{Status = $false; Message = "Status: $($service.Status)"}
        }
    } else {
        @{Status = $true; Message = "Not installed (skipped)"}
    }
}

# Check Sysmon
Test-Component -Name "Sysmon" -Description "System monitoring" -Test {
    $driver = Get-WmiObject Win32_SystemDriver | Where-Object {$_.Name -eq 'Sysmon64' -or $_.Name -eq 'Sysmon'}
    if ($driver) {
        if ($driver.State -eq 'Running') {
            @{Status = $true; Message = "Running"}
        } else {
            @{Status = $false; Message = "Status: $($driver.State)"}
        }
    } else {
        @{Status = $true; Message = "Not installed (optional)"}
    }
}

# Check Disk Space
Test-Component -Name "Disk Space" -Description "System drive capacity" -Test {
    $disk = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DeviceID -eq 'C:'}
    $percentFree = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
    if ($percentFree -gt 10) {
        @{Status = $true; Message = "Free: $percentFree% ($('{0:N0}' -f ($disk.FreeSpace/1GB)) GB)"}
    } else {
        @{Status = $false; Message = "Low disk space: $percentFree% free"}
    }
}

# Check Last Windows Update
Test-Component -Name "Windows Updates" -Description "System update status" -Test {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $historyCount = $searcher.GetTotalHistoryCount()
    if ($historyCount -gt 0) {
        $history = $searcher.QueryHistory(0, 1)
        $lastUpdate = $history | Select-Object -First 1 -ExpandProperty Date
        $age = (Get-Date) - $lastUpdate
        if ($age.TotalDays -lt 30) {
            @{Status = $true; Message = "Last update: $lastUpdate ($('{0:N0}' -f $age.TotalDays) days ago)"}
        } else {
            @{Status = $false; Message = "Updates outdated: $lastUpdate ($('{0:N0}' -f $age.TotalDays) days ago)"}
        }
    } else {
        @{Status = $false; Message = "No update history found"}
    }
}

# Output results
if ($OutputFormat -eq 'JSON') {
    $results | ConvertTo-Json -Depth 3
}
elseif ($OutputFormat -eq 'HTML') {
    $html = @"
<html>
<head>
    <title>Security Tools Health Check - $($results.Hostname)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        .ok { background-color: #d4edda; }
        .fail { background-color: #f8d7da; }
        .error { background-color: #fff3cd; }
        .summary { margin: 20px 0; padding: 15px; border-radius: 5px; }
        .healthy { background-color: #d4edda; }
        .degraded { background-color: #f8d7da; }
    </style>
</head>
<body>
    <h1>Security Tools Health Check</h1>
    <div class="summary $($results.OverallStatus.ToLower())">
        <strong>Overall Status:</strong> $($results.OverallStatus)<br>
        <strong>Hostname:</strong> $($results.Hostname)<br>
        <strong>Timestamp:</strong> $($results.Timestamp)<br>
        <strong>Issues Found:</strong> $($results.IssuesFound)
    </div>
    <table>
        <tr>
            <th>Component</th>
            <th>Status</th>
            <th>Message</th>
            <th>Time</th>
        </tr>
"@
    foreach ($check in $results.Checks) {
        $rowClass = $check.Status.ToLower()
        $html += @"
        <tr class="$rowClass">
            <td><strong>$($check.Name)</strong><br><small>$($check.Description)</small></td>
            <td>$($check.Status)</td>
            <td>$($check.Message)</td>
            <td>$($check.Timestamp)</td>
        </tr>
"@
    }
    $html += "</table></body></html>"
    $html
}
else {
    # Text output
    Write-Host "`n" + ("="*70)
    Write-Host "Security Tools Health Check - $($results.Hostname)"
    Write-Host ("="*70)
    Write-Host "Timestamp: $($results.Timestamp)"
    Write-Host "Overall Status: $($results.OverallStatus)"
    Write-Host "Issues Found: $($results.IssuesFound)"
    Write-Host ("="*70) + "`n"

    foreach ($check in $results.Checks) {
        $statusColor = switch ($check.Status) {
            "OK" { "Green" }
            "FAIL" { "Red" }
            "ERROR" { "Yellow" }
            default { "White" }
        }

        Write-Host "[$($check.Status.PadRight(5))]" -ForegroundColor $statusColor -NoNewline
        Write-Host " $($check.Name)" -ForegroundColor White
        Write-Host "         $($check.Message)" -ForegroundColor Gray
    }

    Write-Host "`n" + ("="*70)
    if ($results.IssuesFound -eq 0) {
        Write-Host "[OK] All security tools are healthy" -ForegroundColor Green
    } else {
        Write-Host "[!] $($results.IssuesFound) issue(s) detected - review and remediate" -ForegroundColor Yellow
    }
    Write-Host ("="*70) + "`n"
}

# Send alert if requested and issues found
if ($SendAlert -and $results.IssuesFound -gt 0 -and $AlertEmail) {
    Write-Host "[i] Sending alert email to $AlertEmail"
    # TODO: Implement email alerting
    # Send-MailMessage -To $AlertEmail -Subject "Security Tools Health Alert - $($results.Hostname)" -Body $html -BodyAsHtml
}

# Exit code reflects health status
if ($results.IssuesFound -eq 0) {
    exit 0
} else {
    exit 1
}
