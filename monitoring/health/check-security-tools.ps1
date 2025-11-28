#Requires -Version 5.1

<#
.SYNOPSIS
    Health check for security tools and services with email alerting

.DESCRIPTION
    Monitors the health and status of security tools including:
    - Antivirus (Windows Defender)
    - Firewall
    - Event logging
    - Splunk Universal Forwarder
    - Sysmon (if installed)
    - Disk Space
    - Windows Updates

    Optionally sends HTML email alerts when issues are detected.

.PARAMETER OutputFormat
    Output format: Text, JSON, or HTML (default: Text)

.PARAMETER SendAlert
    Send email alert if issues detected

.PARAMETER AlertEmail
    Recipient email address for alerts (required if SendAlert is specified)

.PARAMETER FromEmail
    Sender email address (required if SendAlert is specified)

.PARAMETER SmtpServer
    SMTP server hostname or IP (required if SendAlert is specified)

.PARAMETER SmtpPort
    SMTP server port (default: 587 for TLS, 25 for non-TLS)

.PARAMETER UseSSL
    Use TLS/SSL for SMTP connection (recommended for security)

.PARAMETER SmtpCredential
    PSCredential object for SMTP authentication (optional)

.PARAMETER AlertOnWarning
    Also send alerts for warnings, not just failures (default: false)

.EXAMPLE
    .\check-security-tools.ps1
    # Basic health check with console output

.EXAMPLE
    .\check-security-tools.ps1 -OutputFormat JSON
    # Output results as JSON

.EXAMPLE
    .\check-security-tools.ps1 -OutputFormat HTML > report.html
    # Generate HTML report

.EXAMPLE
    .\check-security-tools.ps1 -SendAlert -AlertEmail "security@company.com" -FromEmail "monitor@company.com" -SmtpServer "smtp.company.com"
    # Send email alert on failures

.EXAMPLE
    $cred = Get-Credential
    .\check-security-tools.ps1 -SendAlert -AlertEmail "security@company.com" -FromEmail "monitor@company.com" -SmtpServer "smtp.office365.com" -SmtpPort 587 -UseSSL -SmtpCredential $cred
    # Send email via Office 365 with authentication

.EXAMPLE
    .\check-security-tools.ps1 -SendAlert -AlertEmail "admin@company.com" -FromEmail "healthcheck@company.com" -SmtpServer "mail.company.com" -AlertOnWarning
    # Send alerts for both failures and warnings

.NOTES
    Author: Defensive Toolkit
    Date: 2025-10-15
    Updated: 2025-11-28
    Version: 1.1.0

    SMTP NOTE: Send-MailMessage is deprecated but remains the most compatible
    option for enterprise environments. For Microsoft 365, consider using
    Microsoft Graph API (Send-MgUserMail) or MailKit for modern authentication.
    See: https://aka.ms/smtpclientapiobsoleteinfo
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Text', 'JSON', 'HTML')]
    [string]$OutputFormat = 'Text',

    [Parameter()]
    [switch]$SendAlert,

    [Parameter()]
    [ValidatePattern('^[\w\.\-]+@[\w\.\-]+\.\w+$')]
    [string]$AlertEmail,

    [Parameter()]
    [ValidatePattern('^[\w\.\-]+@[\w\.\-]+\.\w+$')]
    [string]$FromEmail,

    [Parameter()]
    [string]$SmtpServer,

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$SmtpPort = 587,

    [Parameter()]
    [switch]$UseSSL,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $SmtpCredential,

    [Parameter()]
    [switch]$AlertOnWarning
)

$ErrorActionPreference = "Continue"

# Validate email parameters if SendAlert is specified
if ($SendAlert) {
    $missingParams = @()
    if (-not $AlertEmail) { $missingParams += "AlertEmail" }
    if (-not $FromEmail) { $missingParams += "FromEmail" }
    if (-not $SmtpServer) { $missingParams += "SmtpServer" }

    if ($missingParams.Count -gt 0) {
        Write-Error "SendAlert requires the following parameters: $($missingParams -join ', ')"
        Write-Host "[!] Example: .\check-security-tools.ps1 -SendAlert -AlertEmail 'admin@company.com' -FromEmail 'monitor@company.com' -SmtpServer 'smtp.company.com' -UseSSL" -ForegroundColor Yellow
        exit 1
    }
}

function Send-AlertEmail {
    <#
    .SYNOPSIS
        Sends an HTML email alert with health check results
    .DESCRIPTION
        Generates and sends an HTML-formatted email containing the security
        health check results. Uses Send-MailMessage with optional TLS/SSL.
    .NOTES
        Send-MailMessage is deprecated but remains widely compatible.
        For modern auth (OAuth2), consider MailKit or Microsoft Graph.
    #>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Results,

        [Parameter(Mandatory)]
        [string]$To,

        [Parameter(Mandatory)]
        [string]$From,

        [Parameter(Mandatory)]
        [string]$Server,

        [Parameter()]
        [int]$Port = 587,

        [Parameter()]
        [switch]$SSL,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    # Build HTML email body
    $statusColor = if ($Results.OverallStatus -eq "Healthy") { "#28a745" } else { "#dc3545" }
    $emailHtml = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Health Alert - $($Results.Hostname)</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { background: $statusColor; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .header h1 { margin: 0; font-size: 24px; }
        .header p { margin: 5px 0 0 0; opacity: 0.9; }
        .summary { padding: 20px; border-bottom: 1px solid #eee; }
        .stats { display: flex; gap: 15px; flex-wrap: wrap; margin-top: 15px; }
        .stat { padding: 15px 20px; border-radius: 5px; text-align: center; min-width: 80px; }
        .stat-ok { background: #d4edda; color: #155724; }
        .stat-fail { background: #f8d7da; color: #721c24; }
        .stat-warn { background: #fff3cd; color: #856404; }
        .stat h3 { margin: 0; font-size: 28px; }
        .stat p { margin: 5px 0 0 0; font-size: 12px; text-transform: uppercase; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #f8f9fa; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #dee2e6; }
        td { padding: 12px; border-bottom: 1px solid #eee; }
        .status-ok { color: #28a745; font-weight: bold; }
        .status-fail { color: #dc3545; font-weight: bold; }
        .status-error { color: #ff8c00; font-weight: bold; }
        .footer { padding: 15px 20px; background: #f8f9fa; border-radius: 0 0 8px 8px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>[!] Security Health Alert</h1>
            <p>$($Results.Hostname) - $($Results.Timestamp)</p>
        </div>
        <div class="summary">
            <h2 style="margin-top: 0;">Status: $($Results.OverallStatus)</h2>
            <p><strong>$($Results.IssuesFound)</strong> issue(s) detected requiring attention.</p>
            <div class="stats">
                <div class="stat stat-ok"><h3>$(($Results.Checks | Where-Object { $_.Status -eq 'OK' }).Count)</h3><p>Passed</p></div>
                <div class="stat stat-fail"><h3>$(($Results.Checks | Where-Object { $_.Status -eq 'FAIL' }).Count)</h3><p>Failed</p></div>
                <div class="stat stat-warn"><h3>$(($Results.Checks | Where-Object { $_.Status -eq 'ERROR' }).Count)</h3><p>Errors</p></div>
            </div>
        </div>
        <div style="padding: 20px;">
            <h3>Check Details</h3>
            <table>
                <tr>
                    <th>Component</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
"@

    foreach ($check in $Results.Checks) {
        $statusClass = switch ($check.Status) {
            "OK" { "status-ok" }
            "FAIL" { "status-fail" }
            default { "status-error" }
        }
        $emailHtml += @"
                <tr>
                    <td><strong>$($check.Name)</strong><br><small style="color:#666;">$($check.Description)</small></td>
                    <td class="$statusClass">$($check.Status)</td>
                    <td>$($check.Message)</td>
                </tr>
"@
    }

    $emailHtml += @"
            </table>
        </div>
        <div class="footer">
            <p>Generated by Defensive Toolkit Security Health Check v1.1.0</p>
            <p>This is an automated alert. Please investigate failed checks promptly.</p>
        </div>
    </div>
</body>
</html>
"@

    # Prepare Send-MailMessage parameters
    $mailParams = @{
        To          = $To
        From        = $From
        Subject     = "[ALERT] Security Health Check - $($Results.Hostname) - $($Results.IssuesFound) Issue(s)"
        Body        = $emailHtml
        BodyAsHtml  = $true
        SmtpServer  = $Server
        Port        = $Port
        Encoding    = [System.Text.Encoding]::UTF8
    }

    if ($SSL) {
        $mailParams.UseSsl = $true
    }

    if ($Credential) {
        $mailParams.Credential = $Credential
    }

    # Send the email
    try {
        # Suppress the deprecation warning for Send-MailMessage
        $WarningPreference = 'SilentlyContinue'
        Send-MailMessage @mailParams
        $WarningPreference = 'Continue'
        return @{ Success = $true; Message = "Alert email sent successfully to $To" }
    }
    catch {
        return @{ Success = $false; Message = "Failed to send email: $($_.Exception.Message)" }
    }
}

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

# Send alert if requested and issues found (or warnings if AlertOnWarning is set)
$shouldAlert = $SendAlert -and ($results.IssuesFound -gt 0 -or ($AlertOnWarning -and ($results.Checks | Where-Object { $_.Status -eq 'ERROR' }).Count -gt 0))

if ($shouldAlert) {
    Write-Host "[i] Sending alert email to $AlertEmail..." -ForegroundColor Cyan

    $emailResult = Send-AlertEmail -Results $results `
        -To $AlertEmail `
        -From $FromEmail `
        -Server $SmtpServer `
        -Port $SmtpPort `
        -SSL:$UseSSL `
        -Credential $SmtpCredential

    if ($emailResult.Success) {
        Write-Host "[+] $($emailResult.Message)" -ForegroundColor Green
    } else {
        Write-Host "[-] $($emailResult.Message)" -ForegroundColor Red
    }
} elseif ($SendAlert -and $results.IssuesFound -eq 0) {
    Write-Host "[i] No issues detected - alert email not sent" -ForegroundColor Gray
}

# Exit code reflects health status
if ($results.IssuesFound -eq 0) {
    exit 0
} else {
    exit 1
}
