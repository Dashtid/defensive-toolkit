#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configure Windows Event Log forwarding to Splunk Universal Forwarder

.DESCRIPTION
    Automates the configuration of Windows Event Log forwarding to Splunk.
    Sets up Splunk Universal Forwarder inputs for security-critical event logs.

.PARAMETER SplunkHome
    Path to Splunk Universal Forwarder installation (default: C:\Program Files\SplunkUniversalForwarder)

.PARAMETER IndexerHost
    Splunk indexer hostname or IP address

.PARAMETER IndexerPort
    Splunk indexer receiving port (default: 9997)

.PARAMETER EnableSysmon
    Enable Sysmon log collection (requires Sysmon installed)

.EXAMPLE
    .\forward-logs-splunk.ps1 -IndexerHost splunk.example.com -IndexerPort 9997

.EXAMPLE
    .\forward-logs-splunk.ps1 -IndexerHost 10.0.0.50 -EnableSysmon

.NOTES
    Author: Defensive Toolkit
    Date: 2025-10-15
    Requires: Splunk Universal Forwarder installed
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$SplunkHome = "C:\Program Files\SplunkUniversalForwarder",

    [Parameter(Mandatory=$true)]
    [string]$IndexerHost,

    [Parameter()]
    [int]$IndexerPort = 9997,

    [Parameter()]
    [switch]$EnableSysmon
)

$ErrorActionPreference = "Stop"

# Logging function
function Write-Log {
    param([string]$Message, [string]$Type = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Type] $Message"
}

# Check if Splunk Universal Forwarder is installed
if (-not (Test-Path $SplunkHome)) {
    Write-Log "Splunk Universal Forwarder not found at $SplunkHome" "ERROR"
    Write-Log "Download from: https://www.splunk.com/en_us/download/universal-forwarder.html" "INFO"
    exit 1
}

Write-Log "Configuring Splunk Universal Forwarder log forwarding"

# Paths
$inputsConf = Join-Path $SplunkHome "etc\system\local\inputs.conf"
$outputsConf = Join-Path $SplunkHome "etc\system\local\outputs.conf"

# Backup existing configs
if (Test-Path $inputsConf) {
    $backup = "$inputsConf.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item $inputsConf $backup
    Write-Log "Backed up inputs.conf to $backup"
}

if (Test-Path $outputsConf) {
    $backup = "$outputsConf.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item $outputsConf $backup
    Write-Log "Backed up outputs.conf to $backup"
}

# Configure outputs.conf (indexer connection)
Write-Log "Configuring outputs.conf"
$outputsContent = @"
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = ${IndexerHost}:${IndexerPort}
compressed = true

[tcpout-server://${IndexerHost}:${IndexerPort}]
"@

Set-Content -Path $outputsConf -Value $outputsContent -Force
Write-Log "Configured forwarding to ${IndexerHost}:${IndexerPort}"

# Configure inputs.conf (Windows Event Logs)
Write-Log "Configuring inputs.conf"

$inputsContent = @"
# Security-critical Windows Event Logs

[WinEventLog://Security]
disabled = 0
index = windows
sourcetype = WinEventLog:Security
renderXml = true

[WinEventLog://System]
disabled = 0
index = windows
sourcetype = WinEventLog:System
renderXml = true

[WinEventLog://Application]
disabled = 0
index = windows
sourcetype = WinEventLog:Application
renderXml = true

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:Microsoft-Windows-PowerShell/Operational
renderXml = true

[WinEventLog://Windows PowerShell]
disabled = 0
index = windows
sourcetype = WinEventLog:Windows PowerShell
renderXml = true

[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:Microsoft-Windows-Windows Defender/Operational
renderXml = true

[WinEventLog://Microsoft-Windows-TaskScheduler/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:Microsoft-Windows-TaskScheduler/Operational
renderXml = true

[WinEventLog://Microsoft-Windows-TerminalServices-LocalSessionManager/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
renderXml = true

"@

# Add Sysmon if enabled
if ($EnableSysmon) {
    Write-Log "Enabling Sysmon log collection"
    $inputsContent += @"

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:Microsoft-Windows-Sysmon/Operational
renderXml = true

"@
}

Set-Content -Path $inputsConf -Value $inputsContent -Force
Write-Log "Configured Windows Event Log inputs"

# Restart Splunk Universal Forwarder service
Write-Log "Restarting SplunkForwarder service"
try {
    Restart-Service -Name SplunkForwarder -Force
    Start-Sleep -Seconds 5

    $service = Get-Service -Name SplunkForwarder
    if ($service.Status -eq 'Running') {
        Write-Log "SplunkForwarder service restarted successfully" "SUCCESS"
    } else {
        Write-Log "SplunkForwarder service is not running" "ERROR"
        exit 1
    }
} catch {
    Write-Log "Failed to restart SplunkForwarder service: $_" "ERROR"
    exit 1
}

# Test connectivity
Write-Log "Testing connectivity to $IndexerHost`:$IndexerPort"
try {
    $connection = Test-NetConnection -ComputerName $IndexerHost -Port $IndexerPort -WarningAction SilentlyContinue
    if ($connection.TcpTestSucceeded) {
        Write-Log "Successfully connected to Splunk indexer" "SUCCESS"
    } else {
        Write-Log "Cannot connect to Splunk indexer. Check firewall and indexer status" "WARNING"
    }
} catch {
    Write-Log "Connectivity test failed: $_" "WARNING"
}

# Summary
Write-Log "`n" + "="*60
Write-Log "Splunk Universal Forwarder Configuration Complete"
Write-Log "="*60
Write-Log "Indexer: ${IndexerHost}:${IndexerPort}"
Write-Log "Configured Event Logs:"
Write-Log "  - Security"
Write-Log "  - System"
Write-Log "  - Application"
Write-Log "  - PowerShell (Operational & Classic)"
Write-Log "  - Windows Defender"
Write-Log "  - Task Scheduler"
Write-Log "  - Terminal Services"
if ($EnableSysmon) {
    Write-Log "  - Sysmon"
}
Write-Log "`nConfiguration files:"
Write-Log "  - $inputsConf"
Write-Log "  - $outputsConf"
Write-Log "`n[OK] Logs will now be forwarded to Splunk"
Write-Log "="*60
