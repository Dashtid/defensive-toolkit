#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Fix NetBIOS disable using registry method

.DESCRIPTION
    Disables NetBIOS over TCP/IP using registry for all network adapters
    Works when WMI method fails due to PowerShell version incompatibilities
#>

function Write-Log {
    param([string]$Message, [string]$Color = 'White')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-Log "[+] $Message" -Color Green }
function Write-Info { param([string]$Message) Write-Log "[i] $Message" -Color Cyan }
function Write-Warning { param([string]$Message) Write-Log "[!] $Message" -Color Yellow }

Write-Info "Disabling NetBIOS over TCP/IP via registry..."

# Get all network adapter registry keys
$adapters = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue

if (-not $adapters) {
    Write-Warning "No network adapters found in NetBT registry"
    exit 1
}

$count = 0
foreach ($adapter in $adapters) {
    try {
        # Set NetbiosOptions to 2 (Disable NetBIOS)
        # 0 = Default (from DHCP), 1 = Enable, 2 = Disable
        Set-ItemProperty -Path $adapter.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -Force
        $adapterName = Split-Path $adapter.PSPath -Leaf
        Write-Success "Disabled NetBIOS on adapter: $adapterName"
        $count++
    } catch {
        Write-Warning "Failed to disable NetBIOS on adapter: $($adapter.PSPath)"
    }
}

Write-Success "NetBIOS disabled on $count network adapter(s)"
Write-Info "Changes take effect immediately (no reboot required for this setting)"
