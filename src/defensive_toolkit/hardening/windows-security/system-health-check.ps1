#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Comprehensive system health and functionality check

.DESCRIPTION
    Verifies all components are working after hardening and optimization:
    - Security settings
    - Scheduled tasks
    - Network connectivity
    - Development tools
    - System services
#>

function Write-Log {
    param([string]$Message, [string]$Color = 'White')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-Log "[+] $Message" -Color Green }
function Write-Info { param([string]$Message) Write-Log "[i] $Message" -Color Cyan }
function Write-Warning { param([string]$Message) Write-Log "[!] $Message" -Color Yellow }
function Write-Error { param([string]$Message) Write-Log "[-] $Message" -Color Red }

function Test-Component {
    param(
        [string]$Name,
        [scriptblock]$Test
    )

    try {
        $result = & $Test
        if ($result) {
            Write-Success "$Name - OK"
            return $true
        } else {
            Write-Warning "$Name - WARN"
            return $false
        }
    } catch {
        Write-Error "$Name - FAIL: $_"
        return $false
    }
}

Write-Log "`n[*] System Health Check" -Color Magenta
Write-Log "[*] ==================`n" -Color Magenta

$totalTests = 0
$passedTests = 0

# Section 1: Security Settings
Write-Info "Section 1: Security Settings"
Write-Info "----------------------------"

if (Test-Component "Windows Defender Real-Time Protection" {
    (Get-MpPreference).DisableRealtimeMonitoring -eq $false
}) { $passedTests++ }
$totalTests++

if (Test-Component "Windows Firewall Enabled" {
    (Get-NetFirewallProfile -Profile Domain,Public,Private | Where-Object {$_.Enabled -eq $false}).Count -eq 0
}) { $passedTests++ }
$totalTests++

if (Test-Component "UAC Enabled" {
    (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA -eq 1
}) { $passedTests++ }
$totalTests++

if (Test-Component "SMBv1 Disabled" {
    (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State -eq 'Disabled'
}) { $passedTests++ }
$totalTests++

if (Test-Component "Guest Account Disabled" {
    (Get-LocalUser -Name "Guest").Enabled -eq $false
}) { $passedTests++ }
$totalTests++

if (Test-Component "Print Spooler Disabled" {
    (Get-Service -Name Spooler).StartType -eq 'Disabled'
}) { $passedTests++ }
$totalTests++

# Section 2: Scheduled Tasks
Write-Info "`nSection 2: Scheduled Maintenance Tasks"
Write-Info "---------------------------------------"

$expectedTasks = @(
    "SystemMaintenance-WeeklyUpdates",
    "SystemMaintenance-DefenderFullScan",
    "SystemMaintenance-DefenderDefinitions",
    "SystemMaintenance-DiskCleanup",
    "SystemMaintenance-IntegrityCheck"
)

foreach ($taskName in $expectedTasks) {
    if (Test-Component "Task: $taskName" {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        $task -and $task.State -ne 'Disabled'
    }) { $passedTests++ }
    $totalTests++
}

# Section 3: Network Connectivity
Write-Info "`nSection 3: Network Connectivity"
Write-Info "-------------------------------"

if (Test-Component "Internet Connectivity (Google DNS)" {
    Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet
}) { $passedTests++ }
$totalTests++

if (Test-Component "DNS Resolution" {
    (Resolve-DnsName google.com -ErrorAction SilentlyContinue).Count -gt 0
}) { $passedTests++ }
$totalTests++

if (Test-Component "NetBIOS Disabled (Registry)" {
    $adapters = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue
    $disabledCount = 0
    foreach ($adapter in $adapters) {
        $value = (Get-ItemProperty -Path $adapter.PSPath -Name "NetbiosOptions" -ErrorAction SilentlyContinue).NetbiosOptions
        if ($value -eq 2) { $disabledCount++ }
    }
    $disabledCount -gt 0
}) { $passedTests++ }
$totalTests++

# Section 4: Development Tools
Write-Info "`nSection 4: Development Tools"
Write-Info "----------------------------"

if (Test-Component "Git Installed" {
    $null -ne (Get-Command git -ErrorAction SilentlyContinue)
}) { $passedTests++ }
$totalTests++

if (Test-Component "GitHub CLI Authenticated" {
    $status = gh auth status 2>&1 | Select-String "Logged in"
    $status.Count -gt 0
}) { $passedTests++ }
$totalTests++

if (Test-Component "Python Installed" {
    $null -ne (Get-Command python -ErrorAction SilentlyContinue)
}) { $passedTests++ }
$totalTests++

if (Test-Component "PowerShell 7 Installed" {
    $PSVersionTable.PSVersion.Major -ge 7
}) { $passedTests++ }
$totalTests++

# Section 5: Removed/Cleaned Components
Write-Info "`nSection 5: Cleanup Verification"
Write-Info "-------------------------------"

if (Test-Component "OpenVPN Client Removed" {
    -not (winget list | Select-String "OpenVPN")
}) { $passedTests++ }
$totalTests++

if (Test-Component "Python 3.13 Removed" {
    -not (choco list | Select-String "python313")
}) { $passedTests++ }
$totalTests++

if (Test-Component "Old Git Credential Manager Removed" {
    -not (choco list | Select-String "git-credential-manager-for-windows")
}) { $passedTests++ }
$totalTests++

if (Test-Component "HP Support Assistant Removed" {
    -not (choco list | Select-String "hpsupportassistant")
}) { $passedTests++ }
$totalTests++

# Section 6: System Resources
Write-Info "`nSection 6: System Resources"
Write-Info "---------------------------"

$os = Get-CimInstance Win32_OperatingSystem
$freeMemoryGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
$totalMemoryGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
$memoryUsagePercent = [math]::Round((($totalMemoryGB - $freeMemoryGB) / $totalMemoryGB) * 100, 1)

Write-Info "Free Memory: $freeMemoryGB GB / $totalMemoryGB GB (${memoryUsagePercent}% used)"

$disk = Get-PSDrive C
$freeDiskGB = [math]::Round($disk.Free / 1GB, 2)
$totalDiskGB = [math]::Round(($disk.Used + $disk.Free) / 1GB, 2)
$diskUsagePercent = [math]::Round(($disk.Used / ($disk.Used + $disk.Free)) * 100, 1)

Write-Info "Free Disk: $freeDiskGB GB / $totalDiskGB GB (${diskUsagePercent}% used)"

# Final Summary
Write-Log "`n[*] =============================" -Color Cyan
Write-Log "[*] Health Check Summary" -Color Cyan
Write-Log "[*] =============================" -Color Cyan

$successRate = [math]::Round(($passedTests / $totalTests) * 100, 1)

Write-Success "Tests Passed: $passedTests / $totalTests ($successRate%)"

if ($successRate -ge 95) {
    Write-Log "`n[+] System Status: EXCELLENT" -Color Green
    Write-Info "All critical components functioning properly"
} elseif ($successRate -ge 80) {
    Write-Log "`n[!] System Status: GOOD" -Color Yellow
    Write-Info "Minor issues detected, system is functional"
} else {
    Write-Log "`n[-] System Status: NEEDS ATTENTION" -Color Red
    Write-Info "Multiple issues detected, review failed tests"
}

Write-Info "`nNext Steps:"
Write-Info "  1. Test gaming performance (Steam, games)"
Write-Info "  2. Test development workflow (Git, VS Code)"
Write-Info "  3. Review failed tests if any"
Write-Info "  4. System is ready for normal use!"
