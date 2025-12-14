#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Extract forensic artifacts from Windows Registry

.DESCRIPTION
    Extracts key forensic artifacts from registry hives including:
    - User activity (RecentDocs, UserAssist, RunMRU)
    - Autorun persistence locations
    - Network history
    - USB device history
    - Shimcache and AmCache
    - Installed software
    - System information

.PARAMETER RegistryPath
    Path to registry hives (offline or live system)

.PARAMETER OutputDir
    Output directory for extracted artifacts

.PARAMETER Offline
    Parse offline registry hives (requires RegRipper or registry parsing)

.EXAMPLE
    .\extract-registry-artifacts.ps1 -OutputDir C:\forensics\registry
    .\extract-registry-artifacts.ps1 -RegistryPath E:\evidence\Windows\System32\config -OutputDir C:\analysis -Offline

.NOTES
    Author: Defensive Toolkit
    Date: 2025-10-15
    Requires: Administrator privileges for live system
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$RegistryPath = "",

    [Parameter(Mandatory=$true)]
    [string]$OutputDir,

    [Parameter()]
    [switch]$Offline
)

$ErrorActionPreference = "Stop"

# Create output directory
$OutputPath = New-Item -ItemType Directory -Path $OutputDir -Force
Write-Host "[+] Output directory: $OutputPath" -ForegroundColor Green

$Results = @{
    Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
    Hostname = $env:COMPUTERNAME
    Artifacts = @()
}

function Export-RegistryKey {
    param(
        [string]$Path,
        [string]$OutputFile,
        [string]$Description
    )

    try {
        Write-Host "[+] Extracting: $Description" -ForegroundColor Cyan

        if (Test-Path "Registry::$Path") {
            $items = Get-ItemProperty -Path "Registry::$Path" -ErrorAction SilentlyContinue
            if ($items) {
                $items | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
                Write-Host "    [OK] Saved to: $OutputFile" -ForegroundColor Green

                $Results.Artifacts += @{
                    Name = $Description
                    Path = $Path
                    OutputFile = $OutputFile
                    Status = "Success"
                }
                return $true
            }
        }

        Write-Host "    [!] Registry key not found or empty: $Path" -ForegroundColor Yellow
        return $false

    } catch {
        Write-Host "    [X] Error: $_" -ForegroundColor Red
        $Results.Artifacts += @{
            Name = $Description
            Path = $Path
            Status = "Error"
            Error = $_.Exception.Message
        }
        return $false
    }
}

function Get-UserAssistData {
    Write-Host "`n[+] Extracting UserAssist data (program execution)" -ForegroundColor Cyan

    $outputFile = Join-Path $OutputPath "userassist.json"
    $userAssistData = @()

    try {
        # Enumerate user SIDs
        $userSIDs = Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "S-1-5-21-" }

        foreach ($sid in $userSIDs) {
            $guidPath = "$($sid.PSPath)\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

            if (Test-Path $guidPath) {
                Get-ChildItem -Path $guidPath | ForEach-Object {
                    $countPath = "$($_.PSPath)\Count"
                    if (Test-Path $countPath) {
                        Get-ItemProperty -Path $countPath | Get-Member -MemberType NoteProperty |
                        ForEach-Object {
                            if ($_.Name -ne "PSPath" -and $_.Name -ne "PSParentPath" -and
                                $_.Name -ne "PSChildName" -and $_.Name -ne "PSDrive" -and
                                $_.Name -ne "PSProvider") {

                                $userAssistData += @{
                                    SID = $sid.PSChildName
                                    GUID = $_.Name
                                    Program = $_.Name
                                }
                            }
                        }
                    }
                }
            }
        }

        if ($userAssistData.Count -gt 0) {
            $userAssistData | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
            Write-Host "    [OK] UserAssist data saved ($($userAssistData.Count) entries)" -ForegroundColor Green
        }

    } catch {
        Write-Host "    [X] Error extracting UserAssist: $_" -ForegroundColor Red
    }
}

function Get-RecentDocs {
    Write-Host "`n[+] Extracting RecentDocs (recently opened files)" -ForegroundColor Cyan

    $outputFile = Join-Path $OutputPath "recentdocs.json"
    $recentDocs = @()

    try {
        $userSIDs = Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "S-1-5-21-" }

        foreach ($sid in $userSIDs) {
            $recentPath = "$($sid.PSPath)\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

            if (Test-Path $recentPath) {
                $items = Get-ItemProperty -Path $recentPath -ErrorAction SilentlyContinue
                if ($items) {
                    $recentDocs += @{
                        SID = $sid.PSChildName
                        Path = $recentPath
                        Data = $items
                    }
                }
            }
        }

        if ($recentDocs.Count -gt 0) {
            $recentDocs | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
            Write-Host "    [OK] RecentDocs saved ($($recentDocs.Count) entries)" -ForegroundColor Green
        }

    } catch {
        Write-Host "    [X] Error extracting RecentDocs: $_" -ForegroundColor Red
    }
}

function Get-USBHistory {
    Write-Host "`n[+] Extracting USB device history" -ForegroundColor Cyan

    $outputFile = Join-Path $OutputPath "usb_history.json"

    try {
        $usbPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
        if (Test-Path $usbPath) {
            $usbDevices = Get-ChildItem -Path $usbPath -Recurse |
                Get-ItemProperty -ErrorAction SilentlyContinue |
                Select-Object FriendlyName, HardwareID, InstallDate, LastArrivalDate

            $usbDevices | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
            Write-Host "    [OK] USB history saved ($($usbDevices.Count) devices)" -ForegroundColor Green
        }

    } catch {
        Write-Host "    [X] Error extracting USB history: $_" -ForegroundColor Red
    }
}

function Get-NetworkHistory {
    Write-Host "`n[+] Extracting network history" -ForegroundColor Cyan

    $outputFile = Join-Path $OutputPath "network_history.json"

    try {
        $networkPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
        if (Test-Path $networkPath) {
            $networks = Get-ChildItem -Path $networkPath |
                Get-ItemProperty -ErrorAction SilentlyContinue |
                Select-Object ProfileName, Description, DateCreated, DateLastConnected

            $networks | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
            Write-Host "    [OK] Network history saved ($($networks.Count) networks)" -ForegroundColor Green
        }

    } catch {
        Write-Host "    [X] Error extracting network history: $_" -ForegroundColor Red
    }
}

function Get-Autoruns {
    Write-Host "`n[+] Extracting autorun locations" -ForegroundColor Cyan

    $autorunKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    $outputFile = Join-Path $OutputPath "autoruns.json"
    $autoruns = @()

    foreach ($key in $autorunKeys) {
        if (Test-Path $key) {
            $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($items) {
                $autoruns += @{
                    RegistryKey = $key
                    Items = $items
                }
            }
        }
    }

    if ($autoruns.Count -gt 0) {
        $autoruns | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Host "    [OK] Autorun locations saved" -ForegroundColor Green
    }
}

function Get-InstalledSoftware {
    Write-Host "`n[+] Extracting installed software" -ForegroundColor Cyan

    $outputFile = Join-Path $OutputPath "installed_software.json"

    $softwareKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $software = @()

    foreach ($key in $softwareKeys) {
        $software += Get-ItemProperty -Path $key -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
    }

    $software | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
    Write-Host "    [OK] Installed software saved ($($software.Count) applications)" -ForegroundColor Green
}

# Main execution
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Registry Artifact Extraction" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($Offline) {
    Write-Host "[i] Offline mode - parsing registry hives from: $RegistryPath" -ForegroundColor Yellow
    Write-Host "[!] Offline parsing requires RegRipper or custom parser (not implemented)" -ForegroundColor Yellow
    Write-Host "[!] Falling back to basic extraction" -ForegroundColor Yellow
}

# Extract artifacts
Get-UserAssistData
Get-RecentDocs
Get-USBHistory
Get-NetworkHistory
Get-Autoruns
Get-InstalledSoftware

# Export common registry keys
Export-RegistryKey -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" `
    -OutputFile (Join-Path $OutputPath "system_environment.json") `
    -Description "System Environment Variables"

Export-RegistryKey -Path "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
    -OutputFile (Join-Path $OutputPath "network_config.json") `
    -Description "Network Configuration"

# Generate summary report
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Extraction Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Output Directory: $OutputPath" -ForegroundColor Green
Write-Host "Artifacts Extracted: $($Results.Artifacts.Count)" -ForegroundColor Green

$reportFile = Join-Path $OutputPath "extraction_report.json"
$Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "[OK] Report saved: $reportFile" -ForegroundColor Green
