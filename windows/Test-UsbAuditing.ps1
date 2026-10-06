<#
.SYNOPSIS
    Checks whether this Windows computer is set up to log USB storage activity for Wazuh.

.DESCRIPTION
    Read-only by default. Reports:
      1. The two audit policy subcategories (Removable Storage, Plug and Play Events)
      2. The HotPlugSecureOpen registry value
      3. The Wazuh agent service
      4. USB disks connected right now, with the serial number each one reports
         (this is the serial to give to usb-approve and to your USB allow rule)

    With -WriteTest it also writes a small text file to each connected USB
    volume, counts the file-access events (4663) Windows logged for it, and
    deletes the file again. Zero events means auditing is not working for
    that drive.

.PARAMETER WriteTest
    Write, count and delete a test file on each connected USB volume.

.EXAMPLE
    .\Test-UsbAuditing.ps1

.EXAMPLE
    .\Test-UsbAuditing.ps1 -WriteTest

.NOTES
    Run as administrator: reading the Security log and the audit policy needs it.
    Windows PowerShell 5.1 or later. Exit code 0 = no problems found, 1 = something needs attention.
    https://github.com/FarmhouseNetworking/Wazuh-SentinelOne-USB
#>
[CmdletBinding()]
param([switch]$WriteTest)

$ErrorActionPreference = 'Stop'
$script:Problems = 0
function Write-Good([string]$t) { Write-Output "  OK     $t" }
function Write-Bad([string]$t)  { $script:Problems++; Write-Output "  CHECK  $t" }

function Get-AuditSetting([string]$Guid) {
    # /r gives CSV; the 5th column is the setting, in the language of this Windows installation
    $csv = & auditpol.exe /get "/subcategory:$Guid" /r 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $csv) { return $null }
    $row = $csv | Where-Object { $_ -and $_ -notmatch '^Machine Name' } | Select-Object -Last 1
    if (-not $row) { return $null }
    return ($row -split ',')[4]
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script as administrator.'
    }

    Write-Output 'Audit policy'
    $rs = Get-AuditSetting '{0CCE9245-69AE-11D9-BED3-505054503030}'
    $pp = Get-AuditSetting '{0CCE9248-69AE-11D9-BED3-505054503030}'
    if ($null -eq $rs) { Write-Bad 'Removable Storage: could not be read' }
    elseif ($rs -match '(?i)no auditing') { Write-Bad "Removable Storage: $rs (needs Success and Failure)" }
    else { Write-Good "Removable Storage: $rs (needs Success and Failure)" }
    if ($null -eq $pp) { Write-Bad 'Plug and Play Events: could not be read' }
    elseif ($pp -match '(?i)no auditing') { Write-Bad "Plug and Play Events: $pp (needs Success)" }
    else { Write-Good "Plug and Play Events: $pp (needs Success)" }

    Write-Output ''
    Write-Output 'Registry'
    $item = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Storage' -Name HotPlugSecureOpen -ErrorAction SilentlyContinue
    if ($null -ne $item -and $item.HotPlugSecureOpen -eq 1) { Write-Good 'HotPlugSecureOpen = 1' }
    else { Write-Bad 'HotPlugSecureOpen is not 1 (run Set-UsbAuditing.ps1 or link the GPO)' }

    Write-Output ''
    Write-Output 'Wazuh agent'
    $svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
    if ($null -eq $svc) { Write-Bad 'Wazuh agent service (WazuhSvc) not found' }
    elseif ("$($svc.Status)" -ne 'Running') { Write-Bad "Wazuh agent service is $($svc.Status)" }
    else { Write-Good 'Wazuh agent service is running' }

    Write-Output ''
    Write-Output 'USB disks connected now'
    $usb = @(Get-Disk | Where-Object { $_.BusType -eq 'USB' })
    if ($usb.Count -eq 0) {
        Write-Output '  (none - plug in and unlock a drive to see its serial number or to run -WriteTest)'
    }
    foreach ($d in $usb) {
        $letters = @($d | Get-Partition | Where-Object { $_.DriveLetter } | ForEach-Object { $_.DriveLetter })
        Write-Output ("  {0}  serial: {1}  size: {2} GB  drive: {3}" -f $d.FriendlyName, "$($d.SerialNumber)".Trim(), [math]::Round($d.Size / 1GB, 1), ($letters -join ','))
        if ($WriteTest) {
            foreach ($l in $letters) {
                $file = "$($l):\wazuh-usb-audit-test.txt"
                $start = Get-Date
                "USB audit test $start" | Set-Content -Path $file
                Start-Sleep -Seconds 3
                $n = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663; StartTime = $start } -ErrorAction SilentlyContinue).Count
                Remove-Item -Path $file -ErrorAction SilentlyContinue
                if ($n -gt 0) { Write-Good "drive ${l}: wrote a test file, Windows logged $n file-access event(s)" }
                else { Write-Bad "drive ${l}: wrote a test file, Windows logged 0 file-access events. Unplug and re-plug the drive, then test again." }
            }
        }
    }

    Write-Output ''
    if ($script:Problems -eq 0) { Write-Output 'No problems found.'; exit 0 }
    Write-Output "$($script:Problems) item(s) need attention."
    exit 1
}
catch {
    Write-Output "FAILED: $($_.Exception.Message)"
    exit 1
}
