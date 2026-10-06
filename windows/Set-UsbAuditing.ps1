<#
.SYNOPSIS
    Local-only version: makes this one Windows computer log USB storage activity.

.DESCRIPTION
    Sets the registry value
        HKLM\SYSTEM\CurrentControlSet\Control\Storage\HotPlugSecureOpen = 1 (DWORD)

    Without it, some Windows builds log nothing when files are read from or
    written to a hot-plugged USB drive, even though the "Removable Storage"
    audit policy is on. Microsoft documents this for "some versions of
    Windows 10"; it was also needed on Windows 11 build 26200.

    With -IncludeAuditPolicy it also turns on the two audit policy
    subcategories the Wazuh rules need, using auditpol:
        Removable Storage      success and failure   (events 4663, 4656)
        Plug and Play Events   success               (event 6416)
    Skip that switch on domain computers whose audit policy comes from Group
    Policy: the domain policy wins and will overwrite a local setting.

    Use this script for workgroup computers, a single test machine, or as an
    RMM script. For a domain, use New-UsbAuditingGpo.ps1 instead.

    A USB drive that is already plugged in must be unplugged and plugged back
    in before its activity is logged. No restart was needed in testing.

.PARAMETER IncludeAuditPolicy
    Also set the two audit policy subcategories with auditpol.

.PARAMETER Undo
    Remove the registry value. With -IncludeAuditPolicy, also turn the two
    audit subcategories off.

.EXAMPLE
    .\Set-UsbAuditing.ps1
    Registry value only.

.EXAMPLE
    .\Set-UsbAuditing.ps1 -IncludeAuditPolicy
    Registry value and audit policy (workgroup computers).

.EXAMPLE
    .\Set-UsbAuditing.ps1 -Undo

.NOTES
    Run as administrator (or as SYSTEM from an RMM tool). Windows PowerShell 5.1 or later.
    Exit code 0 = done, 1 = failed.
    https://github.com/FarmhouseNetworking/Wazuh-SentinelOne-USB
#>
[CmdletBinding()]
param(
    [switch]$IncludeAuditPolicy,
    [switch]$Undo
)

$ErrorActionPreference = 'Stop'
$KeyPath   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Storage'
$ValueName = 'HotPlugSecureOpen'
# Audit subcategory GUIDs are the same on every language version of Windows; the names are not.
$AuditRemovableStorage = '{0CCE9245-69AE-11D9-BED3-505054503030}'
$AuditPlugAndPlay      = '{0CCE9248-69AE-11D9-BED3-505054503030}'

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CurrentValue {
    $item = Get-ItemProperty -Path $KeyPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$ValueName
}

function Set-AuditSubcategory([string]$Guid, [string]$Label, [string]$Success, [string]$Failure) {
    & auditpol.exe /set "/subcategory:$Guid" "/success:$Success" "/failure:$Failure" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $Label (exit code $LASTEXITCODE)" }
    Write-Output "Audit policy: $Label -> success:$Success failure:$Failure"
}

try {
    if (-not (Test-IsAdmin)) { throw 'Run this script as administrator.' }

    $before = Get-CurrentValue
    if ($null -eq $before) { $beforeText = 'not set' } else { $beforeText = "$before" }

    if ($Undo) {
        if ($null -ne $before) {
            Remove-ItemProperty -Path $KeyPath -Name $ValueName
            Write-Output "$ValueName removed (was $beforeText)."
        } else {
            Write-Output "$ValueName was not set. Nothing to remove."
        }
        if ($IncludeAuditPolicy) {
            Set-AuditSubcategory $AuditRemovableStorage 'Removable Storage' 'disable' 'disable'
            Set-AuditSubcategory $AuditPlugAndPlay 'Plug and Play Events' 'disable' 'disable'
        }
        exit 0
    }

    if ($before -eq 1) {
        Write-Output "$ValueName is already 1. No change."
    } else {
        if (-not (Test-Path -Path $KeyPath)) { New-Item -Path $KeyPath -Force | Out-Null }
        New-ItemProperty -Path $KeyPath -Name $ValueName -PropertyType DWord -Value 1 -Force | Out-Null
        $after = Get-CurrentValue
        if ($after -ne 1) { throw "$ValueName did not read back as 1 (got '$after')." }
        Write-Output "$ValueName set to 1 (was $beforeText)."
    }

    if ($IncludeAuditPolicy) {
        Set-AuditSubcategory $AuditRemovableStorage 'Removable Storage' 'enable' 'enable'
        Set-AuditSubcategory $AuditPlugAndPlay 'Plug and Play Events' 'enable' 'disable'
    }

    Write-Output 'Unplug and re-plug any USB drive that is connected now. No restart is needed.'
    exit 0
}
catch {
    Write-Output "FAILED: $($_.Exception.Message)"
    exit 1
}
