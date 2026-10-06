<#
.SYNOPSIS
    Group Policy version: delivers the HotPlugSecureOpen registry value to domain computers.

.DESCRIPTION
    Creates a Group Policy object holding one computer registry preference:
        HKLM\SYSTEM\CurrentControlSet\Control\Storage\HotPlugSecureOpen = 1 (DWORD), action Update
    and, if you name one or more targets, links it there.

    Without that value, some Windows builds log nothing when files are read
    from or written to a hot-plugged USB drive, even though the "Removable
    Storage" audit policy is on.

    This script does NOT set the audit policy itself. Turn these on in the
    same or another GPO (docs/SETUP.md, step 5, has the click path):
        Advanced Audit Policy > Object Access > Audit Removable Storage   Success, Failure
        Advanced Audit Policy > Detailed Tracking > Audit PNP Activity    Success

    Run without -LinkTarget first: the GPO is created unlinked, so nothing
    changes on any computer until you link it.

.PARAMETER GpoName
    Name of the GPO to create or reuse.

.PARAMETER LinkTarget
    Distinguished name(s) of the OU(s) or domain to link the GPO to, for example
    'OU=Workstations,DC=example,DC=local'.

.PARAMETER ListTargets
    Show which containers hold computer accounts, and what is linked at the
    domain root, then exit. Needs the ActiveDirectory module.

.EXAMPLE
    .\New-UsbAuditingGpo.ps1 -ListTargets

.EXAMPLE
    .\New-UsbAuditingGpo.ps1
    Creates the GPO, unlinked.

.EXAMPLE
    .\New-UsbAuditingGpo.ps1 -LinkTarget 'OU=Workstations,DC=example,DC=local'

.NOTES
    Run on a domain controller, or a computer with the Group Policy Management
    tools (RSAT), as a user allowed to create and link GPOs.
    To remove: unlink or delete the GPO in Group Policy Management. Computers
    that already received the value keep it until you remove it
    (Set-UsbAuditing.ps1 -Undo).
    https://github.com/FarmhouseNetworking/Wazuh-SentinelOne-USB
#>
[CmdletBinding()]
param(
    [string]$GpoName = 'USB Removable Storage Auditing (HotPlugSecureOpen)',
    [string[]]$LinkTarget = @(),
    [switch]$ListTargets
)

$ErrorActionPreference = 'Stop'
$Key       = 'HKLM\SYSTEM\CurrentControlSet\Control\Storage'
$ValueName = 'HotPlugSecureOpen'

try {
    Import-Module GroupPolicy

    if ($ListTargets) {
        Import-Module ActiveDirectory
        Write-Output 'Containers that hold computer accounts (count, distinguished name):'
        Get-ADComputer -Filter * |
            Group-Object { ($_.DistinguishedName -split ',', 2)[1] } |
            Sort-Object Name |
            ForEach-Object { Write-Output ("  {0,4}  {1}" -f $_.Count, $_.Name) }
        Write-Output ''
        Write-Output 'GPOs linked at the domain root:'
        (Get-GPInheritance -Target (Get-ADDomain).DistinguishedName).GpoLinks |
            ForEach-Object { Write-Output ("  {0} (enabled: {1})" -f $_.DisplayName, $_.Enabled) }
        exit 0
    }

    $gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if ($null -eq $gpo) {
        $comment = 'Sets HotPlugSecureOpen=1 so Windows logs file access (events 4663/4656) on hot-plugged USB storage. Needed by the Wazuh USB rules.'
        $gpo = New-GPO -Name $GpoName -Comment $comment
        Write-Output "Created GPO: $GpoName"
    } else {
        Write-Output "GPO already exists: $GpoName"
    }

    $existing = Get-GPPrefRegistryValue -Name $GpoName -Context Computer -Key $Key -ValueName $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $existing -and "$($existing.Value)" -eq '1') {
        Write-Output 'Registry preference already present. No change.'
    } else {
        Set-GPPrefRegistryValue -Name $GpoName -Context Computer -Action Update -Key $Key -ValueName $ValueName -Type DWord -Value 1 | Out-Null
        Write-Output "Registry preference set: $Key\$ValueName = 1 (DWord, Update)"
    }

    if ($LinkTarget.Count -eq 0) {
        Write-Output ''
        Write-Output 'The GPO is NOT linked yet, so no computer is affected.'
        Write-Output 'See where computers live:   .\New-UsbAuditingGpo.ps1 -ListTargets'
        Write-Output "Then link it:               .\New-UsbAuditingGpo.ps1 -LinkTarget 'OU=...,DC=...'"
        exit 0
    }

    foreach ($target in $LinkTarget) {
        $links = (Get-GPInheritance -Target $target).GpoLinks
        if ($links | Where-Object { $_.DisplayName -eq $GpoName }) {
            Write-Output "Already linked to: $target"
        } else {
            New-GPLink -Name $GpoName -Target $target -LinkEnabled Yes | Out-Null
            Write-Output "Linked to: $target"
        }
    }
    Write-Output ''
    Write-Output 'Computers apply it within about two hours, at restart, or at once with: gpupdate /target:computer /force'
    Write-Output 'A USB drive already plugged in must be unplugged and plugged back in before it is audited.'
    exit 0
}
catch {
    Write-Output "FAILED: $($_.Exception.Message)"
    exit 1
}
