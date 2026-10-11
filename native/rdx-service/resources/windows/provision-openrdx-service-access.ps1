# SPDX-FileCopyrightText: 2026 André Fiedler
# SPDX-License-Identifier: AGPL-3.0-or-later

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Provision', 'Verify', 'Remove')]
    [string] $Action,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, [uint32]::MaxValue)]
    [uint32] $ManagerProcessId
)

$provisioner = Join-Path -Path $PSScriptRoot -ChildPath 'openrdx-service-acl.exe'
if (-not (Test-Path -LiteralPath $provisioner -PathType Leaf)) {
    throw 'OpenRDX service access provisioner is missing.'
}

$arguments = @(
    '--action',
    $Action.ToLowerInvariant(),
    '--manager-process-id',
    $ManagerProcessId.ToString([Globalization.CultureInfo]::InvariantCulture)
)

$process = Start-Process -FilePath $provisioner -ArgumentList $arguments -Wait -PassThru
if ($process.ExitCode -ne 0) {
    throw 'OpenRDX service access provisioning failed.'
}
