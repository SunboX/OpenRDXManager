// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

test('Windows worker captures prerequisites and selected Manager token facts without changing candidate selection', async () => {
    const source = await readFile(new URL('../scripts/verify-windows-installation.ps1', import.meta.url), 'utf8')
    const worker = source.slice(source.indexOf('if ($WorkerMode)'), source.indexOf('function Invoke-LocalAction'))
    assert.ok(worker.indexOf('try {') < worker.indexOf("throw 'worker-console-mismatch'"))
    assert.ok(worker.indexOf('try {') < worker.indexOf("throw 'worker-must-be-unelevated'"))
    assert.match(worker, /Get-TokenDiagnostic -ProcessId \$candidates\[0\]\.ProcessId/u)
    assert.match(worker, /if \(\$candidates\.Count -eq 0\) \{ Start-Process -FilePath \$manager \| Out-Null \}/u)
    assert.match(source, /\$setupFailure = \$_[\s\S]*try \{ Write-ManagerWorkerDiagnostic -Path \$ResultPath \| Write-Host \} catch \{\}\s*throw \$setupFailure/u)
    assert.match(source, /Write-ManagerWorkerDiagnostic -Result \$managerResult/u)
    const output = source.slice(source.indexOf('function Write-ManagerWorkerDiagnostic'), source.indexOf('function Invoke-ManagerSetup'))
    assert.doesNotMatch(output, /\$Result\.(?:pid|error)|Write-Output \$Result|ToString\(\)/u)
    assert.match(output, /\[bool\]/u)
})

test('Windows console context diagnostics query UAC and the local builtin Administrator without writing policy or logging identity', async () => {
    const source = await readFile(new URL('../scripts/verify-windows-installation.ps1', import.meta.url), 'utf8')
    const start = source.indexOf('function Get-ConsoleContextDiagnostic')
    assert.ok(start >= 0)
    const reader = source.slice(start, source.indexOf('function Get-TaskRunLevelDiagnostic', start))
    assert.match(reader, /Get-ItemProperty[^\n]*-Name EnableLUA/u)
    assert.match(reader, /Get-LocalUser/u)
    assert.match(reader, /AccountAdministratorSid/u)
    assert.doesNotMatch(reader, /(?:Set|New|Remove)-(?:ItemProperty|LocalUser|LocalGroup)|Write-(?:Output|Host)/u)
    assert.match(source, /context = Get-ConsoleContextDiagnostic/u)
    assert.match(source, /uac-query=\{0\} enablelua-is-one=\{1\} local-builtin-admin-query=\{2\} local-builtin-admin=\{3\}/u)
})

test('Windows token context reads exact elevation type and linked token then closes its owned handle', async () => {
    const source = await readFile(new URL('../scripts/verify-windows-installation.ps1', import.meta.url), 'utf8')
    assert.match(source, /GetTokenInformation\(token, 18, out elevationType, 4, out returned\)/u)
    assert.match(source, /GetLinkedTokenInformation\(token, 19, out linkedToken, \(UInt32\)IntPtr.Size, out returned\)/u)
    assert.match(source, /if \(linkedToken != IntPtr.Zero\) CloseHandle\(linkedToken\)/u)
    for (const field of ['ElevationTypeQueryOk', 'ElevationTypeSizeMatch', 'ElevationTypeDefault', 'ElevationTypeFull', 'ElevationTypeLimited', 'LinkedTokenQueryOk', 'LinkedTokenSizeMatch', 'LinkedTokenAvailable']) assert.ok(source.includes(field), field)
    assert.doesNotMatch(source, /CreateProcessWithToken|CreateRestrictedToken|AdjustTokenPrivileges|SetTokenInformation/u)
})

test('Windows task diagnostic reads actual registration without changing the selected principal or run level', async () => {
    const source = await readFile(new URL('../scripts/verify-windows-installation.ps1', import.meta.url), 'utf8')
    const start = source.indexOf('function Get-TaskRunLevelDiagnostic')
    assert.ok(start >= 0)
    const reader = source.slice(start, source.indexOf('function Write-TokenContextDiagnostic', start))
    assert.match(reader, /Get-ScheduledTask -TaskName \$TaskName -ErrorAction Stop/u)
    assert.doesNotMatch(reader, /(?:New|Set|Register|Start|Stop|Unregister)-ScheduledTask|Write-(?:Output|Host)/u)
    const launch = source.slice(source.indexOf('function Start-Worker'), source.indexOf('$identity = [Security.Principal.WindowsIdentity]::GetCurrent()', source.indexOf('function Start-Worker')))
    assert.ok(launch.indexOf('Register-ScheduledTask') < launch.indexOf('Get-TaskRunLevelDiagnostic'))
    assert.ok(launch.indexOf('Get-TaskRunLevelDiagnostic') < launch.indexOf('Start-ScheduledTask'))
    assert.match(launch, /-UserId \$consoleAccount -LogonType Interactive -RunLevel Limited/u)
    assert.match(launch, /runlevel-query=\{0\} runlevel-is-lua=\{1\}/u)
})
