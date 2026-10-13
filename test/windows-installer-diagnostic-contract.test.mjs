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
