// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import test from 'node:test'
import { runRestrictedTokenProbe, validateRestrictedTokenProbeOutput } from '../scripts/verify-windows-restricted-token-probe.mjs'

const execute = promisify(execFile)
const name = 'service_acl::windows_impl::restricted_token_probe::native_restricted_token_observations'
const passing = `running 1 test\nopenrdx-token-probe source-open=true derived-created=true query-ok=true\ntest ${name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`

test('closed label and mandatory-policy observations survive native failure without authority', async () => {
    const context =
        'openrdx-token-mandatory-context station-label-query-ok=true station-label-query-unsupported=false station-label-parse-valid=true station-label-present=false station-label-single=false station-label-known=true station-label-implicit-medium=true station-label-low=false station-label-medium=true station-label-high=false station-label-system=false station-label-policy-known=false station-label-no-write-up=false station-label-no-read-up=false station-label-no-execute-up=false desktop-label-query-ok=false desktop-label-query-unsupported=true desktop-label-parse-valid=false desktop-label-known=false desktop-label-implicit-medium=false source-policy-query-ok=true source-policy-known=true source-policy-off=false source-policy-no-write-up=true source-policy-new-process-min=true derived-policy-query-ok=true derived-policy-known=true derived-policy-off=false derived-policy-no-write-up=true derived-policy-new-process-min=true'
    const result = await runRestrictedTokenProbe({ mode: 'child', execute: async () => ({ exitCode: 101, stdout: `running 1 test\n${context}\n`, stderr: 'private identity' }) })
    assert.deepEqual(result.mandatoryContext, [context])
    assert.equal(result.passed, false)
    assert.equal(result.exitCode, 101)
    assert.equal(JSON.stringify(result).includes('private'), false)
    assert.equal(validateRestrictedTokenProbeOutput(passing + context + '\n', '').passed, true)
    assert.equal(validateRestrictedTokenProbeOutput(`running 0 tests\n${context}\n`, '', { mode: 'child' }).passed, false)
})

test('unknown, duplicate and nonboolean mandatory fields never pass or leak', async () => {
    for (const pairs of ['private-sid=true', 'station-label-medium=private', 'station-label-known=true station-label-known=false']) {
        const result = await runRestrictedTokenProbe({ execute: async () => ({ exitCode: 0, stdout: passing + `openrdx-token-mandatory-context ${pairs}\n`, stderr: '' }) })
        assert.equal(result.passed, false)
        assert.deepEqual(result.mandatoryContext, [])
        assert.equal(JSON.stringify(result).includes('private'), false)
    }
})

test('label parser runs real host Rust adversarial tests without Windows APIs', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-label-parser-'))
    try {
        const binary = join(directory, process.platform === 'win32' ? 'labels.exe' : 'labels')
        const source = fileURLToPath(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/mandatory_label.rs', import.meta.url))
        await execute('rustc', ['--edition=2024', '--test', source, '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, ['--test-threads=2'])
        assert.match(stdout, /4 passed; 0 failed/u)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})

test('label diagnostic uses only borrowed fixed query handles without privilege or label changes', async () => {
    const source = await readFile(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/mandatory_context.rs', import.meta.url), 'utf8')
    assert.match(source, /GetUserObjectSecurity/u)
    assert.match(source, /LABEL_SECURITY_INFORMATION/u)
    assert.match(source, /TokenMandatoryPolicy/u)
    assert.doesNotMatch(source, /SetTokenInformation|SetUserObjectSecurity|AdjustTokenPrivileges|ACCESS_SYSTEM_SECURITY|SACL_SECURITY_INFORMATION|CloseHandle|CloseDesktop|CloseWindowStation|CreateProcess|assert_eq!|dbg!/u)
})
