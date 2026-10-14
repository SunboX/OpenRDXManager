// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { runRestrictedTokenProbe, validateRestrictedTokenProbeOutput } from '../scripts/verify-windows-restricted-token-probe.mjs'

const name = 'service_acl::windows_impl::restricted_token_probe::medium::native_medium_restricted_token_observations'
const facts = {
    'source-open': true,
    'derived-created': true,
    'query-ok': true,
    'medium-set-ok': true,
    'source-unchanged': true,
    'same-user': true,
    'same-session': true,
    'source-active-console': true,
    'derived-active-console': true,
    'source-console-user-match': true,
    'derived-console-user-match': true,
    'source-elevated': true,
    'derived-elevated': false,
    'source-integrity-high': true,
    'admin-deny-only': true,
    'no-enabled-admins': true,
    'enabled-privilege-whitelist': true,
    'present-privilege-whitelist': true,
    'privileges-reduced': true,
    'no-added-privileges': true,
    'integrity-medium': true,
    'integrity-high': false,
    'integrity-reduced': true,
    'ui-access-zero': true,
    'sandbox-inert-zero': true,
    'primary-token': true,
    'elevation-type-known': true,
    'elevation-type-default': true,
    'elevation-type-limited': false,
    'elevation-type-full': false
}

/** Returns synthetic closed evidence; this is not an actual Windows token observation. */
function output(properties = facts) {
    return `running 1 test\nopenrdx-token-probe ${Object.entries(properties)
        .map(([key, value]) => `${key}=${value}`)
        .join(' ')}\ntest ${name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 122 filtered out; finished in 0.00s\n`
}

test('medium gate accepts complete token-only readback, not a process eligibility claim', () => {
    assert.equal(validateRestrictedTokenProbeOutput(output(), '', { mode: 'medium' }).passed, true)
})

for (const [key, expected] of Object.entries(facts).filter(([key]) => !['elevation-type-default', 'elevation-type-limited'].includes(key))) {
    test(`medium gate rejects missing or incorrect ${key}`, () => {
        const missing = { ...facts }
        delete missing[key]
        assert.equal(validateRestrictedTokenProbeOutput(output(missing), '', { mode: 'medium' }).passed, false)
        assert.equal(validateRestrictedTokenProbeOutput(output({ ...facts, [key]: !expected }), '', { mode: 'medium' }).passed, false)
    })
}

test('medium gate rejects unknown mode, zero tests, wrong native filter and missing successful query marker', async () => {
    assert.equal(validateRestrictedTokenProbeOutput(output(), '', { mode: 'unknown' }).passed, false)
    assert.equal(validateRestrictedTokenProbeOutput(output().replace('running 1 test', 'running 0 tests'), '', { mode: 'medium' }).passed, false)
    assert.equal(validateRestrictedTokenProbeOutput(output().replace(name, 'another_test'), '', { mode: 'medium' }).passed, false)
    assert.equal(validateRestrictedTokenProbeOutput(output({ ...facts, 'query-ok': false }), '', { mode: 'medium' }).passed, false)
    const rejected = await runRestrictedTokenProbe({
        mode: 'unknown',
        execute: async () => {
            throw new Error('must-not-execute')
        }
    })
    assert.equal(rejected.exitCode, 1)
})

test('medium gate invokes only its exact fixed ignored test and preserves Cargo failure', async () => {
    const failed = await runRestrictedTokenProbe({
        mode: 'medium',
        execute: async (command, args) => {
            assert.equal(command, 'cargo')
            assert.ok(args.includes(name))
            assert.deepEqual(args.slice(-3), ['--ignored', '--exact', '--nocapture'])
            return { exitCode: 101, stdout: output(), stderr: '' }
        }
    })
    assert.equal(failed.exitCode, 101)
    assert.equal(failed.passed, false)
})

test('medium probe adjusts only owned derived integrity and snapshots source without launch APIs', async () => {
    const source = await readFile(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium.rs', import.meta.url), 'utf8')
    assert.match(source, /SetTokenInformation\(\s*derived\.0,\s*TokenIntegrityLevel/u)
    assert.match(source, /source_before == source_after/u)
    assert.match(source, /TokenUIAccess/u)
    assert.match(source, /TokenSandBoxInert/u)
    assert.doesNotMatch(source, /CreateProcess|Impersonate|AdjustTokenPrivileges|assert_eq!|dbg!/u)
    const workflow = await readFile(new URL('../.github/workflows/build-installers.yml', import.meta.url), 'utf8')
    assert.ok(workflow.includes('node scripts/verify-windows-restricted-token-probe.mjs --medium'))
})

test('Windows token evidence captures only sanitized wrapper stdout, preserves native status and uploads before packaging', async () => {
    const workflow = await readFile(new URL('../.github/workflows/build-installers.yml', import.meta.url), 'utf8')
    for (const [mode, file] of [
        ['', 'baseline'],
        [' --medium', 'medium']
    ]) {
        assert.ok(workflow.includes(`node scripts/verify-windows-restricted-token-probe.mjs${mode} | Tee-Object -FilePath out/verification/windows-token-${file}.log`))
    }
    const capture = workflow.slice(workflow.indexOf('- name: Observe restricted Windows token'), workflow.indexOf('- name: Verify Windows PowerShell installer boundary'))
    assert.equal((capture.match(/\$probeExitCode = \$LASTEXITCODE\s*exit \$probeExitCode/gu) ?? []).length, 2)
    assert.match(capture, /if: always\(\) && matrix\.platform == 'win'/u)
    assert.match(capture, /name: windows-token-diagnostics-\$\{\{ matrix\.arch \}\}/u)
    assert.match(capture, /retention-days: 3/u)
    assert.doesNotMatch(capture, /cargo test|2>&1|\*\.exe|\*\.zip/u)
    assert.ok(workflow.indexOf('name: windows-token-diagnostics-') < workflow.indexOf('- name: Build installers'))
    assert.match(workflow, /pattern: installers-\*/u)
})
