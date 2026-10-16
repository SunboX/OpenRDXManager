// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { runRestrictedTokenProbe, validateRestrictedTokenProbeOutput } from '../scripts/verify-windows-restricted-token-probe.mjs'

const name = 'service_acl::windows_impl::restricted_token_probe::medium::child::native_medium_restricted_child_observations'
const required = { 'source-open': true, 'derived-created': true, 'query-ok': true, 'fixture-protected': true, 'child-created': true, 'child-image-match': true, 'child-same-user': true, 'child-same-session': true, 'child-console-user-match': true, 'child-active-console': true, 'child-elevated': false, 'child-admin-deny-only': true, 'child-no-enabled-admins': true, 'child-present-privilege-whitelist': true, 'child-medium': true, 'child-ui-access-zero': true, 'child-sandbox-inert-zero': true, 'child-primary': true, 'child-suspended-proof': true, 'child-resumed': true, 'child-exited': true, 'child-exit-zero': true, 'owned-child-cleanup': true, 'negative-proof-reaped': true, 'timeout-reaped': true, 'api-error-rejected': true }

/** Returns synthetic child evidence, never a claimed Windows observation. */
function output(facts = required) {
    return `running 1 test\nopenrdx-token-probe ${Object.entries(facts)
        .map(([key, value]) => `${key}=${value}`)
        .join(' ')}\nopenrdx-token-child-exit phase=positive-wait category=success\ntest ${name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 123 filtered out; finished in 0.00s\n`
}

test('child gate requires actual exact test and complete closed execution evidence', () => {
    assert.equal(validateRestrictedTokenProbeOutput(output(), '', { mode: 'child' }).passed, true)
    assert.equal(validateRestrictedTokenProbeOutput(output().replace('running 1 test', 'running 0 tests'), '', { mode: 'child' }).passed, false)
    assert.equal(validateRestrictedTokenProbeOutput(output().replace(name, 'wrong_test'), '', { mode: 'child' }).passed, false)
    assert.equal(validateRestrictedTokenProbeOutput(output().replace('openrdx-token-child-exit phase=positive-wait category=success\n', ''), '', { mode: 'child' }).passed, false)
})

for (const [key, expected] of Object.entries(required)) {
    test(`child gate rejects missing/incorrect ${key}`, () => {
        const missing = { ...required }
        delete missing[key]
        assert.equal(validateRestrictedTokenProbeOutput(output(missing), '', { mode: 'child' }).passed, false)
        assert.equal(validateRestrictedTokenProbeOutput(output({ ...required, [key]: !expected }), '', { mode: 'child' }).passed, false)
    })
}

test('child invocation uses only its fixed native filter and preserves native failure', async () => {
    const result = await runRestrictedTokenProbe({
        mode: 'child',
        execute: async (command, args) => {
            assert.equal(command, 'cargo')
            assert.ok(args.includes(name))
            return { exitCode: 101, stdout: output(), stderr: 'not-forwarded' }
        }
    })
    assert.equal(result.exitCode, 101)
    assert.equal(result.passed, false)
})

test('child proof owns process/thread handles, never inherits handles, and validates before resume', async () => {
    const source = await readFile(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/child.rs', import.meta.url), 'utf8')
    assert.match(source, /struct OwnedChild/u)
    assert.match(source, /CreateProcessAsUserW/u)
    assert.match(source, /CREATE_SUSPENDED \| CREATE_NO_WINDOW \| CREATE_UNICODE_ENVIRONMENT/u)
    assert.doesNotMatch(source, /STARTF_USESTDHANDLES|ShellExecute|LogonUser|Impersonate|assert_eq!|dbg!/u)
    assert.ok(source.indexOf('prove_child(&child') < source.lastIndexOf('child.resume()'))
    assert.match(source, /TerminateProcess\(self\.process\.0/u)
})

test('argument-free fixture is compiled from fixed checked-in source and evidence is uploaded early', async () => {
    const fixture = await readFile(new URL('../native/rdx-service/windows-native/tests/fixtures/token-child.rs', import.meta.url), 'utf8')
    assert.doesNotMatch(fixture, /println!|eprintln!|std::env::args|Command::|CreateProcess|SetTokenInformation/u)
    assert.match(fixture, /WTSGetActiveConsoleSessionId/u)
    assert.match(fixture, /GetTokenInformation/u)
    const workflow = await readFile(new URL('../.github/workflows/windows-token-diagnostics.yml', import.meta.url), 'utf8')
    assert.ok(workflow.includes('rustc --edition=2024 native/rdx-service/windows-native/tests/fixtures/token-child.rs -o out/verification/openrdx-token-child.exe'))
    assert.ok(workflow.includes('node scripts/verify-windows-restricted-token-probe.mjs --child | Tee-Object'))
    assert.ok(workflow.includes('out/verification/windows-token-child.log'))
})
