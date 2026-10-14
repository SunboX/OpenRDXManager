// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

const name = 'service_acl::windows_impl::restricted_token_probe::native_restricted_token_observations'
const successful = `running 1 test\nopenrdx-token-probe source-open=true\nopenrdx-token-probe derived-created=true\nopenrdx-token-probe query-ok=true same-user=true same-session=true derived-elevated=true integrity-high=true\ntest ${name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 121 filtered out; finished in 0.00s\n`

/** Loads the real gate without invoking Cargo. */
async function gate() {
    return import('../scripts/verify-windows-restricted-token-probe.mjs')
}

for (const [label, output] of [
    ['zero tests despite forged success evidence', successful.replace('running 1 test', 'running 0 tests')],
    ['missing query marker', successful.replace(/openrdx-token-probe query-ok=true[^\n]*\n/u, '')],
    ['native query failed', successful.replace('query-ok=true', 'query-ok=false')],
    ['wrong exact test', successful.replace(name, 'another_test')],
    ['ignored test', successful.replace('1 passed; 0 failed; 0 ignored', '0 passed; 0 failed; 1 ignored')],
    ['native test failed', successful.replace(' ... ok', ' ... FAILED').replace('1 passed; 0 failed', '0 passed; 1 failed')],
    ['duplicate summary', successful + successful],
    ['unclosed diagnostic value', successful.replace('same-user=true', 'same-user=private-user')],
    ['unrecognized diagnostic field', successful.replace('same-user=true', 'private-sid=true')]
]) {
    test(`token probe gate rejects ${label}`, async () => {
        const { validateRestrictedTokenProbeOutput } = await gate()
        assert.equal(validateRestrictedTokenProbeOutput(output, '').passed, false)
    })
}

test('token probe gate accepts one executed exact test with closed query facts, including ineligible observations', async () => {
    const { validateRestrictedTokenProbeOutput } = await gate()
    const result = validateRestrictedTokenProbeOutput(successful.replaceAll('\n', '\r\n'), '    Finished test profile\n')
    assert.equal(result.passed, true)
    assert.equal(
        result.facts.some((line) => line.includes('derived-elevated=true')),
        true
    )
    assert.equal(
        result.facts.some((line) => line.includes('integrity-high=true')),
        true
    )
})

test('token probe gate preserves original Cargo failure and invokes only the fixed ignored exact command', async () => {
    const { runRestrictedTokenProbe } = await gate()
    let calls = 0
    const result = await runRestrictedTokenProbe({
        /** @returns {Promise<object>} Returns an original Cargo failure despite valid-looking output. */
        execute: async (command, args, options) => {
            calls += 1
            assert.equal(command, 'cargo')
            assert.deepEqual(args, ['test', '--manifest-path', 'native/rdx-service/windows-native/Cargo.toml', '--locked', '--lib', name, '--', '--ignored', '--exact', '--nocapture', '--test-threads=2'])
            assert.equal(options.shell, false)
            assert.equal(options.maxBuffer, 65_536)
            return { exitCode: 101, stdout: successful, stderr: 'private arbitrary stderr' }
        }
    })
    assert.equal(calls, 1)
    assert.equal(result.exitCode, 101)
    assert.equal(result.passed, false)
    assert.deepEqual(
        result.facts,
        successful.split('\n').filter((line) => line.startsWith('openrdx-token-probe '))
    )
    assert.equal(result.cargoExitCode, 101)
    assert.equal(result.failureClass, 'native-exit')
})

test('token probe gate fails zero-exit invalid evidence and bounded-output overflow', async () => {
    const { runRestrictedTokenProbe, validateRestrictedTokenProbeOutput } = await gate()
    const result = await runRestrictedTokenProbe({ execute: async () => ({ exitCode: 0, stdout: '', stderr: '' }) })
    assert.equal(result.exitCode, 1)
    assert.equal(result.passed, false)
    assert.equal(validateRestrictedTokenProbeOutput(successful, 'x'.repeat(65_537)).passed, false)
})

test('token probe gate passes exact successful execution and sanitizes launch errors', async () => {
    const { runRestrictedTokenProbe } = await gate()
    const result = await runRestrictedTokenProbe({ execute: async () => ({ exitCode: 0, stdout: successful, stderr: '' }) })
    assert.equal(result.exitCode, 0)
    assert.equal(result.passed, true)
    const failed = await runRestrictedTokenProbe({
        execute: async () => {
            throw new Error('private launch details')
        }
    })
    assert.deepEqual(failed, { exitCode: 1, passed: false, facts: [], context: [], mandatoryContext: [], libraryContext: [], objectContext: [], stage: null, childExit: null, cargoExitCode: null, failureClass: 'execution', failureReason: 'launch' })
})
