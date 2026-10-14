// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { runRestrictedTokenProbe, validateRestrictedTokenProbeOutput } from '../scripts/verify-windows-restricted-token-probe.mjs'

const execute = promisify(execFile)
const name = 'service_acl::windows_impl::restricted_token_probe::native_restricted_token_observations'
const passing = `running 1 test\nopenrdx-token-probe source-open=true derived-created=true query-ok=true\ntest ${name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`
const categories = ['success', 'self-token-open', 'self-process-session', 'self-console-session', 'self-token-session', 'self-elevation', 'self-ui-access', 'self-sandbox-inert', 'self-primary', 'self-integrity', 'status-dll-not-found', 'status-dll-init-failed', 'status-invalid-image-format', 'unknown']

test('native failure preserves only closed owned-child exit category and original 101', async () => {
    for (const category of categories) {
        const childExit = `openrdx-token-child-exit phase=timeout-wait category=${category}`
        const result = await runRestrictedTokenProbe({ mode: 'child', execute: async () => ({ exitCode: 101, stdout: `running 1 test\n${childExit}\n`, stderr: 'private native error' }) })
        assert.equal(result.childExit, childExit)
        assert.equal(result.exitCode, 101)
        assert.equal(result.passed, false)
        assert.equal(JSON.stringify(result).includes('private'), false)
    }
})

test('any timeout-child exit or unsuccessful positive exit is sticky failure evidence', () => {
    for (const phase of ['timeout-wait', 'positive-wait']) {
        for (const category of categories.filter((value) => phase === 'timeout-wait' || value !== 'success')) {
            const result = validateRestrictedTokenProbeOutput(`${passing}openrdx-token-child-exit phase=${phase} category=${category}\nopenrdx-token-probe-stage phase=positive-cleanup status=ok\n`, '')
            assert.equal(result.passed, false)
            assert.equal(result.reason, 'stage-result')
        }
    }
})

test('unclosed or duplicate child exit records never pass or leak', async () => {
    for (const marker of ['phase=private category=unknown', 'phase=timeout-wait category=private', 'phase=timeout-wait category=32', 'phase=positive-wait category=success extra=true', 'phase=positive-wait category=success\nopenrdx-token-child-exit phase=positive-wait category=success']) {
        const result = await runRestrictedTokenProbe({ execute: async () => ({ exitCode: 0, stdout: passing + `openrdx-token-child-exit ${marker}\n`, stderr: '' }) })
        assert.equal(result.passed, false)
        assert.equal(result.childExit, null)
        assert.equal(JSON.stringify(result).includes('private'), false)
    }
})

test('first fatal category survives contradictory success and preserves first failed stage', async () => {
    const fatal = 'openrdx-token-child-exit phase=timeout-wait category=self-integrity'
    const stage = 'openrdx-token-probe-stage phase=timeout-wait status=failed reason=Other'
    const stdout = `${passing}openrdx-token-child-exit phase=positive-wait category=success\n${fatal}\n${stage}\nopenrdx-token-probe-stage phase=positive-cleanup status=ok\n`
    const result = await runRestrictedTokenProbe({ mode: 'child', execute: async () => ({ exitCode: 101, stdout, stderr: '' }) })
    assert.equal(result.childExit, fatal)
    assert.equal(result.stage, stage)
    assert.equal(result.passed, false)
    assert.equal(result.exitCode, 101)
})

test('shared fixed exit-category mapper passes real host Rust tests without executing Windows APIs', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-exit-categories-'))
    try {
        const binary = join(directory, process.platform === 'win32' ? 'categories.exe' : 'categories')
        const source = new URL('../native/rdx-service/windows-native/tests/fixtures/token-child-status.rs', import.meta.url)
        await execute('rustc', ['--edition=2024', '--test', fileURLToPath(source), '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, ['--test-threads=2'])
        assert.match(stdout, /2 passed; 0 failed/u)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})
