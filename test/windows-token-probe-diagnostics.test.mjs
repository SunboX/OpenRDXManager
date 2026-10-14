// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'
import { runRestrictedTokenProbe, validateRestrictedTokenProbeOutput } from '../scripts/verify-windows-restricted-token-probe.mjs'

const execute = promisify(execFile)
const name = 'service_acl::windows_impl::restricted_token_probe::native_restricted_token_observations'
const success = `running 1 test\nopenrdx-token-probe source-open=true derived-created=true query-ok=true\ntest ${name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`

test('fixed gate pins two libtest threads and distinguishes evidence rejection from native failure', async () => {
    const result = await runRestrictedTokenProbe({
        execute: async (_command, args) => {
            assert.ok(args.includes('--test-threads=2'))
            return { exitCode: 0, stdout: '', stderr: '' }
        }
    })
    assert.equal(result.failureClass, 'evidence')
    assert.equal(result.cargoExitCode, 0)
    assert.equal(result.failureReason, 'running-count')
})

test('Cargo failure preserves 101 and only reconstructed closed partial facts and latest stage', async () => {
    const result = await runRestrictedTokenProbe({ mode: 'child', execute: async () => ({ exitCode: 101, stdout: 'running 1 test\nopenrdx-token-probe source-open=true query-ok=false\nopenrdx-token-probe-stage phase=timeout-create status=failed reason=AccessDenied\nprivate panic text\n', stderr: 'private SID/path' }) })
    assert.equal(result.exitCode, 101)
    assert.equal(result.cargoExitCode, 101)
    assert.equal(result.failureClass, 'native-exit')
    assert.deepEqual(result.facts, ['openrdx-token-probe source-open=true query-ok=false'])
    assert.equal(result.stage, 'openrdx-token-probe-stage phase=timeout-create status=failed reason=AccessDenied')
    assert.equal(JSON.stringify(result).includes('private'), false)
})

test('execution errors never masquerade as an observed Cargo exit', async () => {
    for (const kind of ['timeout', 'buffer', 'signal', 'launch']) {
        const result = await runRestrictedTokenProbe({ execute: async () => ({ executionError: kind, exitCode: null, stdout: '', stderr: 'private' }) })
        assert.equal(result.failureClass, 'execution')
        assert.equal(result.failureReason, kind)
        assert.equal(result.cargoExitCode, null)
        assert.equal(result.exitCode, 1)
    }
})

test('a failed or incomplete native checkpoint cannot authorize otherwise successful output', () => {
    for (const stage of ['status=begin', 'status=failed reason=Other']) {
        const result = validateRestrictedTokenProbeOutput(success + `openrdx-token-probe-stage phase=positive-wait ${stage}\n`, '')
        assert.equal(result.passed, false)
        assert.equal(result.reason, 'stage-result')
    }
})

test('first native failure remains sticky through later ok or begin checkpoints', async () => {
    const first = 'openrdx-token-probe-stage phase=positive-proof status=failed reason=Other'
    for (const later of ['status=ok', 'status=begin']) {
        const stdout = success + `${first}\nopenrdx-token-probe-stage phase=positive-cleanup ${later}\n`
        assert.equal(validateRestrictedTokenProbeOutput(stdout, '').passed, false)
        for (const exitCode of [0, 101]) {
            const result = await runRestrictedTokenProbe({ execute: async () => ({ exitCode, stdout, stderr: 'not-forwarded' }) })
            assert.equal(result.passed, false)
            assert.equal(result.stage, first)
            assert.equal(result.exitCode, exitCode === 0 ? 1 : 101)
            assert.equal(result.cargoExitCode, exitCode)
            assert.equal(result.failureClass, exitCode === 0 ? 'evidence' : 'native-exit')
        }
    }
})

test('malformed partial fields or stage vocabulary cannot pass or leak', async () => {
    for (const text of ['query-ok=private', 'query-ok=true query-ok=false', 'private-sid=true', 'stage']) {
        const stdout = text === 'stage' ? success + 'openrdx-token-probe-stage phase=private status=failed reason=private\n' : success + `openrdx-token-probe ${text}\n`
        const result = await runRestrictedTokenProbe({ execute: async () => ({ exitCode: 0, stdout, stderr: '' }) })
        assert.equal(result.passed, false)
        assert.deepEqual(result.facts, [])
        assert.equal(result.stage, null)
    }
})

test('real harmless host libtest serial transcript is rejected; fixed two-thread transcript passes', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-libtest-'))
    try {
        const source = join(directory, 'probe.rs')
        const binary = join(directory, process.platform === 'win32' ? 'probe.exe' : 'probe')
        await writeFile(source, '#[test]\n#[ignore]\nfn probe() { println!("openrdx-token-probe source-open=true derived-created=true query-ok=true"); std::thread::sleep(std::time::Duration::from_millis(50)); }\n')
        await execute('rustc', ['--edition=2024', '--test', source, '-o', binary], { timeout: 30_000 })
        const serial = await execute(binary, ['probe', '--ignored', '--exact', '--nocapture', '--test-threads=1'])
        const threaded = await execute(binary, ['probe', '--ignored', '--exact', '--nocapture', '--test-threads=2'])
        // Host-only formatting proof: neither transcript exercises Windows token APIs.
        assert.match(serial.stdout, /test probe \.\.\. openrdx-token-probe/u)
        assert.equal(validateRestrictedTokenProbeOutput(serial.stdout.replaceAll('test probe ...', `test ${name} ...`), '').passed, false)
        assert.equal(validateRestrictedTokenProbeOutput(threaded.stdout.replaceAll('test probe ...', `test ${name} ...`), '').passed, true)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})

test('argument-free child binds console query to documented Kernel32', async () => {
    const fixture = await readFile(new URL('../native/rdx-service/windows-native/tests/fixtures/token-child.rs', import.meta.url), 'utf8')
    assert.doesNotMatch(fixture, /link\(name = "wtsapi32"\)/u)
    assert.match(fixture, /link\(name = "kernel32"\)[\s\S]*WTSGetActiveConsoleSessionId/u)
})

test('each native closed phase survives failure sanitization and RAII cleanup remains marker-free', async () => {
    const child = await readFile(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/child.rs', import.meta.url), 'utf8')
    const phases = [...child.matchAll(/Self::[A-Za-z]+ => "([a-z-]+)"/gu)].map((match) => match[1])
    assert.ok(phases.length >= 20)
    for (const phase of phases) {
        const stage = `openrdx-token-probe-stage phase=${phase} status=failed reason=Other`
        const result = await runRestrictedTokenProbe({ mode: 'child', execute: async () => ({ exitCode: 101, stdout: `running 1 test\n${stage}\n`, stderr: '' }) })
        assert.equal(result.stage, stage)
        assert.equal(result.passed, false)
    }
    const drop = child.slice(child.indexOf('impl Drop for OwnedChild'), child.indexOf('/// Private token predicates'))
    assert.doesNotMatch(drop, /checkpoint|println!|eprintln!/u)
})
