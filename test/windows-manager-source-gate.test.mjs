// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { runRestrictedTokenProbe, validateRestrictedTokenProbeOutput } from '../scripts/verify-windows-restricted-token-probe.mjs'
import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { delimiter, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { managerSourceEvidence } from '../scripts/windows-manager-source-evidence.mjs'
import { managerSourceFields, donorRows, copyRows, managerSourceName, managerSourceOutput } from './helpers/windows-manager-source-fixture.mjs'

for (const callerEqual of [true, false]) {
    test(`Manager source gate requires exact startup evidence with known caller equality ${callerEqual}`, () => {
        assert.equal(validateRestrictedTokenProbeOutput(managerSourceOutput(callerEqual), '', { mode: 'manager-source-proof' }).passed, true)
    })
}

test('Manager source wrapper invokes only fixed native test and preserves genuine Cargo failure', async () => {
    let calls = 0
    const result = await runRestrictedTokenProbe({
        mode: 'manager-source-proof',
        execute: async (command, args, options) => {
            calls += 1
            assert.equal(command, 'cargo')
            assert.deepEqual(args, ['test', '--manifest-path', 'native/rdx-service/windows-native/Cargo.toml', '--locked', '--lib', managerSourceName, '--', '--ignored', '--exact', '--nocapture', '--test-threads=2'])
            assert.equal(options.maxBuffer, 65536)
            assert.equal(options.timeout, 120000)
            assert.equal(options.shell, false)
            return { exitCode: 101, stdout: managerSourceOutput(), stderr: 'private arbitrary error' }
        }
    })
    assert.equal(calls, 1)
    assert.equal(result.exitCode, 101)
    assert.equal(result.passed, false)
    assert.equal(result.cargoExitCode, 101)
    assert.equal(result.failureClass, 'native-exit')
})

/** @param {string} output Synthetic native transcript. @returns {boolean} Exact new-mode verdict. */
function accepted(output) {
    return validateRestrictedTokenProbeOutput(output, '', { mode: 'manager-source-proof' }).passed
}

for (const [label, mutate] of [
    ['zero tests', (s) => s.replace('running 1 test', 'running 0 tests')],
    ['missing test count', (s) => s.replace('running 1 test\n', '')],
    ['wrong named test', (s) => s.replace(managerSourceName, 'another_test')],
    ['duplicate named test', (s) => `${s}test ${managerSourceName} ... ok\n`],
    ['missing summary', (s) => s.replace(/test result:[^\n]+\n/u, '')],
    ['ignored result', (s) => s.replace('1 passed; 0 failed; 0 ignored', '0 passed; 0 failed; 1 ignored')],
    ['duplicate transcript', (s) => s + s],
    ['wrong mode output', (s) => `${s}openrdx-token-probe query-ok=true\n`],
    ['unknown source prefix', (s) => `${s}openrdx-manager-source-secret private=true\n`],
    ['private value', (s) => s.replace('caller-owned=true', 'caller-owned=private-user')],
    ['unknown field', (s) => s.replace('caller-owned=true', 'private-sid=true')],
    ['duplicate field', (s) => s.replace('caller-owned=true', 'caller-owned=true caller-owned=true')],
    ['unavailable donor', (s) => s.replace('available=true', 'available=false')],
    ['unknown image generation asserted', (s) => s.replaceAll('mapped-generation-known=false', 'mapped-generation-known=true')],
    ['inconsistent caller equality', (s) => s.replace('phase=donor-proof available=true enrolled=true image=true ordinary-medium=true caller-user-equal=false', 'phase=donor-proof available=true enrolled=true image=true ordinary-medium=true caller-user-equal=true')],
    ['missing source field', (s) => s.replace('active-console-session=true', '')],
    [
        'missing nested acquisition',
        (s) =>
            s
                .split('\n')
                .filter((line) => !line.startsWith('openrdx-manager-source-task-one-'))
                .join('\n')
    ],
    ['changed source preservation', (s) => s.replace('descriptor-equal=true', 'descriptor-equal=false')],
    ['extra nested preservation', (s) => s.replace('openrdx-manager-source-stage phase=duplicate status=ok', 'openrdx-manager-source-task-one-preservation query-ok=true instance-known=true instance-equal=true logon-equal=true modified-equal=false properties-equal=true default-dacl-equal=true descriptor-equal=true\nopenrdx-manager-source-stage phase=duplicate status=ok')],
    ['nested observation outside owner phase', (s) => s.replace('phase=copy-proof status=begin', 'phase=copy-proof status=begin\nopenrdx-manager-source-task-one-copy query-ok=true instance-known=true copy-distinct=true logon-equal=true modified-equal=false properties-equal=true default-dacl-equal=true')],
    ['orphan terminal', (s) => s.replace('openrdx-manager-source-stage phase=fixtures status=begin\n', '')],
    ['missing complete phase', (s) => s.replace(/openrdx-manager-source(?:-stage)? phase=complete[^\n]+\n/gu, '')],
    ['skipped phase', (s) => s.replace(/openrdx-manager-source(?:-stage)? phase=fixtures[^\n]+\n/gu, '')],
    ['out of order phase', (s) => s.replaceAll('phase=fixtures', 'phase=wait-create')],
    ['orphan exit', (s) => s.replace('openrdx-manager-source-exit phase=proof-exit category=success\n', '') + 'openrdx-manager-source-exit phase=proof-exit category=success\n'],
    ['duplicate exit', (s) => s.replace('category=alive', 'category=alive\nopenrdx-manager-source-exit phase=wait-observe category=alive')],
    ['missing exit', (s) => s.replace('openrdx-manager-source-exit phase=wait-observe category=alive\n', '')],
    ['loader failure', (s) => s.replace('category=alive', 'category=status-dll-init-failed')],
    ['unknown raw exit', (s) => s.replace('category=alive', 'category=3221225794')],
    ['uncertain successful create', (s) => s.replace('creation-uncertain=false', 'creation-uncertain=true')],
    ['failed reap', (s) => s.replace('phase=wait-reap verified=true', 'phase=wait-reap verified=false')],
    ['deferred successful cleanup', (s) => s.replace('phase=child-cleanup verified=true deferred=false', 'phase=child-cleanup verified=true deferred=true')],
    ['missing proof property', (s) => s.replace('user-equal=true ', '')],
    ['changed caller', (s) => s.replace('phase=caller-check verified=true', 'phase=caller-check verified=false')],
    ['changed donor', (s) => s.replace('phase=donor-check verified=true', 'phase=donor-check verified=false')],
    ['changed duplicate', (s) => s.replace('phase=copy-check verified=true', 'phase=copy-check verified=false')],
    ['failure then ok', (s) => s.replace('phase=fixtures status=ok', 'phase=fixtures status=failed reason=Other\nopenrdx-manager-source-stage phase=fixtures status=ok')],
    ['failure then begin', (s) => s.replace('phase=fixtures status=ok', 'phase=fixtures status=failed reason=Other\nopenrdx-manager-source-stage phase=fixtures status=begin')],
    ['unknown native reason', (s) => s.replace('phase=fixtures status=ok', 'phase=fixtures status=failed reason=NotFound')]
]) {
    test(`Manager source gate rejects ${label}`, () => assert.equal(accepted(mutate(managerSourceOutput())), false))
}

test('Manager source evidence cannot authorize any existing mode', () => {
    for (const mode of ['baseline', 'medium', 'child', 'source-control', 'process-dacl-control', 'object-dacl-controls', 'actual-token-dacl-control', 'debugger-control']) assert.equal(validateRestrictedTokenProbeOutput(managerSourceOutput(), '', { mode }).passed, false)
})

test('Manager source preserves closed partial failure while independent cleanup succeeds', async () => {
    const { managerSourceEvidence } = await import('../scripts/windows-manager-source-evidence.mjs')
    const whole = managerSourceOutput()
    const before = whole.slice(0, whole.indexOf('openrdx-manager-source-stage phase=wait-create status=begin'))
    const cleanup = whole.slice(whole.indexOf('openrdx-manager-source-stage phase=child-cleanup status=begin')).replace('experiment-complete=true startup-proof=true', 'experiment-complete=false startup-proof=false').replace('phase=complete status=ok', 'phase=complete status=failed reason=AccessDenied')
    const stdout = `${before}openrdx-manager-source-stage phase=wait-create status=begin\nopenrdx-manager-source phase=wait-create created=false creation-uncertain=true\nopenrdx-manager-source-stage phase=wait-create status=failed reason=AccessDenied\n${cleanup}`
    const evidence = managerSourceEvidence(stdout.split('\n'))
    assert.equal(evidence.reason, null)
    assert.equal(evidence.complete, false)
    assert.equal(evidence.firstFailure, 'openrdx-manager-source-stage phase=wait-create status=failed reason=AccessDenied')
    const result = await runRestrictedTokenProbe({ mode: 'manager-source-proof', execute: async () => ({ exitCode: 101, stdout, stderr: 'private unrelated text' }) })
    assert.equal(result.exitCode, 101)
    assert.ok(result.managerSource.includes(evidence.firstFailure))
    assert.ok(result.managerSource.includes('openrdx-manager-source-stage phase=copy-check status=ok'))
    assert.equal(JSON.stringify(result).includes('private unrelated'), false)
})

test('Manager source preserves all exact NativeError reasons and refuses nonenum strings', async () => {
    const { managerSourceEvidence } = await import('../scripts/windows-manager-source-evidence.mjs')
    for (const reason of ['UnsupportedPlatform', 'InvalidRequest', 'AccessDenied', 'Busy', 'ReadOnly', 'Cancelled', 'TimedOut', 'DeviceRemoved', 'NoMedia', 'EnumerationFailed', 'EvidenceIncomplete', 'ResourceLimit', 'Other']) {
        const evidence = managerSourceEvidence(['openrdx-manager-source-stage phase=donor-proof status=begin', `openrdx-manager-source-stage phase=donor-proof status=failed reason=${reason}`])
        assert.equal(evidence.reason, null)
        assert.equal(evidence.complete, false)
        assert.equal(evidence.firstFailure, `openrdx-manager-source-stage phase=donor-proof status=failed reason=${reason}`)
    }
})

for (const executionError of ['signal', 'launch', 'timeout', 'buffer']) {
    test(`Manager source ${executionError} has no fabricated Cargo exit or reusable evidence`, async () => {
        const result = await runRestrictedTokenProbe({ mode: 'manager-source-proof', execute: async () => ({ executionError, exitCode: null, stdout: managerSourceOutput(), stderr: '' }) })
        assert.equal(result.passed, false)
        assert.equal(result.exitCode, 1)
        assert.equal(result.cargoExitCode, null)
        assert.equal(result.failureClass, 'execution')
        assert.deepEqual(result.managerSource, [])
    })
}

test('Manager source exact success retains only closed facts and unchanged capture bounds', async () => {
    const stdout = managerSourceOutput()
    const result = await runRestrictedTokenProbe({ mode: 'manager-source-proof', execute: async () => ({ exitCode: 0, stdout, stderr: 'arbitrary stderr not exported' }) })
    assert.equal(result.passed, true)
    assert.equal(result.exitCode, 0)
    assert.equal(
        result.managerSource.join('\n'),
        stdout
            .split('\n')
            .filter((line) => line.startsWith('openrdx-manager-source'))
            .join('\n')
    )
    assert.equal(JSON.stringify(result).includes('arbitrary stderr'), false)
    assert.equal(validateRestrictedTokenProbeOutput(stdout, 'x'.repeat(65536), { mode: 'manager-source-proof' }).passed, false)
})

/** Actual checked-in Rust formatter is executed on the host; source/child observations are synthetic inputs. */
test('actual Rust formatter roundtrips success and every failed checkpoint within the original capture bound', async () => {
    const execute = promisify(execFile)
    const root = await mkdtemp(join(tmpdir(), 'openrdx-manager-source-format-'))
    const formatter = fileURLToPath(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/manager_source_output.rs', import.meta.url))
    try {
        const source = join(root, 'format.rs'),
            binary = join(root, process.platform === 'win32' ? 'format.exe' : 'format')
        const phases = Object.entries(managerSourceFields)
        const body = phases
            .map(([phase, fields], index) => {
                const nested = phase === 'donor-proof' ? donorRows(false) : phase === 'duplicate' ? copyRows() : []
                const tuples = fields.map((key) => `(${JSON.stringify(key)}, ${key === 'caller-user-equal' ? 'caller' : !['mapped-generation-known', 'creation-uncertain', 'deferred'].includes(key)})`).join(',')
                return `if failed.is_none() || failed.is_some_and(|f| ${index} <= f) || ${index} >= 14 {
print!("{}", formatter::stage(${JSON.stringify(phase)}, "begin", None).unwrap());
${nested.map((row) => `println!("{}", ${JSON.stringify(row)}.replace("caller-user-equal=false", if caller { "caller-user-equal=true" } else { "caller-user-equal=false" }));`).join('\n')}
if failed != Some(${index}) {
${phase === 'wait-observe' || phase === 'proof-exit' ? `print!("{}", formatter::exit(${JSON.stringify(phase)}, ${JSON.stringify(phase === 'wait-observe' ? 'alive' : 'success')}).unwrap());` : ''}
let mut values = vec![${tuples}];
if failed.is_some() && ${JSON.stringify(phase)} == "complete" { values = vec![("experiment-complete",false),("startup-proof",false)]; }
print!("{}", formatter::facts(${JSON.stringify(phase)}, &values).unwrap());
}
let bad = failed == Some(${index}) || (failed.is_some() && ${JSON.stringify(phase)} == "complete");
print!("{}", formatter::stage(${JSON.stringify(phase)}, if bad { "failed" } else { "ok" }, bad.then_some("UnsupportedPlatform")).unwrap());
}`
            })
            .join('\n')
        await writeFile(
            source,
            `#[allow(dead_code)] #[path=${JSON.stringify(formatter)}] mod formatter;
fn main() { let args:Vec<String> = std::env::args().collect(); let caller = args[1] == "true"; let failed = args.get(2).map(|s| s.parse::<usize>().unwrap());
${body}
}
`
        )
        await execute('rustc', ['--edition=2024', source, '-o', binary], { timeout: 30000, maxBuffer: 65536 })
        for (const caller of [false, true]) {
            const { stdout } = await execute(binary, [String(caller)], { timeout: 30000, maxBuffer: 65536 })
            const expected = managerSourceOutput(caller)
                .split('\n')
                .filter((line) => line.startsWith('openrdx-manager-source'))
            const evidence = managerSourceEvidence(stdout.replaceAll('\n', '\r\n').split(/\r?\n/u))
            assert.equal(evidence.complete, true)
            assert.deepEqual(evidence.lines, expected)
            const envelope = `running 1 test\n${stdout}test ${managerSourceName} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 150 filtered out; finished in 0.00s\n`
            assert.equal(accepted(envelope), true)
            assert.ok(Buffer.byteLength(envelope.replaceAll('\n', '\r\n')) + 4096 < 65536)
        }
        for (const [index, [phase]] of phases.entries()) {
            const { stdout } = await execute(binary, ['false', String(index)], { timeout: 30000, maxBuffer: 65536 })
            const evidence = managerSourceEvidence(stdout.split('\n'))
            assert.equal(evidence.reason, null, phase)
            assert.equal(evidence.complete, false, phase)
            assert.equal(evidence.firstFailure, `openrdx-manager-source-stage phase=${phase} status=failed reason=UnsupportedPlatform`)
            assert.ok(Buffer.byteLength(stdout.replaceAll('\n', '\r\n')) + 4096 < 65536)
        }
    } finally {
        await rm(root, { recursive: true, force: true })
    }
})

test('Manager source preserves known false duplicate preservation followed by independent rows', () => {
    const stdout = managerSourceOutput().replace('phase=duplicate status=ok', 'phase=duplicate status=failed reason=EvidenceIncomplete')
    const begin = stdout.indexOf('openrdx-manager-source-stage phase=duplicate status=begin')
    const split = stdout.slice(0, begin) + stdout.slice(begin).replace('descriptor-equal=true', 'descriptor-equal=false')
    const before = split.slice(0, split.indexOf('openrdx-manager-source-stage phase=copy-proof status=begin'))
    const cleanup = split.slice(split.indexOf('openrdx-manager-source-stage phase=child-cleanup status=begin'))
    const evidence = managerSourceEvidence(`${before}${cleanup}`.split('\n'))
    assert.equal(evidence.reason, null)
    assert.equal(evidence.complete, false)
    assert.equal(evidence.firstFailure, 'openrdx-manager-source-stage phase=duplicate status=failed reason=EvidenceIncomplete')
    assert.ok(evidence.lines.some((line) => line.includes('descriptor-equal=false')))
})

/** The actual CLI is executed against a private harmless Cargo stand-in, never a Windows token/API. */
test('fixed Manager source CLI accepts only its sole flag and exports reconstructed output', async () => {
    const execute = promisify(execFile)
    const root = await mkdtemp(join(tmpdir(), 'openrdx-manager-source-cli-'))
    try {
        const source = join(root, 'cargo.rs'),
            binary = join(root, process.platform === 'win32' ? 'cargo.exe' : 'cargo')
        const args = ['test', '--manifest-path', 'native/rdx-service/windows-native/Cargo.toml', '--locked', '--lib', managerSourceName, '--', '--ignored', '--exact', '--nocapture', '--test-threads=2']
        await writeFile(source, `fn main() { let expected = [${args.map((arg) => JSON.stringify(arg)).join(',')}]; if std::env::args().skip(1).collect::<Vec<_>>() != expected { std::process::exit(111); } print!("{}", ${JSON.stringify(managerSourceOutput())}); println!("arbitrary stdout not forwarded"); eprintln!("arbitrary stderr not forwarded"); }`)
        await execute('rustc', ['--edition=2024', source, '-o', binary], { timeout: 30000, maxBuffer: 65536 })
        const wrapper = fileURLToPath(new URL('../scripts/verify-windows-restricted-token-probe.mjs', import.meta.url))
        const options = { env: { ...process.env, PATH: `${root}${delimiter}${process.env.PATH}` }, timeout: 30000, maxBuffer: 65536 }
        const { stdout, stderr } = await execute(process.execPath, [wrapper, '--manager-source-proof'], options)
        assert.equal(stderr, '')
        assert.equal(stdout.includes('arbitrary'), false)
        assert.equal(stdout.includes('test result:'), false)
        assert.match(stdout, /openrdx-token-probe-gate passed=true class=none reason=none cargo-exit-observed=true cargo-exit-zero=true cargo-exit-nonzero=false\n$/u)
        assert.equal(
            stdout.split('\n').filter((line) => line.startsWith('openrdx-manager-source')).length,
            managerSourceOutput()
                .split('\n')
                .filter((line) => line.startsWith('openrdx-manager-source')).length
        )
        for (const rejected of [['--manager-source-proof', '--child'], ['--manager-source-proof=private'], ['--manager-source-proof', 'private']]) {
            await assert.rejects(execute(process.execPath, [wrapper, ...rejected], options), (error) => error.code === 1 && error.stdout === '' && error.stderr === 'openrdx-token-probe-gate passed=false arguments-rejected=true\n')
        }
    } finally {
        await rm(root, { recursive: true, force: true })
    }
})

test('Manager source rejects noncleanup work after any failed outer or nested phase', () => {
    for (const stdout of [managerSourceOutput().replace('phase=fixtures status=ok', 'phase=fixtures status=failed reason=Other'), managerSourceOutput().replace('openrdx-manager-source-task-one-stage phase=caller status=ok', 'openrdx-manager-source-task-one-stage phase=caller status=failed reason=Other')]) assert.equal(managerSourceEvidence(stdout.split('\n')).reason, 'manager-source-schema')
})
