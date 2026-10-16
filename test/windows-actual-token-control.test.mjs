// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import test from 'node:test'

import { runRestrictedTokenProbe, validateRestrictedTokenProbeOutput } from '../scripts/verify-windows-restricted-token-probe.mjs'

const root = new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/', import.meta.url)

test('host native admission rejects missing proof, aliases, stale epochs and unresolved fixture cleanup', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-actual-token-'))
    try {
        const driver = join(directory, 'protocol.rs')
        const binary = join(directory, process.platform === 'win32' ? 'protocol.exe' : 'protocol')
        await writeFile(driver, `#[path=${JSON.stringify(fileURLToPath(new URL('actual_token_protocol.rs', root)))}] mod actual_token_protocol;`)
        const execute = promisify(execFile)
        await execute('rustc', ['--edition=2024', '--test', driver, '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, ['--test-threads=2'], { timeout: 30_000 })
        assert.match(stdout, /7 passed; 0 failed/u)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})

const mode = 'actual-token-dacl-control'
const nativeName = 'service_acl::windows_impl::restricted_token_probe::medium::child::actual_token_control::native_actual_child_token_dacl_control'
let cachedTranscript

/** @returns {Promise<string>} Host-only synthetic full branch using the ACTUAL native formatter/schema, never Windows execution evidence. */
async function proof() {
    if (cachedTranscript !== undefined) return cachedTranscript
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-actual-format-'))
    try {
        const matrix = await readFile(new URL('actual_token_control.rs', root), 'utf8')
        const checkpoint = matrix.slice(matrix.indexOf('fn checkpoint'), matrix.indexOf('/// Owns one possible'))
        const driver = join(directory, 'format.rs')
        const binary = join(directory, process.platform === 'win32' ? 'format.exe' : 'format')
        await writeFile(driver, `#[path=${JSON.stringify(fileURLToPath(new URL('actual_token_output.rs', root)))}] mod output;\n#[derive(Debug)] enum NativeError {Other}\n${checkpoint}\nfn main(){for &phase in output::PHASES {checkpoint(phase,||{for &key in output::keys(phase){output::facts(phase,&[(key,!matches!(key,"deferred"|"creation-uncertain"|"modified-equal"))]);}if phase.ends_with("-wait"){output::exit(phase,match phase{"baseline-wait"=>"status-dll-init-failed","treatment-wait"=>"alive",_=>"success"});}Ok(())}).unwrap();}}`)
        const execute = promisify(execFile)
        await execute('rustc', ['--edition=2024', driver, '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, [], { timeout: 30_000 })
        cachedTranscript = `running 1 test\n${stdout}test ${nativeName} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`
        return cachedTranscript
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
}

test('fixed actual-token control gate accepts only one named completed isolated positive branch', async () => {
    const stdout = await proof()
    assert.equal(validateRestrictedTokenProbeOutput(stdout, '', { mode }).passed, true)
    const result = await runRestrictedTokenProbe({
        mode,
        execute: async (_command, args, options) => {
            assert.ok(args.includes(nativeName) && args.includes('--exact') && args.includes('--ignored') && args.includes('--test-threads=2'))
            assert.equal(options.timeout, 120_000)
            assert.equal(options.maxBuffer, 65_536)
            return { exitCode: 0, stdout, stderr: '' }
        }
    })
    assert.equal(result.passed, true)
    for (const other of ['baseline', 'medium', 'child', 'source-control', 'process-dacl-control', 'object-dacl-controls']) assert.equal(validateRestrictedTokenProbeOutput(stdout, '', { mode: other }).passed, false)
})

test('aliases, incomplete isolation, stale admission and contradictory outcomes cannot pass', async () => {
    const complete = await proof()
    const mutations = [
        ['actual-source-distinct=true', 'actual-source-distinct=false'],
        ['actual-derived-distinct=true', 'actual-derived-distinct=false'],
        ['write-handle-same-instance=true', 'write-handle-same-instance=false'],
        ['epoch-fresh=true', 'epoch-fresh=false'],
        ['token-dacl-exact=true', 'token-dacl-exact=false'],
        ['old-aces-retained=true', 'old-aces-retained=false'],
        ['denials-equal=true', 'denials-equal=false'],
        ['default-dacl-equal=true', 'default-dacl-equal=false'],
        ['process-exact=true', 'process-exact=false'],
        ['thread-exact=true', 'thread-exact=false'],
        ['source-unchanged=true', 'source-unchanged=false'],
        ['phase=treatment-wait category=alive', 'phase=treatment-wait category=success'],
        ['phase=positive-wait category=success', 'phase=positive-wait category=status-dll-init-failed'],
        ['creation-uncertain=false', 'creation-uncertain=true'],
        ['deferred=false', 'deferred=true']
    ]
    const rejected = mutations.map(([before, after]) => !validateRestrictedTokenProbeOutput(complete.replace(before, after), '', { mode }).passed)
    assert.deepEqual(
        rejected,
        mutations.map(() => true)
    )
})

test('strict stages, exact execution counts, private fields and cross modes cannot authorize control', async () => {
    const complete = await proof()
    const first = 'openrdx-token-actual-control-stage phase=setup status=begin\n'
    for (const stdout of [complete.replace(first, ''), complete.replace('phase=setup status=begin', 'phase=setup status=ok'), complete.replace('verified=true', 'verified=true verified=true'), complete.replace('phase=treatment-write status=ok', 'phase=treatment-write status=failed reason=Other'), complete.replace('phase=treatment-observe', 'phase=positive-observe'), complete.replace('running 1 test', 'running 0 tests'), complete.replace(nativeName, 'wrong-test'), complete.replace('1 passed; 0 failed', '0 passed; 0 failed'), complete + 'openrdx-token-actual-control-exit phase=positive-wait category=success\n', complete + 'openrdx-token-probe source-open=true\n']) assert.equal(validateRestrictedTokenProbeOutput(stdout, '', { mode }).passed, false)
    for (const stdout of [complete.replace('verified=true', 'private-sid=private-sentinel'), complete.replace('identities-known=true', 'identities-known=private-sentinel'), complete.replace('phase=treatment-write status=ok', 'phase=treatment-write status=failed reason=NotFound')]) {
        const result = await runRestrictedTokenProbe({ mode, execute: async () => ({ exitCode: 101, stdout, stderr: 'private-sentinel' }) })
        assert.equal(result.passed, false)
        assert.equal(result.exitCode, 101)
        assert.equal(result.actualControl.length, 0)
        assert.equal(JSON.stringify(result).includes('private-sentinel'), false)
    }
})

test('first native failure survives later cleanup and every real NativeError token is closed', async () => {
    for (const reason of ['UnsupportedPlatform', 'InvalidRequest', 'AccessDenied', 'Busy', 'ReadOnly', 'Cancelled', 'TimedOut', 'DeviceRemoved', 'NoMedia', 'EnumerationFailed', 'EvidenceIncomplete', 'ResourceLimit', 'Other']) {
        const stdout = `running 1 test\nopenrdx-token-actual-control-stage phase=setup status=begin\nopenrdx-token-actual-control-stage phase=setup status=failed reason=${reason}\nopenrdx-token-actual-control-stage phase=child-cleanup status=begin\nopenrdx-token-actual-control phase=child-cleanup verified=true deferred=false\nopenrdx-token-actual-control-stage phase=child-cleanup status=ok\n`
        const result = await runRestrictedTokenProbe({ mode, execute: async () => ({ exitCode: 101, stdout, stderr: '' }) })
        assert.equal(result.passed, false)
        assert.equal(result.exitCode, 101)
        assert.ok(result.actualControl.some((line) => line.endsWith(`status=failed reason=${reason}`)))
        assert.equal(validateRestrictedTokenProbeOutput(stdout, '', { mode }).passed, false)
    }
})

test('actual native formatter full branch stays bounded with CRLF and Cargo reserve', async (context) => {
    const stdout = await proof()
    const bytes = Buffer.byteLength(stdout.replaceAll('\n', '\r\n'))
    context.diagnostic(`actual-token-control complete host format ${bytes} bytes +4096 Cargo reserve`)
    assert.ok(bytes + 4096 <= 65_536)
    const { actualTokenSchema } = await import('../scripts/windows-actual-token-control-evidence.mjs')
    const observed = new Map()
    for (const line of stdout.split('\n')) {
        const match = /^openrdx-token-actual-control phase=([a-z-]+) (.+)$/u.exec(line)
        if (match !== null) observed.set(match[1], [...(observed.get(match[1]) ?? []), ...match[2].split(' ').map((pair) => pair.split('=')[0])])
    }
    assert.deepEqual(Object.fromEntries(observed), actualTokenSchema)
})

test('used canonical TOKEN builder and identity parser adversarial regressions execute on host', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-actual-descriptor-'))
    try {
        const driver = join(directory, 'descriptor.rs'),
            binary = join(directory, process.platform === 'win32' ? 'descriptor.exe' : 'descriptor')
        await writeFile(driver, ['mandatory_label', 'object_acl', 'process_descriptor', 'token_identity'].map((name) => `#[path=${JSON.stringify(fileURLToPath(new URL(`${name}.rs`, root)))}] mod ${name};`).join('\n'))
        const execute = promisify(execFile)
        await execute('rustc', ['--edition=2024', '--test', driver, '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, ['--test-threads=2'], { timeout: 30_000 })
        assert.match(stdout, /token_user_grant_preserves_original .* ok/u)
        assert.match(stdout, /unsupported_grants_and_aces_fail_closed .* ok/u)
        assert.match(stdout, /unavailable_is_unknown .* ok/u)
        assert.match(stdout, /0 failed/u)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})

test('optional actual-token CI preserves fatal ordinary gate and sanitized artifact separation', async () => {
    const workflow = await readFile(new URL('../.github/workflows/build-installers.yml', import.meta.url), 'utf8')
    assert.match(workflow, /name: Observe actual owned Windows token DACL control\s+if: always\(\) && matrix.platform == 'win' && steps.windows-token-fixtures.outcome == 'success'\s+continue-on-error: true/u)
    assert.match(workflow, /--actual-token-dacl-control \| Tee-Object -FilePath out\/verification\/windows-token-actual-token-dacl-control.log\s+\$probeExitCode = \$LASTEXITCODE\s+exit \$probeExitCode/u)
    const upload = workflow.slice(workflow.indexOf('- name: Upload closed Windows token evidence'), workflow.indexOf('- name: Verify Windows PowerShell'))
    assert.ok(upload.includes('windows-token-actual-token-dacl-control.log'))
    assert.ok(upload.includes('retention-days: 3'))
    assert.match(workflow, /pattern: installers-\*/u)
    const ordinary = workflow.split('- name: Verify owned medium Windows child on disposable runner')[1].split('\n            - name:')[0]
    assert.equal(ordinary.includes('continue-on-error'), false)
})

test('actual checkpoint and cleanup selector preserve first native error while every cleanup runs', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-actual-errors-'))
    try {
        const source = await readFile(new URL('actual_token_control.rs', root), 'utf8')
        const checkpoint = source.slice(source.indexOf('fn checkpoint'), source.indexOf('/// Owns one possible'))
        const retain = source.slice(source.indexOf('fn retain_first'), source.indexOf('/// Fresh untreated'))
        const driver = join(directory, 'errors.rs'),
            binary = join(directory, process.platform === 'win32' ? 'errors.exe' : 'errors')
        await writeFile(driver, `#[path=${JSON.stringify(fileURLToPath(new URL('actual_token_output.rs', root)))}] mod output;\n#[derive(Debug,PartialEq)] enum NativeError{Other,AccessDenied,Busy}\n${checkpoint}\n${retain}\nfn main(){let primary:Result<(),NativeError>=checkpoint("setup",||{output::facts("setup",&[("verified",false)]);Err(NativeError::AccessDenied)});let mut first=None;let mut attempted=0;for phase in ["child-cleanup","proof-cleanup","wait-cleanup","source-check","derived-check"]{let result=checkpoint(phase,||{attempted+=1;Err(NativeError::Busy)});retain_first(&mut first,result);}assert!(attempted==5);let result=match primary{Err(e)=>Err(e),Ok(())=>first.map_or(Ok(()),Err)};assert!(matches!(result,Err(NativeError::AccessDenied)));}`)
        const execute = promisify(execFile)
        await execute('rustc', ['--edition=2024', driver, '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, [], { timeout: 30_000 })
        assert.match(stdout, /phase=setup status=failed reason=AccessDenied/u)
        const result = await runRestrictedTokenProbe({ mode, execute: async () => ({ exitCode: 101, stdout, stderr: '' }) })
        assert.equal(result.exitCode, 101)
        assert.ok(result.actualControl.some((line) => line.endsWith('reason=AccessDenied')))
        assert.equal(result.actualControl.filter((line) => line.endsWith('status=failed reason=Busy')).length, 5)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})
