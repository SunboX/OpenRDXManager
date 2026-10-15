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
import { debuggerControlEvidence, debuggerSchema } from '../scripts/windows-debugger-control-evidence.mjs'
import { runRestrictedTokenProbe, validateRestrictedTokenProbeOutput } from '../scripts/verify-windows-restricted-token-probe.mjs'

const mode = 'debugger-control'
const nativeName = 'service_acl::windows_impl::restricted_token_probe::medium::child::debugger_control::native_owned_medium_debugger_control'
const root = new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/', import.meta.url)
const reasons = ['UnsupportedPlatform', 'InvalidRequest', 'AccessDenied', 'Busy', 'ReadOnly', 'Cancelled', 'TimedOut', 'DeviceRemoved', 'NoMedia', 'EnumerationFailed', 'EvidenceIncomplete', 'ResourceLimit', 'Other']

/** @returns {string} Synthetic parser seed only; the actual formatter driver supplies integration evidence. */
function parserSeed() {
    const lines = []
    for (const [phase, keys] of Object.entries(debuggerSchema)) {
        lines.push(`openrdx-token-debugger-stage phase=${phase} status=begin`)
        for (const key of keys) lines.push(`openrdx-token-debugger-control phase=${phase} ${key}=${!['creation-uncertain', 'deferred', 'debugger-changed-behavior', 'startup-proof'].includes(key)}`)
        if (phase === 'debug-events') lines.push('openrdx-token-debugger-event slot=e000 kind=create-process module=none exception=none first=false continued=true', 'openrdx-token-debugger-event slot=e001 kind=load module=ntdll exception=none first=false continued=true', 'openrdx-token-debugger-event slot=e002 kind=exception module=ntdll exception=breakpoint first=true continued=true', 'openrdx-token-debugger-event slot=e003 kind=exception module=unknown exception=dll-init-failed first=false continued=true', 'openrdx-token-debugger-event slot=e004 kind=exit-process module=none exception=none first=false continued=true')
        lines.push(`openrdx-token-debugger-stage phase=${phase} status=ok`)
    }
    return `${lines.join('\n')}\n`
}

/** @param {string} text Closed formatter rows. @returns {string} Exact single libtest envelope. */
function envelope(text) {
    return `running 1 test\n${text}test ${nativeName} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`
}

test('debugger parser accepts complete matched failure with unknown exception location as observation', () => {
    const result = debuggerControlEvidence(parserSeed().split('\n'))
    assert.equal(result.complete, true)
    assert.equal(result.reproduced, true)
    assert.equal(result.changed, false)
})

test('debugger parser rejects contradictory, orphaned, private, duplicate and cross-mode evidence', () => {
    const baseline = parserSeed()
    for (const mutation of [
        baseline.replace('slot=e001', 'slot=e000'),
        baseline.replace('continued=true', 'continued=false'),
        baseline.replace('source-preserved=true', 'source-preserved=false'),
        baseline.replace('reproduced=true', 'reproduced=false'),
        baseline.replace('startup-proof=false', 'startup-proof=true'),
        baseline.replace('phase=debug-events status=begin\n', ''),
        baseline.replace('phase=debug-events status=ok', 'phase=debug-events status=failed reason=Other\nopenrdx-token-debugger-stage phase=debug-events status=ok'),
        baseline.replace('phase=fixture status=begin', 'phase=debug-proof status=begin'),
        baseline.replace('verified=true', 'verified=true verified=true'),
        baseline.replace('source-minimal=true', 'source-minimal=1'),
        baseline.replace('kind=load module=ntdll', 'kind=create-thread module=ntdll'),
        baseline.replace('exception=breakpoint first=true', 'exception=none first=true'),
        baseline + 'openrdx-token-debugger-event slot=e005 kind=debug-string module=none exception=none first=false continued=true\n',
        baseline + 'openrdx-token-probe source-open=true\n',
        baseline + 'openrdx-token-debugger-private path=C:\\private\\fixture.exe\n',
        baseline.replace('module=unknown', 'module=S-1-5-21-private'),
        baseline.replace('exception=breakpoint', 'exception=0xc0000022'),
        baseline.replace('kind=load', 'kind=private-debug-string')
    ])
        assert.equal(debuggerControlEvidence(mutation.split('\n')).complete, false)
})

test('debugger parser retains first failure during independent cleanup with closed error tokens', () => {
    for (const reason of reasons) {
        const lines = [`openrdx-token-debugger-stage phase=setup status=begin`, `openrdx-token-debugger-stage phase=setup status=failed reason=${reason}`, 'openrdx-token-debugger-stage phase=fixture-cleanup status=begin', 'openrdx-token-debugger-control phase=fixture-cleanup verified=false deferred=true', 'openrdx-token-debugger-stage phase=fixture-cleanup status=failed reason=Busy']
        const result = debuggerControlEvidence(lines)
        assert.equal(result.complete, false)
        assert.equal(result.firstFailure, lines[1])
        assert.ok(result.lines.includes(lines[4]))
    }
})

test('full observation expiry stays changed nonproof while preserving timeout and native failure', async () => {
    const transcript = parserSeed()
        .split('\n')
        .filter((line) => !line.includes('kind=exception module=unknown exception=dll-init-failed'))
        .join('\n')
        .replace('slot=e004', 'slot=e003')
        .replace('held-exit-match=true', 'held-exit-match=false')
        .replace('phase=debug-events status=ok', 'phase=debug-events status=failed reason=TimedOut')
        .replace('experiment-complete=true', 'experiment-complete=false')
        .replace('reproduced=true', 'reproduced=false')
        .replace('debugger-changed-behavior=false', 'debugger-changed-behavior=true')
        .replace('phase=complete status=ok', 'phase=complete status=failed reason=TimedOut')
    const evidence = debuggerControlEvidence(transcript.split('\n'))
    assert.equal(evidence.reason, null)
    assert.equal(evidence.complete, false)
    assert.equal(evidence.reproduced, false)
    assert.equal(evidence.changed, true)
    assert.equal(evidence.firstFailure, 'openrdx-token-debugger-stage phase=debug-events status=failed reason=TimedOut')
    const result = await runRestrictedTokenProbe({ mode, execute: async () => ({ exitCode: 101, stdout: envelope(transcript), stderr: '' }) })
    assert.equal(result.passed, false)
    assert.equal(result.exitCode, 101)
    assert.equal(result.failureClass, 'native-exit')
    assert.ok(result.debuggerControl.includes(evidence.firstFailure))
    assert.ok(result.debuggerControl.some((line) => line.includes('debugger-changed-behavior=true')))
})

let formatterCache
/**
 * Compiles the actual native formatter and exercises all fixed phases with 128
 * events. This synthetic host driver is not Windows debugger execution evidence.
 * @returns {Promise<string>} Normalized LF transcript with the exact libtest envelope.
 */
async function actualFormatterTranscript() {
    if (formatterCache !== undefined) return formatterCache
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-debugger-formatter-'))
    try {
        const driver = join(directory, 'format.rs'),
            binary = join(directory, process.platform === 'win32' ? 'format.exe' : 'format')
        await writeFile(
            driver,
            `#[allow(dead_code)] #[derive(Debug)] enum NativeError{UnsupportedPlatform,InvalidRequest,AccessDenied,Busy,ReadOnly,Cancelled,TimedOut,DeviceRemoved,NoMedia,EnumerationFailed,EvidenceIncomplete,ResourceLimit,Other}
#[path=${JSON.stringify(fileURLToPath(new URL('debugger_output.rs', root)))}] mod output;
fn main(){let failed=std::env::args().any(|arg|arg=="error");for &phase in output::PHASES{output::stage(phase,"begin",None);for &key in output::keys(phase){let mut value=!matches!(key,"creation-uncertain"|"deferred"|"debugger-changed-behavior"|"startup-proof");if failed&&matches!(phase,"debug-reap"|"fixture-cleanup"){value=key=="deferred";}output::facts(phase,&[(key,value)]);}if phase=="debug-events"{output::event(0,"create-process","none","none",false,true);output::event(1,"load","ntdll","none",false,true);output::event(2,"exception","ntdll","breakpoint",true,true);for slot in 3..127{output::event(slot,"exception","kernelbase","access-violation",false,true);}output::event(127,"exit-process","none","none",false,true);}if failed&&matches!(phase,"debug-reap"|"fixture-cleanup"){output::stage(phase,"failed",Some(&NativeError::EvidenceIncomplete));}else{output::stage(phase,"ok",None);}}}`
        )
        const execute = promisify(execFile)
        await execute('rustc', ['--edition=2024', driver, '-o', binary], { timeout: 30_000 })
        const success = await execute(binary, [], { timeout: 30_000 })
        const error = await execute(binary, ['error'], { timeout: 30_000 })
        const complete = envelope(success.stdout.replaceAll('\r\n', '\n'))
        const errorTranscript = envelope(error.stdout.replaceAll('\r\n', '\n'))
        // The failing cleanup branch is independently formatted; it can never pass.
        assert.equal(validateRestrictedTokenProbeOutput(errorTranscript, '', { mode }).passed, false)
        const bytes = Math.max(Buffer.byteLength(complete.replaceAll('\n', '\r\n')), Buffer.byteLength(errorTranscript.replaceAll('\n', '\r\n')))
        assert.ok(bytes + 4096 < 65_536)
        await writeFile(new URL('../.tmp/windows-debugger-formatter-bound.txt', import.meta.url), `actual debugger formatter: maximum 128-event success/error branch CRLF ${bytes} bytes +4096 Cargo reserve <65536\n`)
        formatterCache = complete
        return complete
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
}

test('actual debugger formatter full 128-event branch stays bounded and exactly matches parser schema', async (context) => {
    const baseline = await actualFormatterTranscript()
    assert.equal(validateRestrictedTokenProbeOutput(baseline, '', { mode }).passed, true)
    const observed = new Map()
    for (const line of baseline.split('\n')) {
        const match = /^openrdx-token-debugger-control phase=([a-z-]+) (.+)$/u.exec(line)
        if (match !== null) observed.set(match[1], [...(observed.get(match[1]) ?? []), ...match[2].split(' ').map((pair) => pair.split('=')[0])])
    }
    assert.deepEqual(Object.fromEntries(observed), debuggerSchema)
    assert.equal((baseline.match(/openrdx-token-debugger-event /gu) ?? []).length, 128)
    context.diagnostic(await readFile(new URL('../.tmp/windows-debugger-formatter-bound.txt', import.meta.url), 'utf8'))
    for (const mutation of [baseline.replace('slot=e001', 'slot=e000'), baseline.replace('continued=true', 'continued=false'), baseline.replace('source-preserved=true', 'source-preserved=false'), baseline.replace('reproduced=true', 'reproduced=false'), baseline.replace('startup-proof=false', 'startup-proof=true'), baseline.replace('phase=debug-events status=begin\n', ''), baseline.replace('phase=debug-events status=ok', 'phase=debug-events status=failed reason=Other\nopenrdx-token-debugger-stage phase=debug-events status=ok')]) assert.equal(validateRestrictedTokenProbeOutput(mutation, '', { mode }).passed, false)
})

test('fixed debugger wrapper requires exactly one ignored test and preserves native exit and execution errors', async () => {
    const baseline = await actualFormatterTranscript()
    const result = await runRestrictedTokenProbe({
        mode,
        execute: async (command, args, options) => {
            assert.equal(command, 'cargo')
            assert.deepEqual(args, ['test', '--manifest-path', 'native/rdx-service/windows-native/Cargo.toml', '--locked', '--lib', nativeName, '--', '--ignored', '--exact', '--nocapture', '--test-threads=2'])
            assert.equal(options.timeout, 120_000)
            assert.equal(options.maxBuffer, 65_536)
            assert.equal(options.shell, false)
            return { exitCode: 0, stdout: baseline, stderr: 'private arbitrary Cargo stderr' }
        }
    })
    assert.equal(result.passed, true)
    assert.equal(result.debuggerControl.length, debuggerControlEvidence(baseline.split('\n')).lines.length)
    for (const oldMode of ['baseline', 'medium', 'child', 'source-control', 'process-dacl-control', 'object-dacl-controls', 'actual-token-dacl-control']) assert.equal(validateRestrictedTokenProbeOutput(baseline, '', { mode: oldMode }).passed, false)
    for (const output of ['', envelope('openrdx-token-probe query-ok=true\n'), baseline.replace('running 1 test', 'running 0 tests'), baseline.replace(nativeName, 'wrong-test'), baseline.replace('1 passed; 0 failed', '0 passed; 0 failed'), baseline.replace('0 ignored', '1 ignored'), baseline + 'openrdx-token-probe source-open=true\n']) assert.equal(validateRestrictedTokenProbeOutput(output, '', { mode }).passed, false)
    const failed = await runRestrictedTokenProbe({ mode, execute: async () => ({ exitCode: 101, stdout: baseline, stderr: 'private Cargo path' }) })
    assert.equal(failed.exitCode, 101)
    assert.equal(failed.failureClass, 'native-exit')
    assert.equal(failed.cargoExitCode, 101)
    for (const executionError of ['buffer', 'signal', 'timeout', 'launch']) {
        const execution = await runRestrictedTokenProbe({ mode, execute: async () => ({ exitCode: null, executionError, stdout: baseline, stderr: 'private launch detail' }) })
        assert.equal(execution.passed, false)
        assert.equal(execution.failureReason, executionError)
        assert.deepEqual(execution.debuggerControl, [])
        assert.equal(JSON.stringify(execution).includes('private'), false)
    }
    assert.equal(validateRestrictedTokenProbeOutput(baseline, 'x'.repeat(65_537), { mode }).passed, false)
})

test('debugger wrapper never forwards raw SID, path, address or debug-string fields', async () => {
    const baseline = await actualFormatterTranscript()
    for (const privateText of ['S-1-5-21-private', 'C:\\private\\fixture.exe', '0xabcdef1234', 'private-debug-string']) {
        for (const stdout of [baseline.replace('module=ntdll', `module=${privateText}`), baseline + `openrdx-token-debugger-control phase=complete private=${privateText}\n`, baseline + `unrecognized private line ${privateText}\n`]) {
            const result = await runRestrictedTokenProbe({ mode, execute: async () => ({ exitCode: 101, stdout, stderr: privateText }) })
            assert.equal(result.passed, false)
            assert.equal(JSON.stringify(result).includes(privateText), false)
        }
    }
})

test('actual used debugger policy and ownership model execute adversarial host tests', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-debugger-policy-'))
    try {
        const driver = join(directory, 'protocol.rs'),
            binary = join(directory, process.platform === 'win32' ? 'protocol.exe' : 'protocol')
        await writeFile(driver, `#[path=${JSON.stringify(fileURLToPath(new URL('debugger_protocol.rs', root)))}] mod debugger_protocol;`)
        const execute = promisify(execFile)
        await execute('rustc', ['--edition=2024', '--test', driver, '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, ['--test-threads=2'], { timeout: 30_000 })
        assert.match(stdout, /[1-9]\d* passed; 0 failed/u)
        assert.doesNotMatch(stdout, /(?:^|\s)0 passed;/u)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})

test('optional debugger CI preserves fatal ordinary gate and eight closed diagnostic artifacts', async () => {
    const workflow = await readFile(new URL('../.github/workflows/build-installers.yml', import.meta.url), 'utf8')
    assert.match(workflow, /name: Observe owned Windows debugger control\s+if: always\(\) && matrix.platform == 'win' && steps.windows-token-fixtures.outcome == 'success'\s+continue-on-error: true/u)
    assert.match(workflow, /--debugger-control \| Tee-Object -FilePath out\/verification\/windows-token-debugger-control.log\s+\$probeExitCode = \$LASTEXITCODE\s+exit \$probeExitCode/u)
    const upload = workflow.slice(workflow.indexOf('- name: Upload closed Windows token evidence'), workflow.indexOf('- name: Verify Windows PowerShell'))
    assert.ok(upload.includes('windows-token-debugger-control.log'))
    assert.ok(upload.includes('retention-days: 3'))
    assert.ok(upload.includes('actions/upload-artifact@v7.0.1'))
    assert.equal((upload.match(/out\/verification\/windows-token-[a-z-]+\.log/gu) ?? []).length, 8)
    const ordinary = workflow.slice(workflow.indexOf('- name: Verify owned medium Windows child'), workflow.indexOf('- name: Observe source-context'))
    assert.equal(ordinary.includes('continue-on-error'), false)
    assert.match(workflow, /pattern: installers-\*/u)
})

test('debugger parser rejects orphaned events, post-exit events, fatal RIP and a 129th event', async () => {
    const baseline = await actualFormatterTranscript()
    const firstEvent = 'openrdx-token-debugger-event slot=e000 kind=create-process module=none exception=none first=false continued=true\n'
    const exitEvent = 'openrdx-token-debugger-event slot=e127 kind=exit-process module=none exception=none first=false continued=true\n'
    const rip = baseline.replace('slot=e003 kind=exception module=kernelbase exception=access-violation first=false continued=true', 'slot=e003 kind=rip module=none exception=none first=false continued=true')
    for (const mutation of [baseline.replace(firstEvent, '').replace('openrdx-token-debugger-stage phase=debug-events status=begin\n', `${firstEvent}openrdx-token-debugger-stage phase=debug-events status=begin\n`), baseline.replace(exitEvent, `${exitEvent}openrdx-token-debugger-event slot=e128 kind=debug-string module=none exception=none first=false continued=true\n`), baseline.replace(exitEvent, 'openrdx-token-debugger-event slot=e127 kind=debug-string module=none exception=none first=false continued=true\nopenrdx-token-debugger-event slot=e128 kind=exit-process module=none exception=none first=false continued=true\n'), rip]) assert.equal(validateRestrictedTokenProbeOutput(mutation, '', { mode }).passed, false)
})

test('actual debugger checkpoint preserves primary error while all five independent cleanups execute', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-debugger-errors-'))
    try {
        const source = await readFile(new URL('debugger_control.rs', root), 'utf8')
        const helpers = source.slice(source.indexOf('fn checkpoint'), source.indexOf('/// One possible child'))
        assert.ok(helpers.includes('fn retain_first'))
        const driver = join(directory, 'errors.rs'),
            binary = join(directory, process.platform === 'win32' ? 'errors.exe' : 'errors')
        await writeFile(
            driver,
            `#[path=${JSON.stringify(fileURLToPath(new URL('debugger_output.rs', root)))}] mod output;
#[derive(Debug,PartialEq)] enum NativeError{Other,AccessDenied,Busy}
${helpers}
fn main(){output::start();let primary:Result<(),NativeError>=checkpoint("setup",||Err(NativeError::AccessDenied));let mut first=None;let mut attempted=0;for phase in ["baseline-reap","debug-reap","fixture-cleanup","source-check","derived-check"]{let result=checkpoint(phase,||{attempted+=1;Err(NativeError::Busy)});retain_first(&mut first,result);}assert_eq!(attempted,5);assert_eq!(first,Some(NativeError::Busy));let result=match primary{Err(e)=>Err(e),Ok(())=>first.map_or(Ok(()),Err)};assert_eq!(result,Err(NativeError::AccessDenied));let terminal=checkpoint("complete",||{output::facts("complete",&[("experiment-complete",false),("reproduced",false),("debugger-changed-behavior",false),("startup-proof",false)]);result});assert_eq!(terminal,Err(NativeError::AccessDenied));}`
        )
        const execute = promisify(execFile)
        await execute('rustc', ['--edition=2024', driver, '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, [], { timeout: 30_000 })
        assert.equal((stdout.match(/status=failed reason=Busy/gu) ?? []).length, 5)
        const parsed = debuggerControlEvidence(stdout.split(/\r?\n/u))
        assert.equal(parsed.complete, false)
        assert.equal(parsed.firstFailure, 'openrdx-token-debugger-stage phase=setup status=failed reason=AccessDenied')
        assert.equal(parsed.reason, null)
        assert.ok(parsed.lines.includes('openrdx-token-debugger-control phase=complete experiment-complete=false reproduced=false debugger-changed-behavior=false startup-proof=false'))
        const result = await runRestrictedTokenProbe({ mode, execute: async () => ({ exitCode: 101, stdout, stderr: '' }) })
        assert.equal(result.exitCode, 101)
        assert.equal(result.debuggerControl.filter((line) => line.endsWith('reason=Busy')).length, 5)
        assert.equal(validateRestrictedTokenProbeOutput(envelope(stdout), '', { mode }).passed, false)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})

test('actual debugger event-file guard consumes ownership once on success, failure and early return', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-debugger-event-file-'))
    try {
        const source = await readFile(new URL('debugger_owner.rs', root), 'utf8')
        const guard = source.slice(source.indexOf('struct EventFile'), source.indexOf('/// Dedicated duplicates'))
        assert.ok(guard.includes('impl Drop for EventFile'))
        const driver = join(directory, 'event-file.rs'),
            binary = join(directory, process.platform === 'win32' ? 'event-file.exe' : 'event-file')
        await writeFile(
            driver,
            `use std::cell::Cell;
#[derive(Debug,PartialEq)] enum NativeError{Other}
#[derive(Default,Copy,Clone)] struct HANDLE(usize);
impl HANDLE{fn is_invalid(&self)->bool{self.0==0}}
thread_local!{static CLOSES:Cell<usize>=const{Cell::new(0)};}
/// Host-only adapter counts attempts without invoking any Windows or OS API.
#[allow(non_snake_case)] unsafe fn CloseHandle(handle:HANDLE)->Result<(),NativeError>{CLOSES.with(|count|count.set(count.get()+1));if handle.0==2{Err(NativeError::Other)}else{Ok(())}}
/// Retains the fieldless test error exactly as the SDK boundary adapter does.
fn map_native_error(error:NativeError)->NativeError{error}
${guard}
/// A native-style early error exercises the consumed guard's actual Drop implementation.
fn early_return()->Result<(),NativeError>{let _guard=EventFile(HANDLE(1));Err(NativeError::Other)}
fn main(){CLOSES.with(|v|v.set(0));{let mut guard=EventFile(HANDLE(1));assert_eq!(guard.close(),Ok(()));}CLOSES.with(|v|assert_eq!(v.get(),1));CLOSES.with(|v|v.set(0));{let mut guard=EventFile(HANDLE(2));assert_eq!(guard.close(),Err(NativeError::Other));}CLOSES.with(|v|assert_eq!(v.get(),1));CLOSES.with(|v|v.set(0));assert_eq!(early_return(),Err(NativeError::Other));CLOSES.with(|v|assert_eq!(v.get(),1));CLOSES.with(|v|v.set(0));{let mut guard=EventFile(HANDLE(0));assert_eq!(guard.close(),Ok(()));}CLOSES.with(|v|assert_eq!(v.get(),0));println!("actual event file ownership: four cases passed");}`
        )
        const execute = promisify(execFile)
        await execute('rustc', ['--edition=2024', driver, '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, [], { timeout: 30_000 })
        assert.equal(stdout.trim(), 'actual event file ownership: four cases passed')
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})
