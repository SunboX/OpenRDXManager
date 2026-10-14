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

/** @param {readonly string[]} keys Fixed native boolean keys. @param {boolean} [value] Required matrix facts are true on the full-success branch; optional observations use longest false encoding. @returns {string} Rust data for a conservative formatter bound, never kernel evidence. */
function values(keys, value = false) {
    return `&[${keys.map((key) => `(${JSON.stringify(key)},${value})`).join(',')}]`
}

test('actual checked-in matrix format fits a complete eight-row transcript plus Cargo overhead', async (context) => {
    const root = new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/', import.meta.url)
    const matrix = await readFile(new URL('object_dacl_controls.rs', root), 'utf8')
    const lineage = await readFile(new URL('token_lineage.rs', root), 'utf8')
    const facts = matrix.slice(matrix.indexOf('fn facts('), matrix.indexOf('/// Maps only fixed formatting'))
    const checkpoint = matrix.slice(matrix.indexOf('fn output_error('), matrix.indexOf('/// Reports the exact private exit'))
    const emit = lineage.slice(lineage.indexOf('fn emit('), lineage.indexOf('/// Initial source metadata'))
    const source = [
        ['source-query-ok', 'source-unchanged'],
        ['source-properties-unchanged', 'source-default-dacl-unchanged', 'source-object-unchanged']
    ]
    const read = [['query-ok'], ...['process', 'thread', 'token'].map((object) => ['owner', 'group', 'label', 'control'].map((part) => `${object}-${part}-preserved`)), ['exact', 'process-exact', 'thread-exact', 'token-exact', 'token-propagated']]
    const derive = ['source-observer-unchanged', 'source-rights-open', 'source-handle-exact', 'restricted-created', 'medium-set', 'reduced-proved'].map((key) => [key]).concat([['query-ok', 'exact']])
    const groups = { derive, 'reference-read': [['query-ok', 'exact']], 'reference-resume': [...source, ['child-proof']], intervention: [['query-ok'], ['owner-preserved', 'group-preserved', 'label-preserved', 'control-preserved', 'exact', 'properties-unchanged', 'default-dacl-unchanged']], read, resume: [...source, ['child-proof']], 'positive-read': read, 'positive-resume': [...source, ['child-proof']], 'reference-reap': [['owned-cleanup']], reap: [['owned-cleanup']], 'positive-reap': [['owned-cleanup']], cleanup: [['owned-cleanup']], 'source-check': source, complete: [['experiment-complete', 'startup-proof']] }
    const phases = ['derive', 'reference-create', 'reference-read', 'reference-resume', 'reference-wait', 'reference-reap', 'intervention', 'create', 'read', 'resume', 'wait', 'reap', 'positive-create', 'positive-read', 'positive-resume', 'positive-wait', 'positive-reap', 'cleanup', 'source-check', 'complete']
    const metadata = [
        ['fresh-proof'],
        ['actual-open-ok'],
        ['full-properties-known', 'full-properties-equal'],
        ...['source', 'derived', 'actual', 'source-initial', 'derived-initial'].map((subject) => [`${subject}-query-ok`, `${subject}-layout-valid`]),
        ...['source-stable', 'derived-stable', 'source-derived', 'source-actual', 'derived-actual'].map((pair) => ['known', 'id-equal', 'logon-equal', 'modified-equal'].map((part) => `${pair}-${part}`)),
        ['descriptor-query-ok'],
        ['profile-valid'],
        ...['baseline', 'expected', 'actual'].map((subject) => ['grant-absent', 'grant-single', 'grant-duplicate'].map((part) => `${subject}-${part}`)),
        ...['baseline', 'expected'].map((subject) => ['acl-bytes-equal', 'ace-sequence-equal', 'header-equal', 'padding-equal'].map((part) => `${subject}-${part}`)),
        ['old-aces-retained', 'denials-equal', 'one-addition', 'owner-preserved', 'group-preserved', 'label-preserved', 'control-preserved']
    ]
    let calls = ''
    for (const row of ['baseline', 'process', 'thread', 'process-thread', 'token', 'process-token', 'thread-token', 'process-thread-token'])
        for (const phase of phases) {
            calls += `checkpoint(${JSON.stringify(row)},${JSON.stringify(phase)},|| {`
            for (const keys of groups[phase] ?? []) calls += `facts(${JSON.stringify(row)},${JSON.stringify(phase)},${values(keys, true)});`
            if (phase === 'read' && row.includes('token')) for (const keys of metadata) calls += `emit(${JSON.stringify(row)},"read",${values(keys)});`
            if (phase.endsWith('wait')) calls += `println!("openrdx-token-object-dacl-matrix-exit row=${row} phase=${phase} category=${phase === 'reference-wait' ? 'status-dll-init-failed' : phase === 'positive-wait' ? 'success' : 'alive'}");`
            calls += 'Ok(())}).unwrap();\n'
        }
    const global = { setup: ['verified'], fixture: ['verified'], cleanup: ['owned-cleanup'], 'source-check': ['source-query-ok', 'source-unchanged', 'source-properties-unchanged', 'source-default-dacl-unchanged', 'source-object-unchanged'], complete: ['experiment-complete', 'any-startup-proof'] }
    for (const phase of ['setup', 'fixture', 'cleanup', 'source-check', 'complete']) {
        calls += `checkpoint("matrix",${JSON.stringify(phase)},|| {facts("matrix",${JSON.stringify(phase)},${values(global[phase], true)});`
        if (phase === 'setup') calls += `emit("matrix","setup",${values(['source-initial-query-ok', 'source-initial-layout-valid'])});`
        if (phase === 'source-check') calls += `emit("matrix","source-check",${values(['source-final-query-ok', 'source-final-layout-valid', 'source-stable-known', 'source-stable-id-equal', 'source-stable-logon-equal', 'source-stable-modified-equal'])});`
        calls += 'Ok(())}).unwrap();\n'
    }
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-format-bound-'))
    try {
        const driver = join(directory, 'format.rs'),
            binary = join(directory, process.platform === 'win32' ? 'format.exe' : 'format')
        await writeFile(driver, `#[path=${JSON.stringify(fileURLToPath(new URL('matrix_output.rs', root)))}] mod matrix_output;\n#[derive(Debug)] enum NativeError { Other, ResourceLimit }\n${facts}\n${checkpoint}\n${emit}\nfn main(){${calls}}`)
        const execute = promisify(execFile)
        await execute('rustc', ['--edition=2024', driver, '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, [], { timeout: 30_000, maxBuffer: 262_144 })
        const bytes = Buffer.byteLength(stdout.replaceAll('\n', '\r\n'))
        context.diagnostic(`native full-success formatting upper bound ${bytes} bytes +4096 Cargo reserve`)
        assert.ok(bytes + 4096 <= 65_536, `actual native format=${bytes} bytes plus fixed Cargo reserve exceeds unchanged capture cap`)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})

test('actual phase buffer preserves grouped fields, bounded errors and panic cleanup on the host', async () => {
    const root = new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/', import.meta.url)
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-phase-buffer-'))
    try {
        const driver = join(directory, 'buffer.rs')
        const binary = join(directory, process.platform === 'win32' ? 'buffer.exe' : 'buffer')
        await writeFile(driver, `#[path=${JSON.stringify(fileURLToPath(new URL('matrix_output.rs', root)))}] mod matrix_output;`)
        const execute = promisify(execFile)
        await execute('rustc', ['--edition=2024', '--test', driver, '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, ['--test-threads=2'], { timeout: 30_000 })
        assert.match(stdout, /6 passed; 0 failed/u)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})

test('actual checkpoint flushes before failed terminals and unwind without masking the original error', async () => {
    const root = new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/', import.meta.url)
    const matrix = await readFile(new URL('object_dacl_controls.rs', root), 'utf8')
    const facts = matrix.slice(matrix.indexOf('fn facts('), matrix.indexOf('/// Maps only fixed formatting'))
    const checkpoint = matrix.slice(matrix.indexOf('fn output_error('), matrix.indexOf('/// Reports the exact private exit'))
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-checkpoint-'))
    try {
        const driver = join(directory, 'checkpoint.rs')
        const binary = join(directory, process.platform === 'win32' ? 'checkpoint.exe' : 'checkpoint')
        const main = `fn main(){
            let result:Result<(),NativeError>=checkpoint("token","read",||{
                facts("token","read", &[("query-ok",true)]);
                facts("token","read", &[("query-ok",false)]);
                Err(NativeError::AccessDenied)
            });
            assert!(matches!(result,Err(NativeError::AccessDenied)));
            let rejected:Result<(),NativeError>=checkpoint("token","read",||{
                facts("token","read", &[("query-ok",true),("query-ok",false)]);Ok(())
            });assert!(matches!(rejected,Err(NativeError::Other)));
            std::panic::set_hook(Box::new(|_|{}));
            assert!(std::panic::catch_unwind(||{
                let _:Result<(),NativeError>=checkpoint("token","read",||{
                    facts("token","read", &[("query-ok",true)]);panic!("fixed")
                });
            }).is_err());
            checkpoint("matrix","cleanup",||{facts("matrix","cleanup", &[("owned-cleanup",true)]);Ok(())}).unwrap();
        }`
        await writeFile(driver, `#[path=${JSON.stringify(fileURLToPath(new URL('matrix_output.rs', root)))}] mod matrix_output;\n#[derive(Debug)] enum NativeError { Other, ResourceLimit, AccessDenied }\n${facts}\n${checkpoint}\n${main}`)
        const execute = promisify(execFile)
        await execute('rustc', ['--edition=2024', driver, '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, [], { timeout: 30_000 })
        const lines = stdout.trim().split('\n')
        assert.deepEqual(lines.slice(0, 3), ['openrdx-token-object-dacl-matrix-stage row=token phase=read status=begin', 'openrdx-token-object-dacl-matrix row=token phase=read query-ok=true', 'openrdx-token-object-dacl-matrix-stage row=token phase=read status=failed reason=AccessDenied'])
        assert.equal(lines[5], 'openrdx-token-object-dacl-matrix-stage row=token phase=read status=failed reason=Other')
        assert.deepEqual(lines.slice(6, 9), ['openrdx-token-object-dacl-matrix-stage row=token phase=read status=begin', 'openrdx-token-object-dacl-matrix row=token phase=read query-ok=true', 'openrdx-token-object-dacl-matrix-stage row=matrix phase=cleanup status=begin'])
        assert.equal(lines.at(-1), 'openrdx-token-object-dacl-matrix-stage row=matrix phase=cleanup status=ok')
        assert.equal(stdout.includes('fixed'), false)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})
