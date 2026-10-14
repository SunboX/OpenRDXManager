// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { objectMatrixEvidence } from '../scripts/windows-object-dacl-matrix-evidence.mjs'
import { runRestrictedTokenProbe, validateRestrictedTokenProbeOutput } from '../scripts/verify-windows-restricted-token-probe.mjs'

const mode = 'object-dacl-controls'
const name = 'service_acl::windows_impl::restricted_token_probe::medium::child::object_dacl_controls::native_object_dacl_matrix'
const rows = ['baseline', 'process', 'thread', 'process-thread', 'token', 'process-token', 'thread-token', 'process-thread-token']
const phases = ['derive', 'reference-create', 'reference-read', 'reference-resume', 'reference-wait', 'reference-reap', 'intervention', 'create', 'read', 'resume', 'wait', 'reap', 'cleanup', 'source-check', 'complete']
const prefix = 'openrdx-token-object-dacl-matrix'

/** @param {readonly string[]} successful Fixed synthetic startup rows. @returns {string} Synthetic complete matrix, never native proof. */
function proof(successful = []) {
    const marker = (row, phase, status) => `${prefix}-stage row=${row} phase=${phase} status=${status}\n`
    const fact = (row, phase, pairs) => `${prefix} row=${row} phase=${phase} ${pairs}\n`
    const kept = ['process', 'thread', 'token'].flatMap((object) => ['owner', 'group', 'label', 'control'].map((part) => `${object}-${part}-preserved=true`)).join(' ')
    const sourceKept = 'source-properties-unchanged=true source-default-dacl-unchanged=true source-object-unchanged=true'
    let output = 'running 1 test\n'
    for (const phase of ['setup', 'fixture']) output += marker('matrix', phase, 'begin') + fact('matrix', phase, 'verified=true') + marker('matrix', phase, 'ok')
    for (const row of rows) {
        const startup = successful.includes(row)
        const rowPhases = [...phases.slice(0, 12), ...(startup ? ['positive-create', 'positive-read', 'positive-resume', 'positive-wait', 'positive-reap'] : []), ...phases.slice(12)]
        for (const phase of rowPhases) {
            output += marker(row, phase, 'begin')
            if (['derive', 'reference-read', 'intervention', 'read', 'positive-read'].includes(phase)) output += fact(row, phase, 'query-ok=true exact=true')
            if (['reference-resume', 'resume', 'positive-resume'].includes(phase)) output += fact(row, phase, `source-query-ok=true source-unchanged=true child-proof=true ${sourceKept}`)
            if (phase === 'derive') output += fact(row, phase, 'source-observer-unchanged=true source-rights-open=true source-handle-exact=true restricted-created=true medium-set=true reduced-proved=true')
            if (phase === 'intervention') output += fact(row, phase, 'owner-preserved=true group-preserved=true label-preserved=true control-preserved=true properties-unchanged=true default-dacl-unchanged=true')
            if (['read', 'positive-read'].includes(phase)) output += fact(row, phase, `process-exact=true thread-exact=true token-exact=true ${kept}`)
            if (['read', 'positive-read'].includes(phase)) output += fact(row, phase, 'token-propagated=true')
            if (['reference-wait', 'wait', 'positive-wait'].includes(phase)) output += `${prefix}-exit row=${row} phase=${phase} category=${phase === 'positive-wait' ? 'success' : phase === 'wait' && startup ? 'alive' : 'status-dll-init-failed'}\n`
            if (['reference-reap', 'reap', 'positive-reap', 'cleanup'].includes(phase)) output += fact(row, phase, 'owned-cleanup=true')
            if (phase === 'source-check') output += fact(row, phase, `source-query-ok=true source-unchanged=true ${sourceKept}`)
            if (phase === 'complete') output += fact(row, phase, `experiment-complete=true startup-proof=${startup}`)
            output += marker(row, phase, 'ok')
        }
    }
    for (const phase of ['cleanup', 'source-check', 'complete']) {
        output += marker('matrix', phase, 'begin')
        output += fact('matrix', phase, phase === 'cleanup' ? 'owned-cleanup=true' : phase === 'source-check' ? `source-query-ok=true source-unchanged=true ${sourceKept}` : `experiment-complete=true any-startup-proof=${successful.length !== 0}`)
        output += marker('matrix', phase, 'ok')
    }
    return output + `test ${name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`
}

test('fixed eight-row experiment completion is distinct from startup and ordinary authority', async () => {
    const output = proof()
    assert.equal(validateRestrictedTokenProbeOutput(output, '', { mode }).passed, true)
    for (const other of ['baseline', 'medium', 'child', 'source-control', 'process-dacl-control']) assert.equal(validateRestrictedTokenProbeOutput(output, '', { mode: other }).passed, false)
    const result = await runRestrictedTokenProbe({
        mode,
        execute: async (_command, args) => {
            assert.equal(args.includes(name), true)
            assert.equal(args.includes('--test-threads=2'), true)
            return { exitCode: 0, stdout: output, stderr: '' }
        }
    })
    assert.equal(result.passed, true)
    assert.equal(
        result.objectMatrix.some((line) => line.includes('any-startup-proof=false')),
        true
    )
})

test('missing, wrong, duplicate and out-of-order fixed rows cannot complete', () => {
    for (const output of [proof().replaceAll('row=thread ', 'row=arbitrary '), proof().replaceAll('row=thread ', 'row=process '), proof().replaceAll('row=token ', 'row=process-token '), proof().replace(`${prefix}-stage row=baseline phase=derive status=begin\n`, ''), proof().replaceAll('row=baseline phase=reference-read', 'row=baseline phase=reference-wait')]) assert.equal(validateRestrictedTokenProbeOutput(output, '', { mode }).passed, false)
})

test('propagation false, sticky failed stage, orphan exit and cleanup failures cannot pass', () => {
    const outputs = [proof().replace('token-propagated=true', 'token-propagated=false'), proof().replace('phase=read status=ok', 'phase=read status=failed reason=AccessDenied'), proof() + `${prefix}-exit row=baseline phase=wait category=status-dll-init-failed\n`, proof().replace('owned-cleanup=true', 'owned-cleanup=false'), proof().replace('phase=derive status=begin', 'phase=derive status=ok')]
    for (const output of outputs) assert.equal(validateRestrictedTokenProbeOutput(output, '', { mode }).passed, false)
})

test('malformed private facts stay private and genuine native failure retains its exit', async () => {
    const malformed = proof() + `${prefix} row=baseline phase=complete private-sid=secret\n`
    const result = await runRestrictedTokenProbe({ mode, execute: async () => ({ exitCode: 101, stdout: malformed, stderr: 'private path secret' }) })
    assert.equal(result.passed, false)
    assert.equal(result.exitCode, 101)
    assert.equal(JSON.stringify(result).includes('secret'), false)
    for (const output of [proof().replace('running 1 test', 'running 0 tests'), proof().replace(name, 'wrong'), proof().replace('category=status-dll-init-failed', 'category=unknown'), proof().replace('query-ok=true', 'query-ok=unknown')]) assert.equal(validateRestrictedTokenProbeOutput(output, '', { mode }).passed, false)
})

test('startup observation requires matched positive self-check zero and all positive phases', () => {
    const output = proof(['thread', 'process-thread-token'])
    assert.equal(validateRestrictedTokenProbeOutput(output, '', { mode }).passed, true)
    assert.equal(objectMatrixEvidence(output.split('\n')).anyStartup, true)
    for (const invalid of [output.replace('category=success', 'category=self-token-open'), output.replace('any-startup-proof=true', 'any-startup-proof=false'), output.replace('phase=positive-read status=begin\n', 'phase=positive-read status=ok\n'), output.replace('phase=positive-wait category=success', 'phase=wait category=success'), proof() + 'openrdx-token-probe source-open=true\n']) assert.equal(validateRestrictedTokenProbeOutput(invalid, '', { mode }).passed, false)
    assert.ok(Buffer.byteLength(proof(rows)) < 60_000, 'fixed full transcript leaves Cargo overhead within unchanged 65536 bound')
})

test('real host role and reserve tests execute the checked-in native module', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-matrix-'))
    try {
        const root = new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/', import.meta.url)
        const driver = join(directory, 'matrix.rs')
        const binary = join(directory, process.platform === 'win32' ? 'matrix.exe' : 'matrix')
        await writeFile(driver, `#[path=${JSON.stringify(fileURLToPath(new URL('matrix_protocol.rs', root)))}] mod matrix_protocol;`)
        const execute = promisify(execFile)
        await execute('rustc', ['--edition=2024', '--test', driver, '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, ['--test-threads=2'], { timeout: 30_000 })
        assert.match(stdout, /2 passed; 0 failed/u)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})

test('factory setter and optional CI remain confined to new owned token object', async () => {
    const root = new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/', import.meta.url)
    const factory = await readFile(new URL('owned_derived_token.rs', root), 'utf8')
    const child = await readFile(new URL('child.rs', root), 'utf8')
    const matrix = await readFile(new URL('object_dacl_controls.rs', root), 'utf8')
    assert.match(factory, /SetKernelObjectSecurity\(self\.handle\.0, DACL_SECURITY_INFORMATION/u)
    assert.match(factory, /TOKEN_READ_CONTROL\s*\| TOKEN_WRITE_DAC/u)
    assert.doesNotMatch(factory, /impl (?:From|Deref)|AdjustTokenPrivileges|DuplicateTokenEx|WRITE_OWNER|SANDBOX_INERT[, |]|TokenDefaultDacl,/u)
    assert.match(child, /Self::create_with_object_security\(fixture, derived, process_security, None\)/u)
    assert.match(matrix, /Objects::read\(child\)/u)
    assert.match(matrix, /NativeError::EvidenceIncomplete/u)
    assert.match(matrix, /checkpoint\(name, "read"/u)
    const workflow = await readFile(new URL('../.github/workflows/build-installers.yml', import.meta.url), 'utf8')
    assert.match(workflow, /name: Observe fixed Windows object DACL matrix\s+if: always\(\) && matrix.platform == 'win' && steps.windows-token-fixtures.outcome == 'success'\s+continue-on-error: true/u)
    assert.match(workflow, /--object-dacl-controls \| Tee-Object -FilePath out\/verification\/windows-token-object-dacl-matrix.log\s+\$probeExitCode = \$LASTEXITCODE\s+exit \$probeExitCode/u)
})

test('source-rights acquisition and fresh-token transitions must be proved separately', () => {
    for (const key of ['source-observer-unchanged', 'source-rights-open', 'source-handle-exact', 'restricted-created', 'medium-set', 'reduced-proved']) {
        assert.equal(validateRestrictedTokenProbeOutput(proof().replace(`${key}=true`, ''), '', { mode }).passed, false)
        assert.equal(validateRestrictedTokenProbeOutput(proof().replace(`${key}=true`, `${key}=false`), '', { mode }).passed, false)
    }
})
