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

const execute = promisify(execFile)
const name = 'service_acl::windows_impl::restricted_token_probe::medium::child::process_dacl_control::native_process_dacl_child_control'
const required = ['source-verified', 'derived-verified', 'source-default-dacl-unchanged', 'source-snapshot-unchanged', 'baseline-image-proved', 'baseline-descriptors-valid', 'baseline-dll-init-failed', 'baseline-reaped', 'process-descriptor-built', 'treatment-image-proved', 'treatment-process-dacl-exact', 'treatment-other-components-unchanged', 'treatment-thread-unchanged', 'treatment-token-unchanged', 'treatment-token-proved', 'treatment-console-proved', 'treatment-timeout-alive', 'treatment-reaped', 'positive-image-proved', 'positive-descriptors-proved', 'positive-token-proved', 'positive-console-proved', 'positive-exit-zero', 'positive-reaped', 'fixtures-cleaned']
required.push(...['baseline-source-snapshot-query-ok', 'baseline-source-snapshot-unchanged', 'baseline-source-default-dacl-query-ok', 'baseline-source-default-dacl-unchanged'])
required.push(
    ...[
        'baseline-descriptors-query-ok',
        'treatment-descriptors-query-ok',
        'positive-descriptors-query-ok',
        'positive-process-dacl-exact',
        'owned-children-cleanup-ok',
        'positive-fixture-cleanup-ok',
        'wait-fixture-cleanup-ok',
        'source-snapshot-query-ok',
        'source-default-dacl-query-ok',
        'treatment-process-owner-preserved',
        'treatment-process-group-preserved',
        'treatment-process-label-preserved',
        'treatment-process-control-preserved',
        'positive-process-owner-preserved',
        'positive-process-group-preserved',
        'positive-process-label-preserved',
        'positive-process-control-preserved',
        'treatment-thread-components-exact',
        'treatment-token-components-exact',
        'positive-thread-components-exact',
        'positive-token-components-exact',
        'treatment-source-snapshot-query-ok',
        'treatment-source-snapshot-unchanged',
        'treatment-source-default-dacl-query-ok',
        'treatment-source-default-dacl-unchanged',
        'positive-source-snapshot-query-ok',
        'positive-source-snapshot-unchanged',
        'positive-source-default-dacl-query-ok',
        'positive-source-default-dacl-unchanged'
    ]
)

/** @returns {string} Synthetic strict optional-control evidence, never actual Windows proof. */
const phases = ['setup', 'fixture', 'baseline-create', 'baseline-proof', 'baseline-resume', 'baseline-wait', 'baseline-reap', 'descriptor', 'treatment-create', 'treatment-proof', 'treatment-resume', 'treatment-wait', 'treatment-reap', 'positive-fixture', 'positive-create', 'positive-proof', 'positive-resume', 'positive-wait', 'positive-reap', 'child-cleanup', 'positive-fixture-cleanup', 'wait-fixture-cleanup', 'cleanup', 'source-check']

/** @returns {string} Fixed synthetic ordered phase/exit evidence with all required facts. */
function proof() {
    const markers = phases.map((phase) => `openrdx-token-process-dacl-control-stage phase=${phase} status=begin\n${phase === 'baseline-wait' ? 'openrdx-token-process-dacl-control-exit phase=baseline-wait category=status-dll-init-failed\n' : phase === 'positive-wait' ? 'openrdx-token-process-dacl-control-exit phase=positive-wait category=success\n' : ''}openrdx-token-process-dacl-control-stage phase=${phase} status=ok`).join('\n')
    return `running 1 test\nopenrdx-token-process-dacl-control ${required.map((key) => `${key}=true`).join(' ')}\n${markers}\ntest ${name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`
}

test('separate process-only control requires exact execution, isolated components and cleanup', async () => {
    assert.equal(validateRestrictedTokenProbeOutput(proof(), '', { mode: 'process-dacl-control' }).passed, true)
    for (const mode of ['baseline', 'medium', 'child', 'source-control']) assert.equal(validateRestrictedTokenProbeOutput(proof(), '', { mode }).passed, false)
    for (const key of required) {
        assert.equal(validateRestrictedTokenProbeOutput(proof().replace(`${key}=true`, ''), '', { mode: 'process-dacl-control' }).passed, false)
        assert.equal(validateRestrictedTokenProbeOutput(proof().replace(`${key}=true`, `${key}=false`), '', { mode: 'process-dacl-control' }).passed, false)
    }
    const result = await runRestrictedTokenProbe({
        mode: 'process-dacl-control',
        execute: async (_command, args) => {
            assert.equal(args.includes(name), true)
            return { exitCode: 0, stdout: proof(), stderr: '' }
        }
    })
    assert.equal(result.passed, true)
})

test('orphan, duplicate, unknown and contradictory process-control evidence fails privately', async () => {
    for (const output of [proof().replace('running 1 test', 'running 0 tests'), proof().replace(name, 'wrong'), proof().replace('category=success', 'category=status-dll-init-failed'), proof().replace('phase=cleanup status=begin\n', 'phase=cleanup status=ok\n'), proof() + 'openrdx-token-process-dacl-control-stage phase=proof status=begin\nopenrdx-token-process-dacl-control-stage phase=proof status=failed reason=Other\n', proof() + 'openrdx-token-process-dacl-control private-sid=true\n', proof() + 'openrdx-token-process-dacl-control source-verified=true\n']) {
        const result = await runRestrictedTokenProbe({ mode: 'process-dacl-control', execute: async () => ({ exitCode: 0, stdout: output, stderr: 'private path' }) })
        assert.equal(result.passed, false)
        assert.equal(JSON.stringify(result).includes('private'), false)
    }
    const result = await runRestrictedTokenProbe({ mode: 'process-dacl-control', execute: async () => ({ exitCode: 101, stdout: proof(), stderr: 'private' }) })
    assert.equal(result.exitCode, 101)
    assert.equal(result.passed, false)
})

test('descriptor component transformation runs real host adversarial Rust tests', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-process-dacl-'))
    try {
        const binary = join(directory, process.platform === 'win32' ? 'descriptor.exe' : 'descriptor')
        const root = new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/', import.meta.url)
        const driver = join(directory, 'descriptor.rs')
        await writeFile(driver, ['mandatory_label', 'object_acl', 'process_descriptor'].map((module) => `#[path=${JSON.stringify(fileURLToPath(new URL(`${module}.rs`, root)))}]\nmod ${module};`).join('\n'))
        await execute('rustc', ['--edition=2024', '--test', driver, '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, ['process_descriptor::process_descriptor_tests::', '--test-threads=2'])
        assert.match(stdout, /6 passed; 0 failed/u)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})

test('native control changes private process attributes only, never an existing object or token', async () => {
    const source = await readFile(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/process_dacl_control.rs', import.meta.url), 'utf8')
    assert.match(source, /PROCESS_ALL_ACCESS/u)
    assert.match(source, /Variant::Wait/u)
    assert.match(source, /create_with_process_security/u)
    assert.match(source, /bInheritHandle: false/u)
    assert.match(source, /GetKernelObjectSecurity/u)
    assert.doesNotMatch(source, /SetSecurityInfo|SetKernelObjectSecurity|AdjustTokenPrivileges|ImpersonateLoggedOnUser|CreateProcessW|std::env|assert_eq!|dbg!/u)
    const workflow = await readFile(new URL('../.github/workflows/build-installers.yml', import.meta.url), 'utf8')
    assert.match(workflow, /name: Observe isolated Windows process DACL control\s+if: always\(\) && matrix.platform == 'win' && steps.windows-token-fixtures.outcome == 'success'\s+continue-on-error: true/u)
    assert.match(workflow, /--process-dacl-control \| Tee-Object -FilePath out\/verification\/windows-token-process-dacl-control.log/u)
})

test('every process-control phase and matching live exit phase is mandatory', () => {
    for (const phase of phases) {
        const absent = proof().replace(`openrdx-token-process-dacl-control-stage phase=${phase} status=begin\n`, '').replace(`openrdx-token-process-dacl-control-stage phase=${phase} status=ok\n`, '')
        assert.equal(validateRestrictedTokenProbeOutput(absent, '', { mode: 'process-dacl-control' }).passed, false)
    }
})

test('exit evidence must occur within its matching active wait phase', () => {
    const orphan = proof().replace('openrdx-token-process-dacl-control-exit phase=baseline-wait category=status-dll-init-failed\n', '') + 'openrdx-token-process-dacl-control-exit phase=baseline-wait category=status-dll-init-failed\n'
    assert.equal(validateRestrictedTokenProbeOutput(orphan, '', { mode: 'process-dacl-control' }).passed, false)
})
