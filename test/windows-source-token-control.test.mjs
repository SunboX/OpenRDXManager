// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import test from 'node:test'
import { runRestrictedTokenProbe, validateRestrictedTokenProbeOutput } from '../scripts/verify-windows-restricted-token-probe.mjs'
import { sourceControlRequirements } from '../scripts/windows-source-token-control-evidence.mjs'

const execute = promisify(execFile)

const name = 'service_acl::windows_impl::restricted_token_probe::medium::child::source_control::native_source_context_child_control'
const facts = 'source-open=true source-query-ok=true source-console-match=true source-high-primary=true fixture-protected=true child-created=true child-image-match=true child-source-snapshot-match=true console-revalidated=true source-unchanged-after-create=true source-unchanged-before-resume=true child-resumed=true child-exited=true child-self-elevation-refused=true source-unchanged-after-exit=true owned-child-reaped=true fixture-cleaned=true source-unchanged-after-cleanup=true source-after-create-query-ok=true source-before-resume-query-ok=true source-after-exit-query-ok=true source-after-cleanup-query-ok=true child-user-match=true child-session-match=true child-elevation-match=true child-integrity-match=true child-ui-access-match=true child-sandbox-inert-match=true child-type-match=true child-elevation-type-match=true child-groups-match=true child-privileges-match=true'
const proof = `running 1 test\nopenrdx-token-source-control ${facts}\nopenrdx-token-source-control-exit category=self-elevation\nopenrdx-token-source-control-stage phase=cleanup status=begin\nopenrdx-token-source-control-stage phase=cleanup status=ok\ntest ${name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`

test('source-context control is exact and independent from ordinary child eligibility', async () => {
    assert.equal(validateRestrictedTokenProbeOutput(proof, '', { mode: 'source-control' }).passed, true)
    for (const mode of ['baseline', 'medium', 'child']) assert.equal(validateRestrictedTokenProbeOutput(proof, '', { mode }).passed, false)
    const result = await runRestrictedTokenProbe({
        mode: 'source-control',
        execute: async (command, args) => {
            assert.equal(command, 'cargo')
            assert.equal(args.includes(name), true)
            assert.equal(args.includes('--exact'), true)
            return { exitCode: 0, stdout: proof, stderr: '' }
        }
    })
    assert.equal(result.passed, true)
    assert.equal(result.exitCode, 0)
    assert.equal(result.sourceControl.length, 4)
})

test('zero, wrong, missing, contradictory and loader evidence never passes source control', () => {
    for (const output of [proof.replace('running 1 test', 'running 0 tests'), proof.replace(name, 'wrong_test'), proof.replace('child-image-match=true', ''), proof.replace('self-elevation', 'status-dll-init-failed'), proof.replace('self-elevation', 'success'), proof + 'openrdx-token-source-control-stage phase=proof status=failed reason=Other\nopenrdx-token-source-control-stage phase=proof status=ok\n', proof + 'openrdx-token-source-control-stage phase=proof status=begin\n', proof.replace('fixture-cleaned=true', 'fixture-cleaned=false'), proof.replace('child-privileges-match=true', 'child-privileges-match=false'), proof.replace('owned-child-reaped=true', 'owned-child-reaped=false')]) {
        assert.equal(validateRestrictedTokenProbeOutput(output, '', { mode: 'source-control' }).passed, false)
    }
})

test('every source snapshot, context, execution and cleanup prerequisite is required and exact', () => {
    for (const key of Object.keys(sourceControlRequirements)) {
        assert.equal(validateRestrictedTokenProbeOutput(proof.replace(`${key}=true`, ''), '', { mode: 'source-control' }).passed, false)
        assert.equal(validateRestrictedTokenProbeOutput(proof.replace(`${key}=true`, `${key}=false`), '', { mode: 'source-control' }).passed, false)
    }
})

test('actual creation ownership helper reaps rejection and retains accepted ownership on host', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-creation-ownership-'))
    try {
        const binary = join(directory, process.platform === 'win32' ? 'ownership.exe' : 'ownership')
        const source = fileURLToPath(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/creation_ownership.rs', import.meta.url))
        await execute('rustc', ['--edition=2024', '--test', source, '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, ['--test-threads=2'])
        assert.match(stdout, /2 passed; 0 failed/u)
        const child = await readFile(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/child.rs', import.meta.url), 'utf8')
        assert.match(child, /creation_ownership::retain_valid_creation\([\s\S]*?Self \{[\s\S]*?process,[\s\S]*?thread,[\s\S]*?reaped: false,[\s\S]*?info.dwProcessId/u)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})

test('source API refusal and native status stay closed with original Cargo exit', async () => {
    const safe = 'openrdx-token-source-control-stage phase=create status=begin\nopenrdx-token-source-control-stage phase=create status=failed reason=AccessDenied'
    const result = await runRestrictedTokenProbe({ mode: 'source-control', execute: async () => ({ exitCode: 101, stdout: safe + '\n', stderr: 'private native detail' }) })
    assert.equal(result.passed, false)
    assert.equal(result.exitCode, 101)
    assert.deepEqual(result.sourceControl, safe.split('\n'))
    assert.equal(JSON.stringify(result).includes('private'), false)
    for (const line of ['openrdx-token-source-control private-sid=true', 'openrdx-token-source-control source-open=private', 'openrdx-token-source-control source-open=true source-open=false', 'openrdx-token-source-control-exit category=private', 'openrdx-token-source-control-stage phase=private status=failed reason=Other']) {
        const rejected = await runRestrictedTokenProbe({ mode: 'source-control', execute: async () => ({ exitCode: 0, stdout: proof + line + '\n', stderr: '' }) })
        assert.equal(rejected.passed, false)
        assert.deepEqual(rejected.sourceControl, [])
        assert.equal(JSON.stringify(rejected).includes('private'), false)
    }
})

test('every actual NativeError reason is retained and non-enum reasons are refused', async () => {
    const source = await readFile(new URL('../native/rdx-service/windows-native/src/lib.rs', import.meta.url), 'utf8')
    const block = source.split('pub enum NativeError {')[1].split('\n}')[0]
    const reasons = [...block.matchAll(/^    ([A-Za-z]+),$/gmu)].map((match) => match[1])
    assert.equal(reasons.length, 13)
    for (const reason of reasons) {
        const lines = ['openrdx-token-source-control-stage phase=create status=begin', `openrdx-token-source-control-stage phase=create status=failed reason=${reason}`]
        const result = await runRestrictedTokenProbe({ mode: 'source-control', execute: async () => ({ exitCode: 101, stdout: lines.join('\n'), stderr: '' }) })
        assert.equal(result.exitCode, 101)
        assert.equal(result.passed, false)
        assert.deepEqual(result.sourceControl, lines)
    }
    for (const reason of ['NotFound', 'Unsupported', 'Private', 'AccessDeniedPrivate']) {
        const result = await runRestrictedTokenProbe({ mode: 'source-control', execute: async () => ({ exitCode: 101, stdout: `openrdx-token-source-control-stage phase=create status=begin\nopenrdx-token-source-control-stage phase=create status=failed reason=${reason}`, stderr: '' }) })
        assert.equal(result.exitCode, 101)
        assert.deepEqual(result.sourceControl, [])
    }
})

test('orphan terminal transitions are rejected, including otherwise complete positive evidence', async () => {
    assert.equal(validateRestrictedTokenProbeOutput(proof.replace('openrdx-token-source-control-stage phase=cleanup status=begin\n', ''), '', { mode: 'source-control' }).passed, false)
    for (const terminal of ['ok', 'failed reason=Other']) {
        const result = await runRestrictedTokenProbe({ mode: 'source-control', execute: async () => ({ exitCode: 101, stdout: `openrdx-token-source-control-stage phase=create status=${terminal}`, stderr: '' }) })
        assert.deepEqual(result.sourceControl, [])
        assert.equal(result.passed, false)
        assert.equal(result.exitCode, 101)
    }
})

test('optional CI source control requires compiled fixed fixtures and cannot mask ordinary gate', async () => {
    const source = await readFile(new URL('../.github/workflows/build-installers.yml', import.meta.url), 'utf8')
    assert.match(source, /name: Compile private Windows token child fixtures\s+id: windows-token-fixtures/u)
    assert.match(source, /name: Observe source-context Windows child control[\s\S]*?if: always\(\) && matrix.platform == 'win' && steps.windows-token-fixtures.outcome == 'success'\s+continue-on-error: true/u)
    assert.match(source, /--source-control \| Tee-Object -FilePath out\/verification\/windows-token-source-control.log\s+\$probeExitCode = \$LASTEXITCODE\s+exit \$probeExitCode/u)
    assert.match(source, /path: \|[\s\S]*?out\/verification\/windows-token-source-control.log/u)
    const ordinary = source.split('name: Verify owned medium Windows child on disposable runner')[1].split('name: Observe source-context')[0]
    assert.doesNotMatch(ordinary, /continue-on-error/u)
})

test('separate source fixture observes exact source snapshot without token, privilege or launch adjustment', async () => {
    const source = await readFile(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/source_control.rs', import.meta.url), 'utf8')
    assert.match(source, /TOKEN_QUERY \| TOKEN_DUPLICATE \| TOKEN_ASSIGN_PRIMARY/u)
    assert.match(source, /Variant::Wait/u)
    assert.match(source, /OwnedChild::create\(&fixture, &source\)/u)
    assert.match(source, /prove_image\(child, fixture\)/u)
    assert.match(source, /SelfCheckFailure::Elevation as u32/u)
    assert.match(source, /#\[ignore = "requires administrator on a disposable Windows verifier"\]/u)
    assert.doesNotMatch(source, /SetTokenInformation|TOKEN_ADJUST|AdjustTokenPrivileges|CreateProcessW|Impersonate|SetSecurityInfo|LoadLibrary|std::env|assert_eq!|dbg!/u)
})
