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

const execute = promisify(execFile)

const name = 'service_acl::windows_impl::restricted_token_probe::native_restricted_token_observations'
const passing = `running 1 test\nopenrdx-token-probe source-open=true derived-created=true query-ok=true\ntest ${name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`
const observations = 'openrdx-token-object-context source-default-dacl-query-ok=true source-default-dacl-valid=true source-default-dacl-null=true derived-default-dacl-query-ok=true derived-default-dacl-valid=false derived-default-dacl-null=false child-process-descriptor-query-ok=true child-thread-descriptor-query-ok=true child-token-open-query-ok=false child-token-descriptor-query-ok=false source-process-read-control-query-ok=true source-process-read-control-allowed=true derived-process-query-query-ok=true derived-process-query-allowed=false derived-thread-synchronize-query-ok=true derived-thread-synchronize-allowed=true derived-token-query-query-ok=false derived-token-query-allowed=false source-owner-query-ok=true source-owner-equals-user=false derived-owner-query-ok=true derived-owner-equals-user=true'

test('closed actual child object observations survive native failure without authorizing execution', async () => {
    const result = await runRestrictedTokenProbe({ mode: 'child', execute: async () => ({ exitCode: 101, stdout: `running 1 test\n${observations}\n`, stderr: 'private identity' }) })
    assert.deepEqual(result.objectContext, [observations])
    assert.equal(result.exitCode, 101)
    assert.equal(result.passed, false)
    assert.equal(JSON.stringify(result).includes('private'), false)
    assert.equal(validateRestrictedTokenProbeOutput(passing + observations + '\n', '').passed, true)
    assert.equal(validateRestrictedTokenProbeOutput(observations + '\n', '', { mode: 'child' }).passed, false)
})

test('unknown, duplicate and raw object diagnostics fail closed and never leak', async () => {
    for (const line of ['openrdx-token-object-context private-sid=true', 'openrdx-token-object-context derived-token-query-allowed=private', 'openrdx-token-object-context source-default-dacl-count=1', 'openrdx-token-object-context child-token-open-query-ok=true child-token-open-query-ok=false']) {
        const result = await runRestrictedTokenProbe({ execute: async () => ({ exitCode: 0, stdout: passing + line + '\n', stderr: '' }) })
        assert.equal(result.passed, false)
        assert.deepEqual(result.objectContext, [])
        assert.equal(JSON.stringify(result).includes('private'), false)
    }
})

test('HasRestrictions API success and exact DWORD return-size are independent closed observations', () => {
    const line = 'openrdx-token-library-context source-has-restrictions-api-ok=true source-has-restrictions-size-match=false source-has-restrictions-query-ok=false source-has-restrictions=false derived-has-restrictions-api-ok=false derived-has-restrictions-size-match=false derived-has-restrictions-query-ok=false derived-has-restrictions=false'
    assert.equal(validateRestrictedTokenProbeOutput(passing + line + '\n', '').passed, true)
    assert.equal(validateRestrictedTokenProbeOutput(passing + line.replace('size-match=false', 'size-match=1') + '\n', '').passed, false)
})

test('observer uses retained owned child handles and separate read-only actual primary token', async () => {
    const source = await readFile(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/object_context.rs', import.meta.url), 'utf8')
    assert.match(source, /GetKernelObjectSecurity/u)
    assert.match(source, /TokenDefaultDacl/u)
    assert.match(source, /TokenOwner/u)
    assert.match(source, /TOKEN_QUERY \| TOKEN_DUPLICATE \| TOKEN_READ_CONTROL/u)
    assert.match(source, /OwnedHandle\(handle\)/u)
    assert.match(source, /TOKEN_READ/u)
    assert.match(source, /TOKEN_WRITE/u)
    assert.match(source, /TOKEN_EXECUTE/u)
    assert.match(source, /TOKEN_ALL_ACCESS/u)
    assert.doesNotMatch(source, /OpenProcess\(|OpenThread\(|SetKernelObjectSecurity|SetTokenInformation|AdjustTokenPrivileges|ImpersonateLoggedOnUser|ConvertSidToStringSid|LoadLibrary|CreateProcess|TerminateProcess|ResumeThread|assert_eq!|dbg!/u)
    const child = await readFile(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/child.rs', import.meta.url), 'utf8')
    assert.match(child, /object_context::observe\(&source, &derived, &timeout_child, &wait_fixture\);[\s\S]*?ChildPhase::TimeoutResume/u)
})

test('ordinary object ACL parser runs host Rust malformed, generic and unsupported ACE negatives', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-object-acl-'))
    try {
        const binary = join(directory, process.platform === 'win32' ? 'acl.exe' : 'acl')
        const source = fileURLToPath(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/object_acl.rs', import.meta.url))
        await execute('rustc', ['--edition=2024', '--test', source, '-o', binary], { timeout: 30_000 })
        const { stdout } = await execute(binary, ['--test-threads=2'])
        assert.match(stdout, /3 passed; 0 failed/u)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})
