// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { runRestrictedTokenProbe, validateRestrictedTokenProbeOutput } from '../scripts/verify-windows-restricted-token-probe.mjs'

const name = 'service_acl::windows_impl::restricted_token_probe::native_restricted_token_observations'
const passing = `running 1 test\nopenrdx-token-probe source-open=true derived-created=true query-ok=true\ntest ${name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`
const context =
    'openrdx-token-effective-context child-process-label-query-ok=true child-process-label-query-unsupported=false child-process-label-parse-valid=true child-process-label-known=true child-process-label-high=true child-process-label-medium=false child-process-label-no-write-up=true child-thread-label-query-ok=false child-thread-label-known=false child-token-label-query-ok=true child-token-label-implicit-medium=true fixture-root-label-query-ok=true fixture-root-label-low=true fixture-image-label-query-ok=true fixture-image-label-medium=true fixture-root-descriptor-query-ok=true fixture-image-descriptor-query-ok=true actual-fixture-root-read-query-ok=true actual-fixture-root-read-allowed=false actual-fixture-image-execute-query-ok=true actual-fixture-image-execute-allowed=true actual-snapshot-query-ok=true derived-fresh-snapshot-query-ok=true actual-derived-user-match=true actual-derived-session-match=true actual-derived-elevation-match=true actual-derived-integrity-match=true actual-derived-ui-access-match=true actual-derived-sandbox-inert-match=true actual-derived-type-match=true actual-derived-elevation-type-match=true actual-derived-groups-match=true actual-derived-privileges-match=true actual-derived-snapshot-match=true source-principals-query-ok=true source-builtin-users-enabled=true source-logon-single=true source-logon-enabled=true derived-principals-query-ok=true derived-builtin-users-enabled=false derived-logon-single=true derived-logon-enabled=true actual-principals-query-ok=true actual-builtin-users-enabled=true actual-logon-single=true actual-logon-enabled=true'
const objects = 'openrdx-token-object-context actual-process-all-query-ok=true actual-process-all-allowed=false actual-thread-all-query-ok=true actual-thread-all-allowed=true actual-token-all-query-ok=false actual-token-all-allowed=false source-token-all-query-ok=true source-token-all-allowed=true derived-token-all-query-ok=true derived-token-all-allowed=false'

test('effective context observes optional actual-child and fixture layers without authorizing native success', async () => {
    const result = await runRestrictedTokenProbe({ mode: 'child', execute: async () => ({ exitCode: 101, stdout: context + '\n' + objects, stderr: 'private SID path' }) })
    assert.equal(result.passed, false)
    assert.equal(result.exitCode, 101)
    assert.deepEqual(result.effectiveContext, [context])
    assert.deepEqual(result.objectContext, [objects])
    assert.equal(JSON.stringify(result).includes('private'), false)
    assert.equal(validateRestrictedTokenProbeOutput(passing + context + '\n' + objects + '\n', '').passed, true)
    assert.equal(validateRestrictedTokenProbeOutput(context, '', { mode: 'child' }).passed, false)
    assert.equal(validateRestrictedTokenProbeOutput(context, '', { mode: 'source-control' }).passed, false)
})

test('unknown, duplicate, raw identity and numeric effective-context fields never pass or leak', async () => {
    for (const line of ['openrdx-token-effective-context private-sid=true', 'openrdx-token-effective-context actual-derived-groups-count=2', 'openrdx-token-effective-context actual-logon-single=private', 'openrdx-token-effective-context child-token-label-known=true child-token-label-known=false', 'openrdx-token-object-context actual-token-all-allowed=true actual-token-all-allowed=false']) {
        const result = await runRestrictedTokenProbe({ execute: async () => ({ exitCode: 0, stdout: passing + line, stderr: '' }) })
        assert.equal(result.passed, false)
        assert.deepEqual(result.effectiveContext, [])
        assert.equal(JSON.stringify(result).includes('private'), false)
    }
})

test('read-only observer reuses pinned fixture handles and shared bounded labels with no setters', async () => {
    const root = '../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/'
    const source = await readFile(new URL(root + 'effective_context.rs', import.meta.url), 'utf8')
    assert.match(source, /GetKernelObjectSecurity/u)
    assert.match(source, /LABEL_SECURITY_INFORMATION/u)
    assert.match(source, /mandatory_label::parse/u)
    assert.match(source, /fixture\.retained_payload\(\)/u)
    assert.match(source, /FILE_GENERIC_READ/u)
    assert.match(source, /FILE_GENERIC_EXECUTE/u)
    assert.doesNotMatch(source, /CreateFile|OpenProcess\(|OpenThread\(|SetTokenInformation|SetSecurityInfo|SACL_SECURITY_INFORMATION|ACCESS_SYSTEM_SECURITY|AdjustTokenPrivileges|ImpersonateLoggedOnUser|std::env|LoadLibrary|assert_eq!|dbg!/u)
    const object = await readFile(new URL(root + 'object_context.rs', import.meta.url), 'utf8')
    assert.match(object, /TOKEN_QUERY \| TOKEN_DUPLICATE \| TOKEN_READ_CONTROL/u)
    for (const constant of ['PROCESS_ALL_ACCESS', 'THREAD_ALL_ACCESS', 'TOKEN_ALL_ACCESS']) assert.ok(object.includes(constant))
    const child = await readFile(new URL(root + 'child.rs', import.meta.url), 'utf8')
    assert.match(child, /object_context::observe\(&source, &derived, &timeout_child, &wait_fixture\);[\s\S]*?prove_child_quiet\(&timeout_child, &wait_fixture, &original, &console, session\)[\s\S]*?ChildPhase::TimeoutResume/u)
})
