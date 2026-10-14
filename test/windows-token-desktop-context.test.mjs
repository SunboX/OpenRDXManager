// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { runRestrictedTokenProbe, validateRestrictedTokenProbeOutput } from '../scripts/verify-windows-restricted-token-probe.mjs'

const name = 'service_acl::windows_impl::restricted_token_probe::native_restricted_token_observations'
const success = `running 1 test\nopenrdx-token-probe source-open=true derived-created=true query-ok=true\ntest ${name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`

test('closed read-only context survives native failure without replacing original exit or authorizing pass', async () => {
    const context = 'openrdx-token-desktop-context source-groups-query-ok=true source-logon-single=true derived-groups-query-ok=true derived-logon-single=true logon-same=true source-interactive-enabled=false source-batch-enabled=true source-service-enabled=false derived-interactive-enabled=false derived-batch-enabled=true derived-service-enabled=false current-station-query-ok=true current-station-winsta-zero=false current-desktop-query-ok=true current-desktop-default=true station-descriptor-query-ok=true desktop-descriptor-query-ok=false source-station-access-query-ok=true source-station-access-allowed=true derived-station-access-query-ok=true derived-station-access-allowed=false source-desktop-access-query-ok=false source-desktop-access-allowed=false derived-desktop-access-query-ok=false derived-desktop-access-allowed=false'
    const result = await runRestrictedTokenProbe({ mode: 'child', execute: async () => ({ exitCode: 101, stdout: `running 1 test\n${context}\n`, stderr: 'private raw failure' }) })
    assert.deepEqual(result.context, [context])
    assert.equal(result.passed, false)
    assert.equal(result.exitCode, 101)
    assert.equal(JSON.stringify(result).includes('private'), false)
})

test('query unavailability and DACL denial remain observations, never new child admission', () => {
    assert.equal(validateRestrictedTokenProbeOutput(success + 'openrdx-token-desktop-context derived-desktop-access-query-ok=false derived-desktop-access-allowed=false\n', '').passed, true)
    assert.equal(validateRestrictedTokenProbeOutput('running 0 tests\nopenrdx-token-desktop-context derived-desktop-access-query-ok=true derived-desktop-access-allowed=true\n', '', { mode: 'child' }).passed, false)
})

test('unknown, duplicate or nonboolean desktop context cannot leak or authorize', async () => {
    for (const pairs of ['source-groups-query-ok=private', 'private-sid=true', 'logon-same=true logon-same=false']) {
        const result = await runRestrictedTokenProbe({ execute: async () => ({ exitCode: 0, stdout: success + `openrdx-token-desktop-context ${pairs}\n`, stderr: '' }) })
        assert.equal(result.passed, false)
        assert.deepEqual(result.context, [])
        assert.equal(JSON.stringify(result).includes('private'), false)
    }
})

test('read-only native context closes only owned user handles and never changes desktop or impersonates a thread', async () => {
    const source = await readFile(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/desktop_context.rs', import.meta.url), 'utf8')
    assert.match(source, /CloseWindowStation/u)
    assert.match(source, /CloseDesktop/u)
    assert.match(source, /DuplicateTokenEx/u)
    assert.match(source, /AccessCheck/u)
    assert.doesNotMatch(source, /SetProcessWindowStation|SetThreadDesktop|SetUserObjectSecurity|SetSecurityInfo|ImpersonateLoggedOnUser|SetThreadToken|AdjustTokenPrivileges|ConvertSidToStringSid|assert_eq!|dbg!/u)
    assert.match(source, /SecurityImpersonation,\s*TokenImpersonation/u)
    assert.ok(source.indexOf('current_station_is_fixed') < source.indexOf('OpenDesktopW(PCWSTR'))
})
