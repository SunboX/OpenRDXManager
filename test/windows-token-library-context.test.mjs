// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { runRestrictedTokenProbe, validateRestrictedTokenProbeOutput } from '../scripts/verify-windows-restricted-token-probe.mjs'

const name = 'service_acl::windows_impl::restricted_token_probe::native_restricted_token_observations'
const passing = `running 1 test\nopenrdx-token-probe source-open=true derived-created=true query-ok=true\ntest ${name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`
const restricting = 'openrdx-token-library-context source-restricted-sids-query-ok=true source-restricted-sids-empty=true source-restricted-sids-present=false source-has-restrictions-query-ok=true source-has-restrictions=false derived-restricted-sids-query-ok=true derived-restricted-sids-empty=false derived-restricted-sids-present=true derived-has-restrictions-query-ok=true derived-has-restrictions=true system-directory-query-ok=true kernel32-file-query-ok=true kernel32-descriptor-query-ok=true source-kernel32-read-query-ok=true source-kernel32-read-allowed=true derived-kernel32-read-query-ok=true derived-kernel32-read-allowed=false source-kernel32-execute-query-ok=true source-kernel32-execute-allowed=true derived-kernel32-execute-query-ok=true derived-kernel32-execute-allowed=false'
const window = 'openrdx-token-window-access source-station-read-control-query-ok=true source-station-read-control-allowed=true source-station-full-query-ok=true source-station-full-allowed=true derived-station-read-control-query-ok=true derived-station-read-control-allowed=false derived-station-full-query-ok=true derived-station-full-allowed=false source-desktop-read-control-query-ok=false source-desktop-read-control-allowed=false source-desktop-full-query-ok=false source-desktop-full-allowed=false derived-desktop-read-control-query-ok=false derived-desktop-read-control-allowed=false derived-desktop-full-query-ok=false derived-desktop-full-allowed=false'

test('closed restricting/library/window access observations preserve native failure without authority', async () => {
    const result = await runRestrictedTokenProbe({ mode: 'child', execute: async () => ({ exitCode: 101, stdout: `running 1 test\n${restricting}\n${window}\n`, stderr: 'private native detail' }) })
    assert.deepEqual(result.libraryContext, [restricting, window])
    assert.equal(result.passed, false)
    assert.equal(result.exitCode, 101)
    assert.equal(JSON.stringify(result).includes('private'), false)
    assert.equal(validateRestrictedTokenProbeOutput(passing + restricting + '\n' + window + '\n', '').passed, true)
    assert.equal(validateRestrictedTokenProbeOutput(`running 0 tests\n${restricting}\n${window}\n`, '', { mode: 'child' }).passed, false)
})

test('unknown, duplicate, raw count or nonboolean library/window diagnostics cannot leak or pass', async () => {
    for (const line of ['openrdx-token-library-context private-name=true', 'openrdx-token-library-context derived-restricted-sids-present=private', 'openrdx-token-library-context derived-restricted-sids-count=2', 'openrdx-token-library-context derived-restricted-sids-present=true derived-restricted-sids-present=false', 'openrdx-token-window-access derived-desktop-full-allowed=true derived-desktop-full-allowed=false', 'openrdx-token-window-access private-sid=true']) {
        const result = await runRestrictedTokenProbe({ execute: async () => ({ exitCode: 0, stdout: passing + line + '\n', stderr: '' }) })
        assert.equal(result.passed, false)
        assert.deepEqual(result.libraryContext, [])
        assert.equal(JSON.stringify(result).includes('private'), false)
    }
})

test('fixed library reader uses kernel system directory and held file handles without loader or policy changes', async () => {
    const source = await readFile(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/library_context.rs', import.meta.url), 'utf8')
    assert.match(source, /GetSystemDirectoryW/u)
    assert.match(source, /GetSecurityInfo/u)
    assert.match(source, /TokenRestrictedSids/u)
    assert.match(source, /TokenHasRestrictions/u)
    assert.doesNotMatch(source, /IsTokenRestricted/u)
    assert.match(source, /LocalSize/u)
    assert.match(source, /LocalFree/u)
    assert.match(source, /FILE_GENERIC_READ/u)
    assert.match(source, /FILE_GENERIC_EXECUTE/u)
    assert.doesNotMatch(source, /LoadLibrary|std::env|SetTokenInformation|CreateProcess|WriteFile|AdjustTokenPrivileges|ImpersonateLoggedOnUser|ConvertSidToStringSid|assert_eq!|dbg!/u)
})

test('window completion independently checks READ_CONTROL and full masks without changing object-specific evidence', async () => {
    const source = await readFile(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/desktop_context.rs', import.meta.url), 'utf8')
    assert.match(source, /enum WindowRights/u)
    assert.match(source, /WindowRights::ReadControl => READ_CONTROL_MASK/u)
    assert.match(source, /WindowRights::Full => STANDARD_REQUIRED \| specific/u)
    assert.match(source, /openrdx-token-window-access/u)
})
