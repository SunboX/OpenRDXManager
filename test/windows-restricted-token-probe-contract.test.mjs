// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

/** Reads the opt-in probe without loading any platform APIs. */
async function probeSource() {
    return readFile(new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe.rs', import.meta.url), 'utf8')
}

test('restricted token probe is opt-in, token-only and uses exactly the documented reduction flags', async () => {
    const source = await probeSource()
    assert.match(source, /#\[ignore = "requires administrator on a disposable Windows verifier"\]/u)
    assert.match(source, /LUA_TOKEN \| DISABLE_MAX_PRIVILEGE/u)
    assert.match(source, /CreateRestrictedToken\(\s*source\.0,\s*LUA_TOKEN \| DISABLE_MAX_PRIVILEGE,\s*None,\s*None,\s*None,\s*&mut handle,?\s*\)/u)
    assert.match(source, /let derived = OwnedHandle\(handle\)/u)
    assert.doesNotMatch(source, /SANDBOX_INERT|CreateProcess|Impersonate|SetTokenInformation|AdjustTokenPrivileges|assert_eq!|dbg!/u)
})

test('restricted token probe emits boolean kernel facts without claiming launcher eligibility', async () => {
    const source = await probeSource()
    for (const fact of ['same-user', 'same-session', 'source-elevated', 'derived-elevated', 'admin-deny-only', 'no-enabled-admins', 'enabled-privilege-whitelist', 'present-privilege-whitelist', 'privileges-reduced', 'integrity-medium', 'integrity-high', 'integrity-reduced']) assert.ok(source.includes(fact), fact)
    assert.doesNotMatch(source, /println!\([^;]*(?:bytes\(|sid|session|rid|privileges)\s*\)/u)
    assert.match(source, /Successful queries do not prove/u)
})

test('standalone diagnostics explicitly invoke the ignored token probe without building installers', async () => {
    const workflow = await readFile(new URL('../.github/workflows/windows-token-diagnostics.yml', import.meta.url), 'utf8')
    const command = 'node scripts/verify-windows-restricted-token-probe.mjs'
    assert.ok(workflow.includes(command))
    assert.equal(workflow.includes('- name: Build installers'), false)
})
