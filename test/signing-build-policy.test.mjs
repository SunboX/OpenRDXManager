// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { createLocalInstallerBuildEnvironment, validateSigningBuildEnvironment } from '../scripts/signing-build-policy.mjs'

test('macOS signed builds require one exact team identity across helper and client', () => {
    for (const environment of [{}, { OPENRDX_MANAGER_TEAM_ID: '7UXAQ487HP' }, { OPENRDX_MACOS_TEAM_ID: '7UXAQ487HP' }, { OPENRDX_MANAGER_TEAM_ID: '7UXAQ487HP', OPENRDX_MACOS_TEAM_ID: '7UXAQ487HP' }]) {
        assert.doesNotThrow(() => validateSigningBuildEnvironment(environment))
    }
    assert.throws(() => validateSigningBuildEnvironment({ OPENRDX_MANAGER_TEAM_ID: '7UXAQ487HP', OPENRDX_MACOS_TEAM_ID: 'C79TQ55BDS' }), /native-service-signing-team-mismatch/u)
    for (const name of ['OPENRDX_MANAGER_TEAM_ID', 'OPENRDX_MACOS_TEAM_ID']) {
        for (const value of ['', 'abc', '7uxaq487hp', '7UXAQ487HP ', '7UXAQ487HP\n', '*', 123]) {
            assert.throws(() => validateSigningBuildEnvironment({ [name]: value }), /native-service-signing-team-invalid/u)
        }
    }
})

test('local installer compilation cannot inherit a signed-only helper policy', () => {
    const source = { PATH: '/tools', SDKROOT: '/sdk', OPENRDX_MACOS_TEAM_ID: '7UXAQ487HP', OPENRDX_MANAGER_TEAM_ID: '7UXAQ487HP' }
    const local = createLocalInstallerBuildEnvironment(source)
    assert.deepEqual(local, { PATH: '/tools', SDKROOT: '/sdk' })
    assert.equal(source.OPENRDX_MACOS_TEAM_ID, '7UXAQ487HP')
    assert.equal(source.OPENRDX_MANAGER_TEAM_ID, '7UXAQ487HP')
})
