// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import test from 'node:test'
import { buildMacOsClientAddon, getMacOsClientCompiledTeam } from '../scripts/build-macos-client-addon.mjs'

test('macOS client compiles the same exact team as the helper or explicitly local-only policy', () => {
    assert.equal(getMacOsClientCompiledTeam({}), '')
    assert.equal(getMacOsClientCompiledTeam({ OPENRDX_MACOS_TEAM_ID: 'ABCD123456' }), 'ABCD123456')
    assert.equal(getMacOsClientCompiledTeam({ OPENRDX_MANAGER_TEAM_ID: 'ABCD123456' }), 'ABCD123456')
    assert.equal(getMacOsClientCompiledTeam({ OPENRDX_MACOS_TEAM_ID: 'ABCD123456', OPENRDX_MANAGER_TEAM_ID: 'ABCD123456' }), 'ABCD123456')
})

test('macOS client refuses malformed or mismatched compile-time authority before skipping or building', async () => {
    for (const candidate of ['', 'abcd123456', 'ABCD123456\n', 'ABCD12345', 'ABCD1234567', 'ABCD12345"']) {
        assert.throws(() => getMacOsClientCompiledTeam({ OPENRDX_MACOS_TEAM_ID: candidate }), /signing-team-invalid/u)
        await assert.rejects(buildMacOsClientAddon({ platform: 'linux', environment: { OPENRDX_MACOS_TEAM_ID: candidate } }), /signing-team-invalid/u)
    }
    assert.throws(() => getMacOsClientCompiledTeam({ OPENRDX_MACOS_TEAM_ID: 'ABCD123456', OPENRDX_MANAGER_TEAM_ID: 'ZYXW654321' }), /signing-team-mismatch/u)
})
