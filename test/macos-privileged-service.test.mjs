// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { createMacOsPrivilegedServiceController } from '../src/main/macos-privileged-service.mjs'

/** Creates a complete observable native ServiceManagement adapter. @param {string} initialState - Initial closed state. @returns {{addon: object, calls: string[]}} Adapter and call log. */
function createAddon(initialState) {
    const calls = []
    let state = initialState
    return {
        calls,
        addon: {
            /** @returns {string} Native package mode. */
            installationMode() {
                return 'signed'
            },
            /** @returns {string} Current state. */
            status() {
                calls.push('status')
                return state
            },
            /** @returns {string} Registration result. */
            registerService() {
                calls.push('register')
                state = 'requires-approval'
                return state
            },
            /** @returns {string} Unregistration result. */
            unregisterService() {
                calls.push('unregister')
                state = 'not-registered'
                return state
            },
            /** @returns {boolean} Confirms settings navigation. */
            openApprovalSettings() {
                calls.push('open-settings')
                return true
            }
        }
    }
}

test('maps the fixed macOS registration and approval lifecycle', async () => {
    const fixture = createAddon('not-registered')
    const controller = createMacOsPrivilegedServiceController({ addon: fixture.addon, isPackaged: true, platform: 'darwin' })

    assert.deepEqual(await controller.getStatus(), { state: 'not-registered' })
    assert.deepEqual(await controller.register(), { ok: false, reason: 'requires-approval' })
    assert.deepEqual(await controller.getStatus(), { state: 'requires-approval' })
    assert.deepEqual(await controller.openApprovalSettings(), { ok: true })
    assert.deepEqual(await controller.unregister(), { ok: true })
    assert.deepEqual(await controller.getStatus(), { state: 'not-registered' })
    assert.deepEqual(fixture.calls, ['status', 'register', 'status', 'open-settings', 'unregister', 'status'])
})

test('keeps unpackaged and non-macOS runtimes outside the native registration boundary', async () => {
    for (const options of [
        { isPackaged: false, platform: 'darwin' },
        { isPackaged: true, platform: 'linux' },
        { isPackaged: true, platform: 'win32' }
    ]) {
        const fixture = createAddon('enabled')
        const controller = createMacOsPrivilegedServiceController({ ...options, addon: fixture.addon })
        assert.deepEqual(await controller.getStatus(), { state: 'not-applicable' })
        assert.deepEqual(await controller.register(), { ok: false, reason: 'not-applicable' })
        assert.deepEqual(await controller.unregister(), { ok: false, reason: 'not-applicable' })
        assert.deepEqual(await controller.openApprovalSettings(), { ok: false, reason: 'not-applicable' })
        assert.deepEqual(fixture.calls, [])
    }
})

test('fails closed for malformed native output and native exceptions', async () => {
    const malformed = createMacOsPrivilegedServiceController({ addon: { installationMode: () => 'signed', status: () => 'root-ready', registerService: () => 1, unregisterService: () => null, openApprovalSettings: () => 'yes' }, isPackaged: true, platform: 'darwin' })
    assert.deepEqual(await malformed.getStatus(), { state: 'registration-failed', reason: 'invalid-native-response' })
    assert.deepEqual(await malformed.register(), { ok: false, reason: 'invalid-native-response' })
    assert.deepEqual(await malformed.unregister(), { ok: false, reason: 'invalid-native-response' })
    assert.deepEqual(await malformed.openApprovalSettings(), { ok: false, reason: 'invalid-native-response' })

    const throwing = createMacOsPrivilegedServiceController({
        addon: {
            installationMode: () => 'signed',
            status: () => {
                throw new Error('private')
            },
            registerService: () => {
                throw new Error('private')
            },
            unregisterService: () => {
                throw new Error('private')
            },
            openApprovalSettings: () => {
                throw new Error('private')
            }
        },
        isPackaged: true,
        platform: 'darwin'
    })
    assert.deepEqual(await throwing.getStatus(), { state: 'registration-failed', reason: 'native-service-management-failed' })
    assert.deepEqual(await throwing.register(), { ok: false, reason: 'native-service-management-failed' })
    assert.deepEqual(await throwing.unregister(), { ok: false, reason: 'native-service-management-failed' })
    assert.deepEqual(await throwing.openApprovalSettings(), { ok: false, reason: 'native-service-management-failed' })
})

test('requires the complete zero-argument native adapter on applicable runtimes', () => {
    assert.throws(() => createMacOsPrivilegedServiceController({ addon: {}, isPackaged: true, platform: 'darwin' }), /macos-service-management-addon-invalid/)
    assert.throws(() => createMacOsPrivilegedServiceController({ addon: null, isPackaged: true, platform: 'darwin' }), /macos-service-management-addon-invalid/)
})

test('reports local enrollment and endpoint verification without consulting SMAppService', async () => {
    for (const state of ['enabled', 'installer-required', 'repair-required']) {
        const fixture = createAddon('enabled')
        fixture.addon.installationMode = () => 'local'
        const controller = createMacOsPrivilegedServiceController({ addon: fixture.addon, localTrustAddon: { localTrustStatus: () => state }, isPackaged: true, platform: 'darwin' })
        assert.deepEqual(await controller.getStatus(), { state })
        assert.deepEqual(await controller.register(), { ok: false, reason: state === 'repair-required' ? 'repair-required' : 'installer-required' })
        assert.deepEqual(await controller.unregister(), { ok: false, reason: 'installer-required' })
        assert.deepEqual(await controller.openApprovalSettings(), { ok: false, reason: 'installer-required' })
        assert.deepEqual(fixture.calls, [])
    }
})

test('denies local readiness when the verifier is absent, throws, or returns an unknown token', async () => {
    const fixture = createAddon('enabled')
    fixture.addon.installationMode = () => 'local'
    for (const localTrustAddon of [
        null,
        {},
        { localTrustStatus: () => 'file-exists' },
        {
            localTrustStatus: () => {
                throw new Error('private-path')
            }
        }
    ]) {
        const controller = createMacOsPrivilegedServiceController({ addon: fixture.addon, localTrustAddon, isPackaged: true, platform: 'darwin' })
        assert.deepEqual(await controller.getStatus(), { state: 'repair-required' })
        assert.deepEqual(await controller.register(), { ok: false, reason: 'repair-required' })
    }
    assert.deepEqual(fixture.calls, [])
})

test('never downgrades invalid native installation mode into signed service registration', async () => {
    const fixture = createAddon('enabled')
    for (const mode of ['unexpected', null]) {
        fixture.addon.installationMode = () => mode
        const controller = createMacOsPrivilegedServiceController({ addon: fixture.addon, isPackaged: true, platform: 'darwin' })
        assert.deepEqual(await controller.getStatus(), { state: 'repair-required' })
        assert.deepEqual(await controller.register(), { ok: false, reason: 'repair-required' })
    }
    assert.deepEqual(fixture.calls, [])
})

test('awaits asynchronous local endpoint proof and contains verifier rejection', async () => {
    const fixture = createAddon('enabled')
    fixture.addon.installationMode = () => 'local'
    const verified = createMacOsPrivilegedServiceController({ addon: fixture.addon, localTrustAddon: { localTrustStatus: async () => 'enabled' }, isPackaged: true, platform: 'darwin' })
    assert.deepEqual(await verified.getStatus(), { state: 'enabled' })
    const denied = createMacOsPrivilegedServiceController({
        addon: fixture.addon,
        localTrustAddon: {
            localTrustStatus: async () => {
                throw new Error('private')
            }
        },
        isPackaged: true,
        platform: 'darwin'
    })
    assert.deepEqual(await denied.getStatus(), { state: 'repair-required' })
    assert.deepEqual(fixture.calls, [])
})
