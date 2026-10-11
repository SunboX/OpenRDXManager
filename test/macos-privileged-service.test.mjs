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

    assert.deepEqual(controller.getStatus(), { state: 'not-registered' })
    assert.deepEqual(await controller.register(), { ok: false, reason: 'requires-approval' })
    assert.deepEqual(controller.getStatus(), { state: 'requires-approval' })
    assert.deepEqual(await controller.openApprovalSettings(), { ok: true })
    assert.deepEqual(await controller.unregister(), { ok: true })
    assert.deepEqual(controller.getStatus(), { state: 'not-registered' })
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
        assert.deepEqual(controller.getStatus(), { state: 'not-applicable' })
        assert.deepEqual(await controller.register(), { ok: false, reason: 'not-applicable' })
        assert.deepEqual(await controller.unregister(), { ok: false, reason: 'not-applicable' })
        assert.deepEqual(await controller.openApprovalSettings(), { ok: false, reason: 'not-applicable' })
        assert.deepEqual(fixture.calls, [])
    }
})

test('fails closed for malformed native output and native exceptions', async () => {
    const malformed = createMacOsPrivilegedServiceController({ addon: { status: () => 'root-ready', registerService: () => 1, unregisterService: () => null, openApprovalSettings: () => 'yes' }, isPackaged: true, platform: 'darwin' })
    assert.deepEqual(malformed.getStatus(), { state: 'registration-failed', reason: 'invalid-native-response' })
    assert.deepEqual(await malformed.register(), { ok: false, reason: 'invalid-native-response' })
    assert.deepEqual(await malformed.unregister(), { ok: false, reason: 'invalid-native-response' })
    assert.deepEqual(await malformed.openApprovalSettings(), { ok: false, reason: 'invalid-native-response' })

    const throwing = createMacOsPrivilegedServiceController({
        addon: {
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
    assert.deepEqual(throwing.getStatus(), { state: 'registration-failed', reason: 'native-service-management-failed' })
    assert.deepEqual(await throwing.register(), { ok: false, reason: 'native-service-management-failed' })
    assert.deepEqual(await throwing.unregister(), { ok: false, reason: 'native-service-management-failed' })
    assert.deepEqual(await throwing.openApprovalSettings(), { ok: false, reason: 'native-service-management-failed' })
})

test('requires the complete zero-argument native adapter on applicable runtimes', () => {
    assert.throws(() => createMacOsPrivilegedServiceController({ addon: {}, isPackaged: true, platform: 'darwin' }), /macos-service-management-addon-invalid/)
    assert.throws(() => createMacOsPrivilegedServiceController({ addon: null, isPackaged: true, platform: 'darwin' }), /macos-service-management-addon-invalid/)
})
