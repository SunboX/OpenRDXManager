// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { assertInstalledDeviceDiscovery } from '../src/main/installed-device-verification.mjs'

const readiness = { status: 'ready', mode: 'native', privileged: true, hardwareReady: true }

test('installed device acceptance rejects empty discovery despite authenticated hardware capability', () => {
    for (const result of [undefined, { ok: false }, { ok: true, devices: [] }]) assert.throws(() => assertInstalledDeviceDiscovery(readiness, result), /installed-device-discovery-empty/u)
})

test('installed discovery requires the exact selected dock and a privileged service', () => {
    const inventory = { ok: true, devices: [{ id: 'rdx:selected' }, { id: 'rdx:other' }] }
    assert.equal(assertInstalledDeviceDiscovery(readiness, inventory, 'rdx:selected'), 2)
    assert.throws(() => assertInstalledDeviceDiscovery(readiness, inventory, 'rdx:absent'), /installed-device-target-not-found/u)
    assert.throws(() => assertInstalledDeviceDiscovery(readiness, inventory, 'C:\\disk'), /installed-device-target-invalid/u)
    assert.throws(() => assertInstalledDeviceDiscovery({ ...readiness, privileged: false }, inventory), /installed-service-authentication-unverified/u)
})
