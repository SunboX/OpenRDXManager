// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { assertInstalledDeviceDiscovery } from '../src/main/installed-device-verification.mjs'

const readiness = { status: 'ready', mode: 'native', privileged: true, hardwareReady: true }

test('firmware acceptance requires the reported revision on the exact selected dock', () => {
    const device = { id: 'rdx:selected', drive: { details: { firmwareRevision: { availability: 'reported', value: '0111' } } } }
    const inventory = { ok: true, devices: [device] }
    assert.equal(assertInstalledDeviceDiscovery(readiness, inventory, device.id, '0111'), 1)
    assert.throws(() => assertInstalledDeviceDiscovery(readiness, inventory, device.id, '0110'), /installed-firmware-revision-mismatch/u)
    assert.throws(() => assertInstalledDeviceDiscovery(readiness, inventory, undefined, '0111'), /installed-firmware-target-invalid/u)
    assert.throws(() => assertInstalledDeviceDiscovery(readiness, { ok: true, devices: [{ id: device.id }] }, device.id, '0111'), /installed-firmware-revision-mismatch/u)
    assert.throws(() => assertInstalledDeviceDiscovery(readiness, { ok: true, devices: [{ id: device.id }, { ...device, id: 'rdx:other' }] }, device.id, '0111'), /installed-firmware-revision-mismatch/u)
})

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
