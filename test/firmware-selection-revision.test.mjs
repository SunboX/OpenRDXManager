// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createUtilityOperationController } from '../src/renderer/workflows/utility-operation-controller.mjs'

/** @returns {object} Empty firmware-capable dock with reported identity. */
function emptyDock() {
    const device = structuredClone(createFixtureState({ mode: 'one-device' }).devices[0])
    device.media = null
    device.mediaState = 'no-media'
    return device
}

for (const change of ['refresh', 'selection', 'removed', 'cartridge', 'firmware', 'capability']) {
    test(`firmware selection revalidates an empty dock after ${change}`, async () => {
        const original = emptyDock()
        let current = original
        const requests = []
        const controller = createUtilityOperationController({
            files: {
                /** @returns {Promise<object>} Simulates changes while the operator chooses an image. */
                async chooseFirmware() {
                    current = structuredClone(original)
                    current.revision += 20
                    if (change === 'selection') current.id = 'rdx:replacement'
                    if (change === 'removed') current = null
                    if (change === 'cartridge') {
                        current.media = {}
                        current.mediaState = 'ready'
                    }
                    if (change === 'firmware') current.drive = { ...current.drive, firmwareRevision: '9999', details: { ...current.drive.details, firmwareRevision: { availability: 'reported', value: '9999' } } }
                    if (change === 'capability') current.capabilities['firmware-update'] = { state: 'unsupported-product' }
                    return { ok: true, fileToken: 'firmware:revision-test' }
                }
            },
            operations: {
                /** @param {object} request - Admission request only; never touches hardware. @returns {Promise<object>} Accepted fixture. */
                async start(request) {
                    requests.push(request)
                    return { ok: true, operationId: 'op:revision-test' }
                }
            }
        })
        const result = await controller.start({ kind: 'firmware-update', deviceId: original.id, deviceRevision: original.revision }, { getSelectedDevice: () => current })
        if (change === 'refresh') {
            assert.equal(result.ok, true)
            assert.deepEqual(requests, [{ kind: 'firmware-update', deviceId: original.id, deviceRevision: original.revision + 20, firmwareFileToken: 'firmware:revision-test' }])
        } else {
            assert.deepEqual(result, { ok: false, reason: 'stale-device-revision' })
            assert.deepEqual(requests, [], 'Target changes must never submit firmware')
        }
    })
}
