// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { dispatchApplicationRequest } from '../src/main/application-dispatcher.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createUtilityOperationController } from '../src/renderer/workflows/utility-operation-controller.mjs'

/** @returns {object} Synthetic available empty receiver; never represents live hardware. */
function dock() {
    return { ...structuredClone(createFixtureState({ mode: 'one-device' }).devices[0]), revision: 3, media: null, mediaState: 'no-media' }
}

/** @param {string} change - Change while discovery completes. @returns {object} Main-owned fixture admission services and evidence. */
function admission(change) {
    let device = dock()
    let scanning = true
    let generation = 1
    const requests = []
    const services = {
        operations: {
            /** @returns {object} Current synthetic privileged admission context. */
            getContext() {
                return { device, generation, activeOperation: scanning ? { kind: 'scan' } : null, serviceMode: 'native', hasPrivilege: true, hardwareReady: true, platformCapability: { state: 'available' } }
            },
            /** @returns {Promise<void>} Completes exactly one existing discovery pass. */
            async waitForScan() {
                scanning = false
                device.revision += 1
                if (change === 'removed') device = null
                if (change === 'identity') device.serial = 'different-unit'
                if (change === 'firmware') device.drive.details.firmwareRevision.value = '0112'
                if (change === 'media') {
                    device.media = {}
                    device.mediaState = 'ready'
                }
                if (change === 'capability') device.capabilities['firmware-update'] = { state: 'busy' }
                if (change === 'generation') generation += 1
            },
            /** @param {object} request - Validated fixture request. @returns {Promise<object>} Records admission without device dispatch. */
            async start(request) {
                requests.push(request)
                return { ok: true, operationId: 'op:scan-admission' }
            }
        }
    }
    return { requests, services }
}

for (const change of ['telemetry', 'removed', 'identity', 'firmware', 'media', 'capability', 'generation', 'already-stale']) {
    test(`firmware admission after a pending scan handles ${change}`, async () => {
        const fixture = admission(change)
        const device = dock()
        const request = { kind: 'firmware-update', deviceId: device.id, deviceRevision: change === 'already-stale' ? 2 : 3, firmwareFileToken: 'firmware:scan-test' }
        const result = await dispatchApplicationRequest(fixture.services, 'openrdx:operations:start', request)
        if (change === 'telemetry') {
            assert.deepEqual(result, { ok: true, operationId: 'op:scan-admission' })
            assert.deepEqual(fixture.requests, [{ ...request, deviceRevision: 4 }])
        } else {
            assert.deepEqual(result, { ok: false, reason: change === 'removed' ? 'device-not-found' : 'stale-device-revision' })
            assert.deepEqual(fixture.requests, [])
        }
        assert.equal(request.deviceRevision, change === 'already-stale' ? 2 : 3, 'caller authority is never mutated')
    })
}

test('cached service inventory followed by an in-flight scan advances only the selected empty dock', async () => {
    const original = dock()
    const fixture = admission('telemetry')
    const controller = createUtilityOperationController({
        files: {
            /** @returns {Promise<object>} Synthetic local file authority. */ async chooseFirmware() {
                return { ok: true, fileToken: 'firmware:scan-test' }
            }
        },
        devices: {
            /** @returns {Promise<object>} The cached service is ahead of renderer publication. */ async list() {
                return { ok: true, devices: [original] }
            }
        },
        operations: {
            /** @param {object} request - Real renderer request through fixture main admission. @returns {Promise<object>} No hardware dispatch. */ async start(request) {
                return await dispatchApplicationRequest(fixture.services, 'openrdx:operations:start', request)
            }
        }
    })
    const selected = { ...original, revision: 2 }
    const result = await controller.start({ kind: 'firmware-update', deviceId: selected.id, deviceRevision: 2 }, { getSelectedDevice: () => selected })
    assert.equal(result.ok, true)
    assert.equal(fixture.requests.length, 1)
    assert.equal(fixture.requests[0].deviceRevision, 4)
})

test('other operations retain exact revision checks across discovery', async () => {
    const fixture = admission('telemetry')
    const result = await dispatchApplicationRequest(fixture.services, 'openrdx:operations:start', { kind: 'self-test', deviceId: dock().id, deviceRevision: 3 })
    assert.deepEqual(result, { ok: false, reason: 'stale-device-revision' })
    assert.deepEqual(fixture.requests, [])
})
