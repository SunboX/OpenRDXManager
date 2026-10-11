// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { OperationCoordinator } from '../src/main/operation-coordinator.mjs'
import { dispatchApplicationRequest } from '../src/main/application-dispatcher.mjs'
import { IpcChannel } from '../src/shared/ipc-contract.mjs'

const led = { kind: 'led-test', deviceId: 'rdx:scan-test', deviceRevision: 4 }

/** @returns {object} Controlled scan boundary and current authority context. */
function harness() {
    let completeScan
    let revision = 4
    let nextId = 0
    const calls = []
    const scanResponse = new Promise((resolve) => {
        completeScan = resolve
    })
    const coordinator = new OperationCoordinator({
        dispatch: async (request) => {
            calls.push(request)
            return { ok: true }
        },
        scanDispatch: () => scanResponse,
        getDevice: () => ({ id: led.deviceId, revision, capabilities: { 'led-test': { state: 'available' }, 'self-test': { state: 'available' } } }),
        getPlatformCapability: () => ({ state: 'available' }),
        getServiceMode: () => 'native',
        hasPrivilege: () => true,
        isHardwareReady: () => true,
        idFactory: () => `op:scan-test-${++nextId}`
    })
    const services = { operations: { getContext: coordinator.getContext.bind(coordinator), waitForScan: coordinator.waitForScan?.bind(coordinator), start: coordinator.start.bind(coordinator) } }
    return {
        coordinator,
        calls,
        completeScan,
        services,
        changeRevision: (value) => {
            revision = value
        }
    }
}

/** @returns {Promise<void>} Drains all pending admission continuations. */
async function nextTurn() {
    await new Promise(setImmediate)
}

test('LED Test clicked during Auto Scan waits and starts once after the scan releases the device', async () => {
    const h = harness()
    const scan = h.coordinator.scan({ kind: 'scan' })
    let settled = false
    /** @returns {Promise<object>} Records admission settlement after the discovery pass releases its lock. */
    async function startLedTest() {
        const result = await dispatchApplicationRequest(h.services, IpcChannel.OPERATIONS_START, led)
        settled = true
        return result
    }
    const start = startLedTest()
    await nextTurn()
    assert.equal(settled, false, 'An in-flight discovery pass is not a failed LED Test')
    assert.equal(h.coordinator.getActiveOperation().kind, 'scan')
    assert.equal(h.calls.length, 0)
    h.completeScan({ ok: true })
    await scan
    assert.equal((await start).ok, true)
    assert.equal(h.calls.length, 1)
    assert.deepEqual(h.calls[0].request, led)
    assert.equal(h.coordinator.getActiveOperation().kind, 'led-test')
})

test('direct and tray starts also wait for the scan and only one pending operation wins', async () => {
    const h = harness()
    const scan = h.coordinator.scan({ kind: 'scan' })
    const first = h.coordinator.start(led)
    const second = h.coordinator.start({ ...led, kind: 'self-test' })
    assert.equal(h.calls.length, 0)
    h.completeScan({ ok: true })
    await scan
    assert.equal((await first).ok, true)
    assert.deepEqual(await second, { ok: false, reason: 'operation-in-progress' })
    assert.equal(h.calls.length, 1)
})

test('waiting for a scan never silently retargets a changed device revision', async () => {
    const h = harness()
    const scan = h.coordinator.scan({ kind: 'scan' })
    const start = dispatchApplicationRequest(h.services, IpcChannel.OPERATIONS_START, led)
    await nextTurn()
    h.changeRevision(5)
    h.completeScan({ ok: true })
    await scan
    assert.deepEqual(await start, { ok: false, reason: 'stale-device-revision' })
    assert.equal(h.calls.length, 0)
})

test('a genuine active operation still rejects another test immediately', async () => {
    const h = harness()
    await h.coordinator.start(led)
    assert.deepEqual(await dispatchApplicationRequest(h.services, IpcChannel.OPERATIONS_START, led), { ok: false, reason: 'operation-in-progress' })
    assert.equal(h.calls.length, 1)
})

test('an ambiguous scan keeps its lock and cannot dispatch a waiting test', async () => {
    const h = harness()
    const scan = h.coordinator.scan({ kind: 'scan' })
    const start = dispatchApplicationRequest(h.services, IpcChannel.OPERATIONS_START, led)
    h.completeScan({ ok: false, reason: 'service-timeout', ambiguous: true })
    await scan
    assert.deepEqual(await start, { ok: false, reason: 'operation-in-progress' })
    assert.equal(h.coordinator.getActiveOperation().kind, 'scan')
    assert.equal(h.calls.length, 0)
})
