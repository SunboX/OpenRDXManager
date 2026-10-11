// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { OperationCoordinator } from '../src/main/operation-coordinator.mjs'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createOpenRdxIntentAdapter } from '../src/renderer/intent-adapter.mjs'
import { createStore } from '../src/renderer/store.mjs'

/** @param {object} context - Test cleanup owner. @returns {Promise<object>} Real renderer/coordinator and exact event owner for a writable cartridge. */
async function harness(context) {
    const source = createFixtureState({ mode: 'one-device' })
    const device = source.devices[0]
    const store = createStore({ ...source, activeArea: 'tests' })
    const dom = new JSDOM('<!doctype html><div id="app"></div>', { pretendToBeVisual: true })
    const root = dom.window.document.querySelector('#app')
    const events = []
    const request = { kind: 'write-read-test', deviceId: device.id, deviceRevision: device.revision }
    const coordinator = new OperationCoordinator({
        getDevice: () => device,
        getPlatformCapability: () => ({ state: 'available' }),
        getServiceMode: () => 'native',
        hasPrivilege: () => true,
        isHardwareReady: () => true,
        dispatch: async () => ({ ok: true }),
        idFactory: () => 'op:write-read'
    })
    coordinator.subscribe((event) => {
        events.push(event)
        store.dispatch({ type: 'operation/event', event })
    })
    /** @param {object} request - Renderer request. @returns {Promise<object>} Admission delivered across an asynchronous IPC boundary. */
    async function start(request) {
        await new Promise(setImmediate)
        return coordinator.start(request)
    }
    const controller = mountApplication(root, { store, intentAdapter: createOpenRdxIntentAdapter({ operations: { start } }) })
    context.after(() => {
        controller.destroy()
        dom.window.close()
    })
    /** @returns {HTMLElement} Current reconciled Write/Read Test card. */
    function card() {
        return root.querySelector('[data-test-kind="write-read-test"]')
    }
    card().querySelector('[data-test-action]').click()
    assert.match(card().textContent, /Submitting Write\/Read Test/)
    await new Promise(setImmediate)
    assert.equal(coordinator.getActiveOperation().operationId, 'op:write-read')
    return { coordinator, events, store, root, card, owner: { ...request, operationId: 'op:write-read' } }
}

test('write/read progress closes cancellation before file creation and preserves the visible final result', async (context) => {
    const { coordinator, events, owner, card } = await harness(context)
    assert.equal(await coordinator.handleServiceEvent({ ...owner, state: 'started', stage: 'host-writing' }), true)
    assert.equal(await coordinator.handleServiceEvent({ ...owner, state: 'progress', stage: 'host-writing', progress: 0, cancellationState: 'closed' }), true)
    assert.deepEqual(await coordinator.cancel({ operationId: owner.operationId }), { ok: false, reason: 'operation-not-cancellable' })
    assert.equal(await coordinator.handleServiceEvent({ ...owner, state: 'progress', stage: 'host-reading', progress: 1 / 3, cancellationState: 'closed' }), true)
    assert.equal(card().querySelector('[data-progress-timeline] progress').value, 1 / 3)
    assert.equal(await coordinator.handleServiceEvent({ ...owner, state: 'progress', stage: 'host-cleanup', progress: 2 / 3, cancellationState: 'closed' }), true)
    assert.equal(await coordinator.handleServiceEvent({ ...owner, state: 'succeeded', stage: 'complete' }), true)
    assert.equal(events.at(-1).state, 'succeeded')
    assert.equal(coordinator.getActiveOperation(), null)
    assert.match(card().textContent, /Write\/Read Test passed/)
    assert.equal(card().querySelector('[data-result-status]').dataset.resultStatus, 'succeeded')
})

test('write/read service failure stays visible after the device is rediscovered', async (context) => {
    const { coordinator, owner, card, store, root } = await harness(context)
    const before = store.getState()
    assert.equal(await coordinator.handleServiceEvent({ ...owner, state: 'started', stage: 'host-writing' }), true)
    store.dispatch({ type: 'service/status', status: 'recovering' })
    assert.equal(await coordinator.handleGenerationLoss(0, 'service-exited'), true)
    store.dispatch({ type: 'service/ready', epoch: 2, listRevision: 0, mode: 'native', privileged: true, hardwareReady: true, hardwareVerified: true, platformCapability: { state: 'available' } })
    store.dispatch({ type: 'device/list-replaced', epoch: 2, listRevision: 1, devices: before.devices })
    assert.equal(root.querySelector('[role="tab"][aria-selected="true"]').dataset.area, 'status')
    root.querySelector('[role="tab"][data-area="tests"]').click()
    assert.match(card().textContent, /Write\/Read Test failed/)
    assert.match(card().textContent, /service-exited/)
    assert.equal(card().querySelector('[data-result-status]').dataset.resultStatus, 'failed')
})
