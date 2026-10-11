// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createDashboardDom, createRecordingIntentAdapter } from './helpers/renderer-dom.mjs'

/**
 * Mounts the production controller with deterministic discovery and owned cleanup.
 * @param {import('node:test').TestContext} context - Test cleanup owner.
 * @param {object} state - Safe renderer-only fixture state.
 * @returns {object} Mounted DOM, controller and store; no hardware is accessed.
 */
function mountFixture(context, state) {
    const recorder = createRecordingIntentAdapter(['scan', 'operation'])
    const mounted = createDashboardDom(state, { intentAdapter: recorder.adapter })
    /** @returns {void} Removes listeners and disposes the isolated test DOM. */
    function cleanup() {
        mounted.controller.destroy()
        mounted.dom.window.close()
    }
    context.after(cleanup)
    return { ...mounted, calls: recorder.calls }
}

/**
 * Reads the visible management tab, not the startup preference snapshot.
 * @param {HTMLElement} root - Mounted application root.
 * @returns {string|undefined} Selected area, or undefined on discovery.
 */
function selectedArea(root) {
    return root.querySelector('[role="tab"][aria-selected="true"]')?.dataset.area
}

for (const area of ['encryption', 'tests', 'utilities']) {
    for (const eventType of ['device/list-replaced', 'device/snapshot']) {
        /** @param {import('node:test').TestContext} context - Cleanup owner. @returns {void} Verifies first discovery overrides a restored tab without an operation. */
        function firstConnectionOpensStatus(context) {
            const empty = createFixtureState({ mode: 'no-device' })
            const device = createFixtureState({ mode: 'one-device' }).devices[0]
            const { root, store, calls } = mountFixture(context, { ...empty, activeArea: area, settings: { ...empty.settings, lastSafeView: area }, discovery: { ...empty.discovery, epoch: 1, listRevision: 0, selectionInitialized: false } })
            assert.equal(selectedArea(root), undefined)
            store.dispatch({ type: eventType, epoch: 1, listRevision: 1, ...(eventType === 'device/snapshot' ? { device } : { devices: [device] }) })
            assert.equal(store.getState().selectedDeviceId, device.id)
            assert.equal(selectedArea(root), 'status')
            assert.deepEqual(calls, [], 'Opening Status must not start a hardware operation')
        }
        test(`first ${eventType} opens Status instead of restored ${area}`, firstConnectionOpensStatus)
    }
}

/** @param {import('node:test').TestContext} context - Cleanup owner. @returns {void} Verifies explicit connection selection opens Status. */
function explicitSelectionOpensStatus(context) {
    const fixture = createFixtureState({ mode: 'one-device' })
    const { root, store, calls } = mountFixture(context, { ...fixture, activeArea: 'utilities', selectedDeviceId: null })
    root.querySelector('[data-action="manage-device"]').click()
    assert.equal(store.getState().selectedDeviceId, fixture.devices[0].id)
    assert.equal(selectedArea(root), 'status')
    assert.deepEqual(calls, [])
}
test('selecting a connected drive opens Status instead of Tools', explicitSelectionOpensStatus)

/** @param {import('node:test').TestContext} context - Cleanup owner. @returns {void} Verifies reconnecting the same identity does not restore Tools or retarget implicitly. */
function reconnectedSelectionOpensStatus(context) {
    const fixture = createFixtureState({ mode: 'one-device' })
    const device = fixture.devices[0]
    const { root, store } = mountFixture(context, { ...fixture, activeArea: 'utilities', discovery: { ...fixture.discovery, epoch: 1, listRevision: 1, selectionInitialized: true } })
    assert.equal(selectedArea(root), 'utilities')
    store.dispatch({ type: 'device/removed', deviceId: device.id, deviceRevision: device.revision, epoch: 1, listRevision: 2 })
    store.dispatch({ type: 'device/list-replaced', devices: [{ ...device, revision: device.revision + 1 }], epoch: 1, listRevision: 3 })
    assert.equal(store.getState().selectedDeviceId, null, 'A reconnect must not bypass explicit reselection')
    root.querySelector('[data-device-rail] [data-action="manage-device"]').click()
    assert.equal(selectedArea(root), 'status')
}
test('reselecting a reconnected drive always opens Status', reconnectedSelectionOpensStatus)

/** @param {import('node:test').TestContext} context - Cleanup owner. @returns {void} Verifies a service restart opens Status on the newly established selection. */
function recoveredServiceOpensStatus(context) {
    const fixture = createFixtureState({ mode: 'one-device' })
    const { root, store } = mountFixture(context, { ...fixture, activeArea: 'utilities', discovery: { ...fixture.discovery, epoch: 1, listRevision: 1, selectionInitialized: true } })
    store.dispatch({ type: 'service/status', status: 'recovering' })
    store.dispatch({ type: 'service/ready', epoch: 2, listRevision: 1, mode: 'native', privileged: true, hardwareReady: true, hardwareVerified: false, platformCapability: { state: 'available' } })
    store.dispatch({ type: 'device/list-replaced', devices: fixture.devices, epoch: 2, listRevision: 1 })
    assert.equal(selectedArea(root), 'status')
}
test('a new service epoch selects the connected drive on Status', recoveredServiceOpensStatus)

/** @param {import('node:test').TestContext} context - Cleanup owner. @returns {void} Verifies switching drives resets the tab but reselecting the current one does not. */
function changedSelectionOpensStatus(context) {
    const fixture = createFixtureState({ mode: 'one-device' })
    const first = fixture.devices[0]
    const second = { ...first, id: 'rdx:second-drive', serial: '7810544063' }
    const { root, store } = mountFixture(context, { ...fixture, activeArea: 'utilities', devices: [first, second] })
    store.dispatch({ type: 'device/select', deviceId: first.id })
    assert.equal(selectedArea(root), 'utilities')
    store.dispatch({ type: 'device/select', deviceId: second.id })
    assert.equal(selectedArea(root), 'status')
}
test('a different selected drive starts on Status', changedSelectionOpensStatus)

/** @param {import('node:test').TestContext} context - Cleanup owner. @returns {void} Verifies refreshes and unrelated arrivals cannot interrupt the current tab. */
function unchangedSelectionKeepsCurrentTab(context) {
    const fixture = createFixtureState({ mode: 'one-device' })
    const first = fixture.devices[0]
    const { root, store } = mountFixture(context, { ...fixture, activeArea: 'utilities', discovery: { ...fixture.discovery, epoch: 1, listRevision: 1, selectionInitialized: true } })
    store.dispatch({ type: 'device/snapshot', device: { ...first, revision: first.revision + 1 }, epoch: 1, listRevision: 2 })
    store.dispatch({ type: 'device/list-replaced', devices: [...store.getState().devices, { ...first, id: 'rdx:second-drive', serial: '7810544063' }], epoch: 1, listRevision: 3 })
    store.dispatch({ type: 'device/refreshed', device: { ...store.getState().devices[0], revision: first.revision + 2 } })
    store.dispatch({ type: 'device/select', deviceId: 'rdx:missing-drive' })
    store.dispatch({ type: 'device/snapshot', device: first, epoch: 1, listRevision: 2 })
    assert.equal(selectedArea(root), 'utilities')
    assert.equal(store.getState().selectedDeviceId, first.id)
}
test('refreshes and other connected drives preserve the current management tab', unchangedSelectionKeepsCurrentTab)
