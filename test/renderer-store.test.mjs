// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createStore } from '../src/renderer/store.mjs'

/**
 * Verifies that the no-device fixture represents a ready discovery service
 * without exposing an artificial device.
 * @returns {void} Throws when the no-device fixture is inconsistent.
 */
function testNoDeviceFixtureExposesAReadyServiceAndEmptyList() {
    const state = createFixtureState({ mode: 'no-device' })

    assert.equal(state.service.status, 'ready')
    assert.deepEqual(state.devices, [])
    assert.equal(state.selectedDeviceId, null)
}

/**
 * Verifies that the one-device fixture uses the documented screenshot identity
 * only as renderer fixture data and supplies a selected immutable snapshot.
 * @returns {void} Throws when the fixture state is incomplete or mutable.
 */
function testOneDeviceFixtureSuppliesTheSelectedScreenshotDevice() {
    const state = createFixtureState({ mode: 'one-device' })

    assert.equal(state.devices[0].id, 'rdx:7810544062')
    assert.equal(state.devices[0].product, 'RDX QuikStor USB3+ External')
    assert.equal(state.selectedDeviceId, 'rdx:7810544062')
    assert.equal(Object.isFrozen(state), true)
    assert.equal(Object.isFrozen(state.devices), true)
}

/**
 * Verifies that each documented non-ready fixture state is represented by
 * serializable renderer-safe data without device paths or raw commands.
 * @returns {void} Throws when a fixture mode is absent or exposes unsafe data.
 */
function testFixtureModesExposeServiceBusyAndFailedOperationStates() {
    const unavailable = createFixtureState({ mode: 'service-unavailable' })
    const busy = createFixtureState({ mode: 'busy' })
    const failed = createFixtureState({ mode: 'operation-failed' })

    assert.equal(unavailable.service.status, 'unavailable')
    assert.equal(busy.activeOperation.status, 'started')
    assert.equal(failed.activeOperation, null)
    assert.equal(failed.lastOperation.status, 'failed')
    assert.equal(JSON.stringify({ unavailable, busy, failed }).includes('/dev/'), false)
    assert.equal(JSON.stringify({ unavailable, busy, failed }).includes('rawCdb'), false)
}

/**
 * Verifies that an active operation locks selection so a renderer event cannot
 * retarget an operation to a different device.
 * @returns {void} Throws when selection changes during an active operation.
 */
function testSelectingADeviceDuringAnOperationLeavesTheSelectionUnchanged() {
    const fixture = createFixtureState({ mode: 'one-device' })
    const otherDevice = { ...fixture.devices[0], id: 'rdx:another-device', serial: '7810544063' }
    const store = createStore({ ...fixture, devices: [fixture.devices[0], otherDevice] })

    store.dispatch({ type: 'operation/started', operationId: 'op-1', kind: 'firmware-update' })
    store.dispatch({ type: 'device/select', deviceId: 'rdx:another-device' })

    assert.equal(store.getState().activeOperation.id, 'op-1')
    assert.equal(store.getState().activeOperation.deviceRevision, 4)
    assert.equal(store.getState().selectedDeviceId, 'rdx:7810544062')
}

/**
 * Verifies that a store transition produces a new frozen state and notifies a
 * subscriber exactly once until its unsubscribe function is used.
 * @returns {void} Throws when store notification or immutability fails.
 */
function testStorePublishesFrozenTransitionSnapshotsUntilUnsubscribed() {
    const store = createStore(createFixtureState({ mode: 'one-device' }))
    const receivedStates = []
    const unsubscribe = store.subscribe(recordState)

    store.dispatch({ type: 'operation/started', operationId: 'op-1', kind: 'self-test' })
    unsubscribe()
    store.dispatch({ type: 'operation/succeeded', operationId: 'op-1' })

    assert.equal(receivedStates.length, 1)
    assert.equal(receivedStates[0].activeOperation.id, 'op-1')
    assert.equal(Object.isFrozen(receivedStates[0]), true)

    /**
     * Records a rendered state transition for behavior verification.
     * @param {object} state - New immutable store state.
     * @returns {void} Adds the state to the local test observation list.
     */
    function recordState(state) {
        receivedStates.push(state)
    }
}

/**
 * Verifies that the store rejects Date values because their mutable internal
 * slots are neither made immutable by freezing nor preserved by JSON.
 * @returns {void} Throws when a Date crosses the renderer state boundary.
 */
function testStoreRejectsDateStateValues() {
    const fixture = createFixtureState({ mode: 'one-device' })

    assert.throws(createStoreWithDate, /JSON-safe data/)

    /**
     * Attempts to pass a Date through the initial state boundary.
     * @returns {object} Never returns because the store rejects the state.
     */
    function createStoreWithDate() {
        return createStore({ ...fixture, observedAt: new Date('2026-08-25T00:00:00.000Z') })
    }
}

/**
 * Verifies that the store rejects Map values because freezing a Map leaves its
 * contents mutable and JSON serialization would lose its entries.
 * @returns {void} Throws when a Map crosses the renderer state boundary.
 */
function testStoreRejectsMapStateValues() {
    const fixture = createFixtureState({ mode: 'one-device' })

    assert.throws(createStoreWithMap, /JSON-safe data/)

    /**
     * Attempts to pass a Map through the initial state boundary.
     * @returns {object} Never returns because the store rejects the state.
     */
    function createStoreWithMap() {
        return createStore({ ...fixture, deviceLookup: new Map([['rdx:7810544062', 'selected']]) })
    }
}

/**
 * Verifies that a departed selected device cannot anchor a new operation even
 * when its opaque identifier otherwise has a valid shape.
 * @returns {void} Throws when an operation starts against stale selection.
 */
function testOperationStartRejectsAStaleSelectedDevice() {
    const fixture = createFixtureState({ mode: 'one-device' })
    const store = createStore({ ...fixture, selectedDeviceId: 'rdx:departed-device' })

    store.dispatch({ type: 'operation/started', operationId: 'op-1', kind: 'self-test' })

    assert.equal(store.getState().activeOperation, null)
    assert.equal(store.getState().selectedDeviceId, 'rdx:departed-device')
}

/**
 * Verifies a schema-valid selected-device refresh replaces only that snapshot
 * and preserves the selected identity.
 * @returns {void} Throws when refresh is ignored, stale, or mutable.
 */
function testDeviceRefreshPublishesAValidatedSnapshot() {
    const fixture = createFixtureState({ mode: 'one-device' })
    const store = createStore(fixture)

    store.dispatch({ type: 'device/refreshed', device: { ...fixture.devices[0], revision: 5 } })

    assert.equal(store.getState().devices[0].revision, 5)
    assert.equal(store.getState().selectedDeviceId, fixture.selectedDeviceId)
    assert.equal(Object.isFrozen(store.getState().devices[0]), true)
}

/**
 * Verifies device refresh rejects stale revisions and renderer-unsafe path data.
 * @returns {void} Throws when an invalid refresh crosses the store boundary.
 */
function testDeviceRefreshRejectsStaleOrUnsafeSnapshots() {
    const fixture = createFixtureState({ mode: 'one-device' })
    const store = createStore(fixture)

    store.dispatch({ type: 'device/refreshed', device: { ...fixture.devices[0], revision: 3 } })
    store.dispatch({ type: 'device/refreshed', device: { ...fixture.devices[0], revision: 5, osPath: '/dev/sg4' } })

    assert.equal(store.getState().devices[0].revision, 4)
    assert.equal(JSON.stringify(store.getState()).includes('/dev/'), false)
}

/**
 * Verifies progress updates only the matching active operation and remains
 * bounded data before a terminal event releases the lock.
 * @returns {void} Throws when operation progress is rejected or unsafe.
 */
function testOperationProgressUpdatesTheMatchingLock() {
    const store = createStore(createFixtureState({ mode: 'one-device' }))
    store.dispatch({ type: 'operation/started', operationId: 'op-progress', kind: 'firmware-update' })

    store.dispatch({ type: 'operation/progress', operationId: 'op-progress', stage: 'firmware-verifying', progress: 0.8, cancellationState: 'closed' })

    assert.equal(store.getState().activeOperation.status, 'progress')
    assert.equal(store.getState().activeOperation.stage, 'firmware-verifying')
    assert.equal(store.getState().activeOperation.progress, 0.8)
    assert.equal(store.getState().activeOperation.cancellationState, 'closed')

    const beforeInvalid = store.getState()
    store.dispatch({ type: 'operation/progress', operationId: 'op-progress', stage: 'firmware-writing', progress: 0.9, cancellationState: 'unknown' })
    assert.equal(store.getState(), beforeInvalid)
}

/**
 * Verifies Auto Scan settings remain immutable and reject changes while an
 * operation owns the application lock.
 * @returns {void} Throws when the setting is not persisted or lock-safe.
 */
function testAutoScanSettingPersistsAndRespectsOperationLock() {
    const store = createStore(createFixtureState({ mode: 'one-device' }))

    store.dispatch({ type: 'setting/auto-scan-changed', enabled: false })
    assert.equal(store.getState().settings.autoScan, false)
    store.dispatch({ type: 'operation/started', operationId: 'op-settings', kind: 'self-test' })
    store.dispatch({ type: 'setting/auto-scan-changed', enabled: true })
    assert.equal(store.getState().settings.autoScan, false)
    store.dispatch({ type: 'operation/succeeded', operationId: 'op-settings' })
    store.dispatch({ type: 'setting/auto-scan-changed', enabled: true })
    assert.equal(store.getState().settings.autoScan, true)
    assert.equal(Object.isFrozen(store.getState().settings), true)
}

test('no-device fixture exposes a ready service and empty list', testNoDeviceFixtureExposesAReadyServiceAndEmptyList)
test('one-device fixture supplies the selected screenshot device', testOneDeviceFixtureSuppliesTheSelectedScreenshotDevice)
test('fixture modes expose service, busy, and failed-operation states', testFixtureModesExposeServiceBusyAndFailedOperationStates)
test('selecting a device during an operation leaves the selection unchanged', testSelectingADeviceDuringAnOperationLeavesTheSelectionUnchanged)
test('store publishes frozen transition snapshots until unsubscribed', testStorePublishesFrozenTransitionSnapshotsUntilUnsubscribed)
test('store rejects Date state values', testStoreRejectsDateStateValues)
test('store rejects Map state values', testStoreRejectsMapStateValues)
test('operation start rejects a stale selected device', testOperationStartRejectsAStaleSelectedDevice)
test('device refresh publishes a validated selected snapshot', testDeviceRefreshPublishesAValidatedSnapshot)
test('device refresh rejects stale or unsafe snapshots', testDeviceRefreshRejectsStaleOrUnsafeSnapshots)
test('operation progress updates the matching operation lock', testOperationProgressUpdatesTheMatchingLock)
test('Auto Scan setting persists and respects the operation lock', testAutoScanSettingPersistsAndRespectsOperationLock)
