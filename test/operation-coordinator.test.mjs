// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { OperationCoordinator } from '../src/main/operation-coordinator.mjs'

const validSelfTest = Object.freeze({ kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7 })
const validEject = Object.freeze({ kind: 'eject-safe', deviceId: 'rdx:1', deviceRevision: 7 })

/**
 * Creates a coordinator with a current native/hardware-ready device baseline.
 * @param {object} options - Test-specific dependency overrides.
 * @returns {OperationCoordinator} Fail-open only for this controlled test device.
 */
function createReadyCoordinator(options) {
    /** @returns {object} Current controlled device. */
    function getDevice() {
        return { id: 'rdx:1', revision: 7, mediaState: 'present', capabilities: { 'status-refresh': { state: 'available' }, 'self-test': { state: 'available' }, 'eject-safe': { state: 'available' } } }
    }

    /** @returns {object} Available platform capability. */
    function getPlatformCapability() {
        return { state: 'available' }
    }

    /** @returns {'native'} Native service mode. */
    function getServiceMode() {
        return 'native'
    }

    /** @returns {boolean} Controlled positive gate. */
    function returnTrue() {
        return true
    }

    return new OperationCoordinator({ getDevice, getPlatformCapability, getServiceMode, hasPrivilege: returnTrue, isHardwareReady: returnTrue, ...options })
}

/**
 * Keeps a dispatch promise pending for lock-ownership tests.
 * @returns {void} Intentionally never resolves the owning promise.
 */
function keepPending() {}

/**
 * Allows coordinator dispatch continuations to publish their result.
 * @returns {Promise<void>} Resolves on the next event-loop turn.
 */
async function nextTurn() {
    await new Promise(setImmediate)
}

test('one active operation atomically rejects a second device action', async () => {
    const dispatches = []

    /**
     * Records the main-owned operation identity and stays active.
     * @param {object} operation - Coordinator-owned dispatch envelope.
     * @returns {Promise<object>} Promise that intentionally remains pending.
     */
    async function dispatch(operation) {
        dispatches.push(operation)
        return new Promise(keepPending)
    }

    const coordinator = createReadyCoordinator({ dispatch, idFactory: createOperationId })
    const accepted = await coordinator.start(validSelfTest)

    assert.deepEqual(await coordinator.start(validEject), { ok: false, reason: 'operation-in-progress' })
    assert.deepEqual(accepted, { ok: true, operationId: 'op:owned-1' })
    assert.deepEqual(dispatches, [{ operationId: 'op:owned-1', request: validSelfTest }])
    assert.deepEqual(coordinator.getActiveOperation(), {
        operationId: 'op:owned-1',
        kind: 'self-test',
        deviceId: 'rdx:1',
        deviceRevision: 7,
        generation: 0,
        stage: 'queued',
        cancellationRequested: false,
        irreversible: false
    })

    /**
     * Returns one deterministic application-owned operation identifier.
     * @returns {string} Opaque operation ID.
     */
    function createOperationId() {
        return 'op:owned-1'
    }
})

test('rejects status refresh cancellation locally after Started', async () => {
    const cancellations = []

    /** @returns {Promise<object>} Accepts the controlled status refresh. */
    async function dispatch() {
        return { ok: true }
    }

    /** @param {object} request - Unexpected cancellation request. @returns {Promise<object>} Controlled native acceptance. */
    async function cancelDispatch(request) {
        cancellations.push(request)
        return { ok: true }
    }

    /** @returns {string} Deterministic status operation identity. */
    function createOperationId() {
        return 'op:status-started'
    }

    const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, idFactory: createOperationId })
    await coordinator.start({ kind: 'status-refresh', deviceId: 'rdx:1', deviceRevision: 7 })
    await nextTurn()
    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: 'op:status-started', kind: 'status-refresh', deviceId: 'rdx:1', deviceRevision: 7, stage: 'status-reading' }), true)

    assert.deepEqual(await coordinator.cancel({ operationId: 'op:status-started' }), { ok: false, reason: 'operation-not-cancellable' })
    assert.deepEqual(cancellations, [])
})

test('ignores mismatched service events and releases only the exact terminal owner', async () => {
    const events = []

    /**
     * Accepts the controlled dispatch while service events drive completion.
     * @returns {Promise<object>} Accepted service response.
     */
    async function dispatch() {
        return { ok: true }
    }

    const coordinator = createReadyCoordinator({ dispatch, idFactory: createOperationId })
    coordinator.subscribe(recordEvent)
    await coordinator.start(validSelfTest)
    await nextTurn()

    assert.equal(coordinator.handleServiceEvent({ state: 'succeeded', operationId: 'op:owned-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 8, stage: 'complete' }), false)
    assert.notEqual(coordinator.getActiveOperation(), null)
    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: 'op:owned-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:owned-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running', progress: 0.5, cancellationState: 'cancellable' }), true)
    assert.equal(coordinator.getActiveOperation().stage, 'diagnostic-running')
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:owned-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup', progress: 0.9, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'succeeded', operationId: 'op:owned-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'complete' }), true)
    assert.equal(coordinator.getActiveOperation(), null)
    assert.deepEqual(
        events.map((event) => event.state),
        ['queued', 'started', 'progress', 'progress', 'succeeded']
    )

    /**
     * Returns the deterministic operation identifier.
     * @returns {string} Opaque operation ID.
     */
    function createOperationId() {
        return 'op:owned-1'
    }

    /**
     * Records one validated operation lifecycle event.
     * @param {object} event - Renderer-safe operation event.
     * @returns {void} Completes after recording.
     */
    function recordEvent(event) {
        events.push(event)
    }
})

test('enforces cancellation against the exact operation and current main-owned stage', async () => {
    const cancellations = []

    /**
     * Accepts the operation while controlled service events update its stage.
     * @returns {Promise<object>} Accepted service response.
     */
    async function dispatch() {
        return { ok: true }
    }

    /**
     * Records a cancellation that passed coordinator stage enforcement.
     * @param {object} request - Exact cancellation dispatch.
     * @returns {Promise<object>} Accepted cancellation response.
     */
    async function cancelDispatch(request) {
        cancellations.push(request)
        return { ok: true }
    }

    const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, idFactory: createOperationId })
    await coordinator.start(validSelfTest)
    await nextTurn()
    coordinator.handleServiceEvent({ state: 'started', operationId: 'op:cancel-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running' })
    coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:cancel-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup', progress: 0.9, cancellationState: 'closed' })

    assert.deepEqual(await coordinator.cancel({ operationId: 'op:other' }), { ok: false, reason: 'operation-not-found' })
    assert.deepEqual(await coordinator.cancel({ operationId: 'op:cancel-1' }), { ok: false, reason: 'operation-not-cancellable' })
    assert.deepEqual(cancellations, [])

    coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:cancel-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running', progress: 0.5, cancellationState: 'cancellable' })
    assert.deepEqual(await coordinator.cancel({ operationId: 'op:cancel-1' }), { ok: false, reason: 'operation-not-cancellable' })
    assert.deepEqual(cancellations, [])

    /**
     * Returns the deterministic cancellation-test operation identifier.
     * @returns {string} Opaque operation ID.
     */
    function createOperationId() {
        return 'op:cancel-1'
    }
})

test('allows cancellation while the operation remains in an explicitly cancellable stage', async () => {
    const cancellations = []

    /** @returns {Promise<object>} Accepted service dispatch. */
    async function dispatch() {
        return { ok: true }
    }

    /**
     * Records the exact permitted cancellation.
     * @param {object} request - Owned cancellation request.
     * @returns {Promise<object>} Accepted cancellation.
     */
    async function cancelDispatch(request) {
        cancellations.push(request)
        return { ok: true }
    }

    /** @returns {string} Deterministic operation identity. */
    function createOperationId() {
        return 'op:cancellable-1'
    }

    const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, idFactory: createOperationId })
    await coordinator.start(validSelfTest)
    await nextTurn()
    coordinator.handleServiceEvent({ state: 'started', operationId: 'op:cancellable-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running' })
    coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:cancellable-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running', progress: 0.5, cancellationState: 'cancellable' })

    assert.deepEqual(await coordinator.cancel({ operationId: 'op:cancellable-1' }), { ok: true })
    assert.deepEqual(cancellations, [{ operationId: 'op:cancellable-1' }])
    assert.notEqual(coordinator.getActiveOperation(), null)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:cancellable-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup', progress: 0.9, cancellationState: 'closed' }), false)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:cancellable-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup', progress: 0.9, cancellationState: 'requested' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'cancelled', operationId: 'op:cancellable-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup' }), true)
    assert.equal(coordinator.getActiveOperation(), null)
})

test('progress cancellation state must match coordinator ownership and lifecycle stage', async () => {
    /** @returns {Promise<object>} Accepts the controlled operation. */
    async function dispatch() {
        return { ok: true }
    }

    /** @returns {string} Deterministic operation identity. */
    function createOperationId() {
        return 'op:cancellation-state'
    }

    const coordinator = createReadyCoordinator({ dispatch, idFactory: createOperationId })
    await coordinator.start(validSelfTest)
    await nextTurn()
    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: 'op:cancellation-state', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:cancellation-state', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running', progress: 0.2, cancellationState: 'closed' }), false)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:cancellation-state', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running', progress: 0.2, cancellationState: 'cancellable' }), true)
    assert.equal(coordinator.getActiveOperation().cancellationState, 'cancellable')
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:cancellation-state', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'cancellable' }), false)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:cancellation-state', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'closed' }), true)
    assert.equal(coordinator.getActiveOperation().cancellationState, 'closed')
})

test('safe eject may close cancellation at host-unmounting immediately before dispatch', async () => {
    /** @returns {Promise<object>} Accepts the controlled safe-eject operation. */
    async function dispatch() {
        return { ok: true }
    }

    /** @returns {string} Deterministic operation identity. */
    function createOperationId() {
        return 'op:eject-close-boundary'
    }

    const coordinator = createReadyCoordinator({ dispatch, idFactory: createOperationId })
    await coordinator.start(validEject)
    await nextTurn()

    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: 'op:eject-close-boundary', kind: 'eject-safe', deviceId: 'rdx:1', deviceRevision: 7, stage: 'host-unmounting' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:eject-close-boundary', kind: 'eject-safe', deviceId: 'rdx:1', deviceRevision: 7, stage: 'host-unmounting', progress: 0, cancellationState: 'closed' }), true)
    assert.equal(coordinator.getActiveOperation().cancellationState, 'closed')
})

test('does not let a stale cancellation response mutate a newer lock owner', async () => {
    const cancellationResolvers = []
    let nextOperation = 0

    /** @returns {Promise<object>} Accepted service dispatch. */
    async function dispatch() {
        return { ok: true }
    }

    /**
     * Holds each cancellation response so ownership can change between replies.
     * @returns {Promise<object>} Controlled cancellation result.
     */
    async function cancelDispatch() {
        /**
         * Captures one cancellation resolver in dispatch order.
         * @param {(response: object) => void} resolveCancellation - Result resolver.
         * @returns {void} Completes after capture.
         */
        function captureCancellation(resolveCancellation) {
            cancellationResolvers.push(resolveCancellation)
        }
        return new Promise(captureCancellation)
    }

    /** @returns {string} Next deterministic operation identity. */
    function createOperationId() {
        nextOperation += 1
        return `op:race-${nextOperation}`
    }

    const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, idFactory: createOperationId })
    await coordinator.start(validSelfTest)
    await nextTurn()
    const staleCancellation = coordinator.cancel({ operationId: 'op:race-1' })
    coordinator.failActiveOperation('service-unavailable')

    await coordinator.start(validSelfTest)
    await nextTurn()
    const currentCancellation = coordinator.cancel({ operationId: 'op:race-2' })
    assert.equal(coordinator.getActiveOperation().cancellationRequested, true)

    cancellationResolvers[0]({ ok: false, reason: 'transport-unavailable' })
    assert.deepEqual(await staleCancellation, { ok: false, reason: 'transport-unavailable' })
    assert.equal(coordinator.getActiveOperation().cancellationRequested, true)

    cancellationResolvers[1]({ ok: true })
    assert.deepEqual(await currentCancellation, { ok: true })
})

test('maps rejected dispatch and service loss to structured terminal failures', async () => {
    const rejectedEvents = []

    /**
     * Simulates a safe service rejection without throwing raw details.
     * @returns {Promise<object>} Stable rejected action result.
     */
    async function rejectDispatch() {
        return { ok: false, reason: 'transport-unavailable' }
    }

    const rejected = createReadyCoordinator({ dispatch: rejectDispatch, idFactory: createRejectedId })
    rejected.subscribe(recordRejectedEvent)
    await rejected.start(validSelfTest)
    await nextTurn()

    assert.equal(rejected.getActiveOperation(), null)
    assert.equal(rejectedEvents.at(-1).state, 'failed')
    assert.equal(rejectedEvents.at(-1).error.code, 'transport-unavailable')
    assert.equal(JSON.stringify(rejectedEvents).includes('stack'), false)

    const lostEvents = []

    /**
     * Keeps the second operation active until service loss is reported.
     * @returns {Promise<object>} Promise that intentionally stays pending.
     */
    async function pendingDispatch() {
        return new Promise(keepPending)
    }

    const lost = createReadyCoordinator({ dispatch: pendingDispatch, idFactory: createLostId })
    lost.subscribe(recordLostEvent)
    await lost.start(validSelfTest)
    assert.equal(lost.failActiveOperation('service-unavailable'), true)
    assert.equal(lost.getActiveOperation(), null)
    assert.equal(lostEvents.at(-1).error.code, 'service-unavailable')

    /** @returns {string} Deterministic rejected-operation ID. */
    function createRejectedId() {
        return 'op:rejected-1'
    }

    /** @returns {string} Deterministic service-loss operation ID. */
    function createLostId() {
        return 'op:lost-1'
    }

    /**
     * Records rejected-dispatch lifecycle events.
     * @param {object} event - Structured operation event.
     * @returns {void} Completes after recording.
     */
    function recordRejectedEvent(event) {
        rejectedEvents.push(event)
    }

    /**
     * Records service-loss lifecycle events.
     * @param {object} event - Structured operation event.
     * @returns {void} Completes after recording.
     */
    function recordLostEvent(event) {
        lostEvents.push(event)
    }
})

test('builds safety context from the current device revision and lock owner', async () => {
    /**
     * Keeps the controlled operation active.
     * @returns {Promise<object>} Promise that intentionally stays pending.
     */
    async function dispatch() {
        return new Promise(keepPending)
    }

    /**
     * Resolves only the current service-owned device snapshot.
     * @param {string} deviceId - Opaque requested device identity.
     * @returns {object|null} Matching device or null.
     */
    function getDevice(deviceId) {
        return deviceId === 'rdx:1'
            ? {
                  id: 'rdx:1',
                  revision: 7,
                  mediaState: 'present',
                  capabilities: { 'self-test': { state: 'available' } }
              }
            : null
    }

    const coordinator = createReadyCoordinator({
        dispatch,
        getDevice,
        getPlatformCapability: getAvailablePlatformCapability,
        hasPrivilege: hasPrivilege,
        idFactory: createOperationId,
        validateConfirmation: rejectConfirmation
    })
    await coordinator.start(validSelfTest)
    const context = await coordinator.getContext(validSelfTest)

    assert.equal(context.device.id, 'rdx:1')
    assert.equal(context.device.revision, 7)
    assert.equal(context.activeOperation.id, 'op:context-1')
    assert.deepEqual(context.platformCapability, { state: 'available' })
    assert.equal(context.hasPrivilege, true)
    assert.equal(context.confirmationTokenValid, false)

    /** @returns {object} Current platform capability. */
    function getAvailablePlatformCapability() {
        return { state: 'available' }
    }

    /** @returns {boolean} Controlled privilege state. */
    function hasPrivilege() {
        return true
    }

    /** @returns {string} Deterministic context-test operation ID. */
    function createOperationId() {
        return 'op:context-1'
    }

    /** @returns {boolean} Controlled confirmation resolution. */
    function rejectConfirmation() {
        return false
    }
})

test('revalidates device revision and hardware readiness inside synchronous admission', async () => {
    let dispatchCount = 0

    /** @returns {Promise<object>} Records an incorrectly admitted operation. */
    async function dispatch() {
        dispatchCount += 1
        return { ok: true }
    }

    /** @returns {object} Current device revision owned by discovery. */
    function getDevice() {
        return { id: 'rdx:1', revision: 8, mediaState: 'present', capabilities: { 'self-test': { state: 'available' } } }
    }

    const stale = new OperationCoordinator({ dispatch, getDevice, getPlatformCapability: getAvailablePlatform, hasPrivilege: allowPrivilege, isHardwareReady: allowHardware, getServiceMode: getNativeMode })
    assert.deepEqual(await stale.start(validSelfTest), { ok: false, reason: 'stale-device-revision' })
    assert.equal(dispatchCount, 0)
    assert.equal(stale.getActiveOperation(), null)

    const noHardware = new OperationCoordinator({ dispatch, getDevice: getRevisionSevenDevice, getPlatformCapability: getAvailablePlatform, hasPrivilege: allowPrivilege, isHardwareReady: rejectHardware, getServiceMode: getNoDeviceMode })
    assert.deepEqual(await noHardware.start(validSelfTest), { ok: false, reason: 'hardware-unavailable' })
    assert.equal(dispatchCount, 0)

    /** @returns {object} Available platform capability. */
    function getAvailablePlatform() {
        return { state: 'available' }
    }

    /** @returns {boolean} Controlled privilege approval. */
    function allowPrivilege() {
        return true
    }

    /** @returns {boolean} Controlled native hardware readiness. */
    function allowHardware() {
        return true
    }

    /** @returns {boolean} Controlled unavailable hardware readiness. */
    function rejectHardware() {
        return false
    }

    /** @returns {'native'} Controlled native service mode. */
    function getNativeMode() {
        return 'native'
    }

    /** @returns {'no-device'} Controlled no-device service mode. */
    function getNoDeviceMode() {
        return 'no-device'
    }

    /** @returns {object} Matching current device revision. */
    function getRevisionSevenDevice() {
        return { id: 'rdx:1', revision: 7, mediaState: 'present', capabilities: { 'self-test': { state: 'available' } } }
    }
})

test('keeps the scan reservation until acknowledgement before admitting a waiting operation', async () => {
    let resolveScan

    /** @returns {Promise<object>} Keeps the scan acknowledgement pending. */
    async function scanDispatch() {
        /**
         * Captures the controlled scan result resolver.
         * @param {(response: object) => void} resolveResponse - Scan response resolver.
         * @returns {void} Completes after capture.
         */
        function captureResolver(resolveResponse) {
            resolveScan = resolveResponse
        }
        return new Promise(captureResolver)
    }

    /** @returns {Promise<object>} Keeps operation dispatch pending. */
    async function dispatch() {
        return new Promise(keepPending)
    }

    const coordinator = createReadyCoordinator({ dispatch, scanDispatch })
    const scan = coordinator.scan({ kind: 'scan' })

    assert.equal(coordinator.getActiveOperation().kind, 'scan')
    const operation = coordinator.start(validSelfTest)
    assert.equal(coordinator.getActiveOperation().kind, 'scan')
    resolveScan({ ok: true })
    assert.deepEqual(await scan, { ok: true })
    assert.equal((await operation).ok, true)
    assert.equal(coordinator.getActiveOperation().kind, 'self-test')
})

test('keeps an ambiguous operation-start outcome reserved until exact generation loss', async () => {
    /** @returns {Promise<object>} Returns the controlled ambiguous dispatch result. */
    async function dispatch() {
        return { ok: false, reason: 'operation-outcome-unknown', ambiguous: true }
    }

    /** @returns {number} Current service generation. */
    function getGeneration() {
        return 12
    }

    const coordinator = createReadyCoordinator({ dispatch, getGeneration, idFactory: createOperationId })
    await coordinator.start(validSelfTest)
    await nextTurn()

    assert.equal(coordinator.getActiveOperation().stage, 'outcome-unknown')
    assert.deepEqual(await coordinator.start(validEject), { ok: false, reason: 'operation-in-progress' })
    assert.equal(coordinator.handleGenerationLoss(11, 'service-exited'), false)
    assert.notEqual(coordinator.getActiveOperation(), null)
    assert.equal(coordinator.handleGenerationLoss(12, 'service-exited'), true)
    assert.equal(coordinator.getActiveOperation(), null)

    /** @returns {string} Deterministic ambiguous operation ID. */
    function createOperationId() {
        return 'op:ambiguous-1'
    }
})

test('releases an ambiguous start only for a correlated terminal acknowledgement', async () => {
    /** @returns {Promise<object>} Returns a controlled ambiguous start. */
    async function dispatch() {
        return { ok: false, reason: 'operation-outcome-unknown', ambiguous: true }
    }
    const coordinator = createReadyCoordinator({ dispatch, idFactory: () => 'op:ambiguous-terminal' })
    await coordinator.start(validSelfTest)
    await nextTurn()

    assert.equal(
        coordinator.handleServiceEvent({
            state: 'failed',
            operationId: 'op:ambiguous-terminal',
            kind: 'self-test',
            deviceId: 'rdx:1',
            deviceRevision: 7,
            stage: 'queued',
            error: { code: 'transport-timeout', messageKey: 'errors.transport.timeout', stage: 'queued', category: 'transport', retryable: true, supportCorrelationId: 'support:ambiguous-terminal', cleanupEvidence: [], attemptHistory: [] }
        }),
        true
    )
    assert.equal(coordinator.getActiveOperation(), null)
})

test('keeps an irreversible failure reserved until the operation recovery barrier', async () => {
    const request = { kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, firmwareFileToken: 'firmware:test' }
    /** @returns {Promise<object>} Accepts controlled firmware dispatch. */
    async function dispatch() {
        return { ok: true }
    }
    /** @returns {object} Firmware-capable current device. */
    function getDevice() {
        return { id: 'rdx:1', revision: 7, mediaState: 'no-media', capabilities: { 'firmware-update': { state: 'available' } } }
    }
    const coordinator = createReadyCoordinator({ dispatch, getDevice, idFactory: () => 'op:firmware-barrier' })
    await coordinator.start(request)
    await nextTurn()
    coordinator.handleServiceEvent({ state: 'started', operationId: 'op:firmware-barrier', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'firmware-validating' })
    coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:firmware-barrier', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'firmware-writing', progress: 0.5, cancellationState: 'closed' })
    const writingFailure = { state: 'failed', operationId: 'op:firmware-barrier', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'firmware-writing', error: { code: 'transport-timeout', messageKey: 'errors.transport.timeout', stage: 'firmware-writing', category: 'transport', retryable: true, supportCorrelationId: 'support:firmware-barrier', cleanupEvidence: [], attemptHistory: [] } }

    assert.equal(coordinator.handleServiceEvent(writingFailure), false)
    assert.equal(coordinator.getShutdownPolicy().allowed, false)
    coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:firmware-barrier', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'firmware-finalizing', progress: 0.8, cancellationState: 'closed' })
    coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:firmware-barrier', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'device-reconnecting', progress: 0.9, cancellationState: 'closed' })
    assert.equal(coordinator.handleServiceEvent({ ...writingFailure, stage: 'device-reconnecting' }), false)
    coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:firmware-barrier', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'firmware-readback', progress: 1, cancellationState: 'closed' })
    assert.equal(coordinator.handleServiceEvent({ ...writingFailure, stage: 'firmware-readback' }), true)
    assert.equal(coordinator.getActiveOperation(), null)
})

test('enforces operation stage graph, monotonic progress, and terminal prerequisites', async () => {
    /** @returns {Promise<object>} Accepts the controlled operation. */
    async function dispatch() {
        return { ok: true }
    }

    /** @returns {string} Deterministic graph-test operation ID. */
    function createOperationId() {
        return 'op:graph-1'
    }

    const coordinator = createReadyCoordinator({ dispatch, idFactory: createOperationId })
    await coordinator.start(validSelfTest)
    await nextTurn()

    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:graph-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running', progress: 0.2, cancellationState: 'cancellable' }), false)
    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: 'op:graph-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:graph-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running', progress: 0.7, cancellationState: 'cancellable' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:graph-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running', progress: 0.6, cancellationState: 'cancellable' }), false)
    assert.equal(coordinator.handleServiceEvent({ state: 'succeeded', operationId: 'op:graph-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'complete' }), false)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:graph-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup', progress: 0.9, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'succeeded', operationId: 'op:graph-1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'complete' }), true)
    assert.equal(coordinator.getActiveOperation(), null)
})

test('treats cancel response as acceptance and releases only after a safe correlated terminal', async () => {
    const events = []

    /** @returns {Promise<object>} Leaves operation start outcome ambiguous. */
    async function dispatch() {
        return { ok: false, reason: 'operation-outcome-unknown', ambiguous: true }
    }

    /** @returns {Promise<object>} Acknowledges exact cancellation. */
    async function cancelDispatch() {
        return { ok: true }
    }

    /** @returns {string} Deterministic cancellation operation ID. */
    function createOperationId() {
        return 'op:cancel-ambiguous'
    }

    /** @param {object} event - Coordinator event. @returns {void} Records the event. */
    function recordEvent(event) {
        events.push(event)
    }

    const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, idFactory: createOperationId })
    coordinator.subscribe(recordEvent)
    await coordinator.start(validSelfTest)
    await nextTurn()

    assert.deepEqual(await coordinator.cancel({ operationId: 'op:cancel-ambiguous' }), { ok: true })
    assert.notEqual(coordinator.getActiveOperation(), null)
    assert.equal(events.at(-1).state, 'queued')
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:cancel-ambiguous', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'requested' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'cancelled', operationId: 'op:cancel-ambiguous', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup' }), true)
    assert.equal(coordinator.getActiveOperation(), null)
    assert.equal(events.at(-1).state, 'cancelled')
})

test('buffers graph-valid cleanup and terminal events until the cancellation acknowledgement succeeds', async () => {
    const events = []
    let resolveCancellation

    /** @returns {Promise<object>} Accepts controlled operation dispatch. */
    async function dispatch() {
        return { ok: true }
    }

    /** @returns {Promise<object>} Holds the cancellation acknowledgement. */
    function cancelDispatch() {
        /** @param {(response: object) => void} resolve - Controlled acknowledgement resolver. @returns {void} Captures the resolver. */
        function captureCancellation(resolve) {
            resolveCancellation = resolve
        }
        return new Promise(captureCancellation)
    }

    /** @param {object} event - Accepted coordinator event. @returns {void} Records publication order. */
    function recordEvent(event) {
        events.push(event)
    }

    const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, idFactory: () => 'op:cancel-order' })
    coordinator.subscribe(recordEvent)
    await coordinator.start(validSelfTest)
    await nextTurn()
    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: 'op:cancel-order', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running' }), true)

    const cancellation = coordinator.cancel({ operationId: 'op:cancel-order' })
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:cancel-order', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'requested' }), true)
    const terminalOutcome = coordinator.handleServiceEvent({ state: 'cancelled', operationId: 'op:cancel-order', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup' })
    assert.equal(typeof terminalOutcome?.then, 'function')
    assert.equal(coordinator.getActiveOperation().stage, 'diagnostic-running')
    assert.equal(events.at(-1).state, 'started')

    resolveCancellation({ ok: true })
    assert.deepEqual(await cancellation, { ok: true })
    assert.equal(await terminalOutcome, true)
    assert.equal(coordinator.getActiveOperation(), null)
    assert.deepEqual(
        events.map((event) => event.state),
        ['queued', 'started', 'progress', 'cancelled']
    )
})

test('buffers graph-valid success and failure terminals behind a pending cancel acknowledgement', async () => {
    const terminalEvents = [
        { state: 'succeeded', operationId: 'op:cancel-success', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'complete' },
        {
            state: 'failed',
            operationId: 'op:cancel-failure',
            kind: 'self-test',
            deviceId: 'rdx:1',
            deviceRevision: 7,
            stage: 'diagnostic-cleanup',
            error: { code: 'cleanup-failed', messageKey: 'errors.service.failure', stage: 'diagnostic-cleanup', category: 'transport', retryable: false, supportCorrelationId: 'support:cancel-failure', cleanupEvidence: [], attemptHistory: [] }
        }
    ]
    for (const terminalEvent of terminalEvents) {
        const operationId = terminalEvent.operationId
        let resolveCancellation

        /** @returns {Promise<object>} Accepts controlled operation dispatch. */
        async function dispatch() {
            return { ok: true }
        }

        /** @returns {Promise<object>} Holds the exact cancellation acknowledgement. */
        function cancelDispatch() {
            /** @param {(response: object) => void} resolve - Controlled acknowledgement resolver. @returns {void} Captures the resolver. */
            function captureCancellation(resolve) {
                resolveCancellation = resolve
            }
            return new Promise(captureCancellation)
        }

        const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, idFactory: () => operationId })
        await coordinator.start(validSelfTest)
        await nextTurn()
        coordinator.handleServiceEvent({ state: 'started', operationId, kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running' })

        const cancellation = coordinator.cancel({ operationId })
        assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId, kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'requested' }), true)
        const terminalOutcome = coordinator.handleServiceEvent(terminalEvent)
        assert.equal(typeof terminalOutcome?.then, 'function', terminalEvent.state)
        assert.equal(coordinator.getActiveOperation().stage, 'diagnostic-running', terminalEvent.state)

        resolveCancellation({ ok: true })
        assert.deepEqual(await cancellation, { ok: true })
        assert.equal(await terminalOutcome, true, terminalEvent.state)
        assert.equal(coordinator.getActiveOperation(), null, terminalEvent.state)
    }
})

test('faults the generation and rejects a held cancelled terminal after a failed acknowledgement', async () => {
    const events = []
    const faults = []
    let resolveCancellation

    /** @returns {Promise<object>} Accepts controlled operation dispatch. */
    async function dispatch() {
        return { ok: true }
    }

    /** @returns {Promise<object>} Holds the cancellation acknowledgement. */
    function cancelDispatch() {
        /** @param {(response: object) => void} resolve - Controlled acknowledgement resolver. @returns {void} Captures the resolver. */
        function captureCancellation(resolve) {
            resolveCancellation = resolve
        }
        return new Promise(captureCancellation)
    }

    /** @param {object} event - Accepted coordinator event. @returns {void} Records publication order. */
    function recordEvent(event) {
        events.push(event)
    }

    /** @param {number} generation - Exact generation requiring containment. @returns {boolean} Records it. */
    function faultGeneration(generation) {
        faults.push(generation)
        return true
    }

    const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, faultGeneration, getGeneration: () => 23, idFactory: () => 'op:cancel-rejected' })
    coordinator.subscribe(recordEvent)
    await coordinator.start(validSelfTest)
    await nextTurn()
    coordinator.handleServiceEvent({ state: 'started', operationId: 'op:cancel-rejected', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running' })

    const cancellation = coordinator.cancel({ operationId: 'op:cancel-rejected' })
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:cancel-rejected', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'closed' }), true)
    const terminalOutcome = coordinator.handleServiceEvent({ state: 'cancelled', operationId: 'op:cancel-rejected', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup' })
    assert.equal(typeof terminalOutcome?.then, 'function')

    resolveCancellation({ ok: false, reason: 'transport-unavailable' })
    assert.deepEqual(await cancellation, { ok: false, reason: 'transport-unavailable' })
    assert.equal(await terminalOutcome, false)
    assert.deepEqual(faults, [23])
    assert.equal(coordinator.getActiveOperation().stage, 'diagnostic-running')
    assert.equal(coordinator.getActiveOperation().cancellationRequested, true)
    assert.equal(events.at(-1).state, 'started')
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:cancel-rejected', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'closed' }), false)
    assert.equal(coordinator.handleGenerationLoss(23, 'service-exited', false), true)
    assert.equal(coordinator.getActiveOperation(), null)
})

test('rejects a late cancelled terminal when native declines cancellation after the window closes', async () => {
    const request = { kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, firmwareFileToken: 'firmware:test' }
    /** @returns {Promise<object>} Accepts controlled firmware dispatch. */
    async function dispatch() {
        return { ok: true }
    }
    /** @returns {Promise<object>} Reports that the service cancellation window already closed. */
    async function cancelDispatch() {
        return { ok: false, reason: 'operation-not-cancellable' }
    }
    /** @returns {object} Firmware-capable current device. */
    function getDevice() {
        return { id: 'rdx:1', revision: 7, mediaState: 'no-media', capabilities: { 'firmware-update': { state: 'available' } } }
    }
    const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, getDevice, idFactory: () => 'op:late-cancel' })
    await coordinator.start(request)
    await nextTurn()
    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: 'op:late-cancel', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'firmware-validating' }), true)
    assert.deepEqual(await coordinator.cancel({ operationId: 'op:late-cancel' }), { ok: false, reason: 'operation-not-cancellable' })
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:late-cancel', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'firmware-writing', progress: 0.2, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'cancelled', operationId: 'op:late-cancel', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'firmware-validating' }), false)
    assert.notEqual(coordinator.getActiveOperation(), null)
})

test('requires LED restore and readback before cancellation or failure can release ownership', async () => {
    const request = { kind: 'led-test', deviceId: 'rdx:1', deviceRevision: 7 }
    /** @returns {Promise<object>} Accepts controlled LED dispatch. */
    async function dispatch() {
        return { ok: true }
    }
    /** @returns {Promise<object>} Accepts controlled cancellation. */
    async function cancelDispatch() {
        return { ok: true }
    }
    /** @returns {object} LED-capable current device. */
    function getDevice() {
        return { id: 'rdx:1', revision: 7, mediaState: 'no-media', capabilities: { 'led-test': { state: 'available' } } }
    }
    const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, getDevice, idFactory: () => 'op:led-restore' })
    await coordinator.start(request)
    await nextTurn()
    coordinator.handleServiceEvent({ state: 'started', operationId: 'op:led-restore', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'led-testing' })
    await coordinator.cancel({ operationId: 'op:led-restore' })

    assert.equal(coordinator.handleServiceEvent({ state: 'cancelled', operationId: 'op:led-restore', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'led-testing' }), false)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:led-restore', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'led-readback', progress: 1, cancellationState: 'requested' }), false)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:led-restore', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'led-restoring', progress: 0.7, cancellationState: 'requested' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:led-restore', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'led-readback', progress: 1, cancellationState: 'requested' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'cancelled', operationId: 'op:led-restore', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'led-readback' }), true)
    assert.equal(coordinator.getActiveOperation(), null)
})

test('requires every firmware recovery stage in order after cancelling an ambiguous start', async () => {
    const request = { kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, firmwareFileToken: 'firmware:test' }

    /** @returns {Promise<object>} Leaves the exact firmware start outcome ambiguous. */
    async function dispatch() {
        return { ok: false, reason: 'operation-outcome-unknown', ambiguous: true }
    }

    /** @returns {Promise<object>} Accepts controlled ambiguous recovery cancellation. */
    async function cancelDispatch() {
        return { ok: true }
    }

    /** @returns {object} Current firmware-capable device. */
    function getDevice() {
        return { id: 'rdx:1', revision: 7, mediaState: 'no-media', capabilities: { 'firmware-update': { state: 'available' } } }
    }

    const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, getDevice, idFactory: () => 'op:firmware-recovery' })
    await coordinator.start(request)
    await nextTurn()
    assert.deepEqual(await coordinator.cancel({ operationId: 'op:firmware-recovery' }), { ok: true })

    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:firmware-recovery', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'firmware-readback', progress: 1, cancellationState: 'requested' }), false)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:firmware-recovery', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'firmware-finalizing', progress: 0.7, cancellationState: 'requested' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:firmware-recovery', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'firmware-readback', progress: 1, cancellationState: 'requested' }), false)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:firmware-recovery', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'device-reconnecting', progress: 0.9, cancellationState: 'requested' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:firmware-recovery', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'firmware-readback', progress: 1, cancellationState: 'requested' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'cancelled', operationId: 'op:firmware-recovery', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'firmware-readback' }), true)
    assert.equal(coordinator.getActiveOperation(), null)
})

test('rejects device configuration recovery skips before safe readback', async () => {
    const request = { kind: 'drive-mode-set', deviceId: 'rdx:1', deviceRevision: 7, mode: 'fixed' }

    /** @returns {Promise<object>} Accepts controlled configuration dispatch. */
    async function dispatch() {
        return { ok: true }
    }

    /** @returns {object} Current drive-mode-capable device. */
    function getDevice() {
        return { id: 'rdx:1', revision: 7, mediaState: 'no-media', capabilities: { 'drive-mode-set': { state: 'available' } } }
    }

    const coordinator = createReadyCoordinator({ dispatch, getDevice, idFactory: () => 'op:config-recovery' })
    await coordinator.start(request)
    await nextTurn()
    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: 'op:config-recovery', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'device-configuring' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:config-recovery', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'device-readback', progress: 1, cancellationState: 'closed' }), false)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:config-recovery', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'device-reconnecting', progress: 0.8, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:config-recovery', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'device-readback', progress: 1, cancellationState: 'closed' }), true)
})

test('reports shutdown unsafe while any exact operation or scan reservation exists', async () => {
    /** @returns {Promise<object>} Keeps operation dispatch pending. */
    async function dispatch() {
        return new Promise(keepPending)
    }

    const coordinator = createReadyCoordinator({ dispatch })
    assert.deepEqual(coordinator.getShutdownPolicy(), { allowed: true })
    await coordinator.start(validSelfTest)
    assert.deepEqual(coordinator.getShutdownPolicy(), { allowed: false, reason: 'operation-in-progress' })
})
