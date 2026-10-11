// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { OperationCoordinator } from '../src/main/operation-coordinator.mjs'

const SELF_TEST_REQUEST = Object.freeze({ kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7 })

/**
 * Creates a manually settled promise for acknowledgement-ordering tests.
 * @returns {{promise: Promise<object>, reject: (error: Error) => void, resolve: (response: object) => void}} Deferred response.
 */
function createDeferredResponse() {
    let resolve
    let reject
    const promise = new Promise((resolveResponse, rejectResponse) => {
        resolve = resolveResponse
        reject = rejectResponse
    })
    return { promise, reject, resolve }
}

/**
 * Allows detached coordinator acknowledgement continuations to settle.
 * @returns {Promise<void>} Resolves on the next event-loop turn.
 */
async function nextTurn() {
    await new Promise(setImmediate)
}

/**
 * Creates a native-ready coordinator for the controlled self-test device.
 * @param {object} options - Test-specific coordinator dependencies.
 * @returns {OperationCoordinator} Coordinator with all safety gates open.
 */
function createReadyCoordinator(options) {
    /** @returns {object} Current controlled self-test device. */
    function getDevice() {
        return { id: 'rdx:1', revision: 7, mediaState: 'present', capabilities: { 'self-test': { state: 'available' } } }
    }

    /** @returns {object} Available native platform capability. */
    function getPlatformCapability() {
        return { state: 'available' }
    }

    /** @returns {'native'} Native service mode. */
    function getServiceMode() {
        return 'native'
    }

    /** @returns {boolean} Controlled positive safety gate. */
    function returnTrue() {
        return true
    }

    return new OperationCoordinator({ getDevice, getPlatformCapability, getServiceMode, hasPrivilege: returnTrue, isHardwareReady: returnTrue, ...options })
}

/**
 * Builds one strict self-test event for the controlled operation.
 * @param {string} operationId - Exact operation identity.
 * @param {'started'|'progress'|'succeeded'|'cancelled'} state - Lifecycle state.
 * @param {string} stage - Policy-owned lifecycle stage.
 * @param {number} [progress] - Optional bounded progress value.
 * @param {'cancellable'|'requested'|'closed'} [cancellationState] - Optional exact progress cancellation state.
 * @returns {object} Strict service event.
 */
function operationEvent(operationId, state, stage, progress, cancellationState) {
    return {
        state,
        operationId,
        kind: 'self-test',
        deviceId: 'rdx:1',
        deviceRevision: 7,
        stage,
        ...(progress === undefined ? {} : { progress, cancellationState: cancellationState ?? (stage === 'diagnostic-running' ? 'cancellable' : 'closed') })
    }
}

/**
 * Builds one strict queued failure for the controlled operation.
 * @param {string} operationId - Exact operation identity.
 * @returns {object} Strict renderer-safe service failure.
 */
function queuedFailureEvent(operationId) {
    return {
        state: 'failed',
        operationId,
        kind: 'self-test',
        deviceId: 'rdx:1',
        deviceRevision: 7,
        stage: 'queued',
        error: {
            code: 'operation-rejected',
            messageKey: 'errors.service.failure',
            stage: 'queued',
            category: 'transport',
            retryable: false,
            supportCorrelationId: `support:${operationId.slice(3)}`,
            cleanupEvidence: [],
            attemptHistory: []
        }
    }
}

test('defers an event-advanced success until a delayed positive start acknowledgement', async () => {
    const acknowledgement = createDeferredResponse()
    const events = []

    /** @returns {Promise<object>} Holds the operation-start acknowledgement. */
    function dispatch() {
        return acknowledgement.promise
    }

    const coordinator = createReadyCoordinator({ dispatch, getGeneration: () => 31, idFactory: () => 'op:start-positive' })
    coordinator.subscribe((event) => events.push(event))
    await coordinator.start(SELF_TEST_REQUEST)
    assert.equal(coordinator.handleServiceEvent(operationEvent('op:start-positive', 'started', 'diagnostic-running')), true)
    assert.equal(coordinator.handleServiceEvent(operationEvent('op:start-positive', 'progress', 'diagnostic-running', 0.5)), true)
    assert.equal(coordinator.handleServiceEvent(operationEvent('op:start-positive', 'progress', 'diagnostic-cleanup', 1)), true)
    const terminalOutcome = coordinator.handleServiceEvent(operationEvent('op:start-positive', 'succeeded', 'complete'))
    assert.equal(typeof terminalOutcome?.then, 'function')
    assert.equal(coordinator.getActiveOperation().stage, 'diagnostic-cleanup')
    assert.deepEqual(await coordinator.start(SELF_TEST_REQUEST), { ok: false, reason: 'operation-in-progress' })
    assert.deepEqual(
        events.map((event) => event.state),
        ['queued', 'started', 'progress', 'progress']
    )

    acknowledgement.resolve({ ok: true })
    assert.equal(await terminalOutcome, true)
    await nextTurn()

    assert.equal(coordinator.getActiveOperation(), null)
    assert.equal(events.at(-1).state, 'succeeded')
})

test('defers a valid queued failure until a delayed positive start acknowledgement', async () => {
    const acknowledgement = createDeferredResponse()
    const events = []

    /** @returns {Promise<object>} Holds the operation-start acknowledgement. */
    function dispatch() {
        return acknowledgement.promise
    }

    const coordinator = createReadyCoordinator({ dispatch, getGeneration: () => 31, idFactory: () => 'op:start-failed' })
    coordinator.subscribe((event) => events.push(event))
    await coordinator.start(SELF_TEST_REQUEST)
    const terminalOutcome = coordinator.handleServiceEvent(queuedFailureEvent('op:start-failed'))
    assert.equal(typeof terminalOutcome?.then, 'function')
    assert.notEqual(coordinator.getActiveOperation(), null)
    assert.deepEqual(
        events.map((event) => event.state),
        ['queued']
    )

    acknowledgement.resolve({ ok: true })
    assert.equal(await terminalOutcome, true)
    await nextTurn()

    assert.equal(coordinator.getActiveOperation(), null)
    assert.deepEqual(
        events.map((event) => event.state),
        ['queued', 'failed']
    )
})

test('faults an event-advanced generation after a delayed negative start acknowledgement', async () => {
    const acknowledgement = createDeferredResponse()
    const events = []
    const faults = []
    let coordinator
    let reentrantEventAccepted = null

    /** @returns {Promise<object>} Holds the operation-start acknowledgement. */
    function dispatch() {
        return acknowledgement.promise
    }

    /** @param {number} generation - Exact faulted generation. @returns {boolean} Simulates unconfirmed teardown. */
    function faultGeneration(generation) {
        faults.push(generation)
        reentrantEventAccepted = coordinator.handleServiceEvent(operationEvent('op:start-negative', 'progress', 'diagnostic-cleanup', 1))
        return false
    }

    coordinator = createReadyCoordinator({ dispatch, faultGeneration, getGeneration: () => 32, idFactory: () => 'op:start-negative' })
    coordinator.subscribe((event) => events.push(event))
    await coordinator.start(SELF_TEST_REQUEST)
    assert.equal(coordinator.handleServiceEvent(operationEvent('op:start-negative', 'started', 'diagnostic-running')), true)
    assert.equal(coordinator.handleServiceEvent(operationEvent('op:start-negative', 'progress', 'diagnostic-running', 0.5)), true)
    assert.equal(coordinator.handleServiceEvent(operationEvent('op:start-negative', 'progress', 'diagnostic-cleanup', 1)), true)
    const terminalOutcome = coordinator.handleServiceEvent(operationEvent('op:start-negative', 'succeeded', 'complete'))
    assert.equal(typeof terminalOutcome?.then, 'function')
    assert.equal(coordinator.getActiveOperation().stage, 'diagnostic-cleanup')
    assert.deepEqual(await coordinator.start(SELF_TEST_REQUEST), { ok: false, reason: 'operation-in-progress' })
    assert.equal(
        events.some((event) => event.state === 'succeeded'),
        false
    )

    acknowledgement.resolve({ ok: false, reason: 'operation-rejected' })
    assert.equal(await terminalOutcome, false)
    await nextTurn()

    assert.deepEqual(faults, [32])
    assert.equal(reentrantEventAccepted, false)
    assert.equal(coordinator.getActiveOperation().stage, 'diagnostic-cleanup')
    assert.equal(coordinator.handleServiceEvent(operationEvent('op:start-negative', 'progress', 'diagnostic-cleanup', 1)), false)
    assert.deepEqual(await coordinator.start(SELF_TEST_REQUEST), { ok: false, reason: 'operation-in-progress' })
    assert.equal(coordinator.handleGenerationLoss(31, 'service-malformed-data'), false)
    assert.notEqual(coordinator.getActiveOperation(), null)
    assert.equal(coordinator.handleGenerationLoss(32, 'service-malformed-data'), true)
    assert.equal(coordinator.getActiveOperation(), null)
    assert.deepEqual(
        events.map((event) => event.state),
        ['queued', 'started', 'progress', 'progress', 'failed']
    )
})

test('faults ambiguous, malformed, and thrown start acknowledgements after a buffered terminal', async () => {
    const cases = [
        { name: 'ambiguous', response: { ok: false, reason: 'operation-outcome-unknown', ambiguous: true } },
        { name: 'malformed', response: { accepted: true } },
        { name: 'thrown', throws: true }
    ]

    for (const testCase of cases) {
        const acknowledgement = createDeferredResponse()
        const faults = []
        const operationId = `op:start-${testCase.name}`

        /** @returns {Promise<object>} Holds the operation-start acknowledgement. */
        function dispatch() {
            return acknowledgement.promise
        }

        /** @param {number} generation - Exact faulted generation. @returns {boolean} Records unconfirmed faulting. */
        function faultGeneration(generation) {
            faults.push(generation)
            return false
        }

        const coordinator = createReadyCoordinator({ dispatch, faultGeneration, getGeneration: () => 33, idFactory: () => operationId })
        await coordinator.start(SELF_TEST_REQUEST)
        assert.equal(coordinator.handleServiceEvent(operationEvent(operationId, 'started', 'diagnostic-running')), true, testCase.name)
        assert.equal(coordinator.handleServiceEvent(operationEvent(operationId, 'progress', 'diagnostic-cleanup', 1)), true, testCase.name)
        const terminalOutcome = coordinator.handleServiceEvent(operationEvent(operationId, 'succeeded', 'complete'))
        assert.equal(typeof terminalOutcome?.then, 'function', testCase.name)
        assert.notEqual(coordinator.getActiveOperation(), null, testCase.name)

        if (testCase.throws) {
            acknowledgement.reject(new Error('controlled dispatch failure'))
        } else {
            acknowledgement.resolve(testCase.response)
        }
        assert.equal(await terminalOutcome, false, testCase.name)
        await nextTurn()

        assert.deepEqual(faults, [33], testCase.name)
        assert.equal(coordinator.getActiveOperation().stage, 'diagnostic-cleanup', testCase.name)
        assert.deepEqual(await coordinator.start(SELF_TEST_REQUEST), { ok: false, reason: 'operation-in-progress' }, testCase.name)
        assert.equal(coordinator.handleGenerationLoss(33, 'service-malformed-data'), true, testCase.name)
        assert.equal(coordinator.getActiveOperation(), null, testCase.name)
    }
})

test('does not release a cancel terminal replayed before a negative start acknowledgement', async () => {
    const startAcknowledgement = createDeferredResponse()
    const cancelAcknowledgement = createDeferredResponse()
    const events = []
    const faults = []

    /** @returns {Promise<object>} Holds the operation-start acknowledgement. */
    function dispatch() {
        return startAcknowledgement.promise
    }

    /** @returns {Promise<object>} Holds the cancellation acknowledgement. */
    function cancelDispatch() {
        return cancelAcknowledgement.promise
    }

    /** @param {number} generation - Exact faulted generation. @returns {boolean} Records unconfirmed faulting. */
    function faultGeneration(generation) {
        faults.push(generation)
        return false
    }

    const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, faultGeneration, getGeneration: () => 34, idFactory: () => 'op:cancel-before-start-ack' })
    coordinator.subscribe((event) => events.push(event))
    await coordinator.start(SELF_TEST_REQUEST)
    const cancellation = coordinator.cancel({ operationId: 'op:cancel-before-start-ack' })
    assert.equal(coordinator.handleServiceEvent(operationEvent('op:cancel-before-start-ack', 'progress', 'diagnostic-cleanup', 1, 'requested')), true)
    const terminalOutcome = coordinator.handleServiceEvent(operationEvent('op:cancel-before-start-ack', 'cancelled', 'diagnostic-cleanup'))
    assert.equal(typeof terminalOutcome?.then, 'function')

    cancelAcknowledgement.resolve({ ok: true })
    await nextTurn()
    assert.equal(coordinator.getActiveOperation().stage, 'diagnostic-cleanup')
    assert.deepEqual(
        events.map((event) => event.state),
        ['queued', 'progress']
    )

    startAcknowledgement.resolve({ ok: false, reason: 'operation-rejected' })
    assert.equal(await terminalOutcome, false)
    assert.deepEqual(await cancellation, { ok: true })
    await nextTurn()

    assert.deepEqual(faults, [34])
    assert.equal(coordinator.getActiveOperation().stage, 'diagnostic-cleanup')
    assert.deepEqual(await coordinator.start(SELF_TEST_REQUEST), { ok: false, reason: 'operation-in-progress' })
    assert.equal(coordinator.handleGenerationLoss(34, 'service-malformed-data'), true)
    assert.equal(coordinator.getActiveOperation(), null)
    assert.equal(events.at(-1).state, 'failed')
})

test('faults when cancellation lifecycle evidence is still buffered at a negative start acknowledgement', async () => {
    const startAcknowledgement = createDeferredResponse()
    const cancelAcknowledgement = createDeferredResponse()
    const faults = []

    /** @returns {Promise<object>} Holds the operation-start acknowledgement. */
    function dispatch() {
        return startAcknowledgement.promise
    }

    /** @returns {Promise<object>} Holds the cancellation acknowledgement. */
    function cancelDispatch() {
        return cancelAcknowledgement.promise
    }

    /** @param {number} generation - Exact faulted generation. @returns {boolean} Records unconfirmed faulting. */
    function faultGeneration(generation) {
        faults.push(generation)
        return false
    }

    const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, faultGeneration, getGeneration: () => 35, idFactory: () => 'op:cancel-buffer-before-start-ack' })
    await coordinator.start(SELF_TEST_REQUEST)
    const cancellation = coordinator.cancel({ operationId: 'op:cancel-buffer-before-start-ack' })
    assert.equal(coordinator.handleServiceEvent(operationEvent('op:cancel-buffer-before-start-ack', 'progress', 'diagnostic-cleanup', 1, 'requested')), true)
    const terminalOutcome = coordinator.handleServiceEvent(operationEvent('op:cancel-buffer-before-start-ack', 'cancelled', 'diagnostic-cleanup'))
    assert.equal(typeof terminalOutcome?.then, 'function')

    startAcknowledgement.resolve({ ok: false, reason: 'operation-rejected' })
    assert.equal(await terminalOutcome, false)
    await nextTurn()

    assert.deepEqual(faults, [35])
    assert.notEqual(coordinator.getActiveOperation(), null)
    assert.deepEqual(await coordinator.start(SELF_TEST_REQUEST), { ok: false, reason: 'operation-in-progress' })

    cancelAcknowledgement.resolve({ ok: true })
    assert.deepEqual(await cancellation, { ok: true })
    assert.notEqual(coordinator.getActiveOperation(), null)
    assert.equal(coordinator.handleGenerationLoss(35, 'service-malformed-data'), true)
    assert.equal(coordinator.getActiveOperation(), null)
})

test('does not let a stale start acknowledgement mutate a reused operation ID reservation', async () => {
    const acknowledgements = [createDeferredResponse(), createDeferredResponse()]
    let dispatchIndex = 0
    let generation = 41

    /** @returns {Promise<object>} Returns the next controlled start acknowledgement. */
    function dispatch() {
        const acknowledgement = acknowledgements[dispatchIndex]
        dispatchIndex += 1
        return acknowledgement.promise
    }

    const coordinator = createReadyCoordinator({ dispatch, getGeneration: () => generation, idFactory: () => 'op:reused-start' })
    await coordinator.start(SELF_TEST_REQUEST)
    assert.equal(coordinator.handleGenerationLoss(41, 'service-exited'), true)

    generation = 42
    await coordinator.start(SELF_TEST_REQUEST)
    acknowledgements[0].resolve({ ok: false, reason: 'operation-rejected' })
    await nextTurn()

    assert.equal(coordinator.getActiveOperation().generation, 42)
    assert.equal(coordinator.getActiveOperation().stage, 'queued')
    acknowledgements[1].resolve({ ok: true })
    await nextTurn()
    assert.equal(coordinator.handleServiceEvent(operationEvent('op:reused-start', 'started', 'diagnostic-running')), true)
})

test('does not let a stale scan acknowledgement clear a reused scan reservation', async () => {
    const acknowledgements = [createDeferredResponse(), createDeferredResponse()]
    let dispatchIndex = 0
    let generation = 51

    /** @returns {Promise<object>} Returns the next controlled scan acknowledgement. */
    function scanDispatch() {
        const acknowledgement = acknowledgements[dispatchIndex]
        dispatchIndex += 1
        return acknowledgement.promise
    }

    /** @returns {Promise<object>} Keeps ordinary operation dispatch unused. */
    async function dispatch() {
        return { ok: true }
    }

    const coordinator = createReadyCoordinator({ dispatch, getGeneration: () => generation, idFactory: () => 'op:reused-scan', scanDispatch })
    const firstScan = coordinator.scan({ kind: 'scan' })
    assert.equal(coordinator.handleGenerationLoss(51, 'service-exited'), true)

    generation = 52
    const secondScan = coordinator.scan({ kind: 'scan' })
    acknowledgements[0].resolve({ ok: true })
    assert.deepEqual(await firstScan, { ok: true })
    assert.equal(coordinator.getActiveOperation().generation, 52)
    assert.equal(coordinator.getActiveOperation().kind, 'scan')

    acknowledgements[1].resolve({ ok: true })
    assert.deepEqual(await secondScan, { ok: true })
    assert.equal(coordinator.getActiveOperation(), null)
})

test('fault latch suppresses both start and cancel acknowledgement polarities until exact generation loss', async () => {
    const cases = [
        { name: 'positive', startResponse: { ok: true }, cancelResponse: { ok: true } },
        { name: 'negative', startResponse: { ok: false, reason: 'operation-rejected' }, cancelResponse: { ok: false, reason: 'operation-not-cancellable' } }
    ]

    for (const testCase of cases) {
        const startAcknowledgement = createDeferredResponse()
        const cancelAcknowledgement = createDeferredResponse()
        const faults = []
        const events = []
        const operationId = `op:fault-latch-${testCase.name}`

        /** @returns {Promise<object>} Holds the operation-start acknowledgement. */
        function dispatch() {
            return startAcknowledgement.promise
        }

        /** @returns {Promise<object>} Holds the cancellation acknowledgement. */
        function cancelDispatch() {
            return cancelAcknowledgement.promise
        }

        /** @param {number} generation - Exact faulted generation. @returns {boolean} Records fault admission. */
        function faultGeneration(generation) {
            faults.push(generation)
            return true
        }

        const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, faultGeneration, getGeneration: () => 61, idFactory: () => operationId })
        coordinator.subscribe((event) => events.push(event))
        await coordinator.start(SELF_TEST_REQUEST)
        const cancellation = coordinator.cancel({ operationId })
        assert.equal(coordinator.handleServiceEvent(operationEvent(operationId, 'progress', 'diagnostic-cleanup', 1, 'requested')), true, testCase.name)
        const terminalOutcome = coordinator.handleServiceEvent(operationEvent(operationId, 'cancelled', 'diagnostic-cleanup'))
        assert.equal(typeof terminalOutcome?.then, 'function', testCase.name)
        assert.equal(coordinator.handleServiceEvent(operationEvent(operationId, 'succeeded', 'complete')), false, testCase.name)
        assert.equal(await terminalOutcome, false, testCase.name)
        assert.deepEqual(faults, [61], testCase.name)
        assert.equal(coordinator.handleServiceEvent(operationEvent(operationId, 'started', 'diagnostic-running')), false, testCase.name)

        startAcknowledgement.resolve(testCase.startResponse)
        cancelAcknowledgement.resolve(testCase.cancelResponse)
        await cancellation
        await nextTurn()

        assert.equal(coordinator.getActiveOperation().stage, 'queued', testCase.name)
        assert.equal(coordinator.getActiveOperation().cancellationRequested, true, testCase.name)
        assert.deepEqual(await coordinator.start(SELF_TEST_REQUEST), { ok: false, reason: 'operation-in-progress' }, testCase.name)
        assert.equal(coordinator.failActiveOperation('service-unavailable'), false, testCase.name)
        assert.equal(coordinator.handleGenerationLoss(60, 'service-malformed-data'), false, testCase.name)
        assert.notEqual(coordinator.getActiveOperation(), null, testCase.name)
        assert.equal(coordinator.handleGenerationLoss(61, 'service-malformed-data'), true, testCase.name)
        assert.equal(coordinator.getActiveOperation(), null, testCase.name)
        assert.deepEqual(
            events.map((event) => event.state),
            ['queued', 'failed'],
            testCase.name
        )
    }
})
