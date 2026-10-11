// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { OperationCoordinator } from '../src/main/operation-coordinator.mjs'

const SELF_TEST_REQUEST = Object.freeze({ kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7 })

/**
 * Allows dispatch and cancellation promise continuations to settle.
 * @returns {Promise<void>} Resolves on the next event-loop turn.
 */
async function nextTurn() {
    await new Promise(setImmediate)
}

/**
 * Creates a native-ready coordinator for one controlled operation kind.
 * @param {object} options - Test-specific coordinator dependencies.
 * @param {string} [options.kind='self-test'] - Available operation capability.
 * @returns {OperationCoordinator} Coordinator with a current device baseline.
 */
function createReadyCoordinator(options) {
    const kind = options.kind ?? 'self-test'

    /** @returns {object} Current controlled operation-capable device. */
    function getDevice() {
        return { id: 'rdx:1', revision: 7, mediaState: kind === 'firmware-update' ? 'no-media' : 'present', capabilities: { [kind]: { state: 'available' } } }
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

test('replays only the FIFO progress prefix at the native cancellation cutover', async () => {
    const events = []
    let resolveCancellation

    /** @returns {Promise<object>} Accepts the controlled operation dispatch. */
    async function dispatch() {
        return { ok: true }
    }

    /** @returns {Promise<object>} Holds the exact cutover acknowledgement. */
    function cancelDispatch() {
        /** @param {(response: object) => void} resolve - Controlled response resolver. @returns {void} Captures it. */
        function captureCancellation(resolve) {
            resolveCancellation = resolve
        }
        return new Promise(captureCancellation)
    }

    /** @param {object} event - Accepted lifecycle event. @returns {void} Records it. */
    function recordEvent(event) {
        events.push(event)
    }

    const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, idFactory: () => 'op:fifo-cutover' })
    coordinator.subscribe(recordEvent)
    await coordinator.start(SELF_TEST_REQUEST)
    await nextTurn()
    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: 'op:fifo-cutover', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running' }, 1), true)

    const cancellation = coordinator.cancel({ operationId: 'op:fifo-cutover' })
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:fifo-cutover', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running', progress: 0.2, cancellationState: 'cancellable' }, 10), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:fifo-cutover', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running', progress: 0.3, cancellationState: 'cancellable' }, 11), true)
    resolveCancellation({ ok: true, cancellationCutover: 11 })
    assert.deepEqual(await cancellation, { ok: true })

    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:fifo-cutover', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running', progress: 0.4, cancellationState: 'cancellable' }, 12), false)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:fifo-cutover', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'requested' }, 13), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'cancelled', operationId: 'op:fifo-cutover', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup' }, 14), true)
    assert.equal(coordinator.getActiveOperation(), null)
    assert.deepEqual(
        events.map((event) => event.state),
        ['queued', 'started', 'progress', 'progress', 'cancelled']
    )
    assert.deepEqual(
        events.filter((event) => event.state === 'progress').map((event) => event.progress),
        [0.3, 1]
    )
})

test('rejects held ordinary terminals and faults their generation after a negative cancel acknowledgement', async () => {
    const terminalCases = [
        {
            name: 'success',
            operationId: 'op:negative-success',
            terminal: { state: 'succeeded', operationId: 'op:negative-success', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'complete' }
        },
        {
            name: 'failure',
            operationId: 'op:negative-failure',
            terminal: {
                state: 'failed',
                operationId: 'op:negative-failure',
                kind: 'self-test',
                deviceId: 'rdx:1',
                deviceRevision: 7,
                stage: 'diagnostic-cleanup',
                error: { code: 'cleanup-failed', messageKey: 'errors.service.failure', stage: 'diagnostic-cleanup', category: 'transport', retryable: false, supportCorrelationId: 'support:negative-failure', cleanupEvidence: [], attemptHistory: [] }
            }
        }
    ]

    for (const terminalCase of terminalCases) {
        const events = []
        const faults = []
        let resolveCancellation

        /** @returns {Promise<object>} Accepts the controlled operation dispatch. */
        async function dispatch() {
            return { ok: true }
        }

        /** @returns {Promise<object>} Holds the non-ambiguous cancellation rejection. */
        function cancelDispatch() {
            /** @param {(response: object) => void} resolve - Controlled response resolver. @returns {void} Captures the resolver. */
            function captureCancellation(resolve) {
                resolveCancellation = resolve
            }
            return new Promise(captureCancellation)
        }

        /** @param {object} event - Accepted lifecycle event. @returns {void} Records publication order. */
        function recordEvent(event) {
            events.push(event)
        }

        /** @param {number} generation - Exact generation requiring containment. @returns {boolean} Records it. */
        function faultGeneration(generation) {
            faults.push(generation)
            return true
        }

        /** @returns {string} Exact table-owned operation identity. */
        function createOperationId() {
            return terminalCase.operationId
        }

        const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, faultGeneration, getGeneration: () => 17, idFactory: createOperationId })
        coordinator.subscribe(recordEvent)
        await coordinator.start(SELF_TEST_REQUEST)
        await nextTurn()
        assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: terminalCase.operationId, kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-running' }), true, terminalCase.name)

        const cancellation = coordinator.cancel({ operationId: terminalCase.operationId })
        assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: terminalCase.operationId, kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 7, stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'closed' }), true, terminalCase.name)
        const terminalOutcome = coordinator.handleServiceEvent(terminalCase.terminal)
        assert.equal(typeof terminalOutcome?.then, 'function', terminalCase.name)
        assert.equal(coordinator.getActiveOperation().stage, 'diagnostic-running', terminalCase.name)

        resolveCancellation({ ok: false, reason: 'operation-not-cancellable' })
        assert.deepEqual(await cancellation, { ok: false, reason: 'operation-not-cancellable' }, terminalCase.name)
        assert.equal(await terminalOutcome, false, terminalCase.name)
        assert.deepEqual(faults, [17], terminalCase.name)
        assert.notEqual(coordinator.getActiveOperation(), null, terminalCase.name)
        const eventStates = []
        for (const event of events) {
            eventStates.push(event.state)
        }
        assert.deepEqual(eventStates, ['queued', 'started'], terminalCase.name)
        assert.equal(coordinator.handleGenerationLoss(17, 'service-exited', false), true, terminalCase.name)
        assert.equal(coordinator.getActiveOperation(), null, terminalCase.name)
    }
})

test('faults the exact generation and retains ownership when negative-ack replay contradicts ordinary lifecycle', async () => {
    const request = { kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, firmwareFileToken: 'firmware:test' }
    const faults = []
    let resolveCancellation

    /** @returns {Promise<object>} Accepts the controlled firmware dispatch. */
    async function dispatch() {
        return { ok: true }
    }

    /** @returns {Promise<object>} Holds the non-ambiguous cancellation rejection. */
    function cancelDispatch() {
        /** @param {(response: object) => void} resolve - Controlled response resolver. @returns {void} Captures the resolver. */
        function captureCancellation(resolve) {
            resolveCancellation = resolve
        }
        return new Promise(captureCancellation)
    }

    /** @param {number} generation - Exact faulted service generation. @returns {boolean} Records fault admission. */
    function faultGeneration(generation) {
        faults.push(generation)
        return true
    }

    /** @returns {number} Exact owning service generation. */
    function getGeneration() {
        return 17
    }

    /** @returns {string} Exact contradiction-test operation identity. */
    function createOperationId() {
        return 'op:negative-contradiction'
    }

    const coordinator = createReadyCoordinator({ cancelDispatch, dispatch, faultGeneration, getGeneration, idFactory: createOperationId, kind: 'firmware-update' })
    await coordinator.start(request)
    await nextTurn()
    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: 'op:negative-contradiction', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'firmware-validating' }), true)

    const cancellation = coordinator.cancel({ operationId: 'op:negative-contradiction' })
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:negative-contradiction', kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'firmware-finalizing', progress: 0.8, cancellationState: 'requested' }), true)
    resolveCancellation({ ok: false, reason: 'operation-not-cancellable' })

    assert.deepEqual(await cancellation, { ok: false, reason: 'operation-not-cancellable' })
    assert.deepEqual(faults, [17])
    assert.equal(coordinator.getActiveOperation().stage, 'firmware-validating')
    assert.equal(coordinator.getShutdownPolicy().allowed, false)
    assert.equal(coordinator.handleGenerationLoss(16, 'service-exited'), false)
    assert.equal(coordinator.handleGenerationLoss(17, 'service-exited'), true)
    assert.equal(coordinator.getActiveOperation(), null)
})
