// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { OperationCoordinator } from '../src/main/operation-coordinator.mjs'

/** @returns {Promise<void>} Resolves after queued promise continuations. */
async function nextTurn() {
    await new Promise(setImmediate)
}

/** Creates a caller-controlled promise. @returns {{promise: Promise<object>, resolve: (value: object) => void}} Gate controls. */
function createResponseGate() {
    let resolve
    const promise = new Promise((resolveGate) => {
        resolve = resolveGate
    })
    return { promise, resolve }
}

/** Creates a caller-controlled Boolean barrier. @returns {{promise: Promise<boolean>, resolve: (value: boolean) => void}} Gate controls. */
function createBarrierGate() {
    let resolve
    const promise = new Promise((resolveGate) => {
        resolve = resolveGate
    })
    return { promise, resolve }
}

/**
 * Creates one native-ready coordinator with deterministic identity and fault probes.
 * @param {{kind?: string, operationId?: string, cancelResponse: Promise<object>, terminalBarrier?: (event: object) => boolean|Promise<boolean>}} options - Controlled dependencies.
 * @returns {{coordinator: OperationCoordinator, faults: number[], events: object[], request: object}} Fixture.
 */
function createCoordinator(options) {
    const kind = options.kind ?? 'self-test'
    const operationId = options.operationId ?? 'op:held-terminal'
    const faults = []
    const events = []
    const request = {
        kind,
        deviceId: 'rdx:final-boundary',
        deviceRevision: 7,
        ...(kind === 'firmware-update' ? { firmwareFileToken: 'firmware:final-boundary' } : {})
    }

    /** @returns {Promise<object>} Accepts one exact operation dispatch. */
    async function dispatch() {
        return { ok: true }
    }

    /** @returns {Promise<object>} Returns the caller-controlled cancellation response. */
    function cancelDispatch() {
        return options.cancelResponse
    }

    /** @returns {object} Current exact device snapshot. */
    function getDevice() {
        return {
            id: request.deviceId,
            revision: request.deviceRevision,
            mediaState: kind === 'firmware-update' ? 'no-media' : 'present',
            capabilities: { [kind]: { state: 'available' } }
        }
    }

    /** @param {number} generation - Exact generation requested for containment. @returns {boolean} Records the fault. */
    function faultGeneration(generation) {
        faults.push(generation)
        return true
    }

    const coordinator = new OperationCoordinator({
        cancelDispatch,
        dispatch,
        faultGeneration,
        getDevice,
        getGeneration: () => 9,
        getPlatformCapability: () => ({ state: 'available' }),
        getServiceMode: () => 'native',
        hasPrivilege: () => true,
        idFactory: () => operationId,
        isHardwareReady: () => true,
        terminalBarrier: options.terminalBarrier
    })
    coordinator.subscribe((event) => events.push(event))
    return { coordinator, events, faults, request }
}

/** @param {string} operationId - Exact owner. @param {string} kind - Operation kind. @param {string} stage - Stage. @returns {object} Strict progress event. */
function progressEvent(operationId, kind, stage) {
    return { state: 'progress', operationId, kind, deviceId: 'rdx:final-boundary', deviceRevision: 7, stage, progress: 1, cancellationState: 'requested' }
}

/** @param {string} operationId - Exact owner. @param {string} kind - Operation kind. @param {string} stage - Safe terminal stage. @returns {object} Strict cancellation terminal. */
function cancelledEvent(operationId, kind, stage) {
    return { state: 'cancelled', operationId, kind, deviceId: 'rdx:final-boundary', deviceRevision: 7, stage }
}

test('holds a buffered cancellation terminal through acknowledgement and the durable terminal barrier', async () => {
    const cancellation = createResponseGate()
    const barrier = createBarrierGate()
    let barrierEntered = false
    let terminalSettled = false
    const { coordinator, events, faults, request } = createCoordinator({
        cancelResponse: cancellation.promise,
        terminalBarrier() {
            barrierEntered = true
            return barrier.promise
        }
    })
    const started = await coordinator.start(request)
    await nextTurn()
    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: started.operationId, kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'diagnostic-running' }, 1), true)

    const cancelResult = coordinator.cancel({ operationId: started.operationId })
    assert.equal(coordinator.handleServiceEvent(progressEvent(started.operationId, request.kind, 'diagnostic-cleanup'), 2), true)
    const terminalResult = coordinator.handleServiceEvent(cancelledEvent(started.operationId, request.kind, 'diagnostic-cleanup'), 3)
    assert.equal(typeof terminalResult?.then, 'function')
    /** @returns {Promise<void>} Records terminal settlement only after its durable barrier. */
    async function trackTerminal() {
        await terminalResult
        terminalSettled = true
    }
    const trackedTerminal = trackTerminal()

    cancellation.resolve({ ok: true, cancellationCutover: 3 })
    await nextTurn()
    assert.equal(barrierEntered, true)
    assert.equal(terminalSettled, false)
    assert.notEqual(coordinator.getActiveOperation(), null)
    assert.equal(
        events.some((event) => event.state === 'cancelled'),
        false
    )

    barrier.resolve(true)
    assert.equal(await terminalResult, true)
    await trackedTerminal
    assert.deepEqual(await cancelResult, { ok: true })
    assert.equal(coordinator.getActiveOperation(), null)
    assert.equal(events.at(-1).state, 'cancelled')
    assert.deepEqual(faults, [])
})

test('settles a held cancellation terminal false and faults on a definitive negative acknowledgement', async () => {
    const cancellation = createResponseGate()
    const { coordinator, faults, request } = createCoordinator({ cancelResponse: cancellation.promise, operationId: 'op:negative-held' })
    const started = await coordinator.start(request)
    await nextTurn()
    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: started.operationId, kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'diagnostic-running' }, 1), true)

    const cancelResult = coordinator.cancel({ operationId: started.operationId })
    assert.equal(coordinator.handleServiceEvent(progressEvent(started.operationId, request.kind, 'diagnostic-cleanup'), 2), true)
    const terminalResult = coordinator.handleServiceEvent(cancelledEvent(started.operationId, request.kind, 'diagnostic-cleanup'), 3)
    assert.equal(typeof terminalResult?.then, 'function')

    cancellation.resolve({ ok: false, reason: 'operation-not-cancellable' })
    assert.deepEqual(await cancelResult, { ok: false, reason: 'operation-not-cancellable' })
    assert.equal(await terminalResult, false)
    assert.deepEqual(faults, [9])
    assert.notEqual(coordinator.getActiveOperation(), null)
})

test('settles a held cancellation terminal false and faults when cancellation outcome times out ambiguously', async () => {
    const cancellation = createResponseGate()
    const { coordinator, faults, request } = createCoordinator({ cancelResponse: cancellation.promise, operationId: 'op:timeout-held' })
    const started = await coordinator.start(request)
    await nextTurn()
    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: started.operationId, kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'diagnostic-running' }, 1), true)

    const cancelResult = coordinator.cancel({ operationId: started.operationId })
    assert.equal(coordinator.handleServiceEvent(progressEvent(started.operationId, request.kind, 'diagnostic-cleanup'), 2), true)
    const terminalResult = coordinator.handleServiceEvent(cancelledEvent(started.operationId, request.kind, 'diagnostic-cleanup'), 3)
    assert.equal(typeof terminalResult?.then, 'function')

    cancellation.resolve({ ok: false, reason: 'operation-outcome-unknown', ambiguous: true })
    assert.deepEqual(await cancelResult, { ok: false, reason: 'operation-outcome-unknown' })
    assert.equal(await terminalResult, false)
    assert.deepEqual(faults, [9])
    assert.notEqual(coordinator.getActiveOperation(), null)
})

test('settles a held cancellation terminal false when its generation is lost', async () => {
    const cancellation = createResponseGate()
    const { coordinator, request } = createCoordinator({ cancelResponse: cancellation.promise, operationId: 'op:generation-loss-held' })
    const started = await coordinator.start(request)
    await nextTurn()
    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: started.operationId, kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'diagnostic-running' }, 1), true)

    const cancelResult = coordinator.cancel({ operationId: started.operationId })
    assert.equal(coordinator.handleServiceEvent(progressEvent(started.operationId, request.kind, 'diagnostic-cleanup'), 2), true)
    const terminalResult = coordinator.handleServiceEvent(cancelledEvent(started.operationId, request.kind, 'diagnostic-cleanup'), 3)
    assert.equal(typeof terminalResult?.then, 'function')
    assert.equal(coordinator.handleGenerationLoss(9, 'service-exited', false), true)
    assert.equal(await terminalResult, false)
    assert.equal(coordinator.getActiveOperation(), null)
    cancellation.resolve({ ok: false, reason: 'operation-outcome-unknown', ambiguous: true })
    assert.deepEqual(await cancelResult, { ok: false, reason: 'operation-outcome-unknown' })
})

test('settles a held cancellation terminal false and faults when its durable barrier fails', async () => {
    const cancellation = createResponseGate()
    const barrier = createBarrierGate()
    const { coordinator, faults, request } = createCoordinator({ cancelResponse: cancellation.promise, operationId: 'op:barrier-failure-held', terminalBarrier: () => barrier.promise })
    const started = await coordinator.start(request)
    await nextTurn()
    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: started.operationId, kind: request.kind, deviceId: request.deviceId, deviceRevision: 7, stage: 'diagnostic-running' }, 1), true)

    const cancelResult = coordinator.cancel({ operationId: started.operationId })
    assert.equal(coordinator.handleServiceEvent(progressEvent(started.operationId, request.kind, 'diagnostic-cleanup'), 2), true)
    const terminalResult = coordinator.handleServiceEvent(cancelledEvent(started.operationId, request.kind, 'diagnostic-cleanup'), 3)
    cancellation.resolve({ ok: true, cancellationCutover: 3 })
    await nextTurn()
    barrier.resolve(false)

    assert.equal(await terminalResult, false)
    assert.deepEqual(await cancelResult, { ok: true })
    assert.deepEqual(faults, [9])
    assert.notEqual(coordinator.getActiveOperation(), null)
})

test('keeps a pre-cutover closed latch through later requested recovery for every cancellable recovery policy', async (context) => {
    const cases = [
        { kind: 'self-test', initial: 'diagnostic-running', recovery: ['diagnostic-cleanup'], terminal: 'diagnostic-cleanup' },
        { kind: 'led-test', initial: 'led-testing', recovery: ['led-restoring', 'led-readback'], terminal: 'led-readback' },
        { kind: 'firmware-update', initial: 'firmware-validating', recovery: ['firmware-finalizing', 'device-reconnecting', 'firmware-readback'], terminal: 'firmware-readback' }
    ]
    for (const scenario of cases) {
        await context.test(scenario.kind, async () => {
            const cancellation = createResponseGate()
            const operationId = `op:closed-${scenario.kind}`
            const { coordinator, faults, request } = createCoordinator({ cancelResponse: cancellation.promise, kind: scenario.kind, operationId })
            await coordinator.start(request)
            await nextTurn()
            assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId, kind: scenario.kind, deviceId: request.deviceId, deviceRevision: 7, stage: scenario.initial }, 1), true)

            const cancelResult = coordinator.cancel({ operationId })
            assert.equal(coordinator.handleServiceEvent({ ...progressEvent(operationId, scenario.kind, scenario.recovery[0]), cancellationState: 'closed', progress: 0.7 }, 2), true)
            cancellation.resolve({ ok: true, cancellationCutover: 2 })
            assert.deepEqual(await cancelResult, { ok: true })

            let sequence = 3
            for (const stage of scenario.recovery.slice(1)) {
                assert.equal(coordinator.handleServiceEvent({ ...progressEvent(operationId, scenario.kind, stage), progress: Math.min(1, 0.7 + sequence / 10) }, sequence), true)
                sequence += 1
            }
            assert.equal(coordinator.handleServiceEvent(cancelledEvent(operationId, scenario.kind, scenario.terminal), sequence), false)
            assert.deepEqual(faults, [])
            assert.equal(coordinator.getActiveOperation().cancellationState, scenario.recovery.length === 1 ? 'closed' : 'requested')
        })
    }
})
