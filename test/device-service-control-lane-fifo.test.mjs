// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'

import { DeviceServiceClient } from '../src/main/device-service-client.mjs'

const REQUEST_TIMEOUT_MS = 25

/** @param {Buffer} frame - Complete outbound service frame. @returns {object} Decoded message. */
function decodeFrame(frame) {
    const length = frame.readUInt32BE(0)
    return JSON.parse(frame.subarray(4, length + 4).toString('utf8'))
}

/** @param {object} message - Controlled inbound message. @returns {Buffer} Framed bytes. */
function encodeFrame(message) {
    const payload = Buffer.from(JSON.stringify(message), 'utf8')
    const frame = Buffer.allocUnsafe(payload.length + 4)
    frame.writeUInt32BE(payload.length, 0)
    payload.copy(frame, 4)
    return frame
}

/** @returns {Promise<void>} Resolves after queued promise continuations. */
async function nextTurn() {
    await new Promise(setImmediate)
}

/** @param {() => boolean} predicate - Completion predicate. @returns {Promise<void>} Resolves when true. */
async function waitFor(predicate) {
    for (let attempt = 0; attempt < 80; attempt += 1) {
        if (predicate()) return
        await nextTurn()
    }
    assert.fail('controlled condition did not become true')
}

/** Creates a caller-controlled terminal barrier. @returns {{promise: Promise<void>, resolve: () => void}} Gate controls. */
function createGate() {
    let resolve
    const promise = new Promise((resolveGate) => {
        resolve = resolveGate
    })
    return { promise, resolve }
}

/** Deterministic timer queue for request timeout and restart boundaries. */
class ManualTimers {
    /** Creates an empty timer queue. */
    constructor() {
        this.nextId = 1
        this.pending = new Map()
    }

    /** @param {Function} callback - Timer callback. @param {number} delay - Delay in milliseconds. @returns {number} Timer identity. */
    setTimeout(callback, delay) {
        const id = this.nextId
        this.nextId += 1
        this.pending.set(id, { callback, delay })
        return id
    }

    /** @param {number} id - Timer identity. @returns {void} Clears it. */
    clearTimeout(id) {
        this.pending.delete(id)
    }

    /** @param {number} delay - Exact queued delay. @returns {void} Fires the first matching timer. */
    fireDelay(delay) {
        const entry = [...this.pending.entries()].find(([, timer]) => timer.delay === delay)
        assert.notEqual(entry, undefined)
        this.pending.delete(entry[0])
        entry[1].callback()
    }
}

/** Native-like transport with automatic startup and controlled post-ready responses. */
class ControlLaneTransport extends EventEmitter {
    /** @param {number} generation - Exact service generation. */
    constructor(generation) {
        super()
        this.autoList = true
        this.closed = false
        this.generation = generation
        this.messages = []
    }

    /** @param {Buffer} frame - Main-owned request. @returns {{ok: true}} Accepts it. */
    write(frame) {
        const message = decodeFrame(frame)
        this.messages.push(message)
        if (message.type === 'handshake-request') {
            queueMicrotask(() => this.deliver({ type: 'handshake', protocolVersion: 1, serviceVersion: `control-lane-${this.generation}`, platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
        } else if (message.method === 'devices-list' && this.autoList) {
            queueMicrotask(() => this.respond(message, { ok: true, listRevision: 0, devices: [] }))
        } else if (message.method === 'operation-start') {
            queueMicrotask(() => this.respond(message, { ok: true }))
        }
        return { ok: true }
    }

    /** @param {object} request - Exact request. @param {object} result - Strict result. @returns {void} Delivers it. */
    respond(request, result) {
        this.deliver(responseEnvelope(request, result))
    }

    /** @param {object} message - Strict service message. @returns {void} Emits one frame. */
    deliver(message) {
        this.emit('data', encodeFrame(message))
    }

    /** @param {object[]} messages - Strict ordered messages. @returns {void} Emits one coalesced frame group. */
    deliverMany(messages) {
        this.emit('data', Buffer.concat(messages.map(encodeFrame)))
    }

    /** @param {string} method - Exact request method. @returns {object} Latest matching request. */
    lastRequest(method) {
        const request = this.messages.findLast((message) => message.method === method)
        assert.notEqual(request, undefined)
        return request
    }

    /** @returns {{confirmed: true}} Confirms exact-generation teardown. */
    close() {
        this.closed = true
        return { confirmed: true }
    }
}

/** @param {object} request - Exact pending request. @param {object} result - Strict result. @returns {object} Successful wire response. */
function responseEnvelope(request, result) {
    return { type: 'response', requestId: request.requestId, ok: true, result }
}

/** @param {number} sequence - Native FIFO sequence. @param {object} event - Strict operation event. @returns {object} Wire event envelope. */
function operationEnvelope(sequence, event) {
    return { type: 'event', channel: 'operation', publicationSequence: sequence, event }
}

/** @param {string} operationId - Exact operation owner. @returns {object} Shared owner tuple. */
function owner(operationId) {
    return { operationId, kind: 'self-test', deviceId: 'rdx:control-lane', deviceRevision: 7 }
}

/** @param {string} operationId - Exact operation owner. @returns {object[]} Started and cancellable prefix. */
function cancellablePrefix(operationId) {
    return [operationEnvelope(1, { state: 'started', ...owner(operationId), stage: 'diagnostic-running' }), operationEnvelope(2, { state: 'progress', ...owner(operationId), stage: 'diagnostic-running', progress: 0.5, cancellationState: 'cancellable' })]
}

/** @param {string} operationId - Exact operation owner. @returns {object[]} Requested cleanup and held cancelled terminal. */
function heldTerminal(operationId) {
    return [operationEnvelope(3, { state: 'progress', ...owner(operationId), stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'requested' }), operationEnvelope(4, { state: 'cancelled', ...owner(operationId), stage: 'diagnostic-cleanup' })]
}

/** @returns {object} Device suffix that must remain behind the held terminal. */
function deviceSuffix() {
    return { type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [] } }
}

/**
 * Creates a real client whose first observer holds a cancelled terminal on the
 * cancellation response and optional durable barrier; the second observer is
 * the public publication boundary.
 * @param {{maxRestarts?: number, terminalBarrier?: Promise<void>}} [options] - Controlled lifecycle options.
 * @returns {{client: DeviceServiceClient, publicEvents: object[], state: {cancellation: Promise<object>|null, terminalEntered: boolean}, timers: ManualTimers, transports: ControlLaneTransport[]}} Fixture.
 */
function createFixture(options = {}) {
    const publicEvents = []
    const state = { cancellation: null, terminalEntered: false }
    const timers = new ManualTimers()
    const transports = []

    /** @returns {ControlLaneTransport} Creates the next exact transport generation. */
    function transportFactory() {
        const transport = new ControlLaneTransport(transports.length + 1)
        transports.push(transport)
        return transport
    }

    const client = new DeviceServiceClient({
        executable: '/private/openrdx/openrdx-hardware',
        handshakeTimeoutMs: REQUEST_TIMEOUT_MS,
        maxRestarts: options.maxRestarts ?? 0,
        platform: 'darwin',
        requestTimeoutMs: REQUEST_TIMEOUT_MS,
        restartBackoffMs: [0],
        timers,
        transportFactory
    })
    /** @returns {Promise<boolean>} Accepts the held terminal only after its cancellation acknowledgement and audit barrier. */
    async function acceptCancellationTerminal() {
        const result = await state.cancellation
        if (result.ok !== true) return false
        state.terminalEntered = true
        await (options.terminalBarrier ?? Promise.resolve())
        return true
    }
    client.subscribeEvents((envelope) => {
        if (envelope.channel !== 'operation' || envelope.event.state !== 'cancelled') return true
        if (state.cancellation === null) return false
        return acceptCancellationTerminal()
    })
    client.subscribeEvents((envelope) => {
        publicEvents.push(envelope)
        return true
    })
    return { client, publicEvents, state, timers, transports }
}

/**
 * Starts one operation, publishes its cancellable prefix, and leaves the exact
 * cancellation request pending before the held terminal arrives.
 * @param {ReturnType<typeof createFixture>} fixture - Controlled client fixture.
 * @param {string} operationId - Exact operation identity.
 * @returns {Promise<{cancelRequest: object, operationId: string, transport: ControlLaneTransport}>} Pending sequence controls.
 */
async function beginHeldCancellation(fixture, operationId) {
    assert.equal((await fixture.client.start()).status, 'ready')
    const transport = fixture.transports.at(-1)
    assert.deepEqual(await fixture.client.startOperation({ operationId, request: { kind: 'self-test', deviceId: 'rdx:control-lane', deviceRevision: 7 } }), { ok: true })
    transport.deliverMany(cancellablePrefix(operationId))
    fixture.state.cancellation = fixture.client.cancelOperation({ operationId })
    return { cancelRequest: transport.lastRequest('operation-cancel'), operationId, transport }
}

/** @param {ReturnType<typeof createFixture>} fixture - Controlled client fixture. @returns {boolean} True once the cancelled terminal crossed the public observer. */
function hasPublicTerminal(fixture) {
    return fixture.publicEvents.some((envelope) => envelope.channel === 'operation' && envelope.event.state === 'cancelled')
}

/** @param {ReturnType<typeof createFixture>} fixture - Controlled client fixture. @returns {Promise<void>} Stops the client safely. */
async function disposeFixture(fixture) {
    await fixture.client.stop()
}

test('an unknown response before the cancel acknowledgement faults before held terminal publication', async () => {
    const fixture = createFixture()
    try {
        const { cancelRequest, operationId, transport } = await beginHeldCancellation(fixture, 'op:unknown-response')
        transport.deliverMany([...heldTerminal(operationId), { type: 'response', requestId: 'request:999999', ok: true, result: { ok: true } }, responseEnvelope(cancelRequest, { ok: true, cancellationCutover: 4 })])

        assert.deepEqual(await fixture.state.cancellation, { ok: false, reason: 'operation-outcome-unknown', ambiguous: true })
        await waitFor(() => fixture.client.getState().status === 'unavailable')
        assert.equal(hasPublicTerminal(fixture), false)
        assert.deepEqual(fixture.client.getState(), { status: 'unavailable', reason: 'service-malformed-data', restartCount: 0, terminatedGeneration: 1 })
    } finally {
        await disposeFixture(fixture)
    }
})

test('a valid late discovery reply crosses the control lane without bypassing terminal publication order', async () => {
    const fixture = createFixture()
    try {
        await fixture.client.start()
        const transport = fixture.transports[0]
        transport.autoList = false
        const listing = fixture.client.list()
        const expired = transport.lastRequest('devices-list')
        fixture.timers.fireDelay(REQUEST_TIMEOUT_MS)
        assert.equal((await listing).reason, 'service-request-timeout')
        const { cancelRequest, operationId } = await beginHeldCancellation(fixture, 'op:late-discovery')
        fixture.publicEvents.length = 0
        transport.deliverMany([...heldTerminal(operationId), responseEnvelope(expired, { ok: true, listRevision: 0, devices: [] }), responseEnvelope(cancelRequest, { ok: true, cancellationCutover: 4 }), deviceSuffix()])
        assert.equal((await fixture.state.cancellation).ok, true)
        await waitFor(() => fixture.publicEvents.some((envelope) => envelope.channel === 'device'))
        assert.deepEqual(
            fixture.publicEvents.map((envelope) => (envelope.channel === 'operation' ? envelope.event.state : envelope.channel)),
            ['progress', 'cancelled', 'device']
        )
        assert.equal(fixture.client.getState().status, 'ready')
    } finally {
        await disposeFixture(fixture)
    }
})

test('stale-generation and duplicate settled responses fault before held terminal publication', async (context) => {
    await context.test('stale generation', async () => {
        const fixture = createFixture({ maxRestarts: 1 })
        try {
            assert.equal((await fixture.client.start()).generation, 1)
            const firstTransport = fixture.transports[0]
            firstTransport.autoList = false
            const oldListing = fixture.client.list()
            const oldRequest = firstTransport.lastRequest('devices-list')
            firstTransport.respond(oldRequest, { ok: true, listRevision: 0, devices: [] })
            assert.equal((await oldListing).ok, true)
            firstTransport.emit('exit')
            await waitFor(() => fixture.client.getState().status === 'restarting')
            fixture.timers.fireDelay(0)
            await waitFor(() => fixture.client.getState().status === 'ready' && fixture.client.getGeneration() === 2)

            const { cancelRequest, operationId, transport } = await beginHeldCancellation(fixture, 'op:stale-generation-response')
            transport.deliverMany([...heldTerminal(operationId), responseEnvelope(oldRequest, { ok: true, listRevision: 0, devices: [] }), responseEnvelope(cancelRequest, { ok: true, cancellationCutover: 4 })])

            assert.deepEqual(await fixture.state.cancellation, { ok: false, reason: 'operation-outcome-unknown', ambiguous: true })
            await waitFor(() => fixture.client.getState().status === 'unavailable')
            assert.equal(hasPublicTerminal(fixture), false)
            assert.deepEqual(fixture.client.getState(), { status: 'unavailable', reason: 'service-malformed-data', restartCount: 1, terminatedGeneration: 2 })
        } finally {
            await disposeFixture(fixture)
        }
    })

    await context.test('duplicate settled response', async () => {
        const fixture = createFixture()
        try {
            assert.equal((await fixture.client.start()).status, 'ready')
            const transport = fixture.transports[0]
            transport.autoList = false
            const listing = fixture.client.list()
            const settledRequest = transport.lastRequest('devices-list')
            const settledResponse = responseEnvelope(settledRequest, { ok: true, listRevision: 0, devices: [] })
            transport.deliver(settledResponse)
            assert.equal((await listing).ok, true)

            const { cancelRequest, operationId } = await beginHeldCancellation(fixture, 'op:duplicate-response')
            transport.deliverMany([...heldTerminal(operationId), settledResponse, responseEnvelope(cancelRequest, { ok: true, cancellationCutover: 4 })])

            assert.deepEqual(await fixture.state.cancellation, { ok: false, reason: 'operation-outcome-unknown', ambiguous: true })
            await waitFor(() => fixture.client.getState().status === 'unavailable')
            assert.equal(hasPublicTerminal(fixture), false)
            assert.equal(fixture.client.getState().reason, 'service-malformed-data')
        } finally {
            await disposeFixture(fixture)
        }
    })
})

test('a response with the wrong pending-method shape faults before held terminal publication', async () => {
    const fixture = createFixture()
    try {
        const { cancelRequest, operationId, transport } = await beginHeldCancellation(fixture, 'op:wrong-response-shape')
        transport.autoList = false
        const listing = fixture.client.list()
        const listRequest = transport.lastRequest('devices-list')
        transport.deliverMany([...heldTerminal(operationId), responseEnvelope(listRequest, { ok: true }), responseEnvelope(cancelRequest, { ok: true, cancellationCutover: 4 })])

        assert.deepEqual(await listing, { ok: false, reason: 'invalid-service-response' })
        assert.deepEqual(await fixture.state.cancellation, { ok: false, reason: 'operation-outcome-unknown', ambiguous: true })
        await waitFor(() => fixture.client.getState().status === 'unavailable')
        assert.equal(hasPublicTerminal(fixture), false)
        assert.equal(fixture.client.getState().reason, 'service-malformed-data')
    } finally {
        await disposeFixture(fixture)
    }
})

test('legitimate pending list and scan responses resolve FIFO before the cancel acknowledgement', async (context) => {
    for (const method of ['devices-list', 'devices-scan']) {
        await context.test(method, async () => {
            const gate = createGate()
            const fixture = createFixture({ terminalBarrier: gate.promise })
            try {
                const { cancelRequest, operationId, transport } = await beginHeldCancellation(fixture, `op:pending-${method}`)
                transport.autoList = false
                let pendingSettled = false
                const pending = method === 'devices-list' ? fixture.client.list() : fixture.client.scan({ kind: 'scan' })
                const request = transport.lastRequest(method)
                const result = method === 'devices-list' ? { ok: true, listRevision: 0, devices: [] } : { ok: true }
                const expected = method === 'devices-list' ? { ok: true, status: 'ready', mode: 'native', privileged: true, hardwareReady: true, hardwareVerified: false, platformCapability: { state: 'available' }, epoch: 1, listRevision: 0, devices: [] } : { ok: true }
                /** @returns {Promise<object>} Tracks the read acknowledgement independently of terminal publication. */
                async function trackPendingResponse() {
                    const value = await pending
                    pendingSettled = true
                    return value
                }
                const tracked = trackPendingResponse()
                transport.deliverMany([...heldTerminal(operationId), responseEnvelope(request, result), responseEnvelope(cancelRequest, { ok: true, cancellationCutover: 4 }), deviceSuffix()])

                await waitFor(() => fixture.state.terminalEntered)
                assert.equal(pendingSettled, true)
                assert.equal(hasPublicTerminal(fixture), false)
                assert.equal(
                    fixture.publicEvents.some((envelope) => envelope.channel === 'device' && envelope.event.listRevision === 1),
                    false
                )

                gate.resolve()
                assert.deepEqual(await tracked, expected)
                assert.deepEqual(await fixture.state.cancellation, { ok: true, cancellationCutover: 4 })
                await waitFor(() => fixture.publicEvents.some((envelope) => envelope.channel === 'device' && envelope.event.listRevision === 1))
                const terminalIndex = fixture.publicEvents.findIndex((envelope) => envelope.channel === 'operation' && envelope.event.state === 'cancelled')
                const suffixIndex = fixture.publicEvents.findIndex((envelope) => envelope.channel === 'device' && envelope.event.listRevision === 1)
                assert.equal(terminalIndex >= 0 && suffixIndex > terminalIndex, true)
                assert.equal(fixture.client.getState().status, 'ready')
            } finally {
                gate.resolve()
                await disposeFixture(fixture)
            }
        })
    }
})

test('cancel acknowledgement first retains the durable terminal and suffix barriers', async () => {
    const gate = createGate()
    const fixture = createFixture({ terminalBarrier: gate.promise })
    try {
        const { cancelRequest, operationId, transport } = await beginHeldCancellation(fixture, 'op:ack-first')
        transport.deliverMany([...heldTerminal(operationId), responseEnvelope(cancelRequest, { ok: true, cancellationCutover: 4 }), deviceSuffix()])

        await waitFor(() => fixture.state.terminalEntered)
        assert.equal(hasPublicTerminal(fixture), false)
        assert.equal(
            fixture.publicEvents.some((envelope) => envelope.channel === 'device' && envelope.event.listRevision === 1),
            false
        )

        gate.resolve()
        assert.deepEqual(await fixture.state.cancellation, { ok: true, cancellationCutover: 4 })
        await waitFor(() => fixture.publicEvents.some((envelope) => envelope.channel === 'device' && envelope.event.listRevision === 1))
        assert.equal(hasPublicTerminal(fixture), true)
        assert.equal(fixture.client.getState().status, 'ready')
    } finally {
        gate.resolve()
        await disposeFixture(fixture)
    }
})

test('negative acknowledgement still faults the held terminal and suppresses its suffix', async () => {
    const fixture = createFixture()
    try {
        const { cancelRequest, operationId, transport } = await beginHeldCancellation(fixture, 'op:negative-ack')
        transport.deliverMany([...heldTerminal(operationId), responseEnvelope(cancelRequest, { ok: false, reason: 'operation-not-cancellable' }), deviceSuffix()])

        assert.deepEqual(await fixture.state.cancellation, { ok: false, reason: 'operation-not-cancellable' })
        await waitFor(() => fixture.client.getState().status === 'unavailable')
        assert.equal(hasPublicTerminal(fixture), false)
        assert.equal(
            fixture.publicEvents.some((envelope) => envelope.channel === 'device' && envelope.event.listRevision === 1),
            false
        )
        assert.equal(fixture.client.getState().reason, 'service-malformed-data')
    } finally {
        await disposeFixture(fixture)
    }
})

test('transport fault and request timeout still reject a held terminal without a recursive drain', async (context) => {
    const scenarios = [
        { name: 'transport fault', reason: 'service-exited', trigger: (fixture, transport) => transport.emit('error') },
        { name: 'request timeout', reason: 'service-request-timeout', trigger: (fixture) => fixture.timers.fireDelay(REQUEST_TIMEOUT_MS) }
    ]
    for (const scenario of scenarios) {
        await context.test(scenario.name, async () => {
            const fixture = createFixture()
            try {
                const { operationId, transport } = await beginHeldCancellation(fixture, `op:${scenario.name.replace(' ', '-')}`)
                transport.deliverMany(heldTerminal(operationId))
                scenario.trigger(fixture, transport)

                assert.deepEqual(await fixture.state.cancellation, { ok: false, reason: 'operation-outcome-unknown', ambiguous: true })
                await waitFor(() => fixture.client.getState().status === 'unavailable')
                assert.equal(hasPublicTerminal(fixture), false)
                assert.equal(fixture.client.getState().reason, scenario.reason)
            } finally {
                await disposeFixture(fixture)
            }
        })
    }
})
