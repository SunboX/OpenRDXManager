// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'

import { DeviceServiceClient } from '../src/main/device-service-client.mjs'

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

/** @returns {Promise<void>} Resolves after queued microtasks and promise continuations. */
async function nextTurn() {
    await new Promise(setImmediate)
}

/** @param {() => boolean} predicate - Completion predicate. @returns {Promise<void>} Resolves when it becomes true. */
async function waitFor(predicate) {
    for (let attempt = 0; attempt < 40; attempt += 1) {
        if (predicate()) return
        await nextTurn()
    }
    assert.fail('controlled condition did not become true')
}

/** Creates a caller-controlled promise. @returns {{promise: Promise<boolean>, resolve: (value: boolean) => void, reject: () => void}} Gate controls. */
function createGate() {
    let resolve
    let reject
    const promise = new Promise((resolveGate, rejectGate) => {
        resolve = resolveGate
        reject = rejectGate
    })
    return {
        promise,
        resolve,
        /** @returns {void} Rejects with a fixed non-sensitive failure. */
        reject() {
            reject(new Error('controlled-critical-write-failure'))
        }
    }
}

/** Deterministic restart timer queue. */
class ManualTimers {
    /** Creates an empty timer queue. */
    constructor() {
        this.nextId = 1
        this.pending = new Map()
    }

    /** @param {Function} callback - Timer callback. @param {number} delay - Delay. @returns {number} Timer identity. */
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

    /** @param {number} delay - Exact delay to fire. @returns {void} Fires one matching timer. */
    fireDelay(delay) {
        const entry = [...this.pending.entries()].find(([, timer]) => timer.delay === delay)
        assert.notEqual(entry, undefined)
        this.pending.delete(entry[0])
        entry[1].callback()
    }
}

/** Native-like transport with strict automatic handshake/list and controlled operation messages. */
class BoundaryTransport extends EventEmitter {
    /** @param {number} generation - Exact launch number. */
    constructor(generation) {
        super()
        this.closed = false
        this.generation = generation
        this.messages = []
    }

    /** @param {Buffer} frame - Main-owned request. @returns {{ok: true}} Accepts it. */
    write(frame) {
        const message = decodeFrame(frame)
        this.messages.push(message)
        if (message.type === 'handshake-request') {
            queueMicrotask(() => this.deliver({ type: 'handshake', protocolVersion: 1, serviceVersion: `boundary-${this.generation}`, platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
        } else if (message.method === 'devices-list') {
            queueMicrotask(() => this.respond(message, { ok: true, listRevision: 0, devices: [] }))
        } else if (message.method === 'operation-start') {
            queueMicrotask(() => this.respond(message, { ok: true }))
        }
        return { ok: true }
    }

    /** @param {object} request - Exact request. @param {object} result - Strict result. @returns {void} Delivers it. */
    respond(request, result) {
        this.deliver({ type: 'response', requestId: request.requestId, ok: true, result })
    }

    /** @param {object} message - Strict service message. @returns {void} Emits one frame. */
    deliver(message) {
        this.emit('data', encodeFrame(message))
    }

    /** @param {object[]} messages - Strict service messages. @returns {void} Emits one coalesced frame group. */
    deliverMany(messages) {
        this.emit('data', Buffer.concat(messages.map(encodeFrame)))
    }

    /** @param {string} method - Requested method. @returns {object} Latest exact request. */
    lastRequest(method) {
        const request = this.messages.findLast((message) => message.method === method)
        assert.notEqual(request, undefined)
        return request
    }

    /** @returns {{confirmed: true}} Confirms exact-generation closure. */
    close() {
        this.closed = true
        return { confirmed: true }
    }
}

/**
 * Creates one client and records all launched transports.
 * @param {{logger?: object, maxRestarts?: number, timers?: ManualTimers}} [options] - Controlled client options.
 * @returns {{client: DeviceServiceClient, transports: BoundaryTransport[]}} Fixture.
 */
function createClient(options = {}) {
    const transports = []

    /** @returns {BoundaryTransport} Creates the next exact generation. */
    function transportFactory() {
        const transport = new BoundaryTransport(transports.length + 1)
        transports.push(transport)
        return transport
    }

    const client = new DeviceServiceClient({
        executable: '/private/openrdx/openrdx-hardware',
        logger: options.logger,
        maxRestarts: options.maxRestarts ?? 0,
        platform: 'darwin',
        restartBackoffMs: [0],
        ...(options.timers === undefined ? {} : { timers: options.timers }),
        transportFactory
    })
    return { client, transports }
}

test('a stopped reconciliation never resurrects ready or its initial list after a late critical write', async (context) => {
    const cases = [
        { name: 'successful-write', settle: (gate) => gate.resolve(true) },
        { name: 'rejected-write', settle: (gate) => gate.reject() },
        { name: 'timed-out-write', settle: (gate) => gate.resolve(false) }
    ]
    for (const scenario of cases) {
        await context.test(scenario.name, async () => {
            const gate = createGate()
            const lifecycle = []
            const events = []
            let readyEntered = false
            const logger = {
                /** @param {object} record - Candidate activity or legacy critical record. @returns {boolean|Promise<boolean>} Holds legacy ready persistence too. */
                write(record) {
                    if (record.status === 'ready') {
                        readyEntered = true
                        return gate.promise
                    }
                    return true
                },
                /** @param {object} record - Candidate critical record. @returns {Promise<boolean>} Holds ready persistence. */
                writeCritical(record) {
                    if (record.status === 'ready') {
                        readyEntered = true
                        return gate.promise
                    }
                    return Promise.resolve(true)
                }
            }
            const { client } = createClient({ logger })
            client.subscribeLifecycle((state) => lifecycle.push(state))
            client.subscribeEvents((event) => events.push(event))

            const starting = client.start()
            await waitFor(() => readyEntered)
            await client.stop()
            assert.equal((await starting).status, 'stopped')
            scenario.settle(gate)
            await nextTurn()

            assert.equal(['stopped', 'unavailable'].includes(client.getState().status), true)
            assert.equal(
                lifecycle.some((state) => state.status === 'ready'),
                false
            )
            assert.equal(
                events.some((event) => event.channel === 'device' && event.event.type === 'list'),
                false
            )
        })
    }
})

test('a ready listener that stops the client prevents the immediately following initial list publication', async () => {
    const { client } = createClient({ logger: { write: () => true, writeCritical: () => Promise.resolve(true) } })
    const events = []
    let stopPromise = null
    client.subscribeLifecycle((state) => {
        if (state.status === 'ready') stopPromise = client.stop()
    })
    client.subscribeEvents((event) => events.push(event))

    const outcome = await client.start()
    await stopPromise
    assert.equal(outcome.status, 'stopped')
    assert.equal(client.getState().status, 'stopped')
    assert.equal(
        events.some((event) => event.channel === 'device' && event.event.type === 'list'),
        false
    )
})

test('a restart cannot inherit ready or list publication from a prior blocked reconciliation', async () => {
    const firstReady = createGate()
    const lifecycle = []
    const lists = []
    let readyWrites = 0
    const logger = {
        /** @returns {boolean} Accepts optional activity. */
        write() {
            return true
        },
        /** @param {object} record - Critical lifecycle record. @returns {boolean|Promise<boolean>} Holds only generation one. */
        writeCritical(record) {
            if (record.status !== 'ready') return true
            readyWrites += 1
            return readyWrites === 1 ? firstReady.promise : true
        }
    }
    const { client, transports } = createClient({ logger })
    client.subscribeLifecycle((state) => lifecycle.push(state))
    client.subscribeEvents((envelope) => {
        if (envelope.channel === 'device' && envelope.event.type === 'list') lists.push(envelope.event)
        return true
    })

    const firstStart = client.start()
    await waitFor(() => readyWrites === 1)
    const stopping = client.stop()
    const restarting = client.start()
    assert.equal((await firstStart).status, 'stopped')
    await stopping
    assert.equal((await restarting).generation, 2)
    firstReady.resolve(true)
    await nextTurn()

    assert.equal(transports.length, 2)
    assert.deepEqual(
        lifecycle.filter((state) => state.status === 'ready').map((state) => state.generation),
        [2]
    )
    assert.equal(lists.length, 1)
    await client.stop()
})

test('an old-generation asynchronous observer never resumes into later listeners after restart', async () => {
    const timers = new ManualTimers()
    const observerGate = createGate()
    const later = []
    const { client, transports } = createClient({ maxRestarts: 1, timers })
    client.subscribeEvents((envelope) => (envelope.channel === 'operation' ? observerGate.promise : true))
    client.subscribeEvents((envelope) => later.push(envelope))
    await client.start()
    later.length = 0
    const started = await client.startOperation({ operationId: 'op:stale-observer', request: { kind: 'self-test', deviceId: 'rdx:final-boundary', deviceRevision: 7 } })
    assert.equal(started.ok, true)

    transports[0].deliver({ type: 'event', channel: 'operation', publicationSequence: 1, event: { state: 'started', operationId: 'op:stale-observer', kind: 'self-test', deviceId: 'rdx:final-boundary', deviceRevision: 7, stage: 'diagnostic-running' } })
    await nextTurn()
    transports[0].emit('exit')
    await nextTurn()
    assert.equal(client.getState().status, 'restarting')
    timers.fireDelay(0)
    await waitFor(() => client.getState().generation === 2 && client.getState().status === 'ready')
    later.length = 0

    observerGate.resolve(true)
    await nextTurn()
    assert.deepEqual(later, [])
    assert.equal(transports.length, 2)
    assert.equal(client.getState().generation, 2)
    await client.stop()
})

test('reentrant subscription changes apply only to the next observer delivery snapshot', async () => {
    const gate = createGate()
    const observed = []
    const { client, transports } = createClient()
    let subscribed = false
    client.subscribeEvents((envelope) => {
        if (envelope.channel !== 'operation') return true
        observed.push(`first:${envelope.event.state}`)
        if (!subscribed) {
            subscribed = true
            client.subscribeEvents((laterEnvelope) => {
                if (laterEnvelope.channel === 'operation') observed.push(`new:${laterEnvelope.event.state}`)
                return true
            })
        }
        return gate.promise
    })
    client.subscribeEvents((envelope) => {
        if (envelope.channel === 'operation') observed.push(`second:${envelope.event.state}`)
        return true
    })
    await client.start()
    const operationId = 'op:reentrant-subscribe'
    assert.equal((await client.startOperation({ operationId, request: { kind: 'self-test', deviceId: 'rdx:final-boundary', deviceRevision: 7 } })).ok, true)
    transports[0].deliver({ type: 'event', channel: 'operation', publicationSequence: 1, event: { state: 'started', operationId, kind: 'self-test', deviceId: 'rdx:final-boundary', deviceRevision: 7, stage: 'diagnostic-running' } })
    await nextTurn()
    assert.deepEqual(observed, ['first:started'])

    gate.resolve(true)
    await nextTurn()
    assert.deepEqual(observed, ['first:started', 'second:started'])
    transports[0].deliver({ type: 'event', channel: 'operation', publicationSequence: 2, event: { state: 'progress', operationId, kind: 'self-test', deviceId: 'rdx:final-boundary', deviceRevision: 7, stage: 'diagnostic-running', progress: 0.5, cancellationState: 'cancellable' } })
    await nextTurn()
    assert.deepEqual(observed.slice(-3), ['first:progress', 'second:progress', 'new:progress'])
    await client.stop()
})

test('a closed pre-cutover progress latch rejects a later cancelled terminal before observers', async () => {
    const { client, transports } = createClient()
    const forwarded = []
    client.subscribeEvents((envelope) => {
        forwarded.push(envelope)
        return true
    })
    await client.start()
    const operationId = 'op:sequence-closed'
    assert.equal((await client.startOperation({ operationId, request: { kind: 'self-test', deviceId: 'rdx:final-boundary', deviceRevision: 7 } })).ok, true)
    transports[0].deliver({ type: 'event', channel: 'operation', publicationSequence: 1, event: { state: 'started', operationId, kind: 'self-test', deviceId: 'rdx:final-boundary', deviceRevision: 7, stage: 'diagnostic-running' } })
    const cancellation = client.cancelOperation({ operationId })
    transports[0].deliverMany([
        { type: 'event', channel: 'operation', publicationSequence: 2, event: { state: 'progress', operationId, kind: 'self-test', deviceId: 'rdx:final-boundary', deviceRevision: 7, stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'closed' } },
        { type: 'event', channel: 'operation', publicationSequence: 3, event: { state: 'cancelled', operationId, kind: 'self-test', deviceId: 'rdx:final-boundary', deviceRevision: 7, stage: 'diagnostic-cleanup' } }
    ])
    await nextTurn()

    assert.equal(transports[0].closed, true)
    assert.equal(
        forwarded.some((envelope) => envelope.channel === 'operation' && envelope.event.state === 'cancelled'),
        false
    )
    assert.equal((await cancellation).ok, false)
})

test('fatal logger containment publishes one unavailable notification across repeated stop', async () => {
    const { client } = createClient()
    const unavailable = []
    client.subscribeLifecycle((state) => {
        if (state.status === 'unavailable' && state.reason === 'event-log-unavailable') unavailable.push(state)
    })
    assert.equal(client.faultEventLog(0), true)
    await waitFor(() => client.getState().status === 'unavailable')
    await client.stop()
    await client.stop()

    assert.equal(unavailable.length, 1)
})
