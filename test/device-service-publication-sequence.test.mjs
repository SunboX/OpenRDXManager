// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'

import { DeviceServiceClient } from '../src/main/device-service-client.mjs'

test('native format validation stays cancellable until the layout boundary without losing the service', async (context) => {
    const transports = []
    const client = createClient(transports)
    context.after(() => client.stop())
    await client.start()
    const transport = transports[0]
    const owner = { operationId: 'op:format-validation', kind: 'format', deviceId: 'rdx:sequence-1', deviceRevision: 1 }
    const request = client.startOperation({ operationId: owner.operationId, request: { kind: owner.kind, deviceId: owner.deviceId, deviceRevision: owner.deviceRevision, filesystem: 'ntfs', confirmationToken: 'confirm:format-test' } })
    transport.respond(transport.lastRequest('operation-start'), { ok: true })
    assert.equal((await request).ok, true)
    const events = []
    client.subscribeEvents((envelope) => {
        events.push(envelope.event)
        return true
    })
    let sequence = 0
    /** @param {object} event - Native lifecycle publication. @returns {void} Delivers in causal order. */
    const publish = (event) => transport.deliver({ type: 'event', channel: 'operation', publicationSequence: ++sequence, event: { ...owner, ...event } })
    publish({ state: 'started', stage: 'format-validating' })
    publish({ state: 'progress', stage: 'format-validating', progress: 0, cancellationState: 'cancellable' })
    publish({ state: 'progress', stage: 'format-validating', progress: 0, cancellationState: 'cancellable' })
    for (const [index, stage] of ['format-writing', 'format-finalizing', 'format-readback'].entries()) publish({ state: 'progress', stage, progress: (index + 1) / 4, cancellationState: 'closed' })
    publish({ state: 'succeeded', stage: 'complete' })
    await nextTurn()
    assert.equal(client.getState().status, 'ready')
    assert.equal(events.at(-1).state, 'succeeded')
    assert.equal(transports.length, 1)
})

test('format failures remain visible at each reached native stage without tearing down the service', async (context) => {
    const transports = []
    const client = createClient(transports)
    context.after(() => client.stop())
    await client.start()
    const transport = transports[0]
    const stages = ['format-validating', 'format-writing', 'format-finalizing', 'format-readback']
    let sequence = 0
    for (const [index, terminalStage] of stages.entries()) {
        const owner = { operationId: `op:format-failure-${index}`, kind: 'format', deviceId: 'rdx:sequence-1', deviceRevision: 1 }
        const start = client.startOperation({ operationId: owner.operationId, request: { kind: owner.kind, deviceId: owner.deviceId, deviceRevision: owner.deviceRevision, filesystem: 'ntfs', confirmationToken: 'confirm:format-test' } })
        transport.respond(transport.lastRequest('operation-start'), { ok: true })
        assert.equal((await start).ok, true)
        /** @param {object} event - Native lifecycle publication. @returns {void} Delivers the exact next publication. */
        const publish = (event) => transport.deliver({ type: 'event', channel: 'operation', publicationSequence: ++sequence, event: { ...owner, ...event } })
        publish({ state: 'started', stage: stages[0] })
        for (const stage of stages.slice(0, index + 1)) publish({ state: 'progress', stage, progress: 0, cancellationState: stage === stages[0] ? 'cancellable' : 'closed' })
        publish({ state: 'failed', stage: terminalStage, error: { code: 'format-failed', messageKey: 'errors.operation.failed', stage: terminalStage, category: 'platform', retryable: false, supportCorrelationId: 'support:format-failure', cleanupEvidence: [], attemptHistory: [] } })
        await nextTurn()
        assert.equal(client.getState().status, 'ready')
    }
    assert.equal(transports.length, 1)
})

/** @param {Buffer} frame - Complete outbound frame. @returns {object} Decoded message. */
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

/** Deterministic restart timer queue. */
class ManualTimers {
    /** Creates an empty timer queue. */
    constructor() {
        this.nextId = 1
        this.pending = new Map()
    }

    /** @param {Function} callback - Timer callback. @param {number} delay - Delay. @returns {number} Timer ID. */
    setTimeout(callback, delay) {
        const id = this.nextId
        this.nextId += 1
        this.pending.set(id, { callback, delay })
        return id
    }

    /** @param {number} id - Timer ID. @returns {void} Clears the timer. */
    clearTimeout(id) {
        this.pending.delete(id)
    }

    /** @param {number} delay - Exact queued delay. @returns {void} Fires one matching timer. */
    fireDelay(delay) {
        const entry = [...this.pending.entries()].find(([, timer]) => timer.delay === delay)
        assert.notEqual(entry, undefined)
        this.pending.delete(entry[0])
        entry[1].callback()
    }
}

/** Native-like transport with caller-controlled operation publications. */
class SequenceTransport extends EventEmitter {
    /** Creates an open transport with recorded requests. */
    constructor() {
        super()
        this.closed = false
        this.messages = []
    }

    /** @param {Buffer} frame - Main-owned request frame. @returns {{ok: true}} Accepts the write. */
    write(frame) {
        const message = decodeFrame(frame)
        this.messages.push(message)
        if (message.type === 'handshake-request') {
            queueMicrotask(() => this.deliver({ type: 'handshake', protocolVersion: 1, serviceVersion: 'sequence-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
        } else if (message.method === 'devices-list') {
            queueMicrotask(() => this.respond(message, { ok: true, listRevision: 0, devices: [] }))
        }
        return { ok: true }
    }

    /** @param {object} message - Exact request. @param {object} result - Controlled result. @returns {void} Delivers its response. */
    respond(message, result) {
        this.deliver({ type: 'response', requestId: message.requestId, ok: true, result })
    }

    /** @param {object} message - Controlled strict wire message. @returns {void} Emits one framed message. */
    deliver(message) {
        this.emit('data', encodeFrame(message))
    }

    /** @param {object[]} messages - Controlled strict wire messages. @returns {void} Emits one coalesced transport chunk. */
    deliverMany(messages) {
        this.emit('data', Buffer.concat(messages.map(encodeFrame)))
    }

    /** @param {string} method - Requested method. @returns {object} Latest matching outbound request. */
    lastRequest(method) {
        const request = this.messages.findLast((message) => message.method === method)
        assert.notEqual(request, undefined)
        return request
    }

    /** @returns {{confirmed: true}} Confirms bounded teardown. */
    close() {
        this.closed = true
        return { confirmed: true }
    }
}

/** @param {SequenceTransport[]} transports - Launch sink. @param {ManualTimers|undefined} timers - Optional manual timers. @returns {DeviceServiceClient} Controlled client. */
function createClient(transports, timers) {
    /** @returns {SequenceTransport} Creates the next generation transport. */
    function transportFactory() {
        const transport = new SequenceTransport()
        transports.push(transport)
        return transport
    }
    return new DeviceServiceClient({
        executable: '/private/openrdx/openrdx-hardware',
        maxRestarts: timers === undefined ? 0 : 1,
        platform: 'darwin',
        restartBackoffMs: [0],
        ...(timers === undefined ? {} : { timers }),
        transportFactory
    })
}

/** @param {DeviceServiceClient} client - Ready client. @param {SequenceTransport} transport - Current transport. @param {string} operationId - Operation identity. @returns {Promise<void>} Resolves after positive reservation acknowledgement. */
async function reserveOperation(client, transport, operationId) {
    const result = client.startOperation({ operationId, request: { kind: 'self-test', deviceId: 'rdx:sequence-1', deviceRevision: 1 } })
    transport.respond(transport.lastRequest('operation-start'), { ok: true })
    assert.deepEqual(await result, { ok: true })
}

/** @param {SequenceTransport} transport - Current transport. @param {number} publicationSequence - Exact sequence. @param {string} operationId - Owner. @returns {void} Delivers started evidence. */
function deliverStarted(transport, publicationSequence, operationId) {
    transport.deliver({ type: 'event', channel: 'operation', publicationSequence, event: { state: 'started', operationId, kind: 'self-test', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'diagnostic-running' } })
}

/** @param {SequenceTransport} transport - Current transport. @param {number} publicationSequence - Candidate sequence. @param {string} operationId - Owner. @returns {void} Delivers progress evidence. */
function deliverProgress(transport, publicationSequence, operationId) {
    transport.deliver({ type: 'event', channel: 'operation', publicationSequence, event: { state: 'progress', operationId, kind: 'self-test', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'diagnostic-running', progress: 0.5, cancellationState: 'cancellable' } })
}

/** @param {SequenceTransport} transport - Current transport. @param {number} publicationSequence - Exact sequence. @param {string} operationId - Owner. @returns {void} Delivers final cleanup progress. */
function deliverCleanup(transport, publicationSequence, operationId) {
    transport.deliver({ type: 'event', channel: 'operation', publicationSequence, event: progressEvent(operationId, { stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'closed' }) })
}

/** @param {SequenceTransport} transport - Current transport. @param {number} publicationSequence - Exact sequence. @param {string} operationId - Owner. @returns {void} Delivers success evidence. */
function deliverSuccess(transport, publicationSequence, operationId) {
    transport.deliver({ type: 'event', channel: 'operation', publicationSequence, event: { state: 'succeeded', operationId, kind: 'self-test', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'complete' } })
}

/** @param {number} publicationSequence - Exact sequence. @param {object} event - Strict operation event. @returns {object} Wire envelope. */
function operationEnvelope(publicationSequence, event) {
    return { type: 'event', channel: 'operation', publicationSequence, event }
}

/** @param {string} operationId - Owner. @param {object} [overrides] - Controlled field replacements. @returns {object} Strict started event. */
function startedEvent(operationId, overrides = {}) {
    return { state: 'started', operationId, kind: 'self-test', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'diagnostic-running', ...overrides }
}

/** @param {string} operationId - Owner. @param {object} [overrides] - Controlled field replacements. @returns {object} Strict progress event. */
function progressEvent(operationId, overrides = {}) {
    return { state: 'progress', operationId, kind: 'self-test', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'diagnostic-running', progress: 0.5, cancellationState: 'cancellable', ...overrides }
}

/** @param {string} operationId - Owner. @param {object} [overrides] - Controlled field replacements. @returns {object} Strict success event. */
function successEvent(operationId, overrides = {}) {
    return { state: 'succeeded', operationId, kind: 'self-test', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'complete', ...overrides }
}

test('accepts one exact generation sequence across terminal release and a new reservation', async () => {
    const transports = []
    const client = createClient(transports)
    const events = []
    client.subscribeEvents((event) => events.push(event))
    await client.start()

    await reserveOperation(client, transports[0], 'op:sequence-a')
    deliverStarted(transports[0], 1, 'op:sequence-a')
    deliverCleanup(transports[0], 2, 'op:sequence-a')
    deliverSuccess(transports[0], 3, 'op:sequence-a')
    await reserveOperation(client, transports[0], 'op:sequence-b')
    deliverStarted(transports[0], 4, 'op:sequence-b')

    assert.deepEqual(
        events.filter((event) => event.channel === 'operation').map((event) => [event.publicationSequence, event.event.operationId]),
        [
            [1, 'op:sequence-a'],
            [2, 'op:sequence-a'],
            [3, 'op:sequence-a'],
            [4, 'op:sequence-b']
        ]
    )
    assert.equal(client.getState().status, 'ready')
    await client.stop()
})

test('ordinary firmware updates publish the direct writing edge through the strict service boundary', async () => {
    const transports = []
    const client = createClient(transports)
    const events = []
    client.subscribeEvents((event) => events.push(event))
    try {
        await client.start()
        const transport = transports[0]
        const owner = { operationId: 'op:ordinary-firmware', kind: 'firmware-update', deviceId: 'rdx:sequence-1', deviceRevision: 1 }
        const started = client.startOperation({ operationId: owner.operationId, request: { kind: owner.kind, deviceId: owner.deviceId, deviceRevision: owner.deviceRevision, firmwareFileToken: 'firmware:sequence' } })
        transport.respond(transport.lastRequest('operation-start'), { ok: true })
        assert.deepEqual(await started, { ok: true })
        transport.deliver(operationEnvelope(1, { ...owner, state: 'started', stage: 'firmware-validating' }))
        for (const [index, stage] of ['firmware-writing', 'firmware-finalizing', 'device-reconnecting', 'firmware-readback'].entries()) {
            // Native host progress uses the complete 12-stage graph even for a direct update.
            transport.deliver(operationEnvelope(index + 2, { ...owner, state: 'progress', stage, progress: (index + 8) / 12, cancellationState: 'closed' }))
        }
        transport.deliver(operationEnvelope(6, { ...owner, state: 'succeeded', stage: 'complete' }))
        await nextTurn()
        assert.equal(client.getState().status, 'ready')
        assert.equal(transport.closed, false)
        assert.deepEqual(
            events.filter((event) => event.channel === 'operation').map((event) => event.event.stage),
            ['firmware-validating', 'firmware-writing', 'firmware-finalizing', 'device-reconnecting', 'firmware-readback', 'complete']
        )
    } finally {
        await client.stop()
    }
})

test('faults post-cancellation duplicate, decrement, gap, wrap-attempt, and foreign-owner publications', async (context) => {
    const scenarios = [
        { name: 'duplicate', beforeCancel: [], sequence: 1, operationId: 'op:hostile' },
        { name: 'decrement', beforeCancel: [2], sequence: 1, operationId: 'op:hostile' },
        { name: 'gap', beforeCancel: [], sequence: 3, operationId: 'op:hostile' },
        { name: 'wrap-attempt', beforeCancel: [], sequence: Number.MAX_SAFE_INTEGER, operationId: 'op:hostile' },
        { name: 'foreign-owner', beforeCancel: [], sequence: 2, operationId: 'op:foreign' }
    ]
    for (const scenario of scenarios) {
        /** @returns {Promise<void>} Exercises one independent hostile sequence. */
        async function exercise() {
            const transports = []
            const client = createClient(transports)
            const forwarded = []
            client.subscribeEvents((event) => forwarded.push(event))
            await client.start()
            const transport = transports[0]
            await reserveOperation(client, transport, 'op:hostile')
            deliverStarted(transport, 1, 'op:hostile')
            for (const sequence of scenario.beforeCancel) deliverProgress(transport, sequence, 'op:hostile')
            const cancellation = client.cancelOperation({ operationId: 'op:hostile' })
            transport.respond(transport.lastRequest('operation-cancel'), { ok: true, cancellationCutover: scenario.beforeCancel.at(-1) ?? 1 })
            assert.equal((await cancellation).ok, true)

            deliverProgress(transport, scenario.sequence, scenario.operationId)
            await nextTurn()

            assert.equal(transport.closed, true)
            assert.deepEqual(
                forwarded.filter((event) => event.channel === 'operation').map((event) => event.publicationSequence),
                [1, ...scenario.beforeCancel]
            )
            assert.deepEqual(client.getState(), { status: 'unavailable', reason: 'service-malformed-data', restartCount: 0, terminatedGeneration: 1 })
        }
        await context.test(scenario.name, exercise)
    }
})

test('rejects a cancellation cutover below the highest consumed publication', async () => {
    const transports = []
    const client = createClient(transports)
    await client.start()
    const transport = transports[0]
    await reserveOperation(client, transport, 'op:low-cutover')
    deliverStarted(transport, 1, 'op:low-cutover')
    deliverProgress(transport, 2, 'op:low-cutover')

    const cancellation = client.cancelOperation({ operationId: 'op:low-cutover' })
    transport.respond(transport.lastRequest('operation-cancel'), { ok: true, cancellationCutover: 1 })

    assert.deepEqual(await cancellation, { ok: false, reason: 'operation-outcome-unknown', ambiguous: true })
    await nextTurn()
    assert.deepEqual(client.getState(), { status: 'unavailable', reason: 'service-malformed-data', restartCount: 0, terminatedGeneration: 1 })
})

test('rejects a cancellation cutover beyond the bounded native FIFO prefix', async () => {
    const transports = []
    const client = createClient(transports)
    await client.start()
    const transport = transports[0]
    await reserveOperation(client, transport, 'op:high-cutover')
    deliverStarted(transport, 1, 'op:high-cutover')

    const cancellation = client.cancelOperation({ operationId: 'op:high-cutover' })
    transport.respond(transport.lastRequest('operation-cancel'), { ok: true, cancellationCutover: 132 })

    assert.deepEqual(await cancellation, { ok: false, reason: 'operation-outcome-unknown', ambiguous: true })
    await nextTurn()
    assert.deepEqual(client.getState(), { status: 'unavailable', reason: 'service-malformed-data', restartCount: 0, terminatedGeneration: 1 })
})

test('enforces accepted and rejected cancellation acknowledgements before listeners', async (context) => {
    const scenarios = [
        {
            name: 'accepted-cutover-closes-cancellable-prefix',
            cancellationResult: { ok: true, cancellationCutover: 1 },
            invalidProgress: progressEvent('op:cancellation-proof')
        },
        {
            name: 'rejected-cancellation-rolls-back-requested-state',
            cancellationResult: { ok: false, reason: 'operation-not-cancellable' },
            invalidProgress: progressEvent('op:cancellation-proof', { cancellationState: 'requested' })
        }
    ]
    for (const scenario of scenarios) {
        /** @returns {Promise<void>} Exercises one cancellation acknowledgement boundary. */
        async function exercise() {
            const transports = []
            const client = createClient(transports)
            const forwarded = []
            client.subscribeEvents((event) => forwarded.push(event))
            await client.start()
            const transport = transports[0]
            await reserveOperation(client, transport, 'op:cancellation-proof')
            deliverStarted(transport, 1, 'op:cancellation-proof')

            const cancellation = client.cancelOperation({ operationId: 'op:cancellation-proof' })
            transport.respond(transport.lastRequest('operation-cancel'), scenario.cancellationResult)
            assert.deepEqual(await cancellation, scenario.cancellationResult)
            transport.deliverMany([operationEnvelope(2, scenario.invalidProgress), { type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [] } }])
            await nextTurn()

            assert.equal(transport.closed, true)
            assert.deepEqual(
                forwarded.filter((event) => event.channel === 'operation').map((event) => event.publicationSequence),
                [1]
            )
            assert.equal(
                forwarded.some((event) => event.channel === 'device' && event.event.listRevision === 1),
                false
            )
        }
        await context.test(scenario.name, exercise)
    }
})

test('bounds cancellation cutover at reservation base plus exactly 130 publications', async () => {
    const transports = []
    const client = createClient(transports)
    await client.start()
    const transport = transports[0]

    await reserveOperation(client, transport, 'op:base-prefix')
    deliverStarted(transport, 1, 'op:base-prefix')
    deliverCleanup(transport, 2, 'op:base-prefix')
    deliverSuccess(transport, 3, 'op:base-prefix')
    await reserveOperation(client, transport, 'op:bounded-prefix')
    deliverStarted(transport, 4, 'op:bounded-prefix')

    const accepted = client.cancelOperation({ operationId: 'op:bounded-prefix' })
    transport.respond(transport.lastRequest('operation-cancel'), { ok: true, cancellationCutover: 133 })
    assert.deepEqual(await accepted, { ok: true, cancellationCutover: 133 })

    const transportsTwo = []
    const rejectedClient = createClient(transportsTwo)
    await rejectedClient.start()
    const rejectedTransport = transportsTwo[0]
    await reserveOperation(rejectedClient, rejectedTransport, 'op:base-prefix-two')
    deliverStarted(rejectedTransport, 1, 'op:base-prefix-two')
    deliverCleanup(rejectedTransport, 2, 'op:base-prefix-two')
    deliverSuccess(rejectedTransport, 3, 'op:base-prefix-two')
    await reserveOperation(rejectedClient, rejectedTransport, 'op:bounded-prefix-two')
    deliverStarted(rejectedTransport, 4, 'op:bounded-prefix-two')

    const rejected = rejectedClient.cancelOperation({ operationId: 'op:bounded-prefix-two' })
    rejectedTransport.respond(rejectedTransport.lastRequest('operation-cancel'), { ok: true, cancellationCutover: 134 })
    assert.deepEqual(await rejected, { ok: false, reason: 'operation-outcome-unknown', ambiguous: true })
    await nextTurn()
    assert.equal(rejectedTransport.closed, true)

    await client.stop()
    await rejectedClient.stop()
})

test('rejects the 131st lifecycle publication for one nonzero-base reservation', async () => {
    const transports = []
    const client = createClient(transports)
    const forwarded = []
    client.subscribeEvents((event) => forwarded.push(event))
    await client.start()
    const transport = transports[0]

    await reserveOperation(client, transport, 'op:budget-prefix')
    deliverStarted(transport, 1, 'op:budget-prefix')
    deliverCleanup(transport, 2, 'op:budget-prefix')
    deliverSuccess(transport, 3, 'op:budget-prefix')
    await reserveOperation(client, transport, 'op:budget-owner')
    deliverStarted(transport, 4, 'op:budget-owner')
    for (let sequence = 5; sequence <= 133; sequence += 1) {
        deliverProgress(transport, sequence, 'op:budget-owner')
    }
    assert.equal(forwarded.filter((event) => event.channel === 'operation' && event.event.operationId === 'op:budget-owner').length, 130)

    transport.deliver(operationEnvelope(134, progressEvent('op:budget-owner')))
    await nextTurn()

    assert.equal(transport.closed, true)
    assert.equal(forwarded.filter((event) => event.channel === 'operation' && event.event.operationId === 'op:budget-owner').length, 130)
    assert.deepEqual(client.getState(), { status: 'unavailable', reason: 'service-malformed-data', restartCount: 0, terminatedGeneration: 1 })
})

test('rejects every immutable reservation tuple mismatch before any listener', async (context) => {
    const scenarios = [
        { name: 'kind', replacement: { kind: 'led-test', stage: 'led-testing' } },
        { name: 'device-id', replacement: { deviceId: 'rdx:foreign-device' } },
        { name: 'device-revision', replacement: { deviceRevision: 2 } }
    ]
    for (const scenario of scenarios) {
        /** @returns {Promise<void>} Exercises one exact tuple mismatch. */
        async function exercise() {
            const transports = []
            const client = createClient(transports)
            const forwarded = []
            client.subscribeEvents((event) => forwarded.push(event))
            await client.start()
            await reserveOperation(client, transports[0], 'op:tuple-owner')

            transports[0].deliver(operationEnvelope(1, startedEvent('op:tuple-owner', scenario.replacement)))
            await nextTurn()

            assert.equal(transports[0].closed, true)
            assert.equal(
                forwarded.some((event) => event.channel === 'operation'),
                false
            )
            assert.deepEqual(client.getState(), { status: 'unavailable', reason: 'service-malformed-data', restartCount: 0, terminatedGeneration: 1 })
        }
        await context.test(scenario.name, exercise)
    }
})

test('rejects lifecycle order violations before listeners and stops a coalesced suffix', async (context) => {
    const scenarios = [
        { name: 'progress-before-started', prefix: [], invalid: progressEvent('op:lifecycle-owner') },
        { name: 'duplicate-started', prefix: [startedEvent('op:lifecycle-owner')], invalid: startedEvent('op:lifecycle-owner') },
        { name: 'terminal-stage-mismatch', prefix: [startedEvent('op:lifecycle-owner')], invalid: successEvent('op:lifecycle-owner', { stage: 'diagnostic-running' }) }
    ]
    for (const scenario of scenarios) {
        /** @returns {Promise<void>} Exercises one invalid lifecycle shape. */
        async function exercise() {
            const transports = []
            const client = createClient(transports)
            const forwarded = []
            client.subscribeEvents((event) => forwarded.push(event))
            await client.start()
            await reserveOperation(client, transports[0], 'op:lifecycle-owner')
            const messages = scenario.prefix.map((event, index) => operationEnvelope(index + 1, event))
            messages.push(operationEnvelope(messages.length + 1, scenario.invalid))
            messages.push({ type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [] } })

            transports[0].deliverMany(messages)
            await nextTurn()

            assert.equal(transports[0].closed, true)
            assert.equal(
                forwarded.some((event) => event.channel === 'device' && event.event.listRevision === 1),
                false
            )
            assert.equal(forwarded.filter((event) => event.channel === 'operation').length, scenario.prefix.length)
        }
        await context.test(scenario.name, exercise)
    }
})

test('rejects schema-valid future firmware retry evidence before listeners', async () => {
    const transports = []
    const client = createClient(transports)
    const forwarded = []
    client.subscribeEvents((event) => forwarded.push(event))
    await client.start()
    const transport = transports[0]
    const operationId = 'op:firmware-evidence'
    const start = client.startOperation({ operationId, request: { kind: 'firmware-update', deviceId: 'rdx:sequence-1', deviceRevision: 1, firmwareFileToken: 'firmware:fixture' } })
    transport.respond(transport.lastRequest('operation-start'), { ok: true })
    assert.deepEqual(await start, { ok: true })
    transport.deliverMany([
        operationEnvelope(1, { state: 'started', operationId, kind: 'firmware-update', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'firmware-validating' }),
        operationEnvelope(2, { state: 'progress', operationId, kind: 'firmware-update', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'firmware-writing', progress: 0.2, attempt: 1, cancellationState: 'closed' }),
        operationEnvelope(3, { state: 'progress', operationId, kind: 'firmware-update', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'firmware-writing', progress: 0.4, attempt: 2, cancellationState: 'closed' }),
        operationEnvelope(4, { state: 'progress', operationId, kind: 'firmware-update', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'firmware-finalizing', progress: 0.7, cancellationState: 'closed' }),
        operationEnvelope(5, { state: 'progress', operationId, kind: 'firmware-update', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'device-reconnecting', progress: 0.9, cancellationState: 'closed' }),
        operationEnvelope(6, { state: 'progress', operationId, kind: 'firmware-update', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'firmware-readback', progress: 1, cancellationState: 'closed' }),
        operationEnvelope(7, {
            state: 'failed',
            operationId,
            kind: 'firmware-update',
            deviceId: 'rdx:sequence-1',
            deviceRevision: 1,
            stage: 'firmware-readback',
            error: {
                code: 'firmware-revision-mismatch',
                messageKey: 'errors.firmware.revisionMismatch',
                stage: 'firmware-writing',
                category: 'transport',
                retryable: false,
                supportCorrelationId: 'support:future-attempt',
                cleanupEvidence: [],
                attemptHistory: [{ attempt: 1, stage: 'firmware-finalizing', code: 'transport-unavailable', dispatchCertainty: 'not-sent' }]
            }
        }),
        { type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [] } }
    ])
    await nextTurn()

    assert.equal(transport.closed, true)
    assert.equal(
        forwarded.some((event) => event.channel === 'operation' && event.event.state === 'failed'),
        false
    )
    assert.equal(
        forwarded.some((event) => event.channel === 'device' && event.event.listRevision === 1),
        false
    )
})

test('accepts the safe-eject cancellation-close publication before host unmount dispatch', async () => {
    const transports = []
    const client = createClient(transports)
    const forwarded = []
    client.subscribeEvents((event) => forwarded.push(event))
    await client.start()
    const transport = transports[0]
    const operationId = 'op:eject-close-boundary'
    const start = client.startOperation({ operationId, request: { kind: 'eject-safe', deviceId: 'rdx:sequence-1', deviceRevision: 1 } })
    transport.respond(transport.lastRequest('operation-start'), { ok: true })
    assert.deepEqual(await start, { ok: true })

    transport.deliverMany([operationEnvelope(1, { state: 'started', operationId, kind: 'eject-safe', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'host-unmounting' }), operationEnvelope(2, { state: 'progress', operationId, kind: 'eject-safe', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'host-unmounting', progress: 0, cancellationState: 'closed' })])
    await nextTurn()

    assert.equal(transport.closed, false)
    assert.deepEqual(
        forwarded.filter((event) => event.channel === 'operation').map((event) => event.event.state),
        ['started', 'progress']
    )
    assert.equal(client.getState().status, 'ready')
})

test('faults the exact generation when a lifecycle consumer rejects and skips later listeners and frames', async () => {
    const transports = []
    const client = createClient(transports)
    const laterListener = []
    const deviceEvents = []
    client.subscribeEvents((envelope) => (envelope.channel === 'operation' ? false : deviceEvents.push(envelope)))
    client.subscribeEvents((envelope) => laterListener.push(envelope))
    await client.start()
    laterListener.length = 0
    deviceEvents.length = 0
    await reserveOperation(client, transports[0], 'op:consumer-reject')

    transports[0].deliverMany([operationEnvelope(1, startedEvent('op:consumer-reject')), { type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [] } }])
    await nextTurn()

    assert.equal(transports[0].closed, true)
    assert.deepEqual(laterListener, [])
    assert.deepEqual(deviceEvents, [])
    assert.deepEqual(client.getState(), { status: 'unavailable', reason: 'service-malformed-data', restartCount: 0, terminatedGeneration: 1 })
})

test('contains reentrant transport data behind a rejecting lifecycle listener', async () => {
    const transports = []
    const client = createClient(transports)
    const laterListener = []
    let nestedDelivered = false
    client.subscribeEvents((envelope) => {
        if (envelope.channel === 'operation') {
            transports[0].deliver({ type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [] } })
            return false
        }
        nestedDelivered = true
        return true
    })
    client.subscribeEvents((envelope) => laterListener.push(envelope))
    await client.start()
    laterListener.length = 0
    nestedDelivered = false
    await reserveOperation(client, transports[0], 'op:reentrant-reject')

    deliverStarted(transports[0], 1, 'op:reentrant-reject')
    await nextTurn()

    assert.equal(transports[0].closed, true)
    assert.equal(nestedDelivered, false)
    assert.deepEqual(laterListener, [])
    assert.deepEqual(client.getState(), { status: 'unavailable', reason: 'service-malformed-data', restartCount: 0, terminatedGeneration: 1 })
})

test('resets exact publication sequencing only when a new service generation launches', async () => {
    const transports = []
    const timers = new ManualTimers()
    const client = createClient(transports, timers)
    await client.start()
    await reserveOperation(client, transports[0], 'op:generation-one')
    deliverStarted(transports[0], 1, 'op:generation-one')
    deliverCleanup(transports[0], 2, 'op:generation-one')
    deliverSuccess(transports[0], 3, 'op:generation-one')

    transports[0].emit('exit')
    await nextTurn()
    assert.equal(client.getState().status, 'restarting')
    const restarted = client.start()
    timers.fireDelay(0)
    assert.equal((await restarted).generation, 2)

    await reserveOperation(client, transports[1], 'op:generation-two')
    deliverStarted(transports[1], 1, 'op:generation-two')
    assert.equal(client.getState().status, 'ready')
    await client.stop()
})

// Reproduces the exact native failure seen after a successful Linux unmount.
test('keeps a definitive safe-eject rejection visible without faulting the service', async (context) => {
    const transports = []
    const client = createClient(transports)
    context.after(() => client.stop())
    await client.start()
    const transport = transports[0]
    const operationId = 'op:eject-definitive-rejection'
    const events = []
    client.subscribeEvents((envelope) => {
        events.push(envelope.event)
        return true
    })
    const start = client.startOperation({ operationId, request: { kind: 'eject-safe', deviceId: 'rdx:sequence-1', deviceRevision: 1 } })
    transport.respond(transport.lastRequest('operation-start'), { ok: true })
    assert.deepEqual(await start, { ok: true })
    transport.deliverMany([
        operationEnvelope(1, { state: 'started', operationId, kind: 'eject-safe', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'host-unmounting' }),
        operationEnvelope(2, { state: 'progress', operationId, kind: 'eject-safe', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'host-unmounting', progress: 0, cancellationState: 'closed' }),
        operationEnvelope(3, { state: 'progress', operationId, kind: 'eject-safe', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'host-ejecting', progress: 1 / 3, cancellationState: 'closed' }),
        operationEnvelope(4, { state: 'failed', operationId, kind: 'eject-safe', deviceId: 'rdx:sequence-1', deviceRevision: 1, stage: 'host-ejecting', error: { code: 'host-operation-failed', messageKey: 'operation.failed', stage: 'host-ejecting', category: 'platform', retryable: false, dispatchCertainty: 'definitely-rejected', supportCorrelationId: 'support:eject-test', cleanupEvidence: [], attemptHistory: [] } })
    ])
    await nextTurn()
    assert.equal(client.getState().status, 'ready')
    assert.equal(events.at(-1).state, 'failed')
    assert.equal(events.at(-1).error.dispatchCertainty, 'definitely-rejected')
    assert.equal(transports.length, 1)
})
