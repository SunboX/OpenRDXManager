// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { createApplicationServiceRuntime } from '../src/main/service-runtime.mjs'
import { completeDeviceSnapshot } from './helpers/device-snapshot.mjs'

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

/** @param {() => boolean} predicate - Completion predicate. @returns {Promise<void>} Resolves when true. */
async function waitFor(predicate) {
    for (let attempt = 0; attempt < 80; attempt += 1) {
        if (predicate()) return
        await nextTurn()
    }
    assert.fail('controlled condition did not become true')
}

/** Creates a controlled persistence gate. @returns {{promise: Promise<void>, resolve: () => void}} Gate controls. */
function createGate() {
    let resolve
    const promise = new Promise((resolveGate) => {
        resolve = resolveGate
    })
    return { promise, resolve }
}

/** Native-like runtime transport with controlled cancellation response order. */
class RuntimeBoundaryTransport extends EventEmitter {
    /** @param {number} generation - Exact generation number. */
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
            queueMicrotask(() => this.deliver({ type: 'handshake', protocolVersion: 1, serviceVersion: `runtime-boundary-${this.generation}`, platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
        } else if (message.method === 'devices-list') {
            const device = completeDeviceSnapshot({ id: 'rdx:runtime-boundary', revision: 7, vendor: 'TANDBERG', product: 'RDX', serial: 'BOUNDARY7', media: null, capabilities: { 'self-test': { state: 'available' } } })
            queueMicrotask(() => this.respond(message, { ok: true, listRevision: 0, devices: [device] }))
        } else if (message.method === 'operation-start') {
            queueMicrotask(() => this.respond(message, { ok: true }))
        } else if (message.method === 'service-shutdown') {
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

    /** @param {object[]} messages - Strict service messages. @returns {void} Emits one coalesced group. */
    deliverMany(messages) {
        this.emit('data', Buffer.concat(messages.map(encodeFrame)))
    }

    /** @param {string} method - Request method. @returns {object} Latest matching request. */
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

/** @param {object[]} records - Persistence sink. @param {(record: object) => Promise<void>|void} [action] - Optional controlled action. @returns {object} EventLogger file-security boundary. */
function createFileSecurity(records, action = () => {}) {
    return {
        /** @returns {Promise<void>} Performs no host directory work. */
        async prepareDirectory() {},
        /** @returns {Promise<object>} Returns one controlled append handle. */
        async openAppend() {
            return {
                /** @returns {Promise<{size: number}>} Reports an empty file. */
                async stat() {
                    return { size: 0 }
                },
                /** @param {string} line - Sanitized JSONL. @returns {Promise<void>} Records and applies the action. */
                async writeFile(line) {
                    const record = JSON.parse(line)
                    records.push(record)
                    await action(record)
                },
                /** @returns {Promise<void>} Performs no host close work. */
                async close() {}
            }
        },
        /** @returns {Promise<void>} Removes no backup. */
        async removeFile() {},
        /** @returns {Promise<void>} Renames no current file. */
        async renameFile() {}
    }
}

/**
 * Creates a production-wired runtime with recorded persistence and IPC order.
 * @param {{logAction?: (record: object) => Promise<void>|void}} [options] - Controlled logger behavior.
 * @returns {Promise<object>} Runtime fixture.
 */
async function createFixture(options = {}) {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-final-runtime-'))
    const deviceEvents = []
    const operationEvents = []
    const publications = []
    const records = []
    const services = {}
    const transports = []

    /** @returns {RuntimeBoundaryTransport} Creates a new exact generation transport. */
    function transportFactory() {
        const transport = new RuntimeBoundaryTransport(transports.length + 1)
        transports.push(transport)
        return transport
    }

    const runtime = createApplicationServiceRuntime({
        appPath: '/work/OpenRDXManager',
        eventLoggerOptions: { fileSecurity: createFileSecurity(records, options.logAction) },
        ipcController: {
            /** @param {object} event - Strict device event. @returns {boolean} Records it. */
            publishDeviceEvent(event) {
                deviceEvents.push(event)
                publications.push({ channel: 'device', event })
                return true
            },
            /** @param {object} event - Strict operation event. @returns {boolean} Records it. */
            publishOperationEvent(event) {
                operationEvents.push(event)
                publications.push({ channel: 'operation', event })
                return true
            }
        },
        isPackaged: false,
        logDirectory: directory,
        platform: 'darwin',
        resourcesPath: '/work/OpenRDXManager/resources',
        services,
        transportFactory
    })
    return { deviceEvents, directory, operationEvents, publications, records, runtime, services, transports }
}

/** @param {object} fixture - Runtime fixture. @returns {Promise<void>} Stops and removes local state. */
async function disposeFixture(fixture) {
    await fixture.runtime.stop()
    await rm(fixture.directory, { force: true, recursive: true })
}

/** @param {number} sequence - Exact native sequence. @param {object} event - Operation event. @returns {object} Wire envelope. */
function operationEnvelope(sequence, event) {
    return { type: 'event', channel: 'operation', publicationSequence: sequence, event }
}

/** @param {string} operationId - Exact owner. @returns {object} Common owner tuple. */
function owner(operationId) {
    return { operationId, kind: 'self-test', deviceId: 'rdx:runtime-boundary', deviceRevision: 7 }
}

/** @param {string} operationId - Exact owner. @returns {object[]} Started plus cancellable progress. */
function cancellablePrefix(operationId) {
    return [operationEnvelope(1, { state: 'started', ...owner(operationId), stage: 'diagnostic-running' }), operationEnvelope(2, { state: 'progress', ...owner(operationId), stage: 'diagnostic-running', progress: 0.5, cancellationState: 'cancellable' })]
}

test('processes a cancellation response on the control lane while holding terminal publication and its suffix', async () => {
    const terminalGate = createGate()
    let terminalEntered = false
    const fixture = await createFixture({
        async logAction(record) {
            if (record.details.state === 'cancelled') {
                terminalEntered = true
                await terminalGate.promise
            }
        }
    })
    try {
        assert.equal((await fixture.runtime.start()).status, 'ready')
        const started = await fixture.services.operations.start({ kind: 'self-test', deviceId: 'rdx:runtime-boundary', deviceRevision: 7 })
        await nextTurn()
        fixture.transports[0].deliverMany(cancellablePrefix(started.operationId))
        await nextTurn()
        const cancelling = fixture.services.operations.cancel({ operationId: started.operationId })
        const cancelRequest = fixture.transports[0].lastRequest('operation-cancel')
        fixture.transports[0].deliverMany([operationEnvelope(3, { state: 'progress', ...owner(started.operationId), stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'requested' }), operationEnvelope(4, { state: 'cancelled', ...owner(started.operationId), stage: 'diagnostic-cleanup' }), { type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [] } }, { type: 'response', requestId: cancelRequest.requestId, ok: true, result: { ok: true, cancellationCutover: 4 } }])

        await waitFor(() => terminalEntered)
        assert.equal(
            fixture.operationEvents.some((event) => event.state === 'cancelled'),
            false
        )
        assert.equal(
            fixture.deviceEvents.some((event) => event.type === 'list' && event.listRevision === 1),
            false
        )
        assert.notEqual(fixture.runtime.coordinator.getActiveOperation(), null)

        terminalGate.resolve()
        assert.deepEqual(await cancelling, { ok: true })
        await waitFor(() => fixture.deviceEvents.some((event) => event.type === 'list' && event.listRevision === 1))
        assert.equal(fixture.operationEvents.at(-1).state, 'cancelled')
        const terminalIndex = fixture.publications.findIndex((publication) => publication.channel === 'operation' && publication.event.state === 'cancelled')
        const suffixIndex = fixture.publications.findIndex((publication) => publication.channel === 'device' && publication.event.type === 'list' && publication.event.listRevision === 1)
        assert.equal(terminalIndex >= 0 && suffixIndex > terminalIndex, true)
    } finally {
        terminalGate.resolve()
        await disposeFixture(fixture)
    }
})

test('a negative cancellation response faults the held terminal and suppresses its coalesced suffix', async () => {
    const fixture = await createFixture()
    try {
        assert.equal((await fixture.runtime.start()).status, 'ready')
        const started = await fixture.services.operations.start({ kind: 'self-test', deviceId: 'rdx:runtime-boundary', deviceRevision: 7 })
        await nextTurn()
        fixture.transports[0].deliverMany(cancellablePrefix(started.operationId))
        await nextTurn()
        const cancelling = fixture.services.operations.cancel({ operationId: started.operationId })
        const cancelRequest = fixture.transports[0].lastRequest('operation-cancel')
        fixture.transports[0].deliverMany([operationEnvelope(3, { state: 'progress', ...owner(started.operationId), stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'requested' }), operationEnvelope(4, { state: 'cancelled', ...owner(started.operationId), stage: 'diagnostic-cleanup' }), { type: 'response', requestId: cancelRequest.requestId, ok: true, result: { ok: false, reason: 'operation-not-cancellable' } }, { type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [] } }])

        assert.deepEqual(await cancelling, { ok: false, reason: 'operation-not-cancellable' })
        await waitFor(() => fixture.transports[0].closed)
        assert.equal(
            fixture.operationEvents.some((event) => event.state === 'cancelled'),
            false
        )
        assert.equal(
            fixture.deviceEvents.some((event) => event.type === 'list' && event.listRevision === 1),
            false
        )
    } finally {
        await disposeFixture(fixture)
    }
})

test('a malformed frame before the cancellation response wins over the held terminal', async () => {
    const fixture = await createFixture()
    try {
        assert.equal((await fixture.runtime.start()).status, 'ready')
        const started = await fixture.services.operations.start({ kind: 'self-test', deviceId: 'rdx:runtime-boundary', deviceRevision: 7 })
        await nextTurn()
        fixture.transports[0].deliverMany(cancellablePrefix(started.operationId))
        await nextTurn()
        const cancelling = fixture.services.operations.cancel({ operationId: started.operationId })
        const cancelRequest = fixture.transports[0].lastRequest('operation-cancel')
        fixture.transports[0].deliverMany([operationEnvelope(3, { state: 'progress', ...owner(started.operationId), stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'requested' }), operationEnvelope(4, { state: 'cancelled', ...owner(started.operationId), stage: 'diagnostic-cleanup' }), { type: 'malformed-before-control-response' }, { type: 'response', requestId: cancelRequest.requestId, ok: true, result: { ok: true, cancellationCutover: 4 } }])

        assert.deepEqual(await cancelling, { ok: false, reason: 'operation-outcome-unknown' })
        await waitFor(() => fixture.transports[0].closed)
        assert.equal(
            fixture.operationEvents.some((event) => event.state === 'cancelled'),
            false
        )
    } finally {
        await disposeFixture(fixture)
    }
})

test('an operation suffix before the cancellation response faults before the held terminal commits', async () => {
    const fixture = await createFixture()
    try {
        assert.equal((await fixture.runtime.start()).status, 'ready')
        const started = await fixture.services.operations.start({ kind: 'self-test', deviceId: 'rdx:runtime-boundary', deviceRevision: 7 })
        await nextTurn()
        fixture.transports[0].deliverMany(cancellablePrefix(started.operationId))
        await nextTurn()
        const cancelling = fixture.services.operations.cancel({ operationId: started.operationId })
        const cancelRequest = fixture.transports[0].lastRequest('operation-cancel')
        fixture.transports[0].deliverMany([operationEnvelope(3, { state: 'progress', ...owner(started.operationId), stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'requested' }), operationEnvelope(4, { state: 'cancelled', ...owner(started.operationId), stage: 'diagnostic-cleanup' }), operationEnvelope(5, { state: 'progress', ...owner(started.operationId), stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'requested' }), { type: 'response', requestId: cancelRequest.requestId, ok: true, result: { ok: true, cancellationCutover: 4 } }])

        assert.deepEqual(await cancelling, { ok: false, reason: 'operation-outcome-unknown' })
        await waitFor(() => fixture.transports[0].closed)
        assert.equal(
            fixture.operationEvents.some((event) => event.state === 'cancelled'),
            false
        )
    } finally {
        await disposeFixture(fixture)
    }
})

test('disabled optional logging still durably audits success, failure, and cancellation terminals', async (context) => {
    const scenarios = ['succeeded', 'failed', 'cancelled']
    for (const terminalState of scenarios) {
        await context.test(terminalState, async () => {
            const fixture = await createFixture()
            try {
                assert.equal((await fixture.runtime.start()).status, 'ready')
                assert.deepEqual(await fixture.services.logs.setEnabled({ enabled: false }), { ok: true })
                const started = await fixture.services.operations.start({ kind: 'self-test', deviceId: 'rdx:runtime-boundary', deviceRevision: 7 })
                await nextTurn()
                const transport = fixture.transports[0]
                if (terminalState === 'cancelled') {
                    transport.deliverMany(cancellablePrefix(started.operationId))
                    await nextTurn()
                    const cancelling = fixture.services.operations.cancel({ operationId: started.operationId })
                    const request = transport.lastRequest('operation-cancel')
                    transport.respond(request, { ok: true, cancellationCutover: 2 })
                    assert.deepEqual(await cancelling, { ok: true })
                    transport.deliverMany([operationEnvelope(3, { state: 'progress', ...owner(started.operationId), stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'requested' }), operationEnvelope(4, { state: 'cancelled', ...owner(started.operationId), stage: 'diagnostic-cleanup' })])
                } else {
                    const terminal =
                        terminalState === 'succeeded'
                            ? { state: 'succeeded', ...owner(started.operationId), stage: 'complete' }
                            : {
                                  state: 'failed',
                                  ...owner(started.operationId),
                                  stage: 'diagnostic-cleanup',
                                  error: { code: 'diagnostic-failed', messageKey: 'errors.service.failure', stage: 'diagnostic-cleanup', category: 'transport', retryable: false, supportCorrelationId: `support:${terminalState}`, cleanupEvidence: [], attemptHistory: [] }
                              }
                    transport.deliverMany([...cancellablePrefix(started.operationId), operationEnvelope(3, { state: 'progress', ...owner(started.operationId), stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'closed' }), operationEnvelope(4, terminal)])
                }

                await waitFor(() => fixture.runtime.coordinator.getActiveOperation() === null)
                await fixture.runtime.logger.flush()
                const operationRecords = fixture.records.filter((record) => record.details.operationId === started.operationId)
                assert.equal(
                    operationRecords.some((record) => record.details.state === terminalState),
                    true
                )
                assert.equal(
                    operationRecords.some((record) => ['queued', 'started', 'progress'].includes(record.details.state)),
                    false
                )
                assert.equal(
                    fixture.records.some((record) => record.event === 'logging-setting' && record.details.enabled === false),
                    true
                )
                assert.equal(
                    fixture.deviceEvents.some((event) => event.status === 'unavailable' && event.reason === 'event-log-unavailable'),
                    false
                )
            } finally {
                await disposeFixture(fixture)
            }
        })
    }
})
