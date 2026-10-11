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

/** @param {Buffer} frame - Complete outbound service frame. @returns {object} Decoded message. */
function decodeFrame(frame) {
    const length = frame.readUInt32BE(0)
    return JSON.parse(frame.subarray(4, length + 4).toString('utf8'))
}

/** @param {object} message - Controlled inbound service message. @returns {Buffer} Complete frame. */
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

/** @param {() => boolean} predicate - Completion predicate. @returns {Promise<void>} Resolves once the predicate becomes true. */
async function waitFor(predicate) {
    for (let attempt = 0; attempt < 40; attempt += 1) {
        if (predicate()) return
        await nextTurn()
    }
    assert.fail('controlled condition did not become true')
}

/** Creates a caller-controlled promise gate. @returns {{promise: Promise<void>, resolve: () => void, reject: () => void}} Gate controls. */
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
        /** @returns {void} Rejects with a fixed non-sensitive test failure. */
        reject() {
            reject(new Error('controlled-log-persistence-failure'))
        }
    }
}

/** Deterministic timer queue for one bounded persistence attempt. */
class ManualTimers {
    /** Creates an empty queue. */
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

    /** @param {number} id - Timer identity. @returns {void} Clears the timer. */
    clearTimeout(id) {
        this.pending.delete(id)
    }

    /** @param {number} delay - Exact delay to fire. @returns {void} Fires one timer. */
    fireDelay(delay) {
        const entry = [...this.pending.entries()].find(([, timer]) => timer.delay === delay)
        assert.notEqual(entry, undefined)
        this.pending.delete(entry[0])
        entry[1].callback()
    }
}

/** Native-like operation transport with controlled list and event publication. */
class BarrierTransport extends EventEmitter {
    /** @param {{coalescedStart?: boolean, holdList?: boolean}} [options] - Controlled reconciliation behavior. */
    constructor(options = {}) {
        super()
        this.closed = false
        this.coalescedStart = options.coalescedStart === true
        this.holdList = options.holdList === true
        this.listRequest = null
        this.startRequest = null
    }

    /** @param {Buffer} frame - Main request frame. @returns {{ok: true}} Accepts the write. */
    write(frame) {
        const message = decodeFrame(frame)
        if (message.type === 'handshake-request') {
            queueMicrotask(() => this.deliver({ type: 'handshake', protocolVersion: 1, serviceVersion: 'critical-log-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
        } else if (message.method === 'devices-list') {
            this.listRequest = message
            if (!this.holdList) queueMicrotask(() => this.respondList())
        } else if (message.method === 'operation-start') {
            this.startRequest = message
            if (this.coalescedStart) {
                queueMicrotask(() => {
                    this.deliverMany([{ type: 'response', requestId: message.requestId, ok: true, result: { ok: true } }, ...selfTestPrefix(message.payload.operationId), selfTestSuccess(message.payload.operationId), { type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [] } }])
                })
            } else {
                queueMicrotask(() => this.deliver({ type: 'response', requestId: message.requestId, ok: true, result: { ok: true } }))
            }
        } else if (message.method === 'service-shutdown') {
            queueMicrotask(() => this.deliver({ type: 'response', requestId: message.requestId, ok: true, result: { ok: true } }))
        }
        return { ok: true }
    }

    /** @returns {void} Delivers the held or current strict device list. */
    respondList() {
        assert.notEqual(this.listRequest, null)
        const device = completeDeviceSnapshot({ id: 'rdx:critical-log-1', revision: 7, vendor: 'TANDBERG', product: 'RDX', serial: 'CRITICAL1', media: null, capabilities: { 'self-test': { state: 'available' } } })
        this.deliver({ type: 'response', requestId: this.listRequest.requestId, ok: true, result: { ok: true, listRevision: 0, devices: [device] } })
    }

    /** @param {object} message - One controlled service message. @returns {void} Emits its frame. */
    deliver(message) {
        this.emit('data', encodeFrame(message))
    }

    /** @param {object[]} messages - Ordered messages. @returns {void} Emits one coalesced chunk. */
    deliverMany(messages) {
        this.emit('data', Buffer.concat(messages.map(encodeFrame)))
    }

    /** @returns {{confirmed: true}} Confirms exact-generation teardown. */
    close() {
        this.closed = true
        return { confirmed: true }
    }
}

/**
 * Creates a log adapter with caller-selected record actions.
 * @param {(record: object) => Promise<void>|void} action - Persistence behavior.
 * @returns {object} EventLogger file-security boundary.
 */
function createFileSecurity(action) {
    return {
        /** @returns {Promise<void>} Performs no host directory work. */
        async prepareDirectory() {},
        /** @returns {Promise<object>} Creates one controlled append handle. */
        async openAppend() {
            return {
                /** @returns {Promise<{size: number}>} Reports an empty file. */
                async stat() {
                    return { size: 0 }
                },
                /** @param {string} line - Sanitized JSONL record. @returns {Promise<void>} Applies controlled persistence. */
                async writeFile(line) {
                    await action(JSON.parse(line))
                },
                /** @returns {Promise<void>} Performs no host close work. */
                async close() {}
            }
        },
        /** @returns {Promise<void>} Removes no backup. */
        async removeFile() {},
        /** @returns {Promise<void>} Renames no file. */
        async renameFile() {}
    }
}

/** @param {number} sequence - Exact global sequence. @param {object} event - Operation event. @returns {object} Wire envelope. */
function operationEnvelope(sequence, event) {
    return { type: 'event', channel: 'operation', publicationSequence: sequence, event }
}

/** @param {string} operationId - Exact operation owner. @returns {object[]} Valid self-test lifecycle through cleanup. */
function selfTestPrefix(operationId) {
    const owner = { operationId, kind: 'self-test', deviceId: 'rdx:critical-log-1', deviceRevision: 7 }
    return [operationEnvelope(1, { state: 'started', ...owner, stage: 'diagnostic-running' }), operationEnvelope(2, { state: 'progress', ...owner, stage: 'diagnostic-running', progress: 0.5, cancellationState: 'cancellable' }), operationEnvelope(3, { state: 'progress', ...owner, stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'closed' })]
}

/** @param {string} operationId - Exact operation owner. @returns {object} Valid success terminal. */
function selfTestSuccess(operationId) {
    return operationEnvelope(4, { state: 'succeeded', operationId, kind: 'self-test', deviceId: 'rdx:critical-log-1', deviceRevision: 7, stage: 'complete' })
}

/**
 * Creates a controlled production wiring surface.
 * @param {{coalescedStart?: boolean, eventLoggerOptions?: object, fileSecurity: object, holdList?: boolean}} options - Logger and transport controls.
 * @returns {Promise<object>} Runtime fixture and cleanup roots.
 */
async function createFixture(options) {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-critical-log-'))
    const transport = new BarrierTransport({ coalescedStart: options.coalescedStart, holdList: options.holdList })
    const deviceEvents = []
    const operationEvents = []
    const services = {}
    const runtime = createApplicationServiceRuntime({
        appPath: '/work/OpenRDXManager',
        eventLoggerOptions: { fileSecurity: options.fileSecurity, ...options.eventLoggerOptions },
        ipcController: {
            /** @param {object} event - Strict device event. @returns {boolean} Records publication. */
            publishDeviceEvent(event) {
                deviceEvents.push(event)
                return true
            },
            /** @param {object} event - Strict operation event. @returns {boolean} Records publication. */
            publishOperationEvent(event) {
                operationEvents.push(event)
                return true
            }
        },
        isPackaged: false,
        logDirectory: directory,
        platform: 'darwin',
        resourcesPath: '/work/OpenRDXManager/resources',
        services,
        transportFactory: () => transport
    })
    return { deviceEvents, directory, operationEvents, runtime, services, transport }
}

/** @param {object} fixture - Runtime fixture. @returns {Promise<void>} Stops and removes test state. */
async function disposeFixture(fixture) {
    await fixture.runtime.stop()
    await rm(fixture.directory, { force: true, recursive: true })
}

test('suppresses ready when its critical log admission overflows', async () => {
    const blocker = createGate()
    let writes = 0
    const fixture = await createFixture({
        holdList: true,
        fileSecurity: createFileSecurity(async () => {
            writes += 1
            if (writes === 1) await blocker.promise
        }),
        eventLoggerOptions: { maxBytes: 512, maxPendingBytes: 4096, maxPendingEntries: 6 }
    })
    try {
        const starting = fixture.runtime.start()
        await waitFor(() => fixture.transport.listRequest !== null)
        void fixture.runtime.logger.write({ event: 'audit-fill-one', messageKey: 'activity.audit', severity: 'error' })
        void fixture.runtime.logger.write({ event: 'audit-fill-two', messageKey: 'activity.audit', severity: 'error' })
        void fixture.runtime.logger.write({ event: 'audit-fill-three', messageKey: 'activity.audit', severity: 'error' })
        fixture.transport.respondList()

        assert.deepEqual(await starting, { status: 'unavailable', reason: 'event-log-unavailable', restartCount: 0, terminatedGeneration: 1 })
        assert.equal(
            fixture.deviceEvents.some((event) => event.status === 'ready'),
            false
        )
        assert.equal(fixture.deviceEvents.filter((event) => event.status === 'unavailable' && event.reason === 'event-log-unavailable').length, 1)
    } finally {
        blocker.resolve()
        await disposeFixture(fixture)
    }
})

test('suppresses ready until delayed critical persistence succeeds and returns unavailable on rejection', async () => {
    const readyGate = createGate()
    let readyEntered = false
    const fixture = await createFixture({
        fileSecurity: createFileSecurity(async (record) => {
            if (record.details.status === 'ready') {
                readyEntered = true
                await readyGate.promise
            }
        })
    })
    try {
        const starting = fixture.runtime.start()
        await waitFor(() => readyEntered)
        assert.equal(
            fixture.deviceEvents.some((event) => event.status === 'ready'),
            false
        )
        readyGate.reject()

        assert.deepEqual(await starting, { status: 'unavailable', reason: 'event-log-unavailable', restartCount: 0, terminatedGeneration: 1 })
        assert.equal(
            fixture.deviceEvents.some((event) => event.status === 'ready'),
            false
        )
        assert.equal(fixture.deviceEvents.filter((event) => event.status === 'unavailable' && event.reason === 'event-log-unavailable').length, 1)
    } finally {
        readyGate.resolve()
        await disposeFixture(fixture)
    }
})

test('retains terminal ownership until critical persistence and suppresses a coalesced suffix on rejection', async () => {
    const terminalGate = createGate()
    let terminalEntered = false
    const fixture = await createFixture({
        fileSecurity: createFileSecurity(async (record) => {
            if (record.details.state === 'succeeded') {
                terminalEntered = true
                await terminalGate.promise
            }
        })
    })
    try {
        assert.equal((await fixture.runtime.start()).status, 'ready')
        const started = await fixture.services.operations.start({ kind: 'self-test', deviceId: 'rdx:critical-log-1', deviceRevision: 7 })
        await nextTurn()
        fixture.transport.deliverMany([...selfTestPrefix(started.operationId), selfTestSuccess(started.operationId), { type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [] } }])

        await waitFor(() => terminalEntered)
        assert.notEqual(fixture.runtime.coordinator.getActiveOperation(), null)
        assert.equal(
            fixture.operationEvents.some((event) => event.state === 'succeeded'),
            false
        )
        assert.equal(
            fixture.deviceEvents.some((event) => event.type === 'list' && event.listRevision === 1),
            false
        )
        terminalGate.reject()
        await waitFor(() => fixture.runtime.getReadiness().reason === 'event-log-unavailable')

        assert.equal(fixture.transport.closed, true)
        assert.equal(fixture.runtime.coordinator.getActiveOperation(), null)
        assert.equal(
            fixture.operationEvents.some((event) => event.state === 'succeeded'),
            false
        )
        assert.equal(
            fixture.operationEvents.some((event) => event.state === 'failed'),
            false
        )
        assert.equal(
            fixture.deviceEvents.some((event) => event.type === 'list' && event.listRevision === 1),
            false
        )
        assert.equal(fixture.deviceEvents.filter((event) => event.status === 'unavailable' && event.reason === 'event-log-unavailable').length, 1)
    } finally {
        terminalGate.resolve()
        await disposeFixture(fixture)
    }
})

test('holds a pre-ack coalesced terminal and suffix behind the critical persistence result', async () => {
    const terminalGate = createGate()
    let terminalEntered = false
    const fixture = await createFixture({
        coalescedStart: true,
        fileSecurity: createFileSecurity(async (record) => {
            if (record.details.state === 'succeeded') {
                terminalEntered = true
                await terminalGate.promise
            }
        })
    })
    try {
        assert.equal((await fixture.runtime.start()).status, 'ready')
        const started = await fixture.services.operations.start({ kind: 'self-test', deviceId: 'rdx:critical-log-1', deviceRevision: 7 })
        assert.equal(started.ok, true)
        await waitFor(() => terminalEntered)

        assert.notEqual(fixture.runtime.coordinator.getActiveOperation(), null)
        assert.equal(
            fixture.operationEvents.some((event) => event.state === 'succeeded'),
            false
        )
        assert.equal(
            fixture.deviceEvents.some((event) => event.type === 'list' && event.listRevision === 1),
            false
        )

        terminalGate.reject()
        await waitFor(() => fixture.runtime.coordinator.getActiveOperation() === null)
        assert.equal(
            fixture.deviceEvents.some((event) => event.type === 'list' && event.listRevision === 1),
            false
        )
    } finally {
        terminalGate.resolve()
        await disposeFixture(fixture)
    }
})

test('suppresses terminal on priority overflow and bounded persistence timeout', async (context) => {
    /** @returns {Promise<void>} Exercises terminal admission overflow after valid lifecycle progress. */
    async function overflow() {
        const blocker = createGate()
        let blockNext = false
        let blocked = false
        const fixture = await createFixture({
            fileSecurity: createFileSecurity(async () => {
                if (blockNext) {
                    blockNext = false
                    blocked = true
                    await blocker.promise
                }
            }),
            eventLoggerOptions: { maxBytes: 512, maxPendingBytes: 4096, maxPendingEntries: 6 }
        })
        try {
            assert.equal((await fixture.runtime.start()).status, 'ready')
            const started = await fixture.services.operations.start({ kind: 'self-test', deviceId: 'rdx:critical-log-1', deviceRevision: 7 })
            await nextTurn()
            fixture.transport.deliverMany(selfTestPrefix(started.operationId))
            await fixture.runtime.logger.flush()
            blockNext = true
            void fixture.runtime.logger.write({ event: 'audit-block', messageKey: 'activity.audit', severity: 'error' })
            await waitFor(() => blocked)
            for (let index = 0; index < 5; index += 1) {
                void fixture.runtime.logger.write({ event: `audit-fill-${index}`, messageKey: 'activity.audit', severity: 'error' })
            }

            fixture.transport.deliver(selfTestSuccess(started.operationId))
            await waitFor(() => fixture.runtime.getReadiness().reason === 'event-log-unavailable')
            await waitFor(() => fixture.runtime.coordinator.getActiveOperation() === null)
            assert.equal(
                fixture.operationEvents.some((event) => event.state === 'succeeded'),
                false
            )
            assert.equal(fixture.runtime.coordinator.getActiveOperation(), null)
        } finally {
            blocker.resolve()
            await disposeFixture(fixture)
        }
    }

    /** @returns {Promise<void>} Exercises the critical terminal's absolute persistence deadline. */
    async function timeout() {
        const terminalGate = createGate()
        const timers = new ManualTimers()
        let terminalEntered = false
        const fixture = await createFixture({
            fileSecurity: createFileSecurity(async (record) => {
                if (record.details.state === 'succeeded') {
                    terminalEntered = true
                    await terminalGate.promise
                }
            }),
            eventLoggerOptions: { persistenceTimeoutMs: 100, timers }
        })
        try {
            assert.equal((await fixture.runtime.start()).status, 'ready')
            const started = await fixture.services.operations.start({ kind: 'self-test', deviceId: 'rdx:critical-log-1', deviceRevision: 7 })
            await nextTurn()
            fixture.transport.deliverMany([...selfTestPrefix(started.operationId), selfTestSuccess(started.operationId)])
            await waitFor(() => terminalEntered)
            assert.notEqual(fixture.runtime.coordinator.getActiveOperation(), null)
            timers.fireDelay(100)
            await waitFor(() => fixture.runtime.getReadiness().reason === 'event-log-unavailable')

            assert.equal(
                fixture.operationEvents.some((event) => event.state === 'succeeded'),
                false
            )
            assert.equal(fixture.runtime.coordinator.getActiveOperation(), null)
            assert.deepEqual(await fixture.runtime.logger.close(), { ok: false, reason: 'event-log-persistence-timeout' })
        } finally {
            terminalGate.reject()
            await disposeFixture(fixture)
        }
    }

    await context.test('priority-overflow', overflow)
    await context.test('persistence-timeout', timeout)
})
