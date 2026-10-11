// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { DeviceServiceClient } from '../src/main/device-service-client.mjs'
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

/** @returns {Promise<void>} Resolves after queued microtasks and continuations. */
async function nextTurn() {
    await new Promise(setImmediate)
}

/** Deterministic timer queue used to prove no restart remains scheduled. */
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

    /** @param {number} id - Timer ID. @returns {void} Clears it. */
    clearTimeout(id) {
        this.pending.delete(id)
    }

    /** @param {number} delay - Exact pending delay. @returns {void} Fires one matching timer. */
    fireDelay(delay) {
        const entry = [...this.pending.entries()].find(([, timer]) => timer.delay === delay)
        assert.notEqual(entry, undefined)
        this.pending.delete(entry[0])
        entry[1].callback()
    }
}

/** Native-like transport whose teardown is released explicitly. */
class RecoveringTransport extends EventEmitter {
    /** Creates one current generation and its close gate. */
    constructor() {
        super()
        this.closeEntered = false
        this.releaseClose = null
        this.closeGate = new Promise((resolve) => {
            this.releaseClose = resolve
        })
    }

    /** @param {Buffer} frame - Main-owned frame. @returns {{ok: true}} Accepts the request. */
    write(frame) {
        const message = decodeFrame(frame)
        if (message.type === 'handshake-request') {
            queueMicrotask(() => this.emit('data', encodeFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'logger-latch-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } })))
        } else if (message.method === 'devices-list') {
            const device = completeDeviceSnapshot({ id: 'rdx:logger-latch-1', revision: 1, vendor: 'TANDBERG', product: 'RDX', serial: 'LOGGER1', media: null, capabilities: { 'self-test': { state: 'available' } } })
            queueMicrotask(() => this.emit('data', encodeFrame({ type: 'response', requestId: message.requestId, ok: true, result: { ok: true, listRevision: 0, devices: [device] } })))
        }
        return { ok: true }
    }

    /** @returns {Promise<{confirmed: true}>} Waits for explicit teardown confirmation. */
    async close() {
        this.closeEntered = true
        await this.closeGate
        return { confirmed: true }
    }
}

/**
 * Creates a logger filesystem boundary whose recovery append remains active.
 * @returns {{fileSecurity: object, release: () => void}} Controlled log boundary.
 */
function createBlockedLog() {
    let release
    const gate = new Promise((resolve) => {
        release = resolve
    })
    return {
        release,
        fileSecurity: {
            /** @returns {Promise<void>} Performs no host setup. */
            async prepareDirectory() {},
            /** @returns {Promise<object>} Returns a controlled append handle. */
            async openAppend() {
                return {
                    /** @returns {Promise<{size: number}>} Reports an empty log. */
                    async stat() {
                        return { size: 0 }
                    },
                    /** @param {string} line - Sanitized JSONL line. @returns {Promise<void>} Blocks only recovery. */
                    async writeFile(line) {
                        const record = JSON.parse(line)
                        if (record.details.status === 'recovering') await gate
                    },
                    /** @returns {Promise<void>} Performs no host close. */
                    async close() {}
                }
            },
            /** @returns {Promise<void>} Removes no backup. */
            async removeFile() {},
            /** @returns {Promise<void>} Renames no file. */
            async renameFile() {}
        }
    }
}

test('latches event-log failure while transport recovery is already in flight', async () => {
    const timers = new ManualTimers()
    const launches = []

    /** @returns {RecoveringTransport} Creates and records a generation. */
    function transportFactory() {
        const transport = new RecoveringTransport()
        launches.push(transport)
        return transport
    }

    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 1, platform: 'darwin', restartBackoffMs: [0], timers, transportFactory })
    await client.start()
    launches[0].emit('exit')
    assert.equal(client.getState().status, 'recovering')
    assert.equal(launches[0].closeEntered, true)

    assert.equal(client.faultEventLog(1), true)
    launches[0].releaseClose()
    await nextTurn()

    const unavailable = { status: 'unavailable', reason: 'event-log-unavailable', restartCount: 0, terminatedGeneration: 1 }
    assert.deepEqual(client.getState(), unavailable)
    assert.equal(timers.pending.size, 0)
    assert.equal(launches.length, 1)
    assert.deepEqual(await client.start(), unavailable)
    assert.deepEqual(client.getPlatformCapability(), { state: 'transport-unavailable', reason: 'event-log-unavailable' })
    assert.equal(client.getServiceMode(), null)
    assert.equal(client.isHardwareReady(), false)
    assert.equal(client.hasPrivilege(), false)
    assert.deepEqual(await client.list(), { ok: false, reason: 'event-log-unavailable' })
    assert.deepEqual(await client.scan({ kind: 'scan' }), { ok: false, reason: 'event-log-unavailable' })
    assert.deepEqual(await client.startOperation({ operationId: 'op:blocked', request: { kind: 'self-test', deviceId: 'rdx:logger-latch-1', deviceRevision: 1 } }), { ok: false, reason: 'event-log-unavailable' })
    assert.deepEqual(await client.cancelOperation({ operationId: 'op:blocked' }), { ok: false, reason: 'event-log-unavailable' })
    await client.stop()
    assert.deepEqual(client.getState(), unavailable)
})

test('latches a synchronous logger callback without recursive lifecycle logging', async () => {
    const transports = []
    let client = null
    let insideWrite = false
    let nestedWrite = false
    let failureInjected = false
    let blockedStart = null
    const logger = {
        /** @param {object} event - Safe lifecycle record. @returns {boolean} Rejects persistence. */
        write(event) {
            nestedWrite ||= insideWrite
            insideWrite = true
            if (event.status === 'ready' && !failureInjected) {
                failureInjected = true
                assert.equal(client.faultEventLog(client.getGeneration()), true)
                blockedStart = client.start()
            }
            insideWrite = false
            return false
        }
    }

    /** @returns {RecoveringTransport} Creates an immediately closable generation. */
    function transportFactory() {
        const transport = new RecoveringTransport()
        transport.releaseClose()
        transports.push(transport)
        return transport
    }

    client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', logger, maxRestarts: 1, platform: 'darwin', transportFactory })
    const unavailable = { status: 'unavailable', reason: 'event-log-unavailable', restartCount: 0, terminatedGeneration: 1 }
    assert.deepEqual(await client.start(), unavailable)
    assert.equal(failureInjected, true)
    assert.equal(nestedWrite, false)
    assert.equal(transports.length, 1)
    assert.deepEqual(await blockedStart, unavailable)
})

test('does not launch a restart transport after its starting record latches logger failure', async () => {
    const timers = new ManualTimers()
    const transports = []
    let client = null
    let startingRecords = 0
    const logger = {
        /** @param {object} event - Safe lifecycle record. @returns {boolean} Accepts the record. */
        write(event) {
            if (event.status === 'starting') {
                startingRecords += 1
                if (startingRecords === 2) assert.equal(client.faultEventLog(client.getGeneration()), true)
            }
            return true
        }
    }

    /** @returns {RecoveringTransport} Creates and records an immediately closable transport. */
    function transportFactory() {
        const transport = new RecoveringTransport()
        transport.releaseClose()
        transports.push(transport)
        return transport
    }

    client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', logger, maxRestarts: 1, platform: 'darwin', restartBackoffMs: [0], timers, transportFactory })
    assert.equal((await client.start()).status, 'ready')
    transports[0].emit('exit')
    await nextTurn()
    assert.equal(client.getState().status, 'restarting')

    const restartOutcome = client.start()
    timers.fireDelay(0)
    assert.deepEqual(await restartOutcome, { status: 'unavailable', reason: 'event-log-unavailable', restartCount: 1, terminatedGeneration: 2 })
    assert.equal(startingRecords, 2)
    assert.equal(transports.length, 1)
})

test('logger saturation during recovery prevents relaunch and fails every runtime dispatch gate', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-runtime-logger-latch-'))
    const blockedLog = createBlockedLog()
    const launches = []
    const publishedDeviceEvents = []
    const services = {}

    /** @returns {RecoveringTransport} Creates and records a generation. */
    function transportFactory() {
        const transport = new RecoveringTransport()
        launches.push(transport)
        return transport
    }

    const runtime = createApplicationServiceRuntime({
        appPath: '/work/OpenRDXManager',
        eventLoggerOptions: { fileSecurity: blockedLog.fileSecurity, maxBytes: 512, maxPendingBytes: 4096, maxPendingEntries: 6 },
        ipcController: {
            /** @param {object} event - Safe device event. @returns {boolean} Records publication. */
            publishDeviceEvent(event) {
                publishedDeviceEvents.push(event)
                return true
            },
            /** @returns {boolean} Accepts no operation publication. */
            publishOperationEvent() {
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
    try {
        assert.equal((await runtime.start()).status, 'ready')
        launches[0].emit('exit')
        assert.equal(runtime.client.getState().status, 'recovering')
        for (let index = 0; index < 5; index += 1) {
            void runtime.logger.write({ event: `audit-fill-${index}`, messageKey: 'activity.audit', severity: 'error' })
        }
        assert.equal(await runtime.logger.write({ event: 'audit-overflow', messageKey: 'activity.audit', severity: 'error' }), false)
        await nextTurn()

        launches[0].releaseClose()
        await nextTurn()
        const unavailable = { status: 'unavailable', reason: 'event-log-unavailable', restartCount: 0, terminatedGeneration: 1 }
        assert.deepEqual(runtime.client.getState(), unavailable)
        assert.deepEqual(runtime.getReadiness(), unavailable)
        assert.equal(launches.length, 1)
        assert.deepEqual(await services.devices.list(), { ok: false, reason: 'event-log-unavailable' })
        assert.deepEqual(await services.devices.scan({ kind: 'scan' }), { ok: false, reason: 'event-log-unavailable' })
        assert.deepEqual(await services.operations.start({ kind: 'self-test', deviceId: 'rdx:logger-latch-1', deviceRevision: 1 }), { ok: false, reason: 'event-log-unavailable' })
        assert.equal(runtime.coordinator.getContext({ deviceId: 'rdx:logger-latch-1' }).hardwareReady, false)
        assert.equal(publishedDeviceEvents.filter((event) => event.status === 'unavailable' && event.reason === 'event-log-unavailable').length, 1)

        blockedLog.release()
        assert.deepEqual(await runtime.stop(), { ok: false, reason: 'event-log-priority-overflow' })
        assert.deepEqual(runtime.getReadiness(), unavailable)
    } finally {
        launches[0]?.releaseClose()
        blockedLog.release()
        await runtime.stop()
        await rm(directory, { force: true, recursive: true })
    }
})

/**
 * Creates a persistence adapter whose first append rejects only when directed.
 * @returns {{arm: () => void, fileSecurity: object, reject: () => void}} Controlled hanging log.
 */
function createHangingLog() {
    let armed = false
    let rejectWrite
    const write = new Promise((_resolve, reject) => {
        rejectWrite = reject
    })
    return {
        /** @returns {void} Hangs only the next append. */
        arm() {
            armed = true
        },
        /** @returns {void} Rejects the observed filesystem operation late. */
        reject() {
            rejectWrite(new Error('controlled-sensitive-late-stop-rejection'))
        },
        fileSecurity: {
            /** @returns {Promise<void>} Performs no host setup. */
            async prepareDirectory() {},
            /** @returns {Promise<object>} Returns the hanging append handle. */
            async openAppend() {
                return {
                    /** @returns {Promise<{size: number}>} Reports an empty log. */
                    async stat() {
                        return { size: 0 }
                    },
                    /** @returns {Promise<void>} Hangs only after explicit arming. */
                    async writeFile() {
                        if (armed) {
                            armed = false
                            return write
                        }
                    },
                    /** @returns {Promise<void>} Performs no host close. */
                    async close() {}
                }
            },
            /** @returns {Promise<void>} Removes no backup. */
            async removeFile() {},
            /** @returns {Promise<void>} Renames no file. */
            async renameFile() {}
        }
    }
}

test('latches a final lifecycle overflow during stop and bounds a hung late persistence', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-runtime-stop-overflow-'))
    const hangingLog = createHangingLog()
    const timers = new ManualTimers()
    const publishedDeviceEvents = []

    /** @returns {RecoveringTransport} Creates an immediately closable generation. */
    function transportFactory() {
        const transport = new RecoveringTransport()
        transport.releaseClose()
        return transport
    }

    const runtime = createApplicationServiceRuntime({
        appPath: '/work/OpenRDXManager',
        eventLoggerOptions: { fileSecurity: hangingLog.fileSecurity, maxBytes: 512, maxPendingBytes: 4096, maxPendingEntries: 4, persistenceTimeoutMs: 100, timers },
        ipcController: {
            /** @param {object} event - Safe lifecycle event. @returns {boolean} Records it. */
            publishDeviceEvent(event) {
                publishedDeviceEvents.push(event)
                return true
            },
            /** @returns {boolean} Accepts no operation event. */
            publishOperationEvent() {
                return true
            }
        },
        isPackaged: false,
        logDirectory: directory,
        platform: 'darwin',
        resourcesPath: '/work/OpenRDXManager/resources',
        services: {},
        transportFactory
    })
    const unhandled = []

    /** @param {unknown} reason - Unexpected detached rejection. @returns {void} Records it. */
    function recordUnhandled(reason) {
        unhandled.push(reason)
    }

    process.on('unhandledRejection', recordUnhandled)
    try {
        assert.equal((await runtime.start()).status, 'ready')
        assert.equal(
            publishedDeviceEvents.some((event) => event.status === 'unavailable'),
            false
        )

        hangingLog.arm()
        void runtime.logger.write({ event: 'audit-block', messageKey: 'activity.audit', severity: 'error' })
        void runtime.logger.write({ event: 'audit-fill-one', messageKey: 'activity.audit', severity: 'error' })
        void runtime.logger.write({ event: 'audit-fill-two', messageKey: 'activity.audit', severity: 'error' })
        void runtime.logger.write({ event: 'audit-fill-three', messageKey: 'activity.audit', severity: 'error' })
        const stopping = runtime.stop()
        assert.equal(runtime.stop(), stopping)
        await nextTurn()
        assert.deepEqual(runtime.getReadiness(), { status: 'unavailable', reason: 'event-log-unavailable', restartCount: 0, terminatedGeneration: 1 })
        assert.equal(timers.pending.size, 1)
        timers.fireDelay(100)

        assert.deepEqual(await stopping, { ok: false, reason: 'event-log-priority-overflow' })
        assert.equal(publishedDeviceEvents.filter((event) => event.status === 'unavailable' && event.reason === 'event-log-unavailable').length, 1)
        assert.equal(await runtime.logger.write({ event: 'audit-after-stop', messageKey: 'activity.audit' }), false)

        hangingLog.reject()
        await nextTurn()
        assert.deepEqual(unhandled, [])
        assert.deepEqual(await runtime.stop(), { ok: false, reason: 'event-log-priority-overflow' })
    } finally {
        process.off('unhandledRejection', recordUnhandled)
        for (const timer of [...timers.pending.values()]) timer.callback()
        hangingLog.reject()
        await runtime.stop()
        await rm(directory, { force: true, recursive: true })
    }
})
