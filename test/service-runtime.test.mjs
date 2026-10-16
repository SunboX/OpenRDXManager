// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { registerIpcHandlers } from '../src/main/ipc-controller.mjs'
import { createApplicationServiceRuntime } from '../src/main/service-runtime.mjs'
import { createChildProcessTransportFactory } from '../src/main/device-service-client.mjs'
import { nativeHostReadiness } from './helpers/native-host-readiness.mjs'
import { ownWindowsFixture } from './helpers/windows-fixture-owner.mjs'
import { completeDeviceSnapshot } from './helpers/device-snapshot.mjs'
import { createTerminalRuntimeLog } from './helpers/terminal-runtime-log.mjs'

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

/** @param {Buffer} frame - Complete outbound service frame. @returns {object} Decoded message. */
function decodeFrame(frame) {
    const length = frame.readUInt32BE(0)
    return JSON.parse(frame.subarray(4, length + 4).toString('utf8'))
}

/** @param {object} message - Controlled service message. @returns {Buffer} Complete inbound frame. */
function encodeFrame(message) {
    const payload = Buffer.from(JSON.stringify(message), 'utf8')
    const frame = Buffer.allocUnsafe(payload.length + 4)
    frame.writeUInt32BE(payload.length, 0)
    payload.copy(frame, 4)
    return frame
}

/** @param {() => boolean} predicate - Completion predicate. @returns {Promise<void>} Resolves at a bounded future turn. */
async function waitFor(predicate) {
    for (let attempt = 0; attempt < 100; attempt += 1) {
        if (predicate()) return
        await new Promise((resolve) => setTimeout(resolve, 1))
    }
    assert.fail('controlled runtime condition did not become true')
}

/** Native-like transport whose failed generation can never confirm teardown. */
class UnconfirmedTransport extends EventEmitter {
    /** Creates an initially writable controlled transport. */
    constructor() {
        super()
        this.acceptWrites = true
    }

    /** @param {Buffer} frame - Main request frame. @returns {object} Stable write admission. */
    write(frame) {
        if (!this.acceptWrites) return { ok: false, reason: 'service-unavailable' }
        const message = decodeFrame(frame)
        if (message.type === 'handshake-request') {
            queueMicrotask(() => this.emit('data', encodeFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'runtime-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } })))
        } else if (message.method === 'devices-list') {
            const device = completeDeviceSnapshot({ id: 'rdx:runtime-1', revision: 1, vendor: 'TANDBERG', product: 'RDX', serial: 'RUNTIME1', media: null, capabilities: { 'self-test': { state: 'available' } } })
            queueMicrotask(() => this.emit('data', encodeFrame({ type: 'response', requestId: message.requestId, ok: true, result: { ok: true, listRevision: 0, devices: [device] } })))
        }
        return { ok: true }
    }

    /** @returns {object} Explicitly unconfirmed child teardown result. */
    close() {
        return { confirmed: false, reason: 'service-teardown-unconfirmed' }
    }
}

/** Native-like transport that coalesces cancel acknowledgement and cleanup. */
class CoalescedCancelTransport extends EventEmitter {
    #progressFrameCount

    /**
     * Creates a native-like transport with a controlled repeated progress burst.
     * @param {number} [progressFrameCount=1] - Same-stage progress frame count.
     */
    constructor(progressFrameCount = 1) {
        super()
        this.#progressFrameCount = progressFrameCount
    }

    /** @param {Buffer} frame - Main request frame. @returns {object} Stable write admission. */
    write(frame) {
        const message = decodeFrame(frame)
        if (message.type === 'handshake-request') {
            queueMicrotask(() => this.emit('data', encodeFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'coalesced-cancel-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } })))
            return { ok: true }
        }
        if (message.method === 'devices-list') {
            const device = completeDeviceSnapshot({ id: 'rdx:runtime-1', revision: 1, vendor: 'TANDBERG', product: 'RDX', serial: 'RUNTIME1', media: null, capabilities: { 'self-test': { state: 'available' } } })
            queueMicrotask(() => this.emit('data', encodeFrame({ type: 'response', requestId: message.requestId, ok: true, result: { ok: true, listRevision: 0, devices: [device] } })))
            return { ok: true }
        }
        if (message.method === 'operation-start') {
            const operation = message.payload

            /** @returns {void} Delivers start acknowledgement before the separate started event. */
            const deliverStartResponse = () => {
                this.emit('data', encodeFrame({ type: 'response', requestId: message.requestId, ok: true, result: { ok: true } }))
                queueMicrotask(deliverStarted)
            }

            /** @returns {void} Delivers the exact operation start after acknowledgement continuation. */
            const deliverStarted = () => {
                this.emit('data', encodeFrame({ type: 'event', channel: 'operation', publicationSequence: 1, event: { state: 'started', operationId: operation.operationId, kind: operation.request.kind, deviceId: operation.request.deviceId, deviceRevision: operation.request.deviceRevision, stage: 'diagnostic-running' } }))
            }

            queueMicrotask(deliverStartResponse)
            return { ok: true }
        }
        if (message.method === 'operation-cancel') {
            const operationId = message.payload.operationId

            /** @returns {void} Delivers acknowledgement, cleanup, and terminal in one decoder turn. */
            const deliverCoalescedCancellation = () => {
                const cancellationCutover = this.#progressFrameCount + 1
                const messages = [{ type: 'response', requestId: message.requestId, ok: true, result: { ok: true, cancellationCutover } }]
                for (let index = 1; index <= this.#progressFrameCount; index += 1) {
                    messages.push({ type: 'event', channel: 'operation', publicationSequence: index + 1, event: { state: 'progress', operationId, kind: 'self-test', deviceId: 'rdx:runtime-1', deviceRevision: 1, stage: 'diagnostic-running', progress: index / (this.#progressFrameCount + 1), cancellationState: 'cancellable' } })
                }
                messages.push({ type: 'event', channel: 'operation', publicationSequence: cancellationCutover + 1, event: { state: 'progress', operationId, kind: 'self-test', deviceId: 'rdx:runtime-1', deviceRevision: 1, stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'requested' } })
                messages.push({ type: 'event', channel: 'operation', publicationSequence: cancellationCutover + 2, event: { state: 'cancelled', operationId, kind: 'self-test', deviceId: 'rdx:runtime-1', deviceRevision: 1, stage: 'diagnostic-cleanup' } })
                this.emit('data', Buffer.concat(messages.map(encodeFrame)))
            }

            queueMicrotask(deliverCoalescedCancellation)
            return { ok: true }
        }
        return { ok: false, reason: 'service-unavailable' }
    }

    /** @returns {object} Confirms deterministic transport closure. */
    close() {
        return { confirmed: true }
    }
}

/** Native-like transport that coalesces a start response with already-advanced events. */
class CoalescedStartTransport extends EventEmitter {
    #afterStartChunk
    #closeConfirmed
    #includeTerminal
    #startResponse

    /**
     * Creates one controlled start-acknowledgement ordering scenario.
     * @param {{afterStartChunk?: Function, closeConfirmed: boolean, includeTerminal?: boolean, startResponse: object}} options - Ack result, terminal burst, observation, and teardown proof.
     */
    constructor(options) {
        super()
        this.#afterStartChunk = options.afterStartChunk
        this.#closeConfirmed = options.closeConfirmed
        this.#includeTerminal = options.includeTerminal === true
        this.#startResponse = options.startResponse
    }

    /** @param {Buffer} frame - Main request frame. @returns {object} Stable write admission. */
    write(frame) {
        const message = decodeFrame(frame)
        if (message.type === 'handshake-request') {
            queueMicrotask(() => this.emit('data', encodeFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'coalesced-start-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } })))
            return { ok: true }
        }
        if (message.method === 'devices-list') {
            const device = completeDeviceSnapshot({ id: 'rdx:runtime-1', revision: 1, vendor: 'TANDBERG', product: 'RDX', serial: 'RUNTIME1', media: null, capabilities: { 'self-test': { state: 'available' } } })
            queueMicrotask(() => this.emit('data', encodeFrame({ type: 'response', requestId: message.requestId, ok: true, result: { ok: true, listRevision: 0, devices: [device] } })))
            return { ok: true }
        }
        if (message.method === 'operation-start') {
            const operation = message.payload

            /** @returns {void} Delivers response and operation events in one decoder turn. */
            const deliverCoalescedStart = () => {
                const messages = [
                    { type: 'response', requestId: message.requestId, ok: true, result: this.#startResponse },
                    { type: 'event', channel: 'operation', publicationSequence: 1, event: { state: 'started', operationId: operation.operationId, kind: operation.request.kind, deviceId: operation.request.deviceId, deviceRevision: operation.request.deviceRevision, stage: 'diagnostic-running' } },
                    { type: 'event', channel: 'operation', publicationSequence: 2, event: { state: 'progress', operationId: operation.operationId, kind: operation.request.kind, deviceId: operation.request.deviceId, deviceRevision: operation.request.deviceRevision, stage: 'diagnostic-running', progress: 0.5, cancellationState: 'cancellable' } }
                ]
                if (this.#includeTerminal) {
                    messages.push({ type: 'event', channel: 'operation', publicationSequence: 3, event: { state: 'progress', operationId: operation.operationId, kind: operation.request.kind, deviceId: operation.request.deviceId, deviceRevision: operation.request.deviceRevision, stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'closed' } }, { type: 'event', channel: 'operation', publicationSequence: 4, event: { state: 'succeeded', operationId: operation.operationId, kind: operation.request.kind, deviceId: operation.request.deviceId, deviceRevision: operation.request.deviceRevision, stage: 'complete' } })
                }
                this.emit('data', Buffer.concat(messages.map(encodeFrame)))
                this.#afterStartChunk?.()
            }

            queueMicrotask(deliverCoalescedStart)
            return { ok: true }
        }
        return { ok: false, reason: 'service-unavailable' }
    }

    /** @returns {object} Controlled exact-generation teardown result. */
    close() {
        return { confirmed: this.#closeConfirmed }
    }
}

/** Native-like transport that exposes lifecycle identity before either owning acknowledgement. */
class PreAckCancellationTransport extends EventEmitter {
    /** @param {{duplicateStartResponse?: boolean, responseOrder?: 'start-first'|'cancel-first', splitCancelResponse?: boolean, startResponse?: object}} [options] - Controlled owning response order and result. */
    constructor(options = {}) {
        super()
        this.batchDelivered = false
        this.cancelRequest = null
        this.device = completeDeviceSnapshot({ id: 'rdx:runtime-1', revision: 1, vendor: 'TANDBERG', product: 'RDX', serial: 'RUNTIME1', media: null, capabilities: { 'self-test': { state: 'available' } } })
        this.duplicateStartResponse = options.duplicateStartResponse === true
        this.responseOrder = options.responseOrder ?? 'start-first'
        this.splitCancelResponse = options.splitCancelResponse === true
        this.startRequest = null
        this.startResponse = options.startResponse ?? { ok: true }
    }

    /** @param {Buffer} frame - Main request frame. @returns {object} Stable write admission. */
    write(frame) {
        const message = decodeFrame(frame)
        if (message.type === 'handshake-request') {
            queueMicrotask(() => this.emit('data', encodeFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'pre-ack-cancellation-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } })))
            return { ok: true }
        }
        if (message.method === 'devices-list') {
            queueMicrotask(() => this.emit('data', encodeFrame({ type: 'response', requestId: message.requestId, ok: true, result: { ok: true, listRevision: 0, devices: [this.device] } })))
            return { ok: true }
        }
        if (message.method === 'operation-start') {
            this.startRequest = message
            const operation = message.payload
            queueMicrotask(() =>
                this.emit(
                    'data',
                    Buffer.concat(
                        [
                            { type: 'event', channel: 'operation', publicationSequence: 1, event: { state: 'started', operationId: operation.operationId, kind: operation.request.kind, deviceId: operation.request.deviceId, deviceRevision: operation.request.deviceRevision, stage: 'diagnostic-running' } },
                            { type: 'event', channel: 'operation', publicationSequence: 2, event: { state: 'progress', operationId: operation.operationId, kind: operation.request.kind, deviceId: operation.request.deviceId, deviceRevision: operation.request.deviceRevision, stage: 'diagnostic-running', progress: 0.5, cancellationState: 'cancellable' } }
                        ].map(encodeFrame)
                    )
                )
            )
            return { ok: true }
        }
        if (message.method === 'operation-cancel' && this.startRequest !== null) {
            this.cancelRequest = message
            const operation = this.startRequest.payload
            const startResponse = { type: 'response', requestId: this.startRequest.requestId, ok: true, result: this.startResponse }
            const cancelResponse = { type: 'response', requestId: message.requestId, ok: true, result: { ok: true, cancellationCutover: 4 } }
            const responses = this.responseOrder === 'cancel-first' ? [cancelResponse, startResponse] : this.duplicateStartResponse ? [startResponse, startResponse, cancelResponse] : [startResponse, cancelResponse]
            const messages = [{ type: 'event', channel: 'operation', publicationSequence: 3, event: { state: 'progress', operationId: operation.operationId, kind: operation.request.kind, deviceId: operation.request.deviceId, deviceRevision: operation.request.deviceRevision, stage: 'diagnostic-cleanup', progress: 1, cancellationState: 'requested' } }, { type: 'event', channel: 'operation', publicationSequence: 4, event: { state: 'cancelled', operationId: operation.operationId, kind: operation.request.kind, deviceId: operation.request.deviceId, deviceRevision: operation.request.deviceRevision, stage: 'diagnostic-cleanup' } }, ...(this.splitCancelResponse ? [startResponse] : responses), { type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [this.device] } }]
            queueMicrotask(() => {
                this.batchDelivered = true
                this.emit('data', Buffer.concat(messages.map(encodeFrame)))
            })
            return { ok: true }
        }
        return { ok: false, reason: 'service-unavailable' }
    }

    /** @returns {void} Delivers the exact deferred cancellation response in a later transport callback. */
    deliverDeferredCancellation() {
        assert.notEqual(this.cancelRequest, null)
        this.emit('data', encodeFrame({ type: 'response', requestId: this.cancelRequest.requestId, ok: true, result: { ok: true, cancellationCutover: 4 } }))
    }

    /** @returns {object} Confirms deterministic transport closure. */
    close() {
        return { confirmed: true }
    }
}

/**
 * Creates a logger filesystem boundary whose first write is explicitly released.
 * @returns {{fileSecurity: object, release: () => void}} Controlled append boundary.
 */
function createBlockedRuntimeLog() {
    let release
    const gate = new Promise((resolve) => {
        release = resolve
    })
    let firstWrite = true
    return {
        release,
        fileSecurity: {
            /** @returns {Promise<void>} Prepares no host directory. */
            async prepareDirectory() {},
            /** @returns {Promise<object>} Returns a controlled append handle. */
            async openAppend() {
                return {
                    /** @returns {Promise<{size: number}>} Reports an empty file. */
                    async stat() {
                        return { size: 0 }
                    },
                    /** @returns {Promise<void>} Waits only for the first controlled append. */
                    async writeFile() {
                        if (firstWrite) {
                            firstWrite = false
                            await gate
                        }
                    },
                    /** @returns {Promise<void>} Closes without host work. */
                    async close() {}
                }
            },
            /** @returns {Promise<void>} Removes no backup. */
            async removeFile() {},
            /** @returns {Promise<void>} Renames no current file. */
            async renameFile() {}
        }
    }
}

/**
 * Creates a logger filesystem boundary whose write never settles by itself.
 * @returns {{arm: () => void, fileSecurity: object, reject: () => void, waitForHang: () => Promise<void>}} Controlled hanging append.
 */
function createHangingRuntimeLog() {
    let armed = false
    let markEntered
    let rejectWrite
    const entered = new Promise((resolve) => {
        markEntered = resolve
    })
    const write = new Promise((_resolve, reject) => {
        rejectWrite = reject
    })
    return {
        /** @returns {void} Hangs only the next append. */
        arm() {
            armed = true
        },
        /** @returns {void} Rejects the already-observed write after timeout. */
        reject() {
            rejectWrite(new Error('controlled-sensitive-late-rejection'))
        },
        /** @returns {Promise<void>} Resolves once the armed append owns the persistence attempt. */
        waitForHang() {
            return entered
        },
        fileSecurity: {
            /** @returns {Promise<void>} Prepares no host directory. */
            async prepareDirectory() {},
            /** @returns {Promise<object>} Returns one never-settling append handle. */
            async openAppend() {
                return {
                    /** @returns {Promise<{size: number}>} Reports an empty file. */
                    async stat() {
                        return { size: 0 }
                    },
                    /** @returns {Promise<void>} Hangs only after explicit arming. */
                    async writeFile() {
                        if (armed) {
                            armed = false
                            markEntered()
                            return write
                        }
                    },
                    /** @returns {Promise<void>} Closes without host work. */
                    async close() {}
                }
            },
            /** @returns {Promise<void>} Removes no backup. */
            async removeFile() {},
            /** @returns {Promise<void>} Renames no current file. */
            async renameFile() {}
        }
    }
}

/**
 * Creates deterministic logger-only timers.
 * @returns {{timers: object, fireNext: () => void, pendingCount: () => number}} Controlled timeouts.
 */
function createRuntimeLogTimers() {
    let nextId = 1
    const callbacks = new Map()
    return {
        timers: {
            /** @param {Function} callback - Timeout callback. @returns {number} Timer ID. */
            setTimeout(callback) {
                const id = nextId
                nextId += 1
                callbacks.set(id, callback)
                return id
            },
            /** @param {number} id - Timer ID. @returns {void} Clears one timeout. */
            clearTimeout(id) {
                callbacks.delete(id)
            }
        },
        /** @returns {void} Fires the oldest pending timeout. */
        fireNext() {
            const next = callbacks.entries().next().value
            assert.notEqual(next, undefined)
            const [id, callback] = next
            callbacks.delete(id)
            callback()
        },
        /** @returns {number} Number of pending timeouts. */
        pendingCount() {
            return callbacks.size
        }
    }
}

/**
 * Creates an ipcMain-compatible exact handler registry.
 * @returns {{handlers: Map<string, Function>, ipcMain: object}} Fake IPC registry.
 */
function createIpcMain() {
    const handlers = new Map()
    return {
        handlers,
        ipcMain: {
            /**
             * Registers one exact invoke handler.
             * @param {string} channel - Internal channel.
             * @param {Function} handler - Main handler.
             * @returns {void} Completes after registration.
             */
            handle(channel, handler) {
                handlers.set(channel, handler)
            },
            /**
             * Removes one exact invoke handler.
             * @param {string} channel - Internal channel.
             * @returns {void} Completes after removal.
             */
            removeHandler(channel) {
                handlers.delete(channel)
            }
        }
    }
}

test('uses the compiled stdio runtime through the validated Task 6 handlers', async () => {
    const logDirectory = await mkdtemp(join(tmpdir(), 'openrdx-service-runtime-'))
    await ownWindowsFixture(logDirectory)
    const { handlers, ipcMain } = createIpcMain()
    const publishedDeviceEvents = []
    const publishedOperationEvents = []
    const services = {
        /** @returns {boolean} Accepts the controlled IPC sender. */
        isTrustedSender() {
            return true
        }
    }
    const ipcController = registerIpcHandlers({ ipcMain, services })
    const publishedController = {
        /**
         * Records one strict service/device event.
         * @param {object} event - Renderer-safe event.
         * @returns {boolean} True after recording.
         */
        publishDeviceEvent(event) {
            publishedDeviceEvents.push(event)
            return true
        },
        /**
         * Records one strict operation event.
         * @param {object} event - Renderer-safe event.
         * @returns {boolean} True after recording.
         */
        publishOperationEvent(event) {
            publishedOperationEvents.push(event)
            return true
        }
    }
    let runtime
    try {
        runtime = createApplicationServiceRuntime({
            appPath: projectRoot,
            ipcController: publishedController,
            isPackaged: false,
            logDirectory,
            platform: process.platform,
            resourcesPath: join(projectRoot, 'resources'),
            services,
            transportFactory: createChildProcessTransportFactory({ platform: process.platform, shutdownTimeoutMs: 2_000, forceKillTimeoutMs: 2_000 })
        })
        const state = await runtime.start()
        const nativeDiscovery = ['darwin', 'win32', 'linux'].includes(process.platform)
        const readiness = nativeHostReadiness(process.platform, state.privileged)
        const expectedScan = nativeDiscovery ? { ok: true } : { ok: false, reason: 'hardware-unavailable' }

        assert.equal(state.status, 'ready')
        assert.equal(state.mode, readiness.mode)
        assert.equal(state.hardwareReady, readiness.hardwareReady)
        assert.deepEqual(state.platformCapability, readiness.platformCapability)
        assert.deepEqual(await handlers.get('openrdx:devices:list')({}, {}), { ok: true, status: 'ready', ...readiness, epoch: 1, listRevision: 0, devices: [] })
        assert.deepEqual(await handlers.get('openrdx:devices:scan')({}, { kind: 'scan' }), expectedScan)
        assert.deepEqual(await handlers.get('openrdx:operations:start')({}, { kind: 'self-test', deviceId: 'rdx:not-present', deviceRevision: 1 }), { ok: false, reason: readiness.hardwareReady ? 'device-not-found' : 'hardware-unavailable' })
        const expectedDeviceEvents = [
            { type: 'service', status: 'starting' },
            { type: 'service', status: 'reconciling' },
            { type: 'service', status: 'ready', epoch: 1, listRevision: 0, ...readiness },
            { type: 'list', epoch: 1, listRevision: 0, devices: [] }
        ]
        if (nativeDiscovery) {
            expectedDeviceEvents.push({ type: 'list', epoch: 1, listRevision: 1, devices: [] })
        }
        const eventsWithoutDiagnostics = []
        for (const { diagnostics: _diagnostics, ...event } of publishedDeviceEvents) eventsWithoutDiagnostics.push(event)
        assert.deepEqual(eventsWithoutDiagnostics, expectedDeviceEvents)
        const scanDiagnostics = publishedDeviceEvents.at(-1)?.diagnostics
        if (scanDiagnostics !== undefined) {
            let rejectedCandidates = 0
            for (const rejection of scanDiagnostics.rejections) rejectedCandidates += rejection.count
            assert.equal(scanDiagnostics.acceptedCount, 0)
            assert.equal(rejectedCandidates, scanDiagnostics.candidateCount)
        }
        assert.deepEqual(publishedOperationEvents, [])

        await runtime.stop()
        assert.equal(runtime.getReadiness().status, 'stopped')
        assert.deepEqual(await handlers.get('openrdx:devices:list')({}, {}), { ok: false, reason: 'service-unavailable' })
    } finally {
        await runtime?.stop()
        ipcController.dispose()
        await rm(logDirectory, { force: true, recursive: true })
    }
})

test('escalates all-priority event-log saturation into terminal runtime health loss', async () => {
    const logDirectory = await mkdtemp(join(tmpdir(), 'openrdx-service-runtime-log-saturation-'))
    const blocked = createBlockedRuntimeLog()
    const publishedDeviceEvents = []
    const runtime = createApplicationServiceRuntime({
        appPath: '/work/OpenRDXManager',
        eventLoggerOptions: { fileSecurity: blocked.fileSecurity, maxBytes: 512, maxPendingBytes: 1024, maxPendingEntries: 2 },
        ipcController: {
            /** @param {object} event - Safe device event. @returns {boolean} Records the event. */
            publishDeviceEvent(event) {
                publishedDeviceEvents.push(event)
                return true
            },
            /** @returns {boolean} Accepts no controlled operation events. */
            publishOperationEvent() {
                return true
            }
        },
        isPackaged: false,
        logDirectory,
        platform: 'darwin',
        resourcesPath: '/work/OpenRDXManager/resources',
        services: {},
        transportFactory: () => new CoalescedCancelTransport()
    })
    try {
        const unavailable = { status: 'unavailable', reason: 'event-log-unavailable', restartCount: 0, terminatedGeneration: 1 }
        assert.deepEqual(await runtime.start(), unavailable)
        assert.deepEqual(await runtime.start(), unavailable)
        assert.deepEqual(publishedDeviceEvents.at(-1), { type: 'service', status: 'unavailable', reason: 'event-log-unavailable' })
        blocked.release()
        assert.deepEqual(await runtime.stop(), { ok: false, reason: 'event-log-priority-overflow' })
    } finally {
        blocked.release()
        await runtime.stop()
        await rm(logDirectory, { force: true, recursive: true })
    }
})

test('bounds runtime teardown on a hanging event log and reports one sanitized result', async () => {
    const logDirectory = await mkdtemp(join(tmpdir(), 'openrdx-service-runtime-log-timeout-'))
    const hanging = createHangingRuntimeLog()
    const manual = createRuntimeLogTimers()
    const runtime = createApplicationServiceRuntime({
        appPath: '/work/OpenRDXManager',
        eventLoggerOptions: { fileSecurity: hanging.fileSecurity, persistenceTimeoutMs: 100, timers: manual.timers },
        ipcController: {
            /** @returns {boolean} Accepts controlled device publication. */
            publishDeviceEvent() {
                return true
            },
            /** @returns {boolean} Accepts controlled operation publication. */
            publishOperationEvent() {
                return true
            }
        },
        isPackaged: false,
        logDirectory,
        platform: 'darwin',
        resourcesPath: '/work/OpenRDXManager/resources',
        services: {},
        transportFactory: () => new CoalescedCancelTransport()
    })
    try {
        assert.equal((await runtime.start()).status, 'ready')
        hanging.arm()
        const stopping = runtime.stop()
        assert.equal(runtime.stop(), stopping)
        await hanging.waitForHang()
        assert.equal(manual.pendingCount(), 1)
        manual.fireNext()
        assert.deepEqual(await stopping, { ok: false, reason: 'event-log-persistence-timeout' })

        hanging.reject()
        await new Promise(setImmediate)
        assert.deepEqual(await runtime.stop(), { ok: false, reason: 'event-log-persistence-timeout' })
    } finally {
        await runtime.stop()
        await rm(logDirectory, { force: true, recursive: true })
    }
})

test('retains the exact operation owner when service teardown cannot be confirmed', async () => {
    const logDirectory = await mkdtemp(join(tmpdir(), 'openrdx-service-runtime-stuck-'))
    const { handlers, ipcMain } = createIpcMain()
    const transport = new UnconfirmedTransport()
    const services = { isTrustedSender: () => true }
    const publishedDeviceEvents = []
    const publishedOperationEvents = []
    const ipcController = registerIpcHandlers({ ipcMain, services })
    const runtime = createApplicationServiceRuntime({
        appPath: '/work/OpenRDXManager',
        ipcController: {
            /** @param {object} event - Safe device event. @returns {boolean} Records the event. */
            publishDeviceEvent(event) {
                publishedDeviceEvents.push(event)
                return true
            },
            /** @param {object} event - Safe operation event. @returns {boolean} Records the event. */
            publishOperationEvent(event) {
                publishedOperationEvents.push(event)
                return true
            }
        },
        isPackaged: false,
        logDirectory,
        platform: 'darwin',
        resourcesPath: '/work/OpenRDXManager/resources',
        services,
        transportFactory: () => transport
    })
    try {
        assert.equal((await runtime.start()).status, 'ready')
        transport.acceptWrites = false
        assert.equal((await handlers.get('openrdx:operations:start')({}, { kind: 'self-test', deviceId: 'rdx:runtime-1', deviceRevision: 1 })).ok, true)
        await new Promise(setImmediate)

        assert.equal(runtime.getReadiness().status, 'teardown-unconfirmed')
        assert.notEqual(runtime.coordinator.getActiveOperation(), null)
        assert.equal(publishedDeviceEvents.at(-1).reason, 'service-teardown-unconfirmed')
        assert.equal(
            publishedOperationEvents.some((event) => event.state === 'failed'),
            false
        )
    } finally {
        ipcController.dispose()
        await runtime.stop()
        await rm(logDirectory, { force: true, recursive: true })
    }
})

test('reconciles a 64-event pre-ack FIFO prefix with requested recovery and terminal', async () => {
    const logDirectory = await mkdtemp(join(tmpdir(), 'openrdx-service-runtime-coalesced-'))
    const { handlers, ipcMain } = createIpcMain()
    const services = { isTrustedSender: () => true }
    const publishedOperationEvents = []
    const ipcController = registerIpcHandlers({ ipcMain, services })

    /** @returns {CoalescedCancelTransport} Transport with the 64-frame progress burst. */
    function transportFactory() {
        return new CoalescedCancelTransport(64)
    }

    const runtime = createApplicationServiceRuntime({
        appPath: '/work/OpenRDXManager',
        ipcController: {
            /** @returns {boolean} Accepts controlled device publication. */
            publishDeviceEvent() {
                return true
            },
            /** @param {object} event - Safe operation event. @returns {boolean} Records the event. */
            publishOperationEvent(event) {
                publishedOperationEvents.push(event)
                return true
            }
        },
        isPackaged: false,
        logDirectory,
        platform: 'darwin',
        resourcesPath: '/work/OpenRDXManager/resources',
        services,
        transportFactory
    })
    try {
        assert.equal((await runtime.start()).status, 'ready')
        const started = await handlers.get('openrdx:operations:start')({}, { kind: 'self-test', deviceId: 'rdx:runtime-1', deviceRevision: 1 })
        await new Promise(setImmediate)

        assert.deepEqual(await handlers.get('openrdx:operations:cancel')({}, { operationId: started.operationId }), { ok: true })
        await new Promise(setImmediate)

        assert.equal(runtime.coordinator.getActiveOperation(), null)
        assert.deepEqual(
            publishedOperationEvents.map((event) => event.state),
            ['queued', 'started', 'progress', 'progress', 'cancelled']
        )
        assert.deepEqual(
            publishedOperationEvents.filter((event) => event.state === 'progress').map((event) => event.cancellationState),
            ['cancellable', 'requested']
        )
    } finally {
        ipcController.dispose()
        await runtime.stop()
        await rm(logDirectory, { force: true, recursive: true })
    }
})

test('drains coalesced pre-start-ack cancellation responses without releasing the terminal early', async (context) => {
    const scenarios = [
        { name: 'start then cancel acknowledgements', options: {}, outcome: 'success' },
        { name: 'reversed cancel then start acknowledgements fail closed', options: { responseOrder: 'cancel-first' }, outcome: 'fault-order' },
        { name: 'duplicate start acknowledgement fails closed before cancel acknowledgement', options: { duplicateStartResponse: true }, outcome: 'fault-order' },
        { name: 'start-only batch then later cancel callback', options: { splitCancelResponse: true }, outcome: 'success' },
        { name: 'negative start then positive cancel acknowledgement', options: { startResponse: { ok: false, reason: 'operation-rejected' } }, outcome: 'fault' }
    ]
    for (const scenario of scenarios) {
        await context.test(scenario.name, { timeout: 10_000 }, async () => {
            const logDirectory = await mkdtemp(join(tmpdir(), 'openrdx-service-runtime-start-cancel-'))
            const terminalLog = createTerminalRuntimeLog()
            const terminalPublished = Promise.withResolvers()
            const { handlers, ipcMain } = createIpcMain()
            const services = { isTrustedSender: () => true }
            const published = []
            const ipcController = registerIpcHandlers({ ipcMain, services })
            let firstTransport = null
            const runtime = createApplicationServiceRuntime({
                appPath: '/work/OpenRDXManager',
                eventLoggerOptions: { fileSecurity: terminalLog.fileSecurity },
                ipcController: {
                    /** @param {object} event - Safe device event. @returns {boolean} Records exact publication order. */
                    publishDeviceEvent(event) {
                        published.push({ channel: 'device', event })
                        return true
                    },
                    /** @param {object} event - Safe operation event. @returns {boolean} Records exact publication order. */
                    publishOperationEvent(event) {
                        published.push({ channel: 'operation', event })
                        if (['failed', 'cancelled', 'succeeded'].includes(event.state)) terminalPublished.resolve(event)
                        return true
                    }
                },
                isPackaged: false,
                logDirectory,
                platform: 'darwin',
                resourcesPath: '/work/OpenRDXManager/resources',
                services,
                transportFactory: () => {
                    const transport = new PreAckCancellationTransport(scenario.options)
                    firstTransport ??= transport
                    return transport
                }
            })
            let cancellationResult = null
            try {
                assert.equal((await runtime.start()).status, 'ready')
                const started = await handlers.get('openrdx:operations:start')({}, { kind: 'self-test', deviceId: 'rdx:runtime-1', deviceRevision: 1 })
                await waitFor(() => published.some((entry) => entry.channel === 'operation' && entry.event.state === 'progress'))
                const operationId = published.find((entry) => entry.channel === 'operation' && entry.event.state === 'queued').event.operationId
                assert.deepEqual(started, { ok: true, operationId })
                assert.equal(runtime.coordinator.getActiveOperation().operationId, operationId)
                assert.notEqual(firstTransport.startRequest, null)
                assert.equal(firstTransport.batchDelivered, false)
                assert.equal(firstTransport.cancelRequest, null)

                /** @returns {Promise<object>} Captures cancellation settlement without blocking transport evidence. */
                async function trackCancellation() {
                    cancellationResult = await handlers.get('openrdx:operations:cancel')({}, { operationId })
                    return cancellationResult
                }
                const cancellation = trackCancellation()
                await waitFor(() => firstTransport.batchDelivered)
                await new Promise(setImmediate)
                if (scenario.options.splitCancelResponse === true) {
                    assert.equal(cancellationResult, null)
                    assert.equal(
                        published.some((entry) => entry.channel === 'operation' && entry.event.state === 'cancelled'),
                        false
                    )
                    assert.equal(
                        published.some((entry) => entry.channel === 'device' && entry.event.type === 'list' && entry.event.listRevision === 1),
                        false
                    )
                    firstTransport.deliverDeferredCancellation()
                }

                // Ownership and the decoder suffix must stay held until the
                // terminal actually persists, independent of host I/O latency.
                const terminalRecord = await terminalLog.terminalWriteStarted
                const expectedTerminalState = scenario.outcome === 'success' ? 'cancelled' : 'failed'
                assert.equal(terminalRecord.details.state, expectedTerminalState)
                assert.equal(runtime.coordinator.getActiveOperation().operationId, operationId)
                assert.equal(
                    published.some((entry) => entry.channel === 'operation' && ['failed', 'cancelled', 'succeeded'].includes(entry.event.state)),
                    false
                )
                assert.equal(
                    published.some((entry) => entry.channel === 'device' && entry.event.type === 'list' && entry.event.listRevision === 1),
                    false
                )
                terminalLog.release()
                assert.equal((await terminalPublished.promise).state, expectedTerminalState)
                assert.equal(runtime.coordinator.getActiveOperation(), null)

                if (scenario.outcome !== 'success') {
                    const expectedCancellation = scenario.outcome === 'fault-order' ? { ok: false, reason: 'operation-outcome-unknown' } : { ok: true }
                    assert.deepEqual(await cancellation, expectedCancellation)
                    assert.equal(
                        published.some((entry) => entry.channel === 'operation' && entry.event.state === 'cancelled'),
                        false
                    )
                    assert.equal(
                        published.some((entry) => entry.channel === 'device' && entry.event.type === 'list' && entry.event.listRevision === 1),
                        false
                    )
                    return
                }

                assert.deepEqual(await cancellation, { ok: true })
                assert.deepEqual(cancellationResult, { ok: true })
                await waitFor(() => published.some((entry) => entry.channel === 'device' && entry.event.type === 'list' && entry.event.listRevision === 1))
                const terminalIndex = published.findIndex((entry) => entry.channel === 'operation' && entry.event.state === 'cancelled')
                const suffixIndex = published.findIndex((entry) => entry.channel === 'device' && entry.event.type === 'list' && entry.event.listRevision === 1)
                assert.equal(terminalIndex >= 0 && suffixIndex > terminalIndex, true)
                assert.equal(runtime.getReadiness().status, 'ready')
            } finally {
                terminalLog.release()
                ipcController.dispose()
                await runtime.stop()
                await rm(logDirectory, { force: true, recursive: true })
            }
        })
    }
})

test('defers a coalesced terminal until the positive start promise continuation', async () => {
    const logDirectory = await mkdtemp(join(tmpdir(), 'openrdx-service-runtime-start-positive-'))
    const { handlers, ipcMain } = createIpcMain()
    const services = { isTrustedSender: () => true }
    const publishedOperationEvents = []
    const ipcController = registerIpcHandlers({ ipcMain, services })
    let ownerBeforeStartContinuation = null
    let runtime

    /** @returns {CoalescedStartTransport} Transport with an assembled positive terminal chunk. */
    function transportFactory() {
        return new CoalescedStartTransport({
            afterStartChunk() {
                ownerBeforeStartContinuation = runtime.coordinator.getActiveOperation()
            },
            closeConfirmed: true,
            includeTerminal: true,
            startResponse: { ok: true }
        })
    }

    runtime = createApplicationServiceRuntime({
        appPath: '/work/OpenRDXManager',
        ipcController: {
            /** @returns {boolean} Accepts controlled device publication. */
            publishDeviceEvent() {
                return true
            },
            /** @param {object} event - Safe operation event. @returns {boolean} Records the event. */
            publishOperationEvent(event) {
                publishedOperationEvents.push(event)
                return true
            }
        },
        isPackaged: false,
        logDirectory,
        platform: 'darwin',
        resourcesPath: '/work/OpenRDXManager/resources',
        services,
        transportFactory
    })
    try {
        assert.equal((await runtime.start()).status, 'ready')
        await handlers.get('openrdx:operations:start')({}, { kind: 'self-test', deviceId: 'rdx:runtime-1', deviceRevision: 1 })
        await waitFor(() => runtime.coordinator.getActiveOperation() === null)

        assert.equal(ownerBeforeStartContinuation.stage, 'diagnostic-cleanup')
        assert.equal(runtime.coordinator.getActiveOperation(), null)
        assert.deepEqual(
            publishedOperationEvents.map((event) => event.state),
            ['queued', 'started', 'progress', 'progress', 'succeeded']
        )
    } finally {
        ipcController.dispose()
        await runtime.stop()
        await rm(logDirectory, { force: true, recursive: true })
    }
})

test('faults a coalesced negative start acknowledgement and retains ownership after unconfirmed teardown', async () => {
    const logDirectory = await mkdtemp(join(tmpdir(), 'openrdx-service-runtime-start-negative-'))
    const { handlers, ipcMain } = createIpcMain()
    const services = { isTrustedSender: () => true }
    const publishedOperationEvents = []
    const ipcController = registerIpcHandlers({ ipcMain, services })
    let ownerBeforeStartContinuation = null
    let runtime

    /** @returns {CoalescedStartTransport} Transport with an assembled contradictory terminal chunk. */
    function transportFactory() {
        return new CoalescedStartTransport({
            afterStartChunk() {
                ownerBeforeStartContinuation = runtime.coordinator.getActiveOperation()
            },
            closeConfirmed: false,
            includeTerminal: true,
            startResponse: { ok: false, reason: 'operation-rejected' }
        })
    }

    runtime = createApplicationServiceRuntime({
        appPath: '/work/OpenRDXManager',
        ipcController: {
            /** @returns {boolean} Accepts controlled device publication. */
            publishDeviceEvent() {
                return true
            },
            /** @param {object} event - Safe operation event. @returns {boolean} Records the event. */
            publishOperationEvent(event) {
                publishedOperationEvents.push(event)
                return true
            }
        },
        isPackaged: false,
        logDirectory,
        platform: 'darwin',
        resourcesPath: '/work/OpenRDXManager/resources',
        services,
        transportFactory
    })
    try {
        assert.equal((await runtime.start()).status, 'ready')
        await handlers.get('openrdx:operations:start')({}, { kind: 'self-test', deviceId: 'rdx:runtime-1', deviceRevision: 1 })
        await new Promise(setImmediate)

        assert.equal(runtime.getReadiness().status, 'teardown-unconfirmed')
        assert.equal(ownerBeforeStartContinuation.stage, 'diagnostic-cleanup')
        assert.equal(runtime.coordinator.getActiveOperation().stage, 'diagnostic-cleanup')
        assert.deepEqual(await handlers.get('openrdx:operations:start')({}, { kind: 'self-test', deviceId: 'rdx:runtime-1', deviceRevision: 1 }), { ok: false, reason: 'operation-in-progress' })
        assert.deepEqual(
            publishedOperationEvents.map((event) => event.state),
            ['queued', 'started', 'progress', 'progress']
        )
    } finally {
        ipcController.dispose()
        await runtime.stop()
        await rm(logDirectory, { force: true, recursive: true })
    }
})
