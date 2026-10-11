// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { registerIpcHandlers } from '../src/main/ipc-controller.mjs'
import { createApplicationServiceRuntime } from '../src/main/service-runtime.mjs'
import { completeDeviceSnapshot } from './helpers/device-snapshot.mjs'

/** @param {Buffer} frame - One complete service frame. @returns {object} Parsed frame payload. */
function decodeFrame(frame) {
    const length = frame.readUInt32BE(0)
    return JSON.parse(frame.subarray(4, length + 4).toString('utf8'))
}

/** @param {object} message - Safe service message. @returns {Buffer} Encoded service frame. */
function encodeFrame(message) {
    const payload = Buffer.from(JSON.stringify(message), 'utf8')
    const frame = Buffer.allocUnsafe(payload.length + 4)
    frame.writeUInt32BE(payload.length, 0)
    payload.copy(frame, 4)
    return frame
}

/** Native-like service proving the renderer cannot mint or replay confirmations. */
class ConfirmationTransport extends EventEmitter {
    /** Creates an empty dispatch observation. */
    constructor() {
        super()
        this.operationStarts = []
        this.confirmationIssues = []
    }

    /** @param {Buffer} frame - Exact outbound request frame. @returns {{ok: true}} Write admission. */
    write(frame) {
        const message = decodeFrame(frame)
        if (message.type === 'handshake-request') {
            queueMicrotask(() =>
                this.emit(
                    'data',
                    encodeFrame({
                        type: 'handshake',
                        protocolVersion: 1,
                        serviceVersion: 'confirmation-flow-test',
                        platform: 'darwin',
                        mode: 'native',
                        privileged: true,
                        hardwareVerified: false,
                        platformCapability: { state: 'available' }
                    })
                )
            )
            return { ok: true }
        }
        if (message.method === 'devices-list') {
            const device = completeDeviceSnapshot({
                id: 'rdx:confirmation-1',
                revision: 5,
                vendor: 'TANDBERG',
                product: 'RDX',
                serial: 'CONFIRM1',
                media: { id: 'media:current', serial: 'MEDIUM1', capacityBytes: 1_000_000_000, usedBytes: 0, writable: true, filesystem: 'exfat' },
                mediaState: 'present',
                capabilities: { format: { state: 'available' }, 'eject-force': { state: 'available' } }
            })
            this.#respond(message, { ok: true, listRevision: 0, devices: [device] })
            return { ok: true }
        }
        if (message.method === 'operation-confirmation-issue') {
            this.confirmationIssues.push(message.payload)
            this.#respond(message, { ok: true, confirmationToken: `confirm:service-${this.confirmationIssues.length}` })
            return { ok: true }
        }
        if (message.method === 'operation-start') {
            this.operationStarts.push(message.payload)
            this.#respond(message, { ok: true })
            return { ok: true }
        }
        if (message.method === 'service-shutdown') {
            this.#respond(message, { ok: true })
            return { ok: true }
        }
        return { ok: false, reason: 'unexpected-request' }
    }

    /** @param {object} request - Request carrying its correlation ID. @param {object} result - Strict result. @returns {void} Schedules one response. */
    #respond(request, result) {
        queueMicrotask(() => this.emit('data', encodeFrame({ type: 'response', requestId: request.requestId, ok: true, result })))
    }

    /** @returns {{confirmed: true}} Confirms bounded fake transport closure. */
    close() {
        return { confirmed: true }
    }
}

/** @returns {{handlers: Map<string, Function>, ipcMain: object}} Minimal exact IPC registry. */
function createIpcMain() {
    const handlers = new Map()
    return {
        handlers,
        ipcMain: {
            /** @param {string} channel - Exact channel. @param {Function} handler - Main handler. @returns {void} Registers it. */
            handle(channel, handler) {
                handlers.set(channel, handler)
            },
            /** @param {string} channel - Exact channel. @returns {void} Removes it. */
            removeHandler(channel) {
                handlers.delete(channel)
            }
        }
    }
}

test('service-issued destructive confirmations are exact, one-shot, and renderer-unforgeable', async () => {
    const logDirectory = await mkdtemp(join(tmpdir(), 'openrdx-confirmation-flow-'))
    const transport = new ConfirmationTransport()
    const { handlers, ipcMain } = createIpcMain()
    const services = {
        /** @returns {boolean} Accepts the one controlled main-frame event. */
        isTrustedSender() {
            return true
        }
    }
    const ipcController = registerIpcHandlers({ ipcMain, services })
    const runtime = createApplicationServiceRuntime({
        appPath: '/application/OpenRDXManager',
        ipcController: {
            /** @returns {boolean} Accepts renderer-safe discovery events. */
            publishDeviceEvent() {
                return true
            },
            /** @returns {boolean} Accepts renderer-safe lifecycle events. */
            publishOperationEvent() {
                return true
            }
        },
        isPackaged: false,
        logDirectory,
        platform: 'darwin',
        resourcesPath: '/application/resources',
        services,
        /** @returns {ConfirmationTransport} Returns the single controlled service session. */
        transportFactory() {
            return transport
        }
    })
    const exact = { kind: 'format', deviceId: 'rdx:confirmation-1', deviceRevision: 5, filesystem: 'exfat' }
    const start = handlers.get('openrdx:operations:start')
    try {
        assert.equal((await runtime.start()).status, 'ready')
        assert.deepEqual(await start({}, { ...exact, confirmationToken: 'confirm:renderer-invented' }), { ok: false, reason: 'confirmation-required' })

        const issued = await handlers.get('openrdx:operations:confirm')({}, exact)
        assert.deepEqual(issued, { ok: true, confirmationToken: 'confirm:service-1' })
        assert.deepEqual(await start({}, { ...exact, filesystem: 'ntfs', confirmationToken: issued.confirmationToken }), { ok: false, reason: 'confirmation-required' })
        assert.equal(transport.operationStarts.length, 0)

        const accepted = await start({}, { ...exact, confirmationToken: issued.confirmationToken })
        assert.equal(accepted.ok, true)
        assert.match(accepted.operationId, /^op:/)
        assert.equal(services.operations.getContext({ ...exact, confirmationToken: issued.confirmationToken }).confirmationTokenValid, false)
        assert.deepEqual(transport.confirmationIssues, [exact])
        assert.equal(transport.operationStarts.length, 1)
        assert.deepEqual(transport.operationStarts[0].request, { ...exact, confirmationToken: issued.confirmationToken })
    } finally {
        await runtime.stop()
        ipcController.dispose()
        await rm(logDirectory, { force: true, recursive: true })
    }
})
