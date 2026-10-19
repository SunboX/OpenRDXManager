// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'
import { createApplicationServiceRuntime } from '../src/main/service-runtime.mjs'

/** @param {object} message Controlled response. @returns {Buffer} Strict service frame. */
function frame(message) {
    const payload = Buffer.from(JSON.stringify(message))
    const result = Buffer.alloc(payload.length + 4)
    result.writeUInt32BE(payload.length)
    payload.copy(result, 4)
    return result
}

/** Models native identity completion followed by a delayed verified service response. */
class VerifiedStartupTransport extends EventEmitter {
    isReady = false
    proofVerified = false
    closed = false
    timer = null

    /** Completes the controlled native proof without writing protocol bytes. */
    constructor() {
        super()
        queueMicrotask(() => {
            this.proofVerified = true
            this.isReady = true
            this.emit('ready')
        })
    }

    /** @param {Buffer} bytes Request frame. @returns {object} Bounded write admission. */
    write(bytes) {
        assert.equal(this.proofVerified, true, 'Protocol must follow the native identity gate')
        const request = JSON.parse(bytes.subarray(4).toString())
        if (request.type === 'handshake-request') {
            // Intel CI evidence places complete server-side checks beyond the
            // previous ten-second response allowance, after native peer proof.
            this.timer = setTimeout(() => this.emit('data', frame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'verified-startup-fixture', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } })), 11_000)
        } else if (request.method === 'devices-list') {
            queueMicrotask(() => this.emit('data', frame({ type: 'response', requestId: request.requestId, ok: true, result: { ok: true, listRevision: 0, devices: [] } })))
        }
        return { ok: true }
    }

    /** @returns {object} Confirms teardown and cancels only the owned timer. */
    close() {
        clearTimeout(this.timer)
        this.closed = true
        return { confirmed: true }
    }
}

/** @returns {object} In-memory logging boundary with no host storage. */
function logStorage() {
    return {
        /** @returns {Promise<void>} Creates no directory. */
        async prepareDirectory() {},
        /** @returns {Promise<object>} Opens an in-memory append handle. */
        async openAppend() {
            return {
                /** @returns {Promise<object>} Reports an empty controlled log. */
                async stat() {
                    return { size: 0 }
                },
                /** @returns {Promise<void>} Persists no host data. */
                async writeFile() {},
                /** @returns {Promise<void>} Closes no host descriptor. */
                async close() {}
            }
        },
        /** @returns {Promise<void>} Removes no file. */
        async removeFile() {},
        /** @returns {Promise<void>} Renames no file. */
        async renameFile() {}
    }
}

test('installed macOS runtime admits a verified service whose reply follows the full startup checks', { timeout: 40_000 }, async () => {
    let attempts = 0
    const runtime = createApplicationServiceRuntime({
        appPath: '/controlled/OpenRDXManager.app',
        resourcesPath: '/controlled/OpenRDXManager.app/Contents/Resources',
        isPackaged: true,
        platform: 'darwin',
        logDirectory: '/controlled/logs',
        eventLoggerOptions: { fileSecurity: logStorage() },
        services: {},
        ipcController: {
            /** @returns {boolean} Publishes no UI event. */
            publishDeviceEvent() {
                return true
            },
            /** @returns {boolean} Publishes no operation event. */
            publishOperationEvent() {
                return true
            }
        },
        /** @returns {VerifiedStartupTransport} Creates an isolated verified endpoint fixture. */
        transportFactory() {
            attempts += 1
            return new VerifiedStartupTransport()
        }
    })
    try {
        assert.equal((await runtime.start()).status, 'ready')
        assert.equal(attempts, 1, 'Completed native validation must not cause a premature restart')
    } finally {
        await runtime.stop()
    }
})
