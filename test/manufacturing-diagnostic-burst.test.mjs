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

/** Native boundary reproducing the rapid diagnostics emitted during a full sector read. */
class BackupTransport extends EventEmitter {
    /** @param {object} message - Native protocol envelope. @returns {void} Delivers a framed response. */
    deliver(message) {
        const payload = Buffer.from(JSON.stringify(message))
        const header = Buffer.alloc(4)
        header.writeUInt32BE(payload.length)
        this.emit('data', Buffer.concat([header, payload]))
    }

    /** @param {Buffer} frame - Main-owned request frame. @returns {{ok: true}} Admits one request. */
    write(frame) {
        const message = JSON.parse(frame.subarray(4).toString('utf8'))
        queueMicrotask(() => {
            if (message.type === 'handshake-request') {
                this.deliver({ type: 'handshake', protocolVersion: 1, serviceVersion: 'backup-burst-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } })
                return
            }
            let result = { ok: true }
            if (message.method === 'devices-list') {
                result = { ok: true, listRevision: 0, devices: [completeDeviceSnapshot({ id: 'rdx:backup-burst', revision: 1, vendor: 'TANDBERG', product: 'RDX', serial: '1234567890', media: null, capabilities: {} })] }
            } else if (message.method === 'manufacturing-backup') {
                for (let index = 0; index < 1024; index += 1) {
                    this.emit('diagnostic', { code: index % 2 === 0 ? 'scsi-worker-native-enter' : 'scsi-worker-native-return' })
                }
                result = { ok: true, page: 0, hasMore: false, backups: [{ backupId: 'record-1-1', createdAt: 1, state: 'valid', deviceId: 'rdx:backup-burst', serial: '1234567890' }], backupSupported: true, restoreSupported: false }
            }
            this.deliver({ type: 'response', requestId: message.requestId, ok: true, result })
        })
        return { ok: true }
    }

    /** @returns {{confirmed: true}} Confirms the simulated child has stopped. */
    close() {
        return { confirmed: true }
    }
}

test('manufacturing backup survives diagnostic bursts with the real logger and service coordinator', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-backup-burst-'))
    const services = {}
    const runtime = createApplicationServiceRuntime({
        appPath: '/work/OpenRDXManager',
        resourcesPath: '/work/OpenRDXManager/resources',
        isPackaged: false,
        platform: 'darwin',
        logDirectory: directory,
        services,
        ipcController: { publishDeviceEvent: () => true, publishOperationEvent: () => true },
        transportFactory: () => new BackupTransport()
    })
    try {
        assert.equal((await runtime.start()).status, 'ready')
        assert.deepEqual(await runtime.logger.flush(), { ok: true })
        const result = await services.manufacturing.backup({ deviceId: 'rdx:backup-burst', deviceRevision: 1 })
        assert.equal(result.ok, true)
        assert.equal(result.backups[0].backupId, 'record-1-1')
        assert.deepEqual(await runtime.logger.flush(), { ok: true })
        assert.equal(runtime.getReadiness().status, 'ready')
        assert.equal(runtime.client.isHardwareReady(), true)
    } finally {
        await runtime.stop()
        await rm(directory, { recursive: true, force: true })
    }
})
