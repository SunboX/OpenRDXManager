// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { DeviceServiceClient, createChildProcessTransportFactory, resolveDeviceServiceExecutable } from '../src/main/device-service-client.mjs'
import { nativeHostReadiness } from './helpers/native-host-readiness.mjs'

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const nativeTestBinary = resolveDeviceServiceExecutable({ appPath: projectRoot, resourcesPath: projectRoot, isPackaged: false, platform: process.platform })

test('handshakes with the compiled native service and preserves truthful platform readiness', async (context) => {
    const client = new DeviceServiceClient({
        executable: nativeTestBinary,
        maxRestarts: 0,
        platform: process.platform,
        transportFactory: createChildProcessTransportFactory({
            platform: process.platform,
            shutdownTimeoutMs: 2_000,
            forceKillTimeoutMs: 2_000
        })
    })
    /**
     * Stops the real child even when an assertion rejects this test.
     * @returns {Promise<void>} Resolves after bounded child teardown.
     */
    async function stopNativeClient() {
        await client.stop()
    }
    context.after(stopNativeClient)

    const state = await client.start()
    const initial = await client.list()
    const scan = await client.scan({ kind: 'scan' })
    const rescanned = await client.list()
    const start = await client.startOperation({
        operationId: 'op:native-no-device',
        request: { kind: 'self-test', deviceId: 'rdx:absent', deviceRevision: 1 }
    })
    const cancel = await client.cancelOperation({ operationId: 'op:native-no-device' })
    const nativeDiscovery = ['darwin', 'win32', 'linux'].includes(process.platform)
    const readiness = nativeHostReadiness(process.platform, state.privileged)

    assert.deepEqual(state, {
        status: 'ready',
        ...readiness,
        generation: 1,
        epoch: 1,
        listRevision: 0,
        restartCount: 0
    })
    assert.deepEqual(initial, { ok: true, status: 'ready', ...readiness, epoch: 1, listRevision: 0, devices: [] })
    assert.deepEqual(scan, { ok: true })
    const { diagnostics, ...rescannedSnapshot } = rescanned
    assert.deepEqual(rescannedSnapshot, { ok: true, status: 'ready', ...readiness, epoch: 1, listRevision: 1, devices: [] })
    if (diagnostics !== undefined) {
        let rejectedCandidates = 0
        for (const rejection of diagnostics.rejections) rejectedCandidates += rejection.count
        assert.equal(diagnostics.acceptedCount, 0)
        assert.equal(rejectedCandidates, diagnostics.candidateCount)
    }
    assert.deepEqual(start, { ok: false, reason: readiness.privileged ? 'device-not-found' : nativeDiscovery ? 'privileged-service-unavailable' : 'transport-unavailable' })
    assert.deepEqual(cancel, { ok: false, reason: nativeDiscovery ? 'operation-not-found' : 'transport-unavailable' })
    assert.equal(client.isHardwareReady(), readiness.hardwareReady)
    assert.equal(client.hasPrivilege(), readiness.privileged)

    await client.stop()
    assert.equal(client.getState().status, 'stopped')
})
