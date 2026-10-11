// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { DeviceServiceClient } from '../src/main/device-service-client.mjs'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createRendererIntentAdapter } from '../src/renderer/intent-adapter.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { completeDeviceSnapshot } from './helpers/device-snapshot.mjs'

/**
 * Encodes one strict length-framed service message.
 * @param {object} message - JSON-safe service message.
 * @returns {Buffer} Four-byte length prefix followed by JSON.
 */
function encodeFrame(message) {
    const payload = Buffer.from(JSON.stringify(message), 'utf8')
    const frame = Buffer.allocUnsafe(payload.length + 4)
    frame.writeUInt32BE(payload.length, 0)
    payload.copy(frame, 4)
    return frame
}

/**
 * Decodes one complete strict outbound frame.
 * @param {Buffer} frame - Complete framed request.
 * @returns {object} Parsed request object.
 */
function decodeFrame(frame) {
    const length = frame.readUInt32BE(0)
    return JSON.parse(frame.subarray(4, length + 4).toString('utf8'))
}

/** In-memory native transport used for the cold-start/hotplug regression. */
class HotplugTransport extends EventEmitter {
    /** Creates an open transport with outbound recording. */
    constructor() {
        super()
        this.writes = []
    }

    /**
     * Records one service-owned framed request.
     * @param {Buffer} frame - Complete framed request.
     * @returns {boolean} True while this fixture accepts writes.
     */
    write(frame) {
        this.writes.push(Buffer.from(frame))
        return true
    }

    /** @returns {{confirmed: boolean}} Confirmed fixture closure. */
    close() {
        return { confirmed: true }
    }

    /**
     * Emits one complete framed response or event.
     * @param {object} message - JSON-safe response or event.
     * @returns {void} Completes after synchronous event delivery.
     */
    emitFrame(message) {
        this.emit('data', encodeFrame(message))
    }
}

/** @returns {object} One strict hotplugged device snapshot. */
function hotpluggedDevice() {
    return completeDeviceSnapshot({
        id: 'rdx:live-1',
        revision: 1,
        vendor: 'TANDBERG',
        product: 'RDX',
        serial: 'LIVE1',
        media: null,
        mediaState: 'no-media',
        capabilities: { 'self-test': { state: 'available' } }
    })
}

/** @returns {Promise<void>} Resolves after queued service continuations. */
async function nextTurn() {
    await new Promise(setImmediate)
}

test('discovers a later hotplug after a native authoritative empty cold scan', async () => {
    const transport = new HotplugTransport()
    /** @returns {HotplugTransport} Controlled transport after queued readiness. */
    function transportFactory() {
        queueMicrotask(() => {
            transport.emitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'hotplug-test', platform: 'linux', mode: 'native', privileged: true, hardwareVerified: false, platformCapability: { state: 'available' } })
        })
        return transport
    }
    const client = new DeviceServiceClient({ executable: '/usr/libexec/openrdx-hardware', maxRestarts: 0, platform: 'linux', transportFactory })
    const readiness = client.start()
    await nextTurn()
    const initial = transport.writes.map(decodeFrame).find((message) => message.method === 'devices-list')
    transport.emitFrame({ type: 'response', requestId: initial.requestId, ok: true, result: { ok: true, listRevision: 0, devices: [] } })
    assert.equal((await readiness).hardwareReady, true)

    const scan = client.scan({ kind: 'scan' })
    await nextTurn()
    const request = transport.writes.map(decodeFrame).find((message) => message.method === 'devices-scan')
    const device = hotpluggedDevice()
    transport.emitFrame({ type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [device] } })
    transport.emitFrame({ type: 'response', requestId: request.requestId, ok: true, result: { ok: true } })

    assert.deepEqual(await scan, { ok: true })
    assert.deepEqual(client.getDevice(device.id), device)
    await client.stop()
})

test('keeps native discovery disabled until the privileged capability is available', () => {
    const calls = []
    /**
     * Records one accepted high-level renderer intent.
     * @param {object} intent - Validated renderer intent.
     * @returns {boolean} True after recording.
     */
    function invoke(intent) {
        calls.push(intent)
        return true
    }
    const intentAdapter = createRendererIntentAdapter({ supportedIntents: ['scan'], invoke })
    const fixture = createFixtureState({ mode: 'no-device' })
    const state = { ...fixture, provenance: 'service', service: { status: 'ready', mode: 'native', privileged: false, hardwareReady: false, hardwareVerified: false, platformCapability: { state: 'insufficient-permission', reason: 'privileged-service-unavailable' } } }
    const dom = new JSDOM('<!doctype html><div id="app"></div>', { url: 'file:///openrdxmanager/src/index.html' })
    const controller = mountApplication(dom.window.document.querySelector('#app'), { store: createStore(state), intentAdapter })
    const scan = dom.window.document.querySelector('.empty-state [data-action="scan-devices"]')

    assert.equal(scan.disabled, true)
    scan.click()
    assert.deepEqual(calls, [])
    controller.destroy()
    dom.window.close()
})
