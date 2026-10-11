// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { DeviceServiceClient } from '../src/main/device-service-client.mjs'
import { encodeServiceFrame } from '../src/main/device-service-transport.mjs'
import { completeDeviceSnapshot } from './helpers/device-snapshot.mjs'

/** Controlled request deadlines, without waiting for cartridge spin-up. */
class Timers {
    pending = new Map()
    next = 0
    /** @param {Function} callback - Deadline. @param {number} delay - Bound. @returns {number} Identity. */
    setTimeout(callback, delay) {
        const id = ++this.next
        this.pending.set(id, { callback, delay })
        return id
    }
    /** @param {number} id - Deadline identity. @returns {void} Removes it. */
    clearTimeout(id) {
        this.pending.delete(id)
    }
    /** @param {number} delay - Exact deadline to fire. @returns {void} Fires one owned timer. */
    fire(delay) {
        const found = [...this.pending].find(([, item]) => item.delay === delay)
        assert.ok(found)
        this.pending.delete(found[0])
        found[1].callback()
    }
}

/** Native protocol fixture with a held scan and concurrent device-list request. */
class Transport extends EventEmitter {
    requests = []
    initialized = false
    /** @param {Buffer} frame - Main-owned request. @returns {boolean} Accepted. */
    write(frame) {
        const message = JSON.parse(frame.subarray(4).toString())
        this.requests.push(message)
        if (message.type === 'handshake-request') queueMicrotask(() => this.send({ type: 'handshake', protocolVersion: 1, serviceVersion: 'test', platform: 'win32', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
        if (message.method === 'devices-list' && !this.initialized) {
            this.initialized = true
            queueMicrotask(() => this.send({ type: 'response', requestId: message.requestId, ok: true, result: { ok: true, listRevision: 0, devices: [] } }))
        }
        return true
    }
    /** @param {object} message - Strict inbound frame. @returns {void} Delivers it. */
    send(message) {
        this.emit('data', encodeServiceFrame(message))
    }
    /** @returns {object} Explicit teardown evidence. */
    close() {
        return { confirmed: true }
    }
    /** @param {string} method - Exact method. @returns {object} Latest request. */
    last(method) {
        return this.requests.findLast((request) => request.method === method)
    }
}

/** @param {object} context - Test cleanup owner. @returns {Promise<object>} Ready supervised client. */
async function fixture(context) {
    const timers = new Timers()
    const transport = new Transport()
    const client = new DeviceServiceClient({ executable: fileURLToPath(new URL('../out/native/openrdx-hardware', import.meta.url)), platform: 'win32', maxRestarts: 0, requestTimeoutMs: 25, timers, transportFactory: () => transport })
    context.after(() => client.stop())
    await client.start()
    return { client, timers, transport }
}

/** @param {boolean} present - Cartridge presence. @param {number} revision - Identity revision. @returns {object} Strict synthetic snapshot. */
function device(present, revision = 1) {
    return completeDeviceSnapshot({ id: 'rdx:test', revision, vendor: 'TANDBERG', product: 'RDX', serial: 'SYNTHETIC', media: present ? { id: 'media:test', serial: 'TESTCARTRIDGE', capacityBytes: 3000000000000, usedBytes: 200000000, writable: true, status: 'ready' } : null, capabilities: { 'status-refresh': { state: 'available' } } })
}

test('cartridge insertion accepts its event and consumes late scan/list replies without restarting or rolling back', async (context) => {
    const { client, timers, transport } = await fixture(context)
    transport.send({ type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [device(false)] } })
    const scan = client.scan({ kind: 'scan' })
    const scanId = transport.last('devices-scan').requestId
    const list = client.list()
    const listId = transport.last('devices-list').requestId
    timers.fire(25)
    timers.fire(15000)
    assert.equal((await list).reason, 'service-request-timeout')
    assert.equal((await scan).reason, 'service-request-timeout')
    transport.send({ type: 'event', channel: 'device', event: { type: 'list', listRevision: 2, devices: [device(true, 2)] } })
    transport.send({ type: 'response', requestId: scanId, ok: true, result: { ok: true } })
    // A late read is consumed, never re-applied over newer published identity/media.
    transport.send({ type: 'response', requestId: listId, ok: true, result: { ok: true, listRevision: 1, devices: [device(false)] } })
    assert.equal(client.getState().status, 'ready')
    assert.equal(client.getDevice('rdx:test').mediaState, 'present')
    assert.equal(client.getDevice('rdx:test').revision, 2)
    const next = client.list()
    transport.send({ type: 'response', requestId: transport.last('devices-list').requestId, ok: true, result: { ok: true, listRevision: 2, devices: [device(true, 2)] } })
    assert.equal((await next).ok, true)
    assert.equal(client.getState().generation, 1)
})

for (const invalid of [false, true]) {
    test(`late list replies ${invalid ? 'with invalid data' : 'received twice'} still fault the exact generation`, async (context) => {
        const { client, timers, transport } = await fixture(context)
        const pending = client.list()
        const requestId = transport.last('devices-list').requestId
        timers.fire(25)
        await pending
        const response = { type: 'response', requestId, ok: true, result: invalid ? { ok: true, listRevision: 1, devices: [{ id: 'unvalidated' }] } : { ok: true, listRevision: 0, devices: [] } }
        transport.send(response)
        if (!invalid) {
            assert.equal(client.getState().status, 'ready')
            transport.send(response)
        }
        await new Promise(setImmediate)
        assert.equal(client.getState().reason, 'service-malformed-data')
    })
}

test('expired discovery correlations cannot survive a service generation change', async (context) => {
    const { client, timers, transport } = await fixture(context)
    const pending = client.list()
    const requestId = transport.last('devices-list').requestId
    timers.fire(25)
    await pending
    await client.stop()
    transport.initialized = false
    await client.start()
    transport.send({ type: 'response', requestId, ok: true, result: { ok: true, listRevision: 0, devices: [] } })
    await new Promise(setImmediate)
    assert.equal(client.getState().reason, 'service-malformed-data')
})

test('expired discovery history stays bounded and an evicted response cannot bypass correlation', async (context) => {
    const { client, timers, transport } = await fixture(context)
    let firstId
    for (let index = 0; index < 65; index += 1) {
        const pending = client.list()
        firstId ??= transport.last('devices-list').requestId
        timers.fire(25)
        await pending
    }
    transport.send({ type: 'response', requestId: firstId, ok: true, result: { ok: true, listRevision: 0, devices: [] } })
    await new Promise(setImmediate)
    assert.equal(client.getState().reason, 'service-malformed-data')
})
