// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'
import { DeviceServiceClient } from '../src/main/device-service-client.mjs'

test('the handshake diagnostic marks the actual fixed timer start once after authenticated transport readiness', async () => {
    const transport = new EventEmitter()
    transport.isReady = false
    const frames = []
    /** @param {Buffer} frame - Outbound protocol frame. @returns {boolean} Accepts one frame. */
    transport.write = (frame) => {
        frames.push(frame)
        return true
    }
    /** @returns {object} Confirms local transport teardown. */
    transport.close = () => ({ confirmed: true })
    const timers = new Map()
    const records = []
    const client = new DeviceServiceClient({
        executable: '/controlled/endpoint',
        platform: 'darwin',
        transportFactory: () => transport,
        handshakeTimeoutMs: 10_000,
        emitHandshakeDiagnostics: true,
        maxRestarts: 0,
        timers: {
            /** @param {Function} callback - Owned deadline. @param {number} delay - Fixed configured bound. @returns {number} Owned timer. */
            setTimeout(callback, delay) {
                timers.set(1, { callback, delay })
                return 1
            },
            /** @param {number} timer - Owned timer. @returns {void} Removes it. */
            clearTimeout(timer) {
                timers.delete(timer)
            }
        },
        logger: {
            /** @param {object} event - Production diagnostic. @returns {Promise<boolean>} Records successful persistence. */
            async write(event) {
                records.push({ event, timer: timers.get(1), frameCount: frames.length })
                return true
            }
        }
    })
    const starting = client.start()
    assert.equal(client.getState().status, 'handshaking')
    assert.equal(timers.size, 0)
    assert.equal(records.filter(({ event }) => event.event === 'service-handshake-start').length, 0)
    transport.isReady = true
    transport.emit('ready')
    transport.emit('ready')
    const starts = records.filter(({ event }) => event.event === 'service-handshake-start')
    assert.equal(starts.length, 1)
    assert.deepEqual(starts[0].event, { event: 'service-handshake-start', messageKey: 'activity.service', severity: 'info' })
    assert.equal(starts[0].timer.delay, 10_000)
    assert.equal(starts[0].frameCount, 0)
    assert.equal(frames.length, 1)
    assert.equal(JSON.parse(frames[0].subarray(4).toString()).type, 'handshake-request')
    starts[0].timer.callback()
    assert.deepEqual(await starting, { status: 'unavailable', reason: 'service-handshake-timeout', restartCount: 0, terminatedGeneration: 1 })
    await client.stop()
})

test('a diagnostic sink failure cannot prevent the handshake frame or alter its deadline failure', async () => {
    const transport = new EventEmitter()
    transport.isReady = false
    let writes = 0
    let timeout
    /** @returns {boolean} Records the actual handshake write. */
    transport.write = () => {
        writes += 1
        return true
    }
    /** @returns {object} Confirms teardown. */
    transport.close = () => ({ confirmed: true })
    const client = new DeviceServiceClient({
        executable: '/controlled/endpoint',
        platform: 'darwin',
        transportFactory: () => transport,
        handshakeTimeoutMs: 10_000,
        emitHandshakeDiagnostics: true,
        maxRestarts: 0,
        timers: {
            /** @param {Function} callback - Exact handshake deadline. @returns {number} Owned timer. */
            setTimeout(callback) {
                timeout = callback
                return 1
            },
            /** @returns {void} No additional timers are scheduled. */
            clearTimeout() {}
        },
        logger: {
            /** @param {object} event - Fixed event. @returns {Promise<boolean>} Other lifecycle records persist. */
            write(event) {
                if (event.event === 'service-handshake-start') throw new Error('diagnostic-sink-failed')
                return Promise.resolve(true)
            }
        }
    })
    const starting = client.start()
    transport.isReady = true
    assert.doesNotThrow(() => transport.emit('ready'))
    assert.equal(writes, 1)
    timeout()
    assert.equal((await starting).reason, 'service-handshake-timeout')
    await client.stop()
})

test('ordinary clients preserve their existing lifecycle log volume', async () => {
    const records = []
    const transport = new EventEmitter()
    /** @returns {boolean} Accepts the protocol frame. */
    transport.write = () => true
    /** @returns {object} Confirms teardown. */
    transport.close = () => ({ confirmed: true })
    let timeout
    const client = new DeviceServiceClient({
        executable: '/controlled/endpoint',
        platform: 'darwin',
        transportFactory: () => transport,
        maxRestarts: 0,
        timers: {
            /** @param {Function} callback - Existing deadline. @returns {number} Owned timer. */
            setTimeout(callback) {
                timeout = callback
                return 1
            },
            /** @returns {void} Removes no additional timer. */
            clearTimeout() {}
        },
        logger: {
            /** @param {object} event - Existing lifecycle record. @returns {Promise<boolean>} Persists normally. */
            async write(event) {
                records.push(event)
                return true
            }
        }
    })
    const starting = client.start()
    assert.equal(records.filter((event) => event.event === 'service-handshake-start').length, 0)
    timeout()
    await starting
    await client.stop()
})
