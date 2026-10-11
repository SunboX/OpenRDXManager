// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { EventEmitter } from 'node:events'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { DeviceServiceClient, createChildProcessTransportFactory, createNoDeviceTransportFactory, resolveDeviceServiceExecutable } from '../src/main/device-service-client.mjs'
import { DEFAULT_MAX_FRAME_BYTES, encodeServiceFrame } from '../src/main/device-service-transport.mjs'

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const nativeBinary = resolveDeviceServiceExecutable({ appPath: projectRoot, resourcesPath: projectRoot, isPackaged: false, platform: process.platform })

/** Decodes one complete outbound service frame. @param {Buffer} frame - Framed JSON. @returns {object} Parsed message. */
function decodeFrame(frame) {
    const length = frame.readUInt32BE(0)
    return JSON.parse(frame.subarray(4, length + 4).toString('utf8'))
}

/** Allows queued I/O and promise continuations to settle. @returns {Promise<void>} Next turn. */
async function nextTurn() {
    await new Promise(setImmediate)
}

/**
 * Waits for one bounded lifecycle predicate without retaining its subscription.
 * @param {DeviceServiceClient} client - Supervised client.
 * @param {(state: object) => boolean} predicate - Desired terminal observation.
 * @returns {Promise<object>} Matching lifecycle state.
 */
function waitForLifecycle(client, predicate) {
    if (predicate(client.getState())) return Promise.resolve(client.getState())
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            unsubscribe()
            reject(new Error('native-lifecycle-timeout'))
        }, 5_000)
        const unsubscribe = client.subscribeLifecycle((state) => {
            if (!predicate(state)) return
            clearTimeout(timeout)
            unsubscribe()
            resolve(state)
        })
    })
}

/** Controlled protocol transport that can hold exact list responses. */
class SaturationGapTransport extends EventEmitter {
    /** Creates an empty write ledger and automatic reconciliation. */
    constructor() {
        super()
        this.messages = []
        this.reconciled = false
    }

    /** @param {Buffer} frame - Outbound frame. @returns {{ok: true}} Stable admission. */
    write(frame) {
        const message = decodeFrame(frame)
        this.messages.push(message)
        if (message.type === 'handshake-request') {
            queueMicrotask(() =>
                this.emit(
                    'data',
                    encodeServiceFrame(
                        {
                            type: 'handshake',
                            protocolVersion: 1,
                            serviceVersion: 'gap-test',
                            platform: 'darwin',
                            mode: 'no-device',
                            privileged: false,
                            platformCapability: { state: 'transport-unavailable', reason: 'platform-adapter-not-implemented' }
                        },
                        DEFAULT_MAX_FRAME_BYTES
                    )
                )
            )
        } else if (message.method === 'devices-list' && !this.reconciled) {
            this.reconciled = true
            queueMicrotask(() => this.respond(message.requestId))
        }
        return { ok: true }
    }

    /** @param {string} requestId - Exact held request ID. @returns {void} Delivers an empty list. */
    respond(requestId) {
        this.emit('data', encodeServiceFrame({ type: 'response', requestId, ok: true, result: { ok: true, listRevision: 0, devices: [] } }, DEFAULT_MAX_FRAME_BYTES))
    }

    /** @returns {{confirmed: true}} Confirms fake closure. */
    close() {
        return { confirmed: true }
    }
}

/** Graceful-capable transport that deliberately withholds the shutdown acknowledgement. */
class MissingShutdownAckTransport extends SaturationGapTransport {
    /** Creates an open controlled transport. */
    constructor() {
        super()
        this.closed = false
    }

    /** @returns {true} Requests the client's bounded protocol shutdown path. */
    get supportsGracefulShutdown() {
        return true
    }

    /** @returns {{confirmed: true}} Records fallback closure after the ack bound. */
    close() {
        this.closed = true
        return { confirmed: true }
    }
}

/**
 * Creates a real-child factory that records protocol writes and signal escalation.
 * @param {object[]} children - Spawned child ledger.
 * @returns {Function} Production child transport factory.
 */
function createObservedNativeFactory(children) {
    /** @param {string} command - Native binary. @param {string[]} args - Fixed arguments. @param {object} options - Fixed spawn options. @returns {object} Observed child. */
    function spawnObserved(command, args, options) {
        const child = spawn(command, args, options)
        child.observedMessages = []
        child.observedSignals = []
        const write = child.stdin.write.bind(child.stdin)
        const kill = child.kill.bind(child)

        /** @param {Buffer} frame - Complete protocol frame. @param {...unknown} rest - Native stream arguments. @returns {boolean} Native write result. */
        child.stdin.write = (frame, ...rest) => {
            child.observedMessages.push(decodeFrame(Buffer.from(frame)))
            return write(frame, ...rest)
        }
        /** @param {string} signal - Requested process signal. @returns {boolean} Native kill result. */
        child.kill = (signal) => {
            child.observedSignals.push(signal)
            return kill(signal)
        }
        children.push(child)
        return child
    }

    return createChildProcessTransportFactory({
        forceKillTimeoutMs: 500,
        platform: process.platform,
        shutdownTimeoutMs: 500,
        spawnProcess: spawnObserved
    })
}

test('preserves increasing request IDs across a real native generation restart', async (context) => {
    const children = []
    const client = new DeviceServiceClient({
        executable: nativeBinary,
        handshakeTimeoutMs: 1_000,
        maxRestarts: 1,
        platform: process.platform,
        requestTimeoutMs: 1_000,
        restartBackoffMs: [0],
        transportFactory: createObservedNativeFactory(children)
    })
    context.after(() => client.stop())

    assert.equal((await client.start()).generation, 1)
    const outcome = waitForLifecycle(client, (state) => (state.status === 'ready' && state.generation === 2) || state.status === 'unavailable')
    children[0].kill('SIGKILL')
    const restarted = await outcome

    assert.equal(restarted.status, 'ready')
    assert.equal(restarted.generation, 2)
    assert.equal(children.length, 2)
    assert.equal(children[1].observedMessages.find((message) => message.method === 'devices-list').requestId, 'request:2')
})

test('retains a safe local saturation gap in the strictly increasing request stream', async () => {
    const transport = new SaturationGapTransport()
    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxPendingCount: 1, platform: 'darwin', transportFactory: () => transport })
    await client.start()

    const first = client.list()
    const saturated = await client.list()
    assert.deepEqual(saturated, { ok: false, reason: 'service-saturated' })
    transport.respond('request:2')
    assert.equal((await first).ok, true)

    const afterGap = client.list()
    await nextTurn()
    transport.respond('request:4')
    assert.equal((await afterGap).ok, true)
    assert.deepEqual(
        transport.messages.filter((message) => message.type === 'request').map((message) => message.requestId),
        ['request:1', 'request:2', 'request:4']
    )
    await client.stop()
})

test('matches JavaScript operation ID case and suffix boundaries before native dispatch', async () => {
    const client = new DeviceServiceClient({
        executable: '/private/openrdx/openrdx-hardware',
        platform: 'darwin',
        transportFactory: createNoDeviceTransportFactory({ platform: 'darwin' })
    })
    await client.start()
    const request = { kind: 'self-test', deviceId: 'rdx:absent', deviceRevision: 1 }

    assert.deepEqual(await client.startOperation({ operationId: 'OP:A-:9', request }), { ok: false, reason: 'transport-unavailable' })
    assert.deepEqual(await client.startOperation({ operationId: `op:${'a'.repeat(60)}`, request }), { ok: false, reason: 'transport-unavailable' })
    assert.deepEqual(await client.startOperation({ operationId: 'op:', request }), { ok: false, reason: 'invalid-request' })
    assert.deepEqual(await client.startOperation({ operationId: `op:${'a'.repeat(61)}`, request }), { ok: false, reason: 'invalid-request' })
    await client.stop()
})

test('rejects invalid cancel IDs locally without losing the real native generation', async (context) => {
    const children = []
    const client = new DeviceServiceClient({
        executable: nativeBinary,
        maxRestarts: 0,
        platform: process.platform,
        transportFactory: createObservedNativeFactory(children)
    })
    context.after(() => client.stop())

    const ready = await client.start()
    for (const operationId of ['bad:1', 'op:', `op:${'a'.repeat(61)}`]) {
        assert.deepEqual(await client.cancelOperation({ operationId }), { ok: false, reason: 'invalid-request' })
        assert.equal(client.getState().status, 'ready')
        assert.equal(client.getGeneration(), ready.generation)
    }
    assert.equal(
        children[0].observedMessages.some((message) => message.method === 'operation-cancel'),
        false
    )

    for (const operationId of ['OP:A-:9', `op:${'a'.repeat(60)}`]) {
        assert.deepEqual(await client.cancelOperation({ operationId }), {
            ok: false,
            reason: ['darwin', 'win32', 'linux'].includes(process.platform) ? 'operation-not-found' : 'transport-unavailable'
        })
    }
    const cancellations = children[0].observedMessages.filter((message) => message.method === 'operation-cancel')
    assert.deepEqual(
        cancellations.map((message) => message.requestId),
        ['request:2', 'request:3']
    )
    assert.deepEqual(
        cancellations.map((message) => message.payload),
        [{ operationId: 'OP:A-:9' }, { operationId: `op:${'a'.repeat(60)}` }]
    )
    assert.equal(client.getGeneration(), ready.generation)
})

test('bounds a missing shutdown acknowledgement before transport fallback', async () => {
    const transport = new MissingShutdownAckTransport()
    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', platform: 'darwin', transportFactory: () => transport })
    await client.start()

    const stopping = client.stop()
    await nextTurn()
    assert.equal(transport.closed, false)
    assert.equal(transport.messages.at(-1).method, 'service-shutdown')
    await stopping

    assert.equal(transport.closed, true)
    assert.equal(client.getState().status, 'stopped')
})

test('acknowledges native service shutdown and exits without process signals', async (context) => {
    const children = []
    const client = new DeviceServiceClient({ executable: nativeBinary, maxRestarts: 0, platform: process.platform, transportFactory: createObservedNativeFactory(children) })
    context.after(() => client.stop())

    assert.equal((await client.start()).status, 'ready')
    await client.stop()

    assert.equal(children.length, 1)
    assert.equal(children[0].observedMessages.at(-1).method, 'service-shutdown')
    assert.deepEqual(children[0].observedSignals, [])
    assert.equal(children[0].exitCode, 0)
})
