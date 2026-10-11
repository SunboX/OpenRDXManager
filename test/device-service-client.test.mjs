// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { join, resolve } from 'node:path'
import test from 'node:test'

import { DEVICE_SERVICE_ARGUMENTS, DeviceServiceClient, createChildProcessTransportFactory, createDeviceServiceTransportFactory, createNoDeviceTransportFactory, resolveDeviceServiceExecutable } from '../src/main/device-service-client.mjs'
import { completeDeviceSnapshot } from './helpers/device-snapshot.mjs'

/**
 * Encodes one controlled service message in the production length-framed form.
 * @param {object} message - JSON-safe fake service message.
 * @returns {Buffer} Four-byte length prefix followed by UTF-8 JSON.
 */
function encodeFrame(message) {
    const payload = Buffer.from(JSON.stringify(message), 'utf8')
    const frame = Buffer.allocUnsafe(payload.length + 4)
    frame.writeUInt32BE(payload.length, 0)
    payload.copy(frame, 4)
    return frame
}

/**
 * Decodes one complete controlled outbound frame.
 * @param {Buffer} frame - Four-byte length-prefixed JSON frame.
 * @returns {object} Parsed outbound service message.
 */
function decodeFrame(frame) {
    const length = frame.readUInt32BE(0)
    return JSON.parse(frame.subarray(4, length + 4).toString('utf8'))
}

/**
 * Creates one strict service-discovered device for revision tests.
 * @param {number} revision - Device identity revision.
 * @returns {object} Renderer-safe device snapshot.
 */
function createDevice(revision) {
    return completeDeviceSnapshot({
        id: 'rdx:live-1',
        revision,
        vendor: 'TANDBERG',
        product: 'RDX',
        serial: 'LIVE1',
        media: null,
        mediaState: 'no-media',
        capabilities: { 'self-test': { state: 'available' } }
    })
}

/**
 * Allows queued microtasks and promise continuations to complete.
 * @returns {Promise<void>} Resolves on the next event-loop turn.
 */
async function nextTurn() {
    await new Promise(setImmediate)
}

/** In-memory child-process boundary used to drive framed lifecycle tests. */
class FakeTransport extends EventEmitter {
    /** Creates an open transport with write recording. */
    constructor() {
        super()
        this.acceptWrites = true
        this.autoReconcile = true
        this.closed = false
        this.closeResult = { confirmed: true }
        this.writes = []
    }

    /**
     * Records one main-owned framed write.
     * @param {Buffer} frame - Framed service request.
     * @returns {boolean} True while the fake accepts writes.
     */
    write(frame) {
        this.writes.push(Buffer.from(frame))
        const message = decodeFrame(frame)
        if (this.autoReconcile && message.method === 'devices-list') {
            queueMicrotask(() => this.emitSplitFrame({ type: 'response', requestId: message.requestId, ok: true, result: { ok: true, listRevision: 0, devices: [] } }))
        }
        return this.acceptWrites
    }

    /**
     * Closes the fake without inventing another process exit.
     * @returns {void} Completes after recording closure.
     */
    close() {
        this.closed = true
        return this.closeResult
    }

    /**
     * Delivers one valid framed service message in deliberately split chunks.
     * @param {object} message - Controlled inbound message.
     * @returns {void} Completes after both chunks are emitted.
     */
    emitSplitFrame(message) {
        const frame = encodeFrame(message)
        this.emit('data', frame.subarray(0, 3))
        this.emit('data', frame.subarray(3))
    }
}

/** Deterministic timer queue for restart/backoff tests. */
class ManualTimers {
    /** Creates an empty ordered timer queue. */
    constructor() {
        this.delays = []
        this.nextId = 1
        this.timers = new Map()
    }

    /**
     * Registers one callback without consulting wall-clock time.
     * @param {Function} callback - Timer callback.
     * @param {number} delay - Requested delay in milliseconds.
     * @returns {number} Opaque timer identifier.
     */
    setTimeout(callback, delay) {
        const id = this.nextId
        this.nextId += 1
        this.delays.push(delay)
        this.timers.set(id, callback)
        return id
    }

    /**
     * Removes one queued callback.
     * @param {number} id - Timer identifier.
     * @returns {void} Completes after deletion.
     */
    clearTimeout(id) {
        this.timers.delete(id)
    }

    /**
     * Runs the oldest still-active callback.
     * @returns {void} Completes after synchronous callback invocation.
     */
    runNext() {
        const next = this.timers.entries().next()
        assert.equal(next.done, false)
        const [id, callback] = next.value
        this.timers.delete(id)
        callback()
    }
}

test('resolves native executables by platform without renderer-relative paths', () => {
    const packaged = {
        appPath: resolve('/Applications/OpenRDXManager.app/Contents/Resources/app.asar'),
        isPackaged: true,
        resourcesPath: resolve('/Applications/OpenRDXManager.app/Contents/Resources')
    }

    assert.equal(resolveDeviceServiceExecutable({ ...packaged, platform: 'darwin' }), resolve(packaged.resourcesPath, '..', 'Library', 'LaunchServices', 'openrdx-hardware'))
    assert.equal(resolveDeviceServiceExecutable({ ...packaged, platform: 'linux' }), join(packaged.resourcesPath, 'native', 'linux', 'openrdx-hardware'))
    assert.equal(resolveDeviceServiceExecutable({ ...packaged, platform: 'win32' }), join(packaged.resourcesPath, 'native', 'windows', 'openrdx-hardware.exe'))
    assert.equal(resolveDeviceServiceExecutable({ appPath: resolve('/work/OpenRDXManager'), isPackaged: false, platform: 'darwin', resourcesPath: resolve('/unused') }), resolve('/work/OpenRDXManager/out/native/macos/openrdx-hardware'))
    assert.throws(() => resolveDeviceServiceExecutable({ ...packaged, platform: 'freebsd' }), /unsupported-platform/)
    assert.throws(() => resolveDeviceServiceExecutable({ ...packaged, isPackaged: 'yes', platform: 'darwin' }), /service-resource-root-invalid/)
})

test('packaged production selects the privileged endpoint without spawning a child fallback', () => {
    const endpointConnections = []
    let spawnCount = 0

    /** @param {object} options - Fixed endpoint connection options. @returns {object} Controlled socket. */
    function connectEndpoint(options) {
        endpointConnections.push(options)
        const socket = new EventEmitter()
        socket.destroyed = false
        socket.writableLength = 0
        socket.destroy = () => {
            socket.destroyed = true
        }
        socket.end = () => queueMicrotask(() => socket.emit('close'))
        socket.setNoDelay = () => {}
        socket.write = () => true
        queueMicrotask(() => socket.emit('connect'))
        return socket
    }

    /** @returns {never} Records a forbidden child fallback. */
    function spawnProcess() {
        spawnCount += 1
        throw new Error('child fallback must not run')
    }

    const factory = createDeviceServiceTransportFactory({
        connectEndpoint,
        isPackaged: true,
        platform: 'darwin',
        spawnProcess
    })
    const transport = factory({
        args: DEVICE_SERVICE_ARGUMENTS,
        command: '/Applications/OpenRDXManager.app/Contents/Resources/native/macos/openrdx-hardware'
    })

    assert.equal(transport.supportsGracefulShutdown, true)
    assert.deepEqual(endpointConnections, [{ path: '/var/run/openrdx-hardware.sock' }])
    assert.equal(spawnCount, 0)
})

test('rejects unbounded timeout and restart configuration', () => {
    /** @returns {FakeTransport} Unused controlled transport. */
    function transportFactory() {
        return new FakeTransport()
    }

    const base = { executable: '/private/openrdx/openrdx-hardware', platform: 'darwin', transportFactory }
    assert.throws(() => new DeviceServiceClient({ ...base, handshakeTimeoutMs: -1 }), /lifecycle configuration/)
    assert.throws(() => new DeviceServiceClient({ ...base, requestTimeoutMs: 120_000 }), /lifecycle configuration/)
    assert.throws(() => new DeviceServiceClient({ ...base, restartBackoffMs: [-1] }), /lifecycle configuration/)
    assert.throws(() => new DeviceServiceClient({ ...base, restartBackoffMs: Array(12).fill(1) }), /lifecycle configuration/)
})

test('allows a native scan to finish the bounded macOS storage-rematch window', async () => {
    const timers = new ManualTimers()
    const transport = new FakeTransport()
    /** @returns {FakeTransport} Controlled native transport. */
    function transportFactory() {
        queueMicrotask(() => transport.emitSplitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'scan-rematch-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
        return transport
    }
    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 0, platform: 'darwin', timers, transportFactory })
    await client.start()
    transport.autoReconcile = false

    const scan = client.scan({ kind: 'scan' })
    const request = transport.writes.map(decodeFrame).findLast((message) => message.method === 'devices-scan')

    assert.equal(timers.delays.at(-1), 15_000)
    transport.emitSplitFrame({ type: 'response', requestId: request.requestId, ok: true, result: { ok: true } })
    assert.deepEqual(await scan, { ok: true })
    await client.stop()
})

test('keeps the ready generation and last snapshot when a discovery refresh times out', async () => {
    const timers = new ManualTimers()
    const transport = new FakeTransport()
    /** @returns {FakeTransport} Controlled native transport. */
    function transportFactory() {
        queueMicrotask(() => transport.emitSplitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'scan-timeout-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
        return transport
    }
    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 0, platform: 'darwin', timers, transportFactory })
    await client.start()
    transport.emitSplitFrame({ type: 'event', channel: 'device', event: { type: 'snapshot', listRevision: 1, device: createDevice(1) } })
    transport.autoReconcile = false

    const scan = client.scan({ kind: 'scan' })
    const request = transport.writes.map(decodeFrame).findLast((message) => message.method === 'devices-scan')
    timers.runNext()

    assert.deepEqual(await scan, { ok: false, reason: 'service-request-timeout' })
    assert.equal(client.getState().status, 'ready')
    assert.equal(client.getDevice('rdx:live-1').revision, 1)

    transport.emitSplitFrame({ type: 'event', channel: 'device', event: { type: 'snapshot', listRevision: 2, device: createDevice(2) } })
    transport.emitSplitFrame({ type: 'response', requestId: request.requestId, ok: true, result: { ok: true } })
    await nextTurn()

    assert.equal(client.getState().status, 'ready')
    assert.equal(client.getDevice('rdx:live-1').revision, 2)
    await client.stop()
})

test('handshakes with the explicit no-device adapter without claiming hardware readiness', async () => {
    const launches = []
    const adapterFactory = createNoDeviceTransportFactory({ platform: 'darwin' })

    /**
     * Records the fixed launch contract before delegating to the phase-one adapter.
     * @param {object} launch - Main-owned launch descriptor.
     * @returns {object} In-memory no-device transport.
     */
    function transportFactory(launch) {
        launches.push(launch)
        return adapterFactory(launch)
    }

    const client = new DeviceServiceClient({
        executable: '/private/openrdx/native/openrdx-hardware',
        platform: 'darwin',
        transportFactory
    })

    const state = await client.start()
    const devices = await client.list()

    assert.deepEqual(launches, [{ command: '/private/openrdx/native/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS }])
    assert.deepEqual(state, {
        status: 'ready',
        mode: 'no-device',
        privileged: false,
        hardwareReady: false,
        hardwareVerified: false,
        platformCapability: { state: 'transport-unavailable', reason: 'native-service-not-implemented' },
        generation: 1,
        epoch: 1,
        listRevision: 0,
        restartCount: 0
    })
    assert.deepEqual(devices, { ok: true, status: 'ready', mode: 'no-device', privileged: false, hardwareReady: false, hardwareVerified: false, platformCapability: { state: 'transport-unavailable', reason: 'native-service-not-implemented' }, epoch: 1, listRevision: 0, devices: [] })
    assert.equal(client.getDevice('rdx:fixture'), null)

    await client.stop()
    assert.equal(client.getState().status, 'stopped')
})

test('starts a fresh transport generation after a clean stop', async () => {
    let launchCount = 0
    const adapterFactory = createNoDeviceTransportFactory({ platform: 'darwin' })

    /**
     * Counts every explicit service generation.
     * @param {object} launch - Fixed launch contract.
     * @returns {object} Fresh no-device transport.
     */
    function transportFactory(launch) {
        launchCount += 1
        return adapterFactory(launch)
    }

    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', platform: 'darwin', transportFactory })
    await client.start()
    await client.stop()
    const restarted = await client.start()

    assert.equal(restarted.status, 'ready')
    assert.equal(launchCount, 2)
    await client.stop()
})

test('joins an already queued automatic restart without launching a competing generation', async () => {
    const timers = new ManualTimers()
    const transports = []
    const lifecycle = []

    /**
     * Creates one controlled generation and schedules its valid handshake.
     * @returns {FakeTransport} Fresh controlled transport.
     */
    function transportFactory() {
        const transport = new FakeTransport()
        transports.push(transport)

        /** Delivers the generation handshake after listeners are attached. */
        function deliverHandshake() {
            transport.emitSplitFrame({
                type: 'handshake',
                protocolVersion: 1,
                serviceVersion: '0.1.0-test',
                platform: 'darwin',
                mode: 'native',
                privileged: true,
                platformCapability: { state: 'available' }
            })
        }
        queueMicrotask(deliverHandshake)
        return transport
    }

    const client = new DeviceServiceClient({
        executable: '/private/openrdx/openrdx-hardware',
        maxRestarts: 1,
        platform: 'darwin',
        restartBackoffMs: [25],
        timers,
        transportFactory
    })
    client.subscribeLifecycle((state) => lifecycle.push(state.status))
    await client.start()
    transports[0].emit('exit', 1)

    const restarted = client.start()
    await nextTurn()
    assert.equal(client.getState().status, 'restarting')
    assert.equal(transports.length, 1)

    timers.runNext()
    const restartedState = await restarted
    assert.equal(restartedState.status, 'ready')
    assert.equal(restartedState.generation, 2)
    assert.equal(restartedState.epoch, 2)
    assert.deepEqual(lifecycle.slice(-6), ['recovering', 'restarting', 'starting', 'handshaking', 'reconciling', 'ready'])
    assert.equal(transports.length, 2)
    await client.stop()
})

test('rejects a non-strict direct scan before writing another service frame', async () => {
    const transport = new FakeTransport()

    /**
     * Returns a handshaking transport for direct client-boundary validation.
     * @returns {FakeTransport} Controlled transport.
     */
    function transportFactory() {
        /** Delivers one valid current-platform handshake. */
        function deliverHandshake() {
            transport.emitSplitFrame({
                type: 'handshake',
                protocolVersion: 1,
                serviceVersion: '0.1.0-test',
                platform: 'darwin',
                mode: 'native',
                privileged: true,
                platformCapability: { state: 'available' }
            })
        }
        queueMicrotask(deliverHandshake)
        return transport
    }

    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', platform: 'darwin', transportFactory })
    await client.start()
    const writesBeforeScan = transport.writes.length

    assert.deepEqual(await client.scan({ kind: 'scan', osPath: '/dev/rdx-private' }), { ok: false, reason: 'invalid-request' })
    assert.equal(transport.writes.length, writesBeforeScan)
    await client.stop()
})

test('leaves ready state when the native transport stops accepting requests', async () => {
    const transport = new FakeTransport()

    /**
     * Returns the controlled transport and schedules a valid handshake.
     * @returns {FakeTransport} Controlled service transport.
     */
    function transportFactory() {
        /** Delivers one valid handshake before request failure. */
        function deliverHandshake() {
            transport.emitSplitFrame({
                type: 'handshake',
                protocolVersion: 1,
                serviceVersion: '0.1.0-test',
                platform: 'darwin',
                mode: 'native',
                privileged: true,
                platformCapability: { state: 'available' }
            })
        }
        queueMicrotask(deliverHandshake)
        return transport
    }

    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 0, platform: 'darwin', transportFactory })
    await client.start()
    transport.acceptWrites = false

    assert.deepEqual(await client.list(), { ok: false, reason: 'service-unavailable' })
    assert.deepEqual(client.getState(), { status: 'unavailable', reason: 'service-write-failed', restartCount: 0, terminatedGeneration: 1 })
    assert.equal(transport.closed, true)
})

test('accepts split bounded frames and maps only strict renderer-safe device events', async () => {
    const transport = new FakeTransport()
    const received = []

    /**
     * Returns the controlled transport and schedules a split native handshake.
     * @returns {FakeTransport} Controlled service transport.
     */
    function transportFactory() {
        /** Delivers the handshake after listeners and the request write exist. */
        function deliverHandshake() {
            transport.emitSplitFrame({
                type: 'handshake',
                protocolVersion: 1,
                serviceVersion: '0.1.0-test',
                platform: 'darwin',
                mode: 'native',
                privileged: true,
                platformCapability: { state: 'available' }
            })
        }
        queueMicrotask(deliverHandshake)
        return transport
    }

    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 0, platform: 'darwin', transportFactory })
    client.subscribeEvents(recordEvent)
    await client.start()

    transport.emitSplitFrame({ type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [] } })
    transport.emitSplitFrame({ type: 'event', channel: 'device', event: { type: 'list', listRevision: 2, devices: [], osPath: '/dev/rdx-secret' } })
    await nextTurn()

    assert.deepEqual(received, [
        { channel: 'device', event: { type: 'list', epoch: 1, listRevision: 0, devices: [] } },
        { channel: 'device', event: { type: 'list', epoch: 1, listRevision: 1, devices: [] } }
    ])
    assert.equal(client.getState().status, 'unavailable')

    /**
     * Records one validated client event.
     * @param {object} event - Safe service event envelope.
     * @returns {void} Completes after recording.
     */
    function recordEvent(event) {
        received.push(event)
    }
})

test('parses multiple complete bounded frames coalesced in one transport chunk', async () => {
    const transport = new FakeTransport()
    const received = []

    /**
     * Returns a transport with a scheduled native handshake.
     * @returns {FakeTransport} Controlled transport.
     */
    function transportFactory() {
        /** Delivers one valid handshake. */
        function deliverHandshake() {
            transport.emitSplitFrame({
                type: 'handshake',
                protocolVersion: 1,
                serviceVersion: '0.1.0-test',
                platform: 'darwin',
                mode: 'native',
                privileged: true,
                platformCapability: { state: 'available' }
            })
        }
        queueMicrotask(deliverHandshake)
        return transport
    }

    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxFrameBytes: 256, maxRestarts: 0, platform: 'darwin', transportFactory })
    client.subscribeEvents(recordEvent)
    await client.start()
    const first = encodeFrame({ type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [] } })
    const second = encodeFrame({ type: 'event', channel: 'device', event: { type: 'list', listRevision: 2, devices: [] } })
    transport.emit('data', Buffer.concat([first, second]))

    assert.deepEqual(received, [
        { channel: 'device', event: { type: 'list', epoch: 1, listRevision: 0, devices: [] } },
        { channel: 'device', event: { type: 'list', epoch: 1, listRevision: 1, devices: [] } },
        { channel: 'device', event: { type: 'list', epoch: 1, listRevision: 2, devices: [] } }
    ])
    await client.stop()

    /**
     * Records one strict service event.
     * @param {object} event - Safe client event envelope.
     * @returns {void} Completes after recording.
     */
    function recordEvent(event) {
        received.push(event)
    }
})

test('requires native cancellation cutover and operation publication sequence proofs', async (context) => {
    /**
     * Starts one isolated native-mode client for a missing-proof scenario.
     * @param {string} scenario - Nested scenario label.
     * @param {(client: DeviceServiceClient, transport: FakeTransport) => Promise<void>} exercise - Missing-proof stimulus.
     * @returns {Promise<void>} Resolves after terminal protocol containment.
     */
    async function runScenario(scenario, exercise) {
        await context.test(scenario, async () => {
            const transport = new FakeTransport()

            /** @returns {FakeTransport} Controlled current transport. */
            function transportFactory() {
                queueMicrotask(() => transport.emitSplitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'publication-proof-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
                return transport
            }

            const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 0, platform: 'darwin', transportFactory })
            await client.start()
            await exercise(client, transport)
            await nextTurn()
            assert.deepEqual(client.getState(), { status: 'unavailable', reason: 'service-malformed-data', restartCount: 0, terminatedGeneration: 1 })
        })
    }

    await runScenario('cancel acknowledgement without cutover', async (client, transport) => {
        transport.autoReconcile = false
        const pending = client.cancelOperation({ operationId: 'op:missing-cutover' })
        const request = transport.writes.map(decodeFrame).at(-1)
        transport.emitSplitFrame({ type: 'response', requestId: request.requestId, ok: true, result: { ok: true } })
        assert.deepEqual(await pending, { ok: false, reason: 'operation-outcome-unknown', ambiguous: true })
    })
    await runScenario('operation event without publication sequence', async (_client, transport) => {
        transport.emitSplitFrame({ type: 'event', channel: 'operation', event: { state: 'started', operationId: 'op:missing-sequence', kind: 'self-test', deviceId: 'rdx:live-1', deviceRevision: 1, stage: 'diagnostic-running' } })
    })
})

test('applies bounded restart backoff and reaches a terminal unavailable state', async () => {
    const timers = new ManualTimers()
    const launches = []
    const lifecycle = []

    /**
     * Simulates a missing native executable without exposing the thrown details.
     * @param {object} launch - Fixed launch descriptor.
     * @throws {Error} Always throws the controlled spawn failure.
     */
    function unavailableTransportFactory(launch) {
        launches.push(launch)
        throw new Error('spawn failed for /private/secret/service with token=never-log')
    }

    const client = new DeviceServiceClient({
        executable: '/private/openrdx/openrdx-hardware',
        maxRestarts: 2,
        platform: 'darwin',
        restartBackoffMs: [5, 25],
        timers,
        transportFactory: unavailableTransportFactory
    })
    client.subscribeLifecycle(recordLifecycle)
    const terminalState = client.start()

    await nextTurn()
    assert.equal(client.getState().status, 'restarting')
    timers.runNext()
    await nextTurn()
    assert.equal(client.getState().restartCount, 2)
    timers.runNext()
    await nextTurn()

    assert.deepEqual(await terminalState, { status: 'unavailable', reason: 'service-start-failed', restartCount: 2, terminatedGeneration: 3 })
    assert.equal(launches.length, 3)
    assert.deepEqual(timers.delays, [5, 25])
    assert.equal(JSON.stringify(lifecycle).includes('/private/secret'), false)
    assert.equal(JSON.stringify(lifecycle).includes('never-log'), false)

    /**
     * Records sanitized lifecycle state.
     * @param {object} state - Frozen service state.
     * @returns {void} Completes after recording.
     */
    function recordLifecycle(state) {
        lifecycle.push(state)
    }
})

test('contains oversized frames as terminal protocol failure and never forwards bytes', async () => {
    const transport = new FakeTransport()
    const events = []

    /**
     * Returns a transport that completes a valid handshake before corruption.
     * @returns {FakeTransport} Controlled transport.
     */
    function transportFactory() {
        /** Delivers one valid handshake on the next microtask. */
        function deliverHandshake() {
            transport.emitSplitFrame({
                type: 'handshake',
                protocolVersion: 1,
                serviceVersion: '0.1.0-test',
                platform: 'darwin',
                mode: 'native',
                privileged: true,
                platformCapability: { state: 'available' }
            })
        }
        queueMicrotask(deliverHandshake)
        return transport
    }

    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxFrameBytes: 64, maxRestarts: 0, platform: 'darwin', transportFactory })
    client.subscribeEvents(recordEvent)
    await client.start()
    const oversizedHeader = Buffer.alloc(4)
    oversizedHeader.writeUInt32BE(65)
    transport.emit('data', oversizedHeader)
    await nextTurn()

    assert.deepEqual(client.getState(), { status: 'unavailable', reason: 'service-malformed-data', restartCount: 0, terminatedGeneration: 1 })
    assert.equal(transport.closed, true)
    assert.deepEqual(events, [])

    /**
     * Records any incorrectly forwarded service event.
     * @param {object} event - Candidate safe event.
     * @returns {void} Completes after recording.
     */
    function recordEvent(event) {
        events.push(event)
    }
})

test('does not report ready until a generation establishes a strict empty discovery baseline', async () => {
    const transport = new FakeTransport()
    transport.autoReconcile = false

    /** @returns {FakeTransport} Controlled handshaking transport. */
    function transportFactory() {
        /** Delivers one native handshake without a discovery baseline. */
        function deliverHandshake() {
            transport.emitSplitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: '0.1.0-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } })
        }
        queueMicrotask(deliverHandshake)
        return transport
    }

    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 0, platform: 'darwin', transportFactory })
    const readiness = client.start()
    await nextTurn()

    assert.equal(client.getState().status, 'reconciling')
    const request = transport.writes.map(decodeFrame).find((message) => message.method === 'devices-list')
    assert.equal(request.type, 'request')
    transport.emitSplitFrame({ type: 'response', requestId: request.requestId, ok: true, result: { ok: true, listRevision: 0, devices: [] } })

    assert.deepEqual(await readiness, {
        status: 'ready',
        mode: 'native',
        privileged: true,
        hardwareReady: true,
        hardwareVerified: false,
        platformCapability: { state: 'available' },
        generation: 1,
        epoch: 1,
        listRevision: 0,
        restartCount: 0
    })
    await client.stop()
})

test('rejects a cross-inconsistent no-device handshake before readiness', async () => {
    const transport = new FakeTransport()

    /** @returns {FakeTransport} Controlled invalid no-device transport. */
    function transportFactory() {
        /** Delivers a no-device handshake that falsely claims privilege. */
        function deliverHandshake() {
            transport.emitSplitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'invalid-test', platform: 'darwin', mode: 'no-device', privileged: true, platformCapability: { state: 'transport-unavailable', reason: 'native-service-not-implemented' } })
        }
        queueMicrotask(deliverHandshake)
        return transport
    }

    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 0, platform: 'darwin', transportFactory })
    assert.deepEqual(await client.start(), { status: 'unavailable', reason: 'service-malformed-data', restartCount: 0, terminatedGeneration: 1 })
})

test('rejects nonempty discovery state from the explicit no-device mode', async () => {
    const transport = new FakeTransport()
    transport.autoReconcile = false

    /** @returns {FakeTransport} Controlled no-device transport. */
    function transportFactory() {
        /** Delivers a valid no-device handshake. */
        function deliverHandshake() {
            transport.emitSplitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'no-device-test', platform: 'darwin', mode: 'no-device', privileged: false, platformCapability: { state: 'transport-unavailable', reason: 'native-service-not-implemented' } })
        }
        queueMicrotask(deliverHandshake)
        return transport
    }

    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 0, platform: 'darwin', transportFactory })
    const readiness = client.start()
    await nextTurn()
    const request = transport.writes.map(decodeFrame).find((message) => message.method === 'devices-list')
    assert.equal(request.type, 'request')
    transport.emitSplitFrame({ type: 'response', requestId: request.requestId, ok: true, result: { ok: true, listRevision: 0, devices: [createDevice(1)] } })

    assert.deepEqual(await readiness, { status: 'unavailable', reason: 'service-malformed-data', restartCount: 0, terminatedGeneration: 1 })
    assert.equal(client.getDevice('rdx:live-1'), null)
})

test('rejects delayed discovery rollback and tombstone resurrection in main', async () => {
    const transport = new FakeTransport()
    /** @returns {FakeTransport} Controlled native transport. */
    function transportFactory() {
        queueMicrotask(() => transport.emitSplitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'ordering-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
        return transport
    }
    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 0, platform: 'darwin', transportFactory })
    const received = []
    client.subscribeEvents((event) => received.push(event))
    await client.start()
    const device = createDevice(1)

    transport.emitSplitFrame({ type: 'event', channel: 'device', event: { type: 'snapshot', listRevision: 1, device } })
    transport.emitSplitFrame({ type: 'event', channel: 'device', event: { type: 'removed', listRevision: 2, deviceId: device.id, deviceRevision: 1 } })
    transport.emitSplitFrame({ type: 'event', channel: 'device', event: { type: 'list', listRevision: 1, devices: [device] } })
    transport.emitSplitFrame({ type: 'event', channel: 'device', event: { type: 'snapshot', listRevision: 3, device } })

    assert.equal(client.getDevice(device.id), null)
    assert.deepEqual(
        received.map((envelope) => envelope.event.type),
        ['list', 'snapshot', 'removed']
    )
    await client.stop()
})

test('returns an explicit ambiguous timeout for operation dispatch', async () => {
    const timers = new ManualTimers()
    const transport = new FakeTransport()
    /** @returns {FakeTransport} Controlled native transport. */
    function transportFactory() {
        queueMicrotask(() => transport.emitSplitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'timeout-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
        return transport
    }
    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 0, platform: 'darwin', timers, transportFactory })
    await client.start()
    transport.autoReconcile = false
    const operation = client.startOperation({ operationId: 'op:timeout', request: { kind: 'self-test', deviceId: 'rdx:live-1', deviceRevision: 1 } })

    timers.runNext()

    assert.deepEqual(await operation, { ok: false, reason: 'operation-outcome-unknown', ambiguous: true })
    await nextTurn()
    assert.deepEqual(client.getState(), { status: 'unavailable', reason: 'service-request-timeout', restartCount: 0, terminatedGeneration: 1 })
    await client.stop()
})

test('maps a mutating write fault to ambiguity before confirmed generation loss', async () => {
    const transport = new FakeTransport()
    /** @returns {FakeTransport} Controlled native transport. */
    function transportFactory() {
        queueMicrotask(() => transport.emitSplitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'fault-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
        return transport
    }
    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 0, platform: 'darwin', transportFactory })
    await client.start()
    transport.acceptWrites = false

    assert.deepEqual(await client.scan({ kind: 'scan' }), { ok: false, reason: 'operation-outcome-unknown', ambiguous: true })
    assert.deepEqual(client.getState(), { status: 'unavailable', reason: 'service-write-failed', restartCount: 0, terminatedGeneration: 1 })
})

test('enters terminal teardown-unconfirmed without publishing a terminated generation', async () => {
    const transport = new FakeTransport()
    transport.closeResult = { confirmed: false, reason: 'service-teardown-unconfirmed' }
    /** @returns {FakeTransport} Controlled native transport. */
    function transportFactory() {
        queueMicrotask(() => transport.emitSplitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'stuck-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
        return transport
    }
    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 1, platform: 'darwin', transportFactory })
    await client.start()
    transport.acceptWrites = false

    assert.deepEqual(await client.startOperation({ operationId: 'op:stuck', request: { kind: 'self-test', deviceId: 'rdx:live-1', deviceRevision: 1 } }), { ok: false, reason: 'operation-outcome-unknown', ambiguous: true })
    await nextTurn()
    assert.deepEqual(client.getState(), { status: 'teardown-unconfirmed', reason: 'service-teardown-unconfirmed', restartCount: 0, generation: 1 })
    await client.stop()
    assert.deepEqual(client.getState(), { status: 'teardown-unconfirmed', reason: 'service-teardown-unconfirmed', restartCount: 0, generation: 1 })
    assert.deepEqual(await client.start(), { status: 'teardown-unconfirmed', reason: 'service-teardown-unconfirmed', restartCount: 0, generation: 1 })
})

test('preserves ambiguity for scan, operation, and cancel across crash and malformed faults', async () => {
    const scenarios = [
        { method: 'scan', fault: 'error' },
        { method: 'operation', fault: 'malformed' },
        { method: 'cancel', fault: 'exit' }
    ]
    for (const scenario of scenarios) {
        const transport = new FakeTransport()
        /** @returns {FakeTransport} Controlled current scenario transport. */
        function transportFactory() {
            queueMicrotask(() => transport.emitSplitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'ambiguity-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
            return transport
        }
        const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 0, platform: 'darwin', transportFactory })
        await client.start()
        transport.autoReconcile = false
        const request = scenario.method === 'scan' ? client.scan({ kind: 'scan' }) : scenario.method === 'operation' ? client.startOperation({ operationId: 'op:fault', request: { kind: 'self-test', deviceId: 'rdx:live-1', deviceRevision: 1 } }) : client.cancelOperation({ operationId: 'op:fault' })

        if (scenario.fault === 'malformed') {
            transport.emit('data', Buffer.alloc(4))
        } else {
            transport.emit(scenario.fault)
        }

        assert.deepEqual(await request, { ok: false, reason: 'operation-outcome-unknown', ambiguous: true }, scenario.method)
        await nextTurn()
        assert.equal(client.getState().status, 'unavailable')
    }
})

test('faults matched invalid results for every ambiguous method without releasing an unconfirmed generation', async (context) => {
    const methods = ['scan', 'operation', 'cancel']
    for (const method of methods) {
        /** @returns {Promise<void>} Verifies one independent ambiguous method correlation. */
        async function exerciseAmbiguousMethod() {
            const transport = new FakeTransport()
            transport.closeResult = { confirmed: false, reason: 'service-teardown-unconfirmed' }

            /** @returns {FakeTransport} Controlled current-method transport. */
            function transportFactory() {
                queueMicrotask(deliverHandshake)
                return transport
            }

            /** @returns {void} Delivers one valid current-generation handshake. */
            function deliverHandshake() {
                transport.emitSplitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'invalid-result-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } })
            }

            const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 1, platform: 'darwin', transportFactory })
            await client.start()
            transport.autoReconcile = false
            const pending = method === 'scan' ? client.scan({ kind: 'scan' }) : method === 'operation' ? client.startOperation({ operationId: 'op:invalid-result', request: { kind: 'self-test', deviceId: 'rdx:live-1', deviceRevision: 1 } }) : client.cancelOperation({ operationId: 'op:invalid-result' })
            const request = transport.writes.map(decodeFrame).at(-1)

            transport.emitSplitFrame({ type: 'response', requestId: request.requestId, ok: true, result: { accepted: true } })

            assert.deepEqual(await pending, { ok: false, reason: 'operation-outcome-unknown', ambiguous: true }, method)
            await nextTurn()
            assert.deepEqual(client.getState(), { status: 'teardown-unconfirmed', reason: 'service-teardown-unconfirmed', restartCount: 0, generation: 1 }, method)
        }

        await context.test(method, exerciseAmbiguousMethod)
    }
})

test('bounds aggregate pending requests with a stable saturation result', async () => {
    const transport = new FakeTransport()
    /** @returns {FakeTransport} Controlled native transport. */
    function transportFactory() {
        queueMicrotask(() => transport.emitSplitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'saturation-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
        return transport
    }
    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxPendingCount: 1, maxRestarts: 0, platform: 'darwin', transportFactory })
    await client.start()
    transport.autoReconcile = false
    const pendingList = client.list()

    assert.deepEqual(await client.scan({ kind: 'scan' }), { ok: false, reason: 'service-saturated' })
    const request = transport.writes.map(decodeFrame).at(-1)
    transport.emitSplitFrame({ type: 'response', requestId: request.requestId, ok: true, result: { ok: true, listRevision: 0, devices: [] } })
    assert.equal((await pendingList).ok, true)
    await client.stop()
})

test('bounds aggregate pending bytes independently of request count', async () => {
    const transport = new FakeTransport()
    /** @returns {FakeTransport} Controlled native transport. */
    function transportFactory() {
        queueMicrotask(() => transport.emitSplitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'byte-bound-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
        return transport
    }
    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxFrameBytes: 256, maxPendingBytes: 256, maxPendingCount: 10, maxRestarts: 0, platform: 'darwin', transportFactory })
    await client.start()
    transport.autoReconcile = false
    const pendingList = client.list()
    const pendingScan = client.scan({ kind: 'scan' })

    assert.deepEqual(await client.scan({ kind: 'scan' }), { ok: false, reason: 'service-saturated' })
    await client.stop()
    assert.deepEqual(await pendingList, { ok: false, reason: 'service-unavailable' })
    assert.deepEqual(await pendingScan, { ok: false, reason: 'service-unavailable' })
})

test('faults only the exact current generation through bounded teardown', async () => {
    const transport = new FakeTransport()

    /** @returns {FakeTransport} Controlled current-generation transport. */
    function transportFactory() {
        /** @returns {void} Delivers the current strict native handshake. */
        function deliverHandshake() {
            transport.emitSplitFrame({ type: 'handshake', protocolVersion: 1, serviceVersion: 'exact-fault-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } })
        }
        queueMicrotask(deliverHandshake)
        return transport
    }

    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 0, platform: 'darwin', transportFactory })
    await client.start()

    assert.equal(client.faultGeneration(0), false)
    assert.equal(client.getState().status, 'ready')
    assert.equal(client.faultGeneration(1), true)
    assert.equal(client.getState().status, 'recovering')
    await nextTurn()
    assert.equal(transport.closed, true)
    assert.deepEqual(client.getState(), { status: 'unavailable', reason: 'service-malformed-data', restartCount: 0, terminatedGeneration: 1 })
})
