// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'

import { DeviceServiceClient } from '../src/main/device-service-client.mjs'
import { DEFAULT_MAX_FRAME_BYTES, DEVICE_SERVICE_ARGUMENTS, createChildProcessTransportFactory, encodeServiceFrame } from '../src/main/device-service-transport.mjs'

/**
 * Decodes one complete outbound service frame.
 * @param {Buffer} frame - Length-prefixed JSON service frame.
 * @returns {object} Parsed service message.
 */
function decodeFrame(frame) {
    const length = frame.readUInt32BE(0)
    return JSON.parse(frame.subarray(4, length + 4).toString('utf8'))
}

/**
 * Allows promise continuations to settle without advancing controlled timers.
 * @returns {Promise<void>} Resolves on the next event-loop turn.
 */
async function nextTurn() {
    await new Promise(setImmediate)
}

/**
 * Waits for a predicate across chained real timers without assuming one event-loop wake.
 * @param {() => boolean} predicate - Observable condition produced by the timer chain.
 * @param {number} timeoutMs - Bounded wall-clock deadline.
 * @returns {Promise<void>} Resolves when the condition becomes true.
 */
async function waitFor(predicate, timeoutMs) {
    const deadline = Date.now() + timeoutMs
    while (!predicate()) {
        assert.ok(Date.now() < deadline, 'timed out waiting for transport timer chain')
        await new Promise((resolve) => setTimeout(resolve, 5))
    }
}

/** Controlled writable stream with explicit callback and drain delivery. */
class FakeStdin extends EventEmitter {
    /** Creates an open fake stdin. */
    constructor() {
        super()
        this.callbacks = []
        this.frames = []
        this.writable = true
        this.accept = true
    }

    /** @param {Buffer} frame - Serialized frame. @param {Function} callback - Completion callback. @returns {boolean} Current backpressure flag. */
    write(frame, callback) {
        this.frames.push(Buffer.from(frame))
        this.callbacks.push(callback)
        return this.accept
    }

    /** @returns {void} Marks stdin closed. */
    end() {
        this.writable = false
    }
}

/** Controlled readable stderr stream used to verify fixed diagnostic filtering. */
class FakeStderr extends EventEmitter {
    /** @returns {void} Mirrors the readable-stream drain call without side effects. */
    resume() {}
}

/** Controlled child-process shape for transport supervision. */
class FakeChild extends EventEmitter {
    /** Creates pipes and termination recording. */
    constructor() {
        super()
        this.exitCode = null
        this.signalCode = null
        this.kills = []
        this.stdin = new FakeStdin()
        this.stdout = new EventEmitter()
        this.stderr = new FakeStderr()
    }

    /** @param {string} signal - Requested termination signal. @returns {boolean} True after recording. */
    kill(signal) {
        this.kills.push(signal)
        return true
    }

    /**
     * Mirrors ChildProcess termination properties before emitting exit.
     * @param {number|null} exitCode - Numeric exit code or null for signal exit.
     * @param {string|null} signalCode - Terminating signal or null for code exit.
     * @param {boolean} emitClose - Whether all stdio pipes close in the same turn.
     * @returns {void} Completes after synchronous listener notification.
     */
    exit(exitCode, signalCode = null, emitClose = true) {
        this.exitCode = exitCode
        this.signalCode = signalCode
        this.emit('exit', exitCode, signalCode)
        if (emitClose) this.emit('close', exitCode, signalCode)
    }
}

/** Deterministic timer queue for client restart tests. */
class ManualTimers {
    /** Creates an empty timer queue. */
    constructor() {
        this.nextId = 1
        this.timers = new Map()
    }

    /** @param {Function} callback - Timer callback. @returns {number} Opaque timer identity. */
    setTimeout(callback) {
        const id = this.nextId
        this.nextId += 1
        this.timers.set(id, callback)
        return id
    }

    /** @param {number} id - Timer identity. @returns {void} Removes the timer. */
    clearTimeout(id) {
        this.timers.delete(id)
    }

    /** @returns {void} Runs the oldest active timer. */
    runNext() {
        const next = this.timers.entries().next()
        assert.equal(next.done, false)
        const [id, callback] = next.value
        this.timers.delete(id)
        callback()
    }
}

/**
 * Completes one native child generation's handshake and empty discovery.
 * @param {FakeChild} child - Exact spawned generation.
 * @param {string} serviceVersion - Generation-specific service version.
 * @returns {Promise<void>} Resolves after client reconciliation continuations.
 */
async function reconcileChild(child, serviceVersion) {
    assert.deepEqual(decodeFrame(child.stdin.frames.at(-1)), { type: 'handshake-request', protocolVersion: 1 })
    child.stdin.callbacks.shift()(null)
    child.stdout.emit(
        'data',
        encodeServiceFrame(
            {
                type: 'handshake',
                protocolVersion: 1,
                serviceVersion,
                platform: 'darwin',
                mode: 'native',
                privileged: true,
                platformCapability: { state: 'available' }
            },
            DEFAULT_MAX_FRAME_BYTES
        )
    )
    const listRequest = decodeFrame(child.stdin.frames.at(-1))
    assert.equal(listRequest.method, 'devices-list')
    child.stdin.callbacks.shift()(null)
    child.stdout.emit('data', encodeServiceFrame({ type: 'response', requestId: listRequest.requestId, ok: true, result: { ok: true, listRevision: 0, devices: [] } }, DEFAULT_MAX_FRAME_BYTES))
    await nextTurn()
}

test('spawns with fixed arguments and deterministic non-ambient environment', () => {
    const calls = []
    const child = new FakeChild()
    const factory = createChildProcessTransportFactory({ platform: 'darwin', spawnProcess: (...args) => (calls.push(args), child) })

    factory({ command: '/private/openrdx/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS })

    assert.deepEqual(calls[0][1], [...DEVICE_SERVICE_ARGUMENTS])
    assert.deepEqual(calls[0][2].env, { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' })
    assert.equal(JSON.stringify(calls[0][2].env).includes(process.env.HOME ?? 'never'), false)
})

test('serializes writes across callback and drain and returns stable saturation', () => {
    const child = new FakeChild()
    child.stdin.accept = false
    const transport = createChildProcessTransportFactory({ maxQueueBytes: 64, maxQueueCount: 2, platform: 'darwin', spawnProcess: () => child })({ command: '/private/openrdx/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS })

    assert.deepEqual(transport.write(Buffer.alloc(16, 1)), { ok: true })
    assert.deepEqual(transport.write(Buffer.alloc(16, 2)), { ok: true })
    assert.deepEqual(transport.write(Buffer.alloc(16, 3)), { ok: false, reason: 'service-saturated' })
    assert.equal(child.stdin.frames.length, 1)

    child.stdin.callbacks.shift()(null)
    assert.equal(child.stdin.frames.length, 1)
    child.stdin.accept = true
    child.stdin.emit('drain')
    assert.equal(child.stdin.frames.length, 2)
})

test('bounds queued aggregate bytes independently of frame count', () => {
    const child = new FakeChild()
    child.stdin.accept = false
    const transport = createChildProcessTransportFactory({ maxQueueBytes: 64, maxQueueCount: 10, platform: 'darwin', spawnProcess: () => child })({ command: '/private/openrdx/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS })

    for (let index = 0; index < 4; index += 1) {
        assert.deepEqual(transport.write(Buffer.alloc(16, index)), { ok: true })
    }
    assert.deepEqual(transport.write(Buffer.alloc(1)), { ok: false, reason: 'service-saturated' })
})

test('reports stdin callback/error/process-exit races exactly once', () => {
    const child = new FakeChild()
    const transport = createChildProcessTransportFactory({ platform: 'darwin', spawnProcess: () => child })({ command: '/private/openrdx/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS })
    const signals = []
    transport.on('error', () => signals.push('error'))
    transport.on('exit', () => signals.push('exit'))

    transport.write(Buffer.alloc(8, 1))
    child.stdin.callbacks.shift()(new Error('EPIPE secret'))
    child.stdin.emit('error', new Error('EPIPE secret'))
    child.emit('error', new Error('spawn secret'))
    child.exit(1)

    assert.deepEqual(signals, ['error'])
    assert.deepEqual(transport.write(Buffer.alloc(8)), { ok: false, reason: 'service-unavailable' })
})

test('retains allowlisted native breadcrumbs and appends the sanitized process exit', () => {
    const child = new FakeChild()
    const transport = createChildProcessTransportFactory({ platform: 'darwin', spawnProcess: () => child })({ command: '/private/openrdx/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS })
    const diagnostics = []
    let exitEvidence = null
    transport.on('diagnostic', (diagnostic) => diagnostics.push(diagnostic))
    transport.on('exit', (evidence) => {
        exitEvidence = evidence
    })

    child.stderr.emit('data', Buffer.from('host path /private/secret and payload\nopenrdx-hardware: trace eject-release-scsi-'))
    child.stderr.emit('data', Buffer.from('enter\nopenrdx-hardware: trace eject-invalidate-mapping-enter\nopenrdx-hardware: trace usb-release-device-enter\nopenrdx-hardware: trace eject-invalidate-mapping-return\nopenrdx-hardware: trace eject-pin-media-enter\n'))
    child.exit(null, 'SIGABRT')

    assert.deepEqual(diagnostics, [{ code: 'eject-release-scsi-enter' }, { code: 'eject-invalidate-mapping-enter' }, { code: 'usb-release-device-enter' }, { code: 'eject-invalidate-mapping-return' }, { code: 'eject-pin-media-enter' }, { code: 'service-exit-sigabrt' }])
    assert.deepEqual(exitEvidence, { diagnosticCode: 'service-exit-sigabrt' })
})

test('retains bounded firmware failure diagnostics without raw command data', () => {
    const child = new FakeChild()
    const transport = createChildProcessTransportFactory({ platform: 'darwin', spawnProcess: () => child })({ command: '/private/openrdx/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS })
    const diagnostics = []
    transport.on('diagnostic', (diagnostic) => diagnostics.push(diagnostic))
    const codes = ['firmware-transfer-attempt-one', 'firmware-transfer-first-chunk-failed', 'firmware-transfer-intermediate-chunk-failed', 'firmware-transfer-final-chunk-failed', 'firmware-command-invalid', 'firmware-transfer-retry-suppressed', 'firmware-transfer-retry-eligible', 'firmware-transfer-attempt-two', 'firmware-transfer-complete']
    child.stderr.emit('data', Buffer.from(codes.map((code) => `openrdx-hardware: trace ${code}\n`).join('')))
    child.stderr.emit('data', Buffer.from('openrdx-hardware: trace firmware-command-invalid raw-sense=05/24/00\nopenrdx-hardware: trace firmware-secret-payload\n'))
    assert.deepEqual(
        diagnostics,
        codes.map((code) => ({ code }))
    )
})

test('retains the Safe Eject preflight boundary without forwarding native stderr', () => {
    const child = new FakeChild()
    const transport = createChildProcessTransportFactory({ platform: 'darwin', spawnProcess: () => child })({ command: '/private/openrdx/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS })
    const diagnostics = []
    transport.on('diagnostic', (diagnostic) => diagnostics.push(diagnostic))

    child.stderr.emit('data', Buffer.from('openrdx-hardware: trace eject-preflight-enter\n'))

    assert.deepEqual(diagnostics, [{ code: 'eject-preflight-enter' }])
})

test('retains closed macOS Disk Arbitration and diskutil outcome diagnostics', () => {
    const child = new FakeChild()
    const transport = createChildProcessTransportFactory({ platform: 'darwin', spawnProcess: () => child })({ command: '/private/openrdx/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS })
    const diagnostics = []
    transport.on('diagnostic', (diagnostic) => diagnostics.push(diagnostic))

    child.stderr.emit('data', Buffer.from(['openrdx-hardware: trace macos-da-direct-already-unmounted', 'openrdx-hardware: trace macos-da-direct-access-denied', 'openrdx-hardware: trace macos-diskutil-unmount-enter', 'openrdx-hardware: trace macos-diskutil-unmount-exit-nonzero', 'openrdx-hardware: trace macos-diskutil-eject-target-revalidated', 'openrdx-hardware: trace macos-diskutil-eject-target-identity-changed', ''].join('\n')))

    assert.deepEqual(diagnostics, [{ code: 'macos-da-direct-already-unmounted' }, { code: 'macos-da-direct-access-denied' }, { code: 'macos-diskutil-unmount-enter' }, { code: 'macos-diskutil-unmount-exit-nonzero' }, { code: 'macos-diskutil-eject-target-revalidated' }, { code: 'macos-diskutil-eject-target-identity-changed' }])
})

test('retains closed macOS pinned-authority preflight diagnostics', () => {
    const child = new FakeChild()
    const transport = createChildProcessTransportFactory({ platform: 'darwin', spawnProcess: () => child })({ command: '/private/openrdx/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS })
    const diagnostics = []
    transport.on('diagnostic', (diagnostic) => diagnostics.push(diagnostic))

    child.stderr.emit(
        'data',
        Buffer.from(
            [
                'openrdx-hardware: trace macos-da-pinned-authority-missing',
                'openrdx-hardware: trace macos-da-pinned-raw-disk-mismatch',
                'openrdx-hardware: trace macos-da-pinned-raw-identity-mismatch',
                'openrdx-hardware: trace macos-da-pinned-media-missing',
                'openrdx-hardware: trace macos-da-pinned-media-object-mismatch',
                'openrdx-hardware: trace macos-da-pinned-media-id-unavailable',
                'openrdx-hardware: trace macos-da-pinned-media-id-mismatch',
                'openrdx-hardware: trace macos-da-pinned-authority-succeeded',
                'openrdx-hardware: trace macos-da-registry-busy',
                'openrdx-hardware: trace macos-da-context-unavailable',
                'openrdx-hardware: trace eject-media-rematch-enter',
                'openrdx-hardware: trace eject-media-rematch-return',
                'openrdx-hardware: trace eject-media-rematch-stale',
                'openrdx-hardware: trace eject-media-rematch-timed-out',
                'openrdx-hardware: trace eject-readback-enter',
                'openrdx-hardware: trace eject-readback-waiting',
                'openrdx-hardware: trace eject-readback-departed',
                'openrdx-hardware: trace eject-readback-failed',
                'openrdx-hardware: trace eject-readback-timed-out',
                'openrdx-hardware: trace macos-eject-raw-authority-released',
                ''
            ].join('\n')
        )
    )

    assert.deepEqual(diagnostics, [{ code: 'macos-da-pinned-authority-missing' }, { code: 'macos-da-pinned-raw-disk-mismatch' }, { code: 'macos-da-pinned-raw-identity-mismatch' }, { code: 'macos-da-pinned-media-missing' }, { code: 'macos-da-pinned-media-object-mismatch' }, { code: 'macos-da-pinned-media-id-unavailable' }, { code: 'macos-da-pinned-media-id-mismatch' }, { code: 'macos-da-pinned-authority-succeeded' }, { code: 'macos-da-registry-busy' }, { code: 'macos-da-context-unavailable' }, { code: 'eject-media-rematch-enter' }, { code: 'eject-media-rematch-return' }, { code: 'eject-media-rematch-stale' }, { code: 'eject-media-rematch-timed-out' }, { code: 'eject-readback-enter' }, { code: 'eject-readback-waiting' }, { code: 'eject-readback-departed' }, { code: 'eject-readback-failed' }, { code: 'eject-readback-timed-out' }, { code: 'macos-eject-raw-authority-released' }])
})

test('retains closed worker command boundaries without forwarding native stderr', () => {
    const child = new FakeChild()
    const transport = createChildProcessTransportFactory({ platform: 'darwin', spawnProcess: () => child })({ command: '/private/openrdx/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS })
    const diagnostics = []
    transport.on('diagnostic', (diagnostic) => diagnostics.push(diagnostic))

    child.stderr.emit('data', Buffer.from(['openrdx-hardware: trace scsi-worker-command-write-enter', 'openrdx-hardware: trace scsi-worker-command-write-return', 'openrdx-hardware: trace scsi-worker-native-enter', 'openrdx-hardware: trace scsi-worker-native-return', 'openrdx-hardware: trace scsi-worker-response-write-enter', 'openrdx-hardware: trace scsi-worker-response-write-return', 'openrdx-hardware: trace scsi-worker-response-read-enter', 'openrdx-hardware: trace scsi-worker-response-read-return', ''].join('\n')))

    assert.deepEqual(diagnostics, [{ code: 'scsi-worker-command-write-enter' }, { code: 'scsi-worker-command-write-return' }, { code: 'scsi-worker-native-enter' }, { code: 'scsi-worker-native-return' }, { code: 'scsi-worker-response-write-enter' }, { code: 'scsi-worker-response-write-return' }, { code: 'scsi-worker-response-read-enter' }, { code: 'scsi-worker-response-read-return' }])
})

test('classifies child termination without exposing raw process evidence', () => {
    const cases = [
        { exitCode: 0, signalCode: null, expected: 'service-exit-code-zero' },
        { exitCode: 70, signalCode: null, expected: 'service-exit-code-nonzero' },
        { exitCode: null, signalCode: 'SIGPIPE', expected: 'service-exit-sigpipe' },
        { exitCode: null, signalCode: 'SIGKILL', expected: 'service-exit-sigkill' },
        { exitCode: null, signalCode: 'SIGUSR1', expected: 'service-exit-signal-other' }
    ]

    for (const { exitCode, signalCode, expected } of cases) {
        const child = new FakeChild()
        const transport = createChildProcessTransportFactory({ platform: 'darwin', spawnProcess: () => child })({ command: '/private/openrdx/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS })
        const diagnostics = []
        let exitEvidence = null
        transport.on('diagnostic', (diagnostic) => diagnostics.push(diagnostic))
        transport.on('exit', (evidence) => {
            exitEvidence = evidence
        })

        child.exit(exitCode, signalCode)

        assert.deepEqual(diagnostics, [{ code: expected }])
        assert.deepEqual(exitEvidence, { diagnosticCode: expected })
    }
})

test('persists the final native breadcrumb before the classified recovering lifecycle state', async () => {
    const child = new FakeChild()
    const records = []
    const client = new DeviceServiceClient({
        executable: '/private/openrdx/openrdx-hardware',
        logger: { write: (record) => (records.push(record), Promise.resolve(true)) },
        maxRestarts: 0,
        platform: 'darwin',
        transportFactory: createChildProcessTransportFactory({ platform: 'darwin', spawnProcess: () => child })
    })

    const started = client.start()
    await reconcileChild(child, 'diagnostic-generation')
    await started
    child.stderr.emit('data', Buffer.from('openrdx-hardware: trace eject-unmount-enter\n'))
    child.exit(null, 'SIGABRT')
    await nextTurn()

    assert.equal(
        records.some((record) => record.event === 'service-diagnostic' && record.nativeDiagnostic === 'eject-unmount-enter'),
        true
    )
    assert.equal(
        records.some((record) => record.status === 'recovering' && record.reason === 'service-exited' && record.nativeDiagnostic === 'service-exit-sigabrt'),
        true
    )
})

test('persists every allowlisted native boundary before process exit', async () => {
    const child = new FakeChild()
    const records = []
    const client = new DeviceServiceClient({
        executable: '/private/openrdx/openrdx-hardware',
        logger: { write: (record) => (records.push(record), Promise.resolve(true)) },
        maxRestarts: 0,
        platform: 'darwin',
        transportFactory: createChildProcessTransportFactory({ platform: 'darwin', spawnProcess: () => child })
    })

    const started = client.start()
    await reconcileChild(child, 'diagnostic-sequence')
    await started
    child.stderr.emit(
        'data',
        Buffer.from(
            [
                'openrdx-hardware: trace eject-rematch-enter',
                'openrdx-hardware: trace eject-release-authority-enter',
                'openrdx-hardware: trace eject-release-authority-return',
                'openrdx-hardware: trace eject-release-scsi-enter',
                'openrdx-hardware: trace eject-release-scsi-return',
                'openrdx-hardware: trace eject-authority-reopen-enter',
                'openrdx-hardware: trace eject-authority-enumerate-enter',
                'openrdx-hardware: trace eject-authority-enumerate-return',
                'openrdx-hardware: trace eject-authority-select-return',
                'openrdx-hardware: trace eject-authority-open-enter',
                'openrdx-hardware: trace eject-authority-open-return',
                'openrdx-hardware: trace eject-authority-reopen-return',
                'openrdx-hardware: trace eject-rematch-return',
                'openrdx-hardware: trace eject-da-unmount-enter',
                'openrdx-hardware: trace eject-da-unmount-return',
                'openrdx-hardware: trace eject-da-eject-enter',
                'openrdx-hardware: trace eject-da-eject-return',
                ''
            ].join('\n')
        )
    )
    await nextTurn()

    assert.deepEqual(
        records.filter((record) => record.event === 'service-diagnostic').map((record) => record.nativeDiagnostic),
        ['eject-rematch-enter', 'eject-release-authority-enter', 'eject-release-authority-return', 'eject-release-scsi-enter', 'eject-release-scsi-return', 'eject-authority-reopen-enter', 'eject-authority-enumerate-enter', 'eject-authority-enumerate-return', 'eject-authority-select-return', 'eject-authority-open-enter', 'eject-authority-open-return', 'eject-authority-reopen-return', 'eject-rematch-return', 'eject-da-unmount-enter', 'eject-da-unmount-return', 'eject-da-eject-enter', 'eject-da-eject-return']
    )
})

test('waits for child stdio closure before publishing crash evidence', async () => {
    const child = new FakeChild()
    const records = []
    const client = new DeviceServiceClient({
        executable: '/private/openrdx/openrdx-hardware',
        logger: { write: (record) => (records.push(record), Promise.resolve(true)) },
        maxRestarts: 0,
        platform: 'darwin',
        transportFactory: createChildProcessTransportFactory({ platform: 'darwin', spawnProcess: () => child })
    })

    const started = client.start()
    await reconcileChild(child, 'delayed-stderr-generation')
    await started
    child.exit(null, 'SIGABRT', false)
    child.stderr.emit('data', Buffer.from('openrdx-hardware: trace eject-release-scsi-enter\n'))
    child.emit('close', null, 'SIGABRT')
    await nextTurn()

    assert.equal(
        records.some((record) => record.status === 'recovering' && record.reason === 'service-exited' && record.nativeDiagnostic === 'eject-release-scsi-enter'),
        true
    )
})

test('awaits graceful close and escalates only a child that does not exit', async () => {
    const gracefulChild = new FakeChild()
    const graceful = createChildProcessTransportFactory({ platform: 'darwin', shutdownTimeoutMs: 20, spawnProcess: () => gracefulChild })({ command: '/private/openrdx/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS })
    const gracefulClose = graceful.close()
    assert.deepEqual(gracefulChild.kills, [])
    gracefulChild.exit(0)
    assert.deepEqual(await gracefulClose, { confirmed: true })
    assert.deepEqual(gracefulChild.kills, [])

    const stuckChild = new FakeChild()
    const stuck = createChildProcessTransportFactory({ forceKillTimeoutMs: 1, platform: 'darwin', shutdownTimeoutMs: 1, spawnProcess: () => stuckChild })({ command: '/private/openrdx/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS })
    assert.deepEqual(await stuck.close(), { confirmed: false, reason: 'service-teardown-unconfirmed' })
    assert.deepEqual(stuckChild.kills, ['SIGTERM', 'SIGKILL'])
})

test('does not treat SIGKILL delivery as exit and confirms only the observed exit', async () => {
    const child = new FakeChild()
    const transport = createChildProcessTransportFactory({ forceKillTimeoutMs: 20, platform: 'darwin', shutdownTimeoutMs: 1, spawnProcess: () => child })({ command: '/private/openrdx/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS })
    const closing = transport.close()

    await waitFor(() => child.kills.length === 2, 100)
    assert.deepEqual(child.kills, ['SIGTERM', 'SIGKILL'])
    child.exit(null, 'SIGKILL')

    assert.deepEqual(await closing, { confirmed: true })
})

test('confirms a signal exit when close is awaited reentrantly from transport exit', async () => {
    const child = new FakeChild()
    const transport = createChildProcessTransportFactory({ forceKillTimeoutMs: 1, platform: 'darwin', shutdownTimeoutMs: 1, spawnProcess: () => child })({ command: '/private/openrdx/openrdx-hardware', args: DEVICE_SERVICE_ARGUMENTS })
    const closedFromExit = new Promise((resolve) => {
        transport.once('exit', async () => resolve(await transport.close()))
    })

    child.exit(null, 'SIGTERM')

    assert.deepEqual(await closedFromExit, { confirmed: true })
    assert.deepEqual(child.kills, [])
})

test('reconciles and restarts a client generation after a signal exit', async () => {
    const children = []
    const lifecycle = []
    const timers = new ManualTimers()
    let resolvePostExit
    const postExit = new Promise((resolve) => {
        resolvePostExit = resolve
    })

    /** @returns {FakeChild} Creates one realistic child generation. */
    function spawnProcess() {
        const child = new FakeChild()
        children.push(child)
        return child
    }

    /** @param {object} state - Published client lifecycle. @returns {void} Records and resolves the post-exit outcome. */
    function recordLifecycle(state) {
        lifecycle.push(state)
        if (['restarting', 'teardown-unconfirmed'].includes(state.status)) {
            resolvePostExit(state)
        }
    }

    const transportFactory = createChildProcessTransportFactory({ forceKillTimeoutMs: 1, platform: 'darwin', shutdownTimeoutMs: 1, spawnProcess })
    const client = new DeviceServiceClient({ executable: '/private/openrdx/openrdx-hardware', maxRestarts: 1, platform: 'darwin', restartBackoffMs: [25], timers, transportFactory })
    client.subscribeLifecycle(recordLifecycle)

    const started = client.start()
    await reconcileChild(children[0], 'signal-generation-1')
    assert.equal((await started).generation, 1)

    children[0].exit(null, 'SIGTERM')
    const postExitState = await postExit

    assert.deepEqual(postExitState, {
        status: 'restarting',
        reason: 'service-exited',
        restartCount: 1,
        terminatedGeneration: 1,
        nativeDiagnostic: 'service-exit-sigterm'
    })
    assert.deepEqual(client.getState(), postExitState)
    assert.deepEqual(children[0].kills, [])
    assert.equal(
        lifecycle.some((state) => state.status === 'teardown-unconfirmed'),
        false
    )

    timers.runNext()
    await reconcileChild(children[1], 'signal-generation-2')
    assert.equal(client.getState().status, 'ready')
    assert.equal(client.getState().generation, 2)
    assert.equal(client.getState().epoch, 2)

    const stopping = client.stop()
    children[1].exit(0)
    await stopping
})
