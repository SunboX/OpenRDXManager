// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'

import { DEVICE_SERVICE_ARGUMENTS, DeviceServiceClient, createDeviceServiceTransportFactory } from '../src/main/device-service-client.mjs'

/** Creates one writable local-socket fixture without native access. @returns {object} Controlled socket. */
function createSocket() {
    const socket = new EventEmitter()
    socket.destroyed = false
    socket.writableLength = 0
    socket.destroy = () => {
        socket.destroyed = true
    }
    socket.end = () => queueMicrotask(() => socket.emit('close'))
    socket.pause = () => {
        socket.paused = true
    }
    socket.resume = () => {
        socket.paused = false
    }
    socket.setNoDelay = () => {}
    socket.write = () => true
    return socket
}

/** @param {Buffer} frame - One complete service frame. @returns {object} Decoded JSON message. */
function decodeFrame(frame) {
    const length = frame.readUInt32BE(0)
    return JSON.parse(frame.subarray(4, length + 4).toString('utf8'))
}

test('development mode uses stdio only through the explicit child-process contract', () => {
    const launches = []

    /** @param {string} command - Native executable. @param {string[]} args - Fixed arguments. @param {object} options - Spawn options. @returns {object} Controlled child. */
    function spawnProcess(command, args, options) {
        launches.push({ command, args, options })
        return {
            stderr: { resume() {} },
            stdin: Object.assign(new EventEmitter(), {
                end() {},
                writable: true,
                write(_frame, callback) {
                    callback()
                    return true
                }
            }),
            stdout: new EventEmitter(),
            on() {},
            once() {}
        }
    }

    const factory = createDeviceServiceTransportFactory({ isPackaged: false, platform: 'linux', spawnProcess })
    factory({ args: DEVICE_SERVICE_ARGUMENTS, command: '/work/OpenRDXManager/out/native/linux/openrdx-hardware' })

    assert.equal(launches.length, 1)
    assert.deepEqual(launches[0].args, [...DEVICE_SERVICE_ARGUMENTS])
    assert.deepEqual(launches[0].options.stdio, ['pipe', 'pipe', 'pipe'])
})

test('hardware development wraps only the fixed service command with non-interactive sudo', () => {
    const launches = []

    /** @param {string} command - Native executable. @param {string[]} args - Fixed arguments. @param {object} options - Spawn options. @returns {object} Controlled child. */
    function spawnProcess(command, args, options) {
        launches.push({ command, args, options })
        return {
            stderr: { resume() {} },
            stdin: Object.assign(new EventEmitter(), {
                end() {},
                writable: true,
                write(_frame, callback) {
                    callback()
                    return true
                }
            }),
            stdout: new EventEmitter(),
            on() {},
            once() {}
        }
    }

    const factory = createDeviceServiceTransportFactory({ elevateDevelopmentService: true, isPackaged: false, platform: 'darwin', spawnProcess })
    factory({ args: DEVICE_SERVICE_ARGUMENTS, command: '/work/OpenRDXManager/out/native/macos/openrdx-hardware' })

    assert.equal(launches.length, 1)
    assert.equal(launches[0].command, '/usr/bin/sudo')
    assert.deepEqual(launches[0].args, ['-n', '--', '/work/OpenRDXManager/out/native/macos/openrdx-hardware', ...DEVICE_SERVICE_ARGUMENTS])
    assert.deepEqual(launches[0].options.stdio, ['pipe', 'pipe', 'pipe'])
})

test('a missing privileged endpoint reports service not installed without child fallback', async () => {
    const socket = createSocket()
    const factory = createDeviceServiceTransportFactory({
        connectEndpoint: () => socket,
        isPackaged: true,
        platform: 'darwin'
    })
    const client = new DeviceServiceClient({
        executable: '/Applications/OpenRDXManager.app/Contents/Resources/native/macos/openrdx-hardware',
        maxRestarts: 0,
        platform: 'darwin',
        transportFactory: factory
    })
    const startup = client.start()
    const missing = new Error('private native detail')
    missing.code = 'ENOENT'
    socket.emit('error', missing)

    assert.deepEqual(await startup, {
        status: 'unavailable',
        reason: 'service-not-installed',
        restartCount: 0,
        terminatedGeneration: 1
    })
})

test('a privileged endpoint connection timeout destroys the pending native socket', () => {
    const socket = createSocket()
    const callbacks = new Map()
    let timerId = 0
    const timers = {
        /** @param {Function} callback - Scheduled callback. @returns {number} Stable timer identity. */
        setTimeout(callback) {
            timerId += 1
            callbacks.set(timerId, callback)
            return timerId
        },
        /** @param {number} id - Timer identity. @returns {void} Removes a scheduled callback. */
        clearTimeout(id) {
            callbacks.delete(id)
        }
    }
    const factory = createDeviceServiceTransportFactory({
        connectEndpoint: () => socket,
        connectTimeoutMs: 100,
        isPackaged: true,
        platform: 'linux',
        timers
    })
    const transport = factory({ command: '/ignored', args: [] })
    let failure = null
    transport.once('error', (error) => {
        failure = error
    })

    callbacks.get(1)()

    assert.equal(socket.destroyed, true)
    assert.deepEqual(failure, { reason: 'service-exited' })
})

test('Windows endpoint fails closed before forwarding bytes when server identity is absent', async () => {
    const socket = createSocket()
    const factory = createDeviceServiceTransportFactory({
        connectEndpoint: () => socket,
        isPackaged: true,
        platform: 'win32'
    })
    const transport = factory({ command: '/ignored', args: [] })
    const failures = []
    const bytes = []
    transport.on('error', (failure) => failures.push(failure))
    transport.on('data', (chunk) => bytes.push(chunk))

    socket.emit('connect')
    socket.emit('data', Buffer.from([0, 0, 0, 1, 1]))
    await new Promise((resolve) => setImmediate(resolve))

    assert.equal(socket.destroyed, true)
    assert.deepEqual(bytes, [])
    assert.deepEqual(failures, [{ reason: 'service-identity-unverified' }])
})

test('Windows endpoint resumes framed bytes only after exact native server identity proof', async () => {
    const socket = createSocket()
    const factory = createDeviceServiceTransportFactory({
        connectEndpoint: () => socket,
        isPackaged: true,
        platform: 'win32',
        verifyWindowsServerIdentity: async () => true
    })
    const transport = factory({ command: '/ignored', args: [] })
    const bytes = []
    transport.on('data', (chunk) => bytes.push(chunk))

    assert.equal(socket.paused, true)
    socket.emit('connect')
    await new Promise((resolve) => setImmediate(resolve))
    assert.equal(socket.paused, false)
    socket.emit('data', Buffer.from([0, 0, 0, 1, 1]))

    assert.deepEqual(bytes, [Buffer.from([0, 0, 0, 1, 1])])
})

test('Windows initial handshake waits for verified native connection readiness', async () => {
    const socket = createSocket()
    const writes = []
    socket.write = (frame) => {
        writes.push(Buffer.from(frame))
        return true
    }
    const factory = createDeviceServiceTransportFactory({
        connectEndpoint: () => socket,
        isPackaged: true,
        platform: 'win32',
        verifyWindowsServerIdentity: async () => true
    })
    const client = new DeviceServiceClient({
        executable: '/work/OpenRDXManager/openrdx-hardware.exe',
        maxRestarts: 0,
        platform: 'win32',
        transportFactory: factory
    })
    const startup = client.start()

    assert.deepEqual(writes, [])
    socket.emit('connect')
    await new Promise(setImmediate)
    assert.equal(writes.length, 1)
    assert.deepEqual(decodeFrame(writes[0]), { type: 'handshake-request', protocolVersion: 1 })

    socket.emit('error', new Error('controlled shutdown'))
    await startup
})

test('Windows runtime verification can exceed eight seconds before the post-readiness handshake deadline', async () => {
    const socket = createSocket()
    const writes = []
    const callbacks = new Map()
    const scheduled = []
    let timerId = 0
    const timers = {
        /** @param {Function} callback - Scheduled callback. @param {number} delay - Exact delay. @returns {number} Stable timer identity. */
        setTimeout(callback, delay) {
            timerId += 1
            callbacks.set(timerId, callback)
            scheduled.push({ id: timerId, delay })
            return timerId
        },
        /** @param {number} id - Timer identity. @returns {void} Removes one scheduled callback. */
        clearTimeout(id) {
            callbacks.delete(id)
        }
    }
    socket.write = (frame) => {
        writes.push(Buffer.from(frame))
        return true
    }
    const factory = createDeviceServiceTransportFactory({
        connectEndpoint: () => socket,
        isPackaged: true,
        platform: 'win32',
        timers,
        verifyWindowsServerIdentity: async () => true
    })
    const client = new DeviceServiceClient({
        executable: '/work/OpenRDXManager/openrdx-hardware.exe',
        handshakeTimeoutMs: 2_000,
        maxRestarts: 0,
        platform: 'win32',
        timers,
        transportFactory: factory
    })
    const startup = client.start()

    assert.deepEqual(
        scheduled.map(({ delay }) => delay),
        [53_000],
        'complete runtime verification needs its own allowance before the native seven-second activation deadline'
    )
    assert.deepEqual(writes, [])

    // A slow disk can still be verifying enrollment when the former watchdog
    // expired. Advancing past it must neither cancel the socket nor write bytes.
    for (const { id, delay } of scheduled) {
        if (delay <= 8_000) callbacks.get(id)?.()
    }
    assert.equal(socket.destroyed, false)
    assert.equal(client.getState().status, 'handshaking')
    assert.deepEqual(writes, [])

    socket.emit('connect')
    await new Promise(setImmediate)

    assert.deepEqual(
        scheduled.map(({ delay }) => delay),
        [53_000, 2_000],
        'the absolute first-frame deadline starts only after verified transport readiness'
    )
    assert.equal(writes.length, 1)
    assert.deepEqual(decodeFrame(writes[0]), { type: 'handshake-request', protocolVersion: 1 })

    socket.emit('error', new Error('controlled shutdown'))
    await startup
})

test('macOS gives full policy verification its own budget before the unchanged post-proof handshake deadline', async () => {
    const socket = createSocket()
    const scheduled = []
    const writes = []
    const callbacks = new Map()
    let id = 0
    const timers = {
        /** @param {Function} callback - Bounded callback. @param {number} delay - Budget. @returns {number} Timer identity. */
        setTimeout(callback, delay) {
            scheduled.push(delay)
            callbacks.set(++id, callback)
            return id
        },
        /** @param {number} timer - Timer identity. @returns {void} Cancels the timer. */
        clearTimeout(timer) {
            callbacks.delete(timer)
        }
    }
    socket.serverIdentityVerified = () => true
    socket.write = (frame) => {
        writes.push(frame)
        return true
    }
    const client = new DeviceServiceClient({
        executable: '/Library/PrivilegedHelperTools/openrdx-hardware',
        platform: 'darwin',
        maxRestarts: 0,
        handshakeTimeoutMs: 10_000,
        timers,
        transportFactory: createDeviceServiceTransportFactory({ platform: 'darwin', isPackaged: true, connectEndpoint: () => socket, timers })
    })
    const startup = client.start()
    assert.deepEqual(scheduled, [53_000], '45s own proof plus 7s endpoint proof and 1s watchdog margin')
    assert.deepEqual(writes, [])
    socket.emit('connect')
    assert.deepEqual(scheduled, [53_000, 10_000])
    assert.equal(writes.length, 1)
    socket.emit('error', new Error('controlled shutdown'))
    await startup
})

test('Windows activation timeout wins error and late-ready races without writing', async () => {
    const socket = createSocket()
    const writes = []
    const callbacks = new Map()
    let timerId = 0
    const timers = {
        /** @param {Function} callback - Scheduled callback. @returns {number} Stable timer identity. */
        setTimeout(callback) {
            timerId += 1
            callbacks.set(timerId, callback)
            return timerId
        },
        /** @param {number} id - Timer identity. @returns {void} Removes one scheduled callback. */
        clearTimeout(id) {
            callbacks.delete(id)
        }
    }
    socket.write = (frame) => {
        writes.push(Buffer.from(frame))
        return true
    }
    const factory = createDeviceServiceTransportFactory({
        connectEndpoint: () => socket,
        isPackaged: true,
        platform: 'win32',
        timers,
        verifyWindowsServerIdentity: async () => true
    })
    const client = new DeviceServiceClient({
        executable: '/work/OpenRDXManager/openrdx-hardware.exe',
        maxRestarts: 0,
        platform: 'win32',
        timers,
        transportFactory: factory
    })
    const startup = client.start()

    callbacks.get(1)()
    socket.emit('error', { reason: 'service-exited' })
    socket.emit('connect')
    await new Promise(setImmediate)

    assert.deepEqual(writes, [])
    assert.equal(socket.destroyed, true)
    assert.deepEqual(await startup, {
        status: 'unavailable',
        reason: 'service-exited',
        restartCount: 0,
        terminatedGeneration: 1
    })
})

test('endpoint teardown requires observed close instead of destroy intent', async () => {
    const socket = createSocket()
    const callbacks = new Map()
    let timerId = 0
    socket.end = () => {}
    const timers = {
        /** @param {Function} callback - Scheduled callback. @returns {number} Stable timer identity. */
        setTimeout(callback) {
            timerId += 1
            callbacks.set(timerId, callback)
            return timerId
        },
        /** @param {number} id - Timer identity. @returns {void} Removes one scheduled callback. */
        clearTimeout(id) {
            callbacks.delete(id)
        }
    }
    const factory = createDeviceServiceTransportFactory({
        connectEndpoint: () => socket,
        isPackaged: true,
        platform: 'linux',
        teardownTimeoutMs: 25,
        timers
    })
    const transport = factory({ command: '/ignored', args: [] })
    socket.emit('connect')
    socket.destroy()

    const closing = transport.close()
    let settled = false
    /** @returns {Promise<void>} Records actual endpoint-close settlement. */
    async function observeClosing() {
        await closing
        settled = true
    }
    const observed = observeClosing()
    await Promise.resolve()
    assert.equal(settled, false, 'destroy intent is not terminal native close evidence')

    socket.emit('close')
    assert.deepEqual(await closing, { confirmed: true })
    await observed
})

test('endpoint timeout stays unconfirmed until a late observed close', async () => {
    const socket = createSocket()
    const callbacks = new Map()
    let timerId = 0
    socket.end = () => {}
    const timers = {
        /** @param {Function} callback - Scheduled callback. @returns {number} Stable timer identity. */
        setTimeout(callback) {
            timerId += 1
            callbacks.set(timerId, callback)
            return timerId
        },
        /** @param {number} id - Timer identity. @returns {void} Removes one scheduled callback. */
        clearTimeout(id) {
            callbacks.delete(id)
        }
    }
    const factory = createDeviceServiceTransportFactory({
        connectEndpoint: () => socket,
        isPackaged: true,
        platform: 'linux',
        teardownTimeoutMs: 25,
        timers
    })
    const transport = factory({ command: '/ignored', args: [] })
    socket.emit('connect')
    const closing = transport.close()

    callbacks.get(2)()
    assert.deepEqual(await closing, { confirmed: false, reason: 'service-teardown-unconfirmed' })

    socket.emit('close')
    assert.deepEqual(await transport.close(), { confirmed: true })
})

test('client retains generation ownership when pre-connect error has no terminal close', async () => {
    const socket = createSocket()
    socket.end = () => {}
    const factory = createDeviceServiceTransportFactory({
        connectEndpoint: () => socket,
        isPackaged: true,
        platform: 'win32',
        teardownTimeoutMs: 5,
        verifyWindowsServerIdentity: async () => true
    })
    const client = new DeviceServiceClient({
        executable: '/work/OpenRDXManager/openrdx-hardware.exe',
        maxRestarts: 1,
        platform: 'win32',
        transportFactory: factory
    })
    const startup = client.start()

    socket.emit('error', { reason: 'service-not-installed' })

    assert.deepEqual(await startup, {
        status: 'teardown-unconfirmed',
        reason: 'service-teardown-unconfirmed',
        restartCount: 0,
        generation: 1
    })
    assert.equal('terminatedGeneration' in client.getState(), false)
})

test('Windows native false write is a truthful endpoint failure', async () => {
    const socket = createSocket()
    socket.write = () => false
    const factory = createDeviceServiceTransportFactory({
        connectEndpoint: () => socket,
        isPackaged: true,
        platform: 'win32',
        verifyWindowsServerIdentity: async () => true
    })
    const transport = factory({ command: String.raw`C:\Program Files\OpenRDXManager\openrdx-hardware.exe`, args: [] })
    const failures = []
    transport.on('error', (failure) => failures.push(failure))
    socket.emit('connect')
    await new Promise(setImmediate)

    assert.deepEqual(transport.write(Buffer.from([0, 0, 0, 1, 1])), { ok: false, reason: 'service-unavailable' })
    assert.equal(socket.destroyed, true)
    assert.deepEqual(failures, [{ reason: 'service-exited' }])
})

test('Windows native startup reasons preserve only the fixed endpoint allowlist', () => {
    const cases = [
        ['service-not-installed', 'service-not-installed'],
        ['insufficient-permission', 'insufficient-permission'],
        ['service-identity-unverified', 'service-identity-unverified'],
        ['attacker-controlled-detail', 'service-exited']
    ]

    for (const [nativeReason, expectedReason] of cases) {
        const socket = createSocket()
        const factory = createDeviceServiceTransportFactory({
            connectEndpoint: () => socket,
            isPackaged: true,
            platform: 'win32',
            verifyWindowsServerIdentity: async () => true
        })
        const transport = factory({ command: String.raw`C:\Program Files\OpenRDXManager\openrdx-hardware.exe`, args: [] })
        let failure
        transport.once('error', (error) => {
            failure = error
        })

        socket.emit('error', { reason: nativeReason })

        assert.deepEqual(failure, { reason: expectedReason })
    }
})

test('service client preserves all typed Windows startup reasons and sanitizes unknown values', async () => {
    const cases = [
        ['service-not-installed', 'service-not-installed'],
        ['insufficient-permission', 'insufficient-permission'],
        ['service-identity-unverified', 'service-identity-unverified'],
        ['attacker-controlled-detail', 'service-exited']
    ]

    for (const [nativeReason, expectedReason] of cases) {
        const socket = createSocket()
        const factory = createDeviceServiceTransportFactory({
            connectEndpoint: () => socket,
            isPackaged: true,
            platform: 'win32',
            verifyWindowsServerIdentity: async () => true
        })
        const client = new DeviceServiceClient({
            executable: '/work/OpenRDXManager/openrdx-hardware.exe',
            maxRestarts: 0,
            platform: 'win32',
            transportFactory: factory
        })
        const startup = client.start()

        socket.emit('error', { reason: nativeReason })

        assert.deepEqual(await startup, {
            status: 'unavailable',
            reason: expectedReason,
            restartCount: 0,
            terminatedGeneration: 1
        })
    }
})

test('macOS endpoint rejects an unauthenticated helper before ready or protocol data', async () => {
    const socket = createSocket()
    const factory = createDeviceServiceTransportFactory({ connectEndpoint: () => socket, isPackaged: true, platform: 'darwin' })
    const transport = factory({ command: '/ignored', args: [] })
    const events = []
    transport.on('ready', () => events.push('ready'))
    transport.on('data', () => events.push('data'))
    transport.on('error', (error) => events.push(error.reason))
    assert.deepEqual(transport.write(Buffer.from([1])), { ok: false, reason: 'service-unavailable' })
    socket.emit('connect')
    socket.emit('data', Buffer.from([1]))
    await new Promise(setImmediate)
    assert.equal(socket.destroyed, true)
    assert.deepEqual(events, ['service-identity-unverified'])
})

test('macOS endpoint admits bytes only after the retained native socket proves helper identity', async () => {
    const socket = createSocket()
    socket.serverIdentityVerified = () => true
    const factory = createDeviceServiceTransportFactory({ connectEndpoint: () => socket, isPackaged: true, platform: 'darwin' })
    const transport = factory({ command: '/ignored', args: [] })
    const events = []
    transport.on('ready', () => events.push('ready'))
    transport.on('data', () => events.push('data'))
    socket.emit('connect')
    await new Promise(setImmediate)
    socket.emit('data', Buffer.from([1]))
    assert.deepEqual(events, ['ready', 'data'])
    assert.deepEqual(transport.write(Buffer.from([1])), { ok: true })
    await transport.close()
})

test('macOS retained native socket write failure terminates admission instead of reporting backpressure', async () => {
    const socket = createSocket()
    socket.serverIdentityVerified = () => true
    socket.write = () => false
    const factory = createDeviceServiceTransportFactory({ connectEndpoint: () => socket, isPackaged: true, platform: 'darwin' })
    const transport = factory({ command: '/ignored', args: [] })
    const errors = []
    transport.on('error', (error) => errors.push(error))
    socket.emit('connect')
    await new Promise(setImmediate)
    assert.deepEqual(transport.write(Buffer.from([1])), { ok: false, reason: 'service-unavailable' })
    assert.deepEqual(errors, [{ reason: 'service-exited' }])
    assert.equal(socket.destroyed, true)
})

test('macOS endpoint discards late bytes after identity-verified transport failure', async () => {
    const socket = createSocket()
    socket.serverIdentityVerified = () => true
    const factory = createDeviceServiceTransportFactory({ connectEndpoint: () => socket, isPackaged: true, platform: 'darwin' })
    const transport = factory({ command: '/ignored', args: [] })
    const bytes = []
    transport.on('error', () => {})
    transport.on('data', (data) => bytes.push(data))
    socket.emit('connect')
    await new Promise(setImmediate)
    socket.emit('error', new Error('disconnected'))
    socket.emit('data', Buffer.from('late'))
    assert.deepEqual(bytes, [])
})

test('macOS verified native connect and immediate data preserve ordered admission within one callback turn', () => {
    const socket = createSocket()
    socket.serverIdentityVerified = () => true
    const factory = createDeviceServiceTransportFactory({ connectEndpoint: () => socket, isPackaged: true, platform: 'darwin' })
    const transport = factory({ command: '/ignored', args: [] })
    const events = []
    transport.on('ready', () => events.push('ready'))
    transport.on('data', () => events.push('data'))
    transport.on('error', (error) => events.push(error.reason))
    socket.emit('connect')
    socket.emit('data', Buffer.from([1]))
    assert.deepEqual(events, ['ready', 'data'])
    socket.emit('error', new Error('cleanup'))
})
