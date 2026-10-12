// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import test from 'node:test'
import { join } from 'node:path'
import { createMacOsNativeEndpointConnector } from '../src/main/macos-native-endpoint.mjs'

/** @returns {{socket: object, callback: Function, writes: Buffer[], destroys: number}} Controlled native addon fixture. */
function fixture() {
    let callback
    const writes = []
    let destroys = 0
    const connect = createMacOsNativeEndpointConnector({
        addonPath: join(process.cwd(), 'fixture.node'),
        loadAddon: () => ({
            /** @param {Function} handler - Native callback. @returns {object} Native connection fixture. */
            connect(handler) {
                callback = handler
                return {
                    /** @param {Buffer} bytes - Request bytes. @returns {boolean} Admission evidence. */
                    write(bytes) {
                        writes.push(bytes)
                        return true
                    },
                    /** @returns {void} Records cancellation intent. */
                    destroy() {
                        destroys += 1
                    },
                    /** @returns {void} Ends the fixture. */
                    end() {}
                }
            }
        })
    })
    const socket = connect({ path: '/var/run/openrdx-hardware.sock' })
    return {
        socket,
        callback,
        writes,
        get destroys() {
            return destroys
        }
    }
}

test('macOS native adapter never writes before native identity proof or after close', () => {
    const { socket, callback, writes } = fixture()
    assert.equal(socket.serverIdentityVerified(), false)
    assert.equal(socket.write(Buffer.from('secret')), false)
    callback({ type: 'connect' })
    assert.equal(socket.serverIdentityVerified(), true)
    assert.equal(socket.write(Buffer.from('request')), true)
    callback({ type: 'close' })
    assert.equal(socket.serverIdentityVerified(), false)
    assert.equal(socket.write(Buffer.from('late')), false)
    assert.deepEqual(writes, [Buffer.from('request')])
})

test('macOS native adapter closes on early data and never admits a late ready', () => {
    const fixtureState = fixture()
    const { socket, callback, writes } = fixtureState
    const events = []
    socket.on('error', (error) => events.push(error.reason))
    socket.on('data', () => events.push('data'))
    socket.on('connect', () => events.push('connect'))
    socket.on('close', () => events.push('close'))
    callback({ type: 'data', data: Buffer.from('spoofed') })
    callback({ type: 'connect' })
    callback({ type: 'close' })
    callback({ type: 'close' })
    assert.equal(fixtureState.destroys, 1)
    assert.deepEqual(events, ['service-identity-unverified', 'close'])
    assert.deepEqual(writes, [])
})

test('macOS native connector refuses caller paths and identity policy before addon load', () => {
    const connect = createMacOsNativeEndpointConnector({ addonPath: join(process.cwd(), 'missing.node') })
    for (const options of [{ path: '/tmp/spoofed.sock' }, { path: '/var/run/openrdx-hardware.sock', requirement: 'true' }, { path: '/var/run/openrdx-hardware.sock', expectedExecutable: '/tmp/helper' }]) {
        assert.throws(() => connect(options), /macos-client-endpoint-invalid/u)
    }
})

test('actual macOS native addon rejects Node and portable callers without sending hardware protocol bytes', { skip: process.platform !== 'darwin' }, async () => {
    const { createRequire } = await import('node:module')
    const addon = createRequire(import.meta.url)(join(process.cwd(), 'out/native/macos/openrdx-macos-client.node'))
    assert.equal(await addon.localTrustStatus(), 'installer-required')
    assert.throws(() => addon.localTrustStatus('/tmp/app'), /macos-client-status-arguments-invalid/u)
    assert.throws(() => addon.connect('/tmp/socket', () => {}), /macos-client-callback-invalid/u)
    const events = []
    await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('native-close-timeout')), 10_000)
        const native = addon.connect((event) => {
            events.push(event.type)
            if (event.type === 'close') {
                clearTimeout(timer)
                resolve()
            }
        })
        assert.equal(native.write(Buffer.from('never-send-this')), false)
    })
    assert.deepEqual(events, ['error', 'close'])
})
