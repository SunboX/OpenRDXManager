// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { publishContained } from '../src/main/contained-observers.mjs'
import { encodeServiceFrame } from '../src/main/device-service-transport.mjs'
import { EventLogger } from '../src/main/event-logger.mjs'
import { createLogFileSecurity } from '../src/main/log-file-security.mjs'
import { ServiceInboundQueue } from '../src/main/service-inbound-queue.mjs'

test('contained publication stays synchronous until an observer introduces a barrier', async () => {
    const delivered = []
    const gate = Promise.withResolvers()
    const listeners = new Set([
        /** @returns {void} Records delivery before throwing a contained observer error. */
        () => {
            delivered.push('throwing')
            throw new Error('controlled-observer-failure')
        },
        /** @returns {void} Records immediate delivery. */
        () => {
            delivered.push('sync')
        }
    ])
    assert.equal(publishContained(listeners, {}), true)
    assert.deepEqual(delivered, ['throwing', 'sync'])

    listeners.add(
        /** @returns {Promise<boolean>} Holds ordered delivery at a controlled barrier. */
        () => {
            delivered.push('barrier')
            return gate.promise
        }
    )
    listeners.add(
        /** @returns {void} Records delivery only after asynchronous acceptance. */
        () => {
            delivered.push('suffix')
        }
    )
    const outcome = publishContained(listeners, {})
    assert.equal(typeof outcome?.then, 'function')
    assert.deepEqual(delivered, ['throwing', 'sync', 'throwing', 'sync', 'barrier'])
    gate.resolve(true)
    assert.equal(await outcome, true)
    assert.equal(delivered.at(-1), 'suffix')
})

test('contained publication stops its suffix on rejection or invalidated delivery currency', async (context) => {
    for (const outcome of ['false', 'rejected', 'stale']) {
        await context.test(outcome, async () => {
            const gate = Promise.withResolvers()
            let current = true
            let suffixCalled = false
            const listeners = new Set([
                /** @returns {Promise<boolean>} Exposes a controlled asynchronous observer. */
                () => gate.promise,
                /** @returns {void} Detects an incorrectly published suffix. */
                () => {
                    suffixCalled = true
                }
            ])
            const published = publishContained(
                listeners,
                {},
                /** @returns {boolean} Captures whether this delivery remains current. */
                () => current
            )
            if (outcome === 'stale') current = false
            if (outcome === 'rejected') gate.reject(new Error('controlled-observer-rejection'))
            else gate.resolve(outcome !== 'false')
            assert.equal(await published, false)
            assert.equal(suffixCalled, false)
        })
    }
})

/** @returns {Promise<void>} Resolves after queued publication continuations. */
async function nextTurn() {
    await new Promise(setImmediate)
}

test('inbound FIFO retains synchronous delivery and invalidates a suspended old generation', async () => {
    const gate = Promise.withResolvers()
    const delivered = []
    const faults = []
    let generation = 1
    const inbound = new ServiceInboundQueue({
        maxFrameBytes: 1024,
        pending: new Map(),
        /** @param {number} candidate - Message generation. @returns {boolean} True only for the exact current generation. */
        isCurrent: (candidate) => candidate === generation,
        /** @returns {number} Current test generation. */
        getGeneration: () => generation,
        /** @param {object} message - Decoded test message. @returns {boolean|Promise<boolean>} Holds only the selected test message. */
        handleMessage(message) {
            delivered.push(message.id)
            return message.id === 'held' ? gate.promise : true
        },
        /** @returns {boolean} No control response is owned by this fixture. */
        handleResponse: () => false,
        /** @returns {boolean} No expired discovery response is owned by this fixture. */
        consumeExpiredDiscoveryResponse: () => false,
        /** @param {number} owner - Faulted generation. @returns {void} Records unexpected protocol faults. */
        fault: (owner) => faults.push(owner)
    })

    inbound.receive(encodeServiceFrame({ id: 'first' }), generation, 0)
    assert.deepEqual(delivered, ['first'])
    inbound.receive(Buffer.concat([encodeServiceFrame({ id: 'held' }), encodeServiceFrame({ id: 'old-suffix' })]), generation, 0)
    assert.deepEqual(delivered, ['first', 'held'])
    const oldEpoch = inbound.getEpoch()
    generation = 2
    inbound.reset()
    assert.equal(inbound.getEpoch(), oldEpoch + 1)
    inbound.receive(encodeServiceFrame({ id: 'new-generation' }), generation, 0)
    gate.reject(new Error('late-old-generation-rejection'))
    await nextTurn()
    assert.deepEqual(delivered, ['first', 'held', 'new-generation'])
    assert.deepEqual(faults, [])
})

test('logger arms its deadline before storage can enqueue a reentrant critical write', async () => {
    const lines = []
    const storageDeadlines = []
    const timers = new Set()
    let reentrantWrite
    const logger = new EventLogger({
        directory: '/controlled/async-boundary',
        timers: {
            /** @param {Function} callback - Controlled deadline callback. @returns {Function} Stable timer identity. */
            setTimeout(callback) {
                timers.add(callback)
                return callback
            },
            /** @param {Function} timer - Exact controlled timer. @returns {void} Removes its deadline. */
            clearTimeout(timer) {
                timers.delete(timer)
            }
        },
        fileSecurity: {
            /** @returns {Promise<void>} Queues one critical record from inside the first storage call. */
            async prepareDirectory() {
                storageDeadlines.push(timers.size)
                reentrantWrite ??= logger.writeCritical({ event: 'reentrant', messageKey: 'activity.reentrant' })
            },
            /** @returns {Promise<object>} Controlled append-only descriptor. */
            async openAppend() {
                return {
                    /** @returns {Promise<object>} Current in-memory log size. */
                    async stat() {
                        return { size: Buffer.byteLength(lines.join(''), 'utf8') }
                    },
                    /** @param {string} line - Sanitized record. @returns {Promise<void>} Appends one whole line. */
                    async writeFile(line) {
                        lines.push(line)
                    },
                    /** @returns {Promise<void>} Closes the in-memory descriptor. */
                    async close() {}
                }
            }
        }
    })

    const originalWrite = logger.writeCritical({ event: 'original', messageKey: 'activity.original' })
    assert.deepEqual(storageDeadlines, [])
    assert.equal(timers.size, 1)
    assert.equal(await originalWrite, true)
    assert.equal(await reentrantWrite, true)
    assert.deepEqual(await logger.close(), { ok: true })
    assert.deepEqual(storageDeadlines, [1, 1])
    assert.deepEqual(
        lines.map((line) => JSON.parse(line).event),
        ['original', 'reentrant']
    )
    assert.equal(timers.size, 0)
})

test('rejected Windows handle proof retains its failure when descriptor cleanup fails', async (context) => {
    for (const asynchronous of [false, true]) {
        await context.test(asynchronous ? 'rejected close' : 'throwing close', async () => {
            let closeCalls = 0
            const fileSecurity = createLogFileSecurity({
                platform: 'win32',
                windowsSecurityAdapter: {
                    /** @returns {Promise<object>} Unused directory proof. */
                    async ensurePrivateDirectory() {
                        return {}
                    },
                    /** @returns {Promise<object>} Invalid proof with a cleanup-failing descriptor. */
                    async openVerifiedFile() {
                        return {
                            noFollowVerified: false,
                            handle: {
                                /** @returns {Promise<void>} Rejects cleanup when asynchronous; otherwise throws immediately. @throws {Error} For synchronous close failure. */
                                close() {
                                    closeCalls += 1
                                    const error = new Error('controlled-close-failure')
                                    if (asynchronous) return Promise.reject(error)
                                    throw error
                                }
                            }
                        }
                    },
                    /** @returns {Promise<object>} Unused removal proof. */
                    async removeVerifiedFile() {
                        return {}
                    },
                    /** @returns {Promise<object>} Unused rename proof. */
                    async renameVerifiedFile() {
                        return {}
                    }
                }
            })
            await assert.rejects(fileSecurity.openAppend('/controlled/log'), /windows-log-handle-unverified/)
            assert.equal(closeCalls, 1)
        })
    }
})
