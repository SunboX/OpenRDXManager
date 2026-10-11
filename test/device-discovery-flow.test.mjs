// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { createDeviceController } from '../src/renderer/app-controller.mjs'
import { createRuntimeState } from '../src/renderer/service-binding.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { createDeviceSnapshot } from '../src/shared/contracts.mjs'

/** Deterministic timer queue for discovery scheduling tests. */
class FixtureTimers {
    #clock = 0
    #nextId = 0
    #timers = new Map()

    /** @param {Function} callback - Timer callback. @param {number} delay - Delay in milliseconds. @returns {number} Fixture timer ID. */
    setTimeout(callback, delay) {
        const id = ++this.#nextId
        this.#timers.set(id, { callback, dueAt: this.#clock + delay })
        return id
    }

    /** @param {number} id - Fixture timer ID. @returns {void} Removes the timer when present. */
    clearTimeout(id) {
        this.#timers.delete(id)
    }

    /** @param {number} elapsedMs - Milliseconds to advance. @returns {Promise<void>} Resolves after due callbacks and microtasks run. */
    async advance(elapsedMs) {
        const target = this.#clock + elapsedMs
        while (true) {
            let next = null
            for (const [id, timer] of this.#timers) {
                if (timer.dueAt <= target && (next === null || timer.dueAt < next.timer.dueAt || (timer.dueAt === next.timer.dueAt && id < next.id))) {
                    next = { id, timer }
                }
            }
            if (next === null) break
            this.#clock = next.timer.dueAt
            this.#timers.delete(next.id)
            next.timer.callback()
            await Promise.resolve()
            await Promise.resolve()
        }
        this.#clock = target
        await Promise.resolve()
        await Promise.resolve()
    }
}

/** Creates a service whose scans remain pending until the test resolves them. @returns {{service: object, scanCount: () => number, maxConcurrent: () => number, resolveNext: (result?: object) => void}} Controlled service. */
function createDeferredScanService() {
    const resolvers = []
    let active = 0
    let maximum = 0
    let count = 0

    /** @returns {Promise<object>} One controlled scan result. */
    async function scan() {
        count += 1
        active += 1
        maximum = Math.max(maximum, active)
        /** @param {(result: object) => void} resolve - Promise completion callback. @returns {void} Registers one controlled scan completion. */
        function registerPendingScan(resolve) {
            /** @param {object} result - Safe scan result. @returns {void} Completes this scan and releases its concurrency slot. */
            function completeScan(result) {
                active -= 1
                resolve(result)
            }
            resolvers.push(completeScan)
        }
        return new Promise(registerPendingScan)
    }

    /** @returns {number} Number of scans started by the controller. */
    function scanCount() {
        return count
    }

    /** @returns {number} Highest observed concurrent scan count. */
    function maxConcurrent() {
        return maximum
    }

    return {
        service: { scan },
        scanCount,
        maxConcurrent,
        /** @param {object} [result] - Safe scan result. @returns {void} Resolves the oldest pending scan. */
        resolveNext(result = { ok: true }) {
            resolvers.shift()?.(result)
        }
    }
}

/** Builds one complete renderer-safe no-media device. @param {number} revision - Discovery revision. @returns {object} Device snapshot. */
function noMediaDevice(revision) {
    return createDeviceSnapshot({
        id: 'rdx:stable-device',
        revision,
        vendor: 'TANDBERG',
        product: 'RDX',
        serial: '7820999743',
        media: null,
        capabilities: { 'status-refresh': { state: 'available' } }
    })
}

test('auto scan never overlaps a slow native scan', async () => {
    const timers = new FixtureTimers()
    const deferred = createDeferredScanService()
    const controller = createDeviceController({ service: deferred.service, intervalMs: 1_000, timers })

    controller.startAutoScan()
    await timers.advance(3_100)

    assert.equal(deferred.scanCount(), 1)
    assert.equal(deferred.maxConcurrent(), 1)

    deferred.resolveNext()
    await timers.advance(0)
    await timers.advance(0)
    await timers.advance(1_000)
    assert.equal(deferred.scanCount(), 2)
    assert.equal(deferred.maxConcurrent(), 1)
    controller.destroy()
})

test('rapid manual scans debounce to one shared native scan', async () => {
    const timers = new FixtureTimers()
    let scans = 0
    const controller = createDeviceController({
        service: {
            /** @returns {Promise<object>} Counts one real dispatch. */
            async scan() {
                scans += 1
                return { ok: true }
            }
        },
        manualDebounceMs: 250,
        timers
    })

    const first = controller.requestManualScan()
    await timers.advance(100)
    const second = controller.requestManualScan()
    await timers.advance(149)
    assert.equal(scans, 0)
    await timers.advance(101)

    assert.equal(scans, 1)
    assert.deepEqual(await first, { ok: true })
    assert.deepEqual(await second, { ok: true })
    controller.destroy()
})

test('operation preflight waits for the current scan and returns its refreshed snapshot boundary', async () => {
    const timers = new FixtureTimers()
    const deferred = createDeferredScanService()
    const controller = createDeviceController({ service: deferred.service, intervalMs: 1_000, timers })

    controller.startAutoScan()
    await timers.advance(1_000)
    const preflight = controller.refreshForOperation()

    assert.equal(deferred.scanCount(), 1)
    assert.equal(deferred.maxConcurrent(), 1)

    deferred.resolveNext()
    await timers.advance(0)

    assert.deepEqual(await preflight, { ok: true })
    assert.equal(deferred.scanCount(), 1)
    controller.destroy()
})

test('full scan snapshots preserve selection and invalidate stale authentication revisions', () => {
    const store = createStore(createRuntimeState())
    const first = noMediaDevice(1)
    store.dispatch({ type: 'service/ready', epoch: 1, listRevision: 0, mode: 'native', privileged: true, hardwareReady: true, hardwareVerified: false, platformCapability: { state: 'available' } })
    store.dispatch({ type: 'device/list-replaced', epoch: 1, listRevision: 1, devices: [first], diagnostics: { candidateCount: 2, acceptedCount: 1, rejections: [{ reason: 'candidate-validation-failed', count: 1 }] } })
    store.dispatch({ type: 'authentication/session-established', deviceId: first.id, deviceRevision: first.revision, sessionId: 'session:current' })

    assert.equal(store.getState().selectedDeviceId, first.id)
    assert.equal(store.getState().devices[0].mediaState, 'no-media')
    assert.deepEqual(store.getState().discovery.diagnostics, { candidateCount: 2, acceptedCount: 1, rejections: [{ reason: 'candidate-validation-failed', count: 1 }] })
    assert.equal(store.getState().authenticationSessions[first.id].sessionId, 'session:current')

    store.dispatch({ type: 'device/list-replaced', epoch: 1, listRevision: 2, devices: [noMediaDevice(2)], diagnostics: { candidateCount: 1, acceptedCount: 1, rejections: [] } })

    assert.equal(store.getState().selectedDeviceId, first.id)
    assert.equal(store.getState().authenticationSessions[first.id], undefined)
})

test('removing the selected device clears selection and its authentication session', () => {
    const store = createStore(createRuntimeState())
    const device = noMediaDevice(3)
    const remaining = { ...noMediaDevice(3), id: 'rdx:remaining-device', serial: '7820999744' }
    store.dispatch({ type: 'service/ready', epoch: 2, listRevision: 0, mode: 'native', privileged: true, hardwareReady: true, hardwareVerified: false, platformCapability: { state: 'available' } })
    store.dispatch({ type: 'device/list-replaced', epoch: 2, listRevision: 1, devices: [device, remaining] })
    store.dispatch({ type: 'authentication/session-established', deviceId: device.id, deviceRevision: device.revision, sessionId: 'session:removed' })
    store.dispatch({ type: 'device/removed', epoch: 2, listRevision: 2, deviceId: device.id, deviceRevision: device.revision })

    assert.equal(store.getState().selectedDeviceId, null)
    assert.deepEqual(store.getState().authenticationSessions, {})

    store.dispatch({ type: 'device/list-replaced', epoch: 2, listRevision: 3, devices: [remaining] })

    assert.equal(store.getState().selectedDeviceId, null)
})
