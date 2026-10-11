// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { AutoScanController, DesktopLifecycleController, TrayController } from '../src/main/tray-controller.mjs'
import { completeDeviceSnapshot } from './helpers/device-snapshot.mjs'

/** @param {{available?: boolean, id?: string, ready?: boolean}} [options={}] - Device state. @returns {object} Complete tray device. */
function trayDevice(options = {}) {
    return completeDeviceSnapshot({
        capabilities: { 'eject-safe': { state: options.available === false ? 'wrong-media-state' : 'available' } },
        drive: { connectionType: 'USB 3', firmwareRevision: '0283', operationMode: 'Removable Disk', powerSource: 'external', productType: 'USB 3 / SATA III' },
        id: options.id ?? 'rdx:tray-1',
        media: options.ready === false ? null : { capacityBytes: 1_000_000, encrypted: false, filesystem: 'exfat', id: `media:${options.id ?? 'tray-1'}`, serial: 'MEDIA-TRAY-01', status: 'ready', usedBytes: 1, writable: true },
        product: 'RDX QuikStor',
        revision: 4,
        serial: 'DOCK-TRAY-01',
        vendor: 'TANDBERG'
    })
}

/** @returns {{Menu: object, Tray: Function, instances: object[]}} Injectable Electron tray doubles. */
function createTrayDoubles() {
    const instances = []
    class FakeTray {
        /** @param {unknown} icon - Owned icon. */
        constructor(icon) {
            this.icon = icon
            this.menu = null
            this.tooltip = null
            instances.push(this)
        }

        /** @param {object} menu - Built menu. @returns {void} Stores the menu. */
        setContextMenu(menu) {
            this.menu = menu
        }

        /** @param {string} tooltip - Safe tooltip. @returns {void} Stores the tooltip. */
        setToolTip(tooltip) {
            this.tooltip = tooltip
        }

        /** @returns {void} Marks native resource disposal. */
        destroy() {
            this.destroyCount = (this.destroyCount ?? 0) + 1
        }
    }
    return { Menu: { buildFromTemplate: (template) => template }, Tray: FakeTray, instances }
}

/** @param {object[]} menu - Menu template. @param {string} id - Item ID. @returns {object} Matching menu item. */
function item(menu, id) {
    return menu.find((entry) => entry.id === id)
}

/** @returns {Promise<void>} Verifies tray safe eject is capability and identity gated. */
async function testTrayEjectGate() {
    const doubles = createTrayDoubles()
    const operations = []
    const controller = new TrayController({
        ...doubles,
        actions: {
            exit() {},
            open() {},
            scan: async () => ({ ok: true }),
            setLogging: async () => ({ ok: true }),
            startOperation: async (request) => {
                operations.push(request)
                return { ok: true }
            }
        },
        icon: {}
    })
    controller.update({ devices: [], loggingEnabled: true, selectedDeviceId: null, serviceStatus: 'ready' })
    assert.equal(item(doubles.instances[0].menu, 'safe-eject').enabled, false)

    const first = trayDevice()
    controller.update({ devices: [first, trayDevice({ id: 'rdx:tray-2' })], loggingEnabled: true, selectedDeviceId: null, serviceStatus: 'ready' })
    assert.equal(item(doubles.instances[0].menu, 'safe-eject').enabled, false)

    controller.update({ devices: [first, trayDevice({ id: 'rdx:tray-2' })], loggingEnabled: true, selectedDeviceId: first.id, serviceStatus: 'ready' })
    const eject = item(doubles.instances[0].menu, 'safe-eject')
    assert.equal(eject.enabled, true)
    await eject.click()
    assert.deepEqual(operations, [{ deviceId: first.id, deviceRevision: first.revision, kind: 'eject-safe' }])

    controller.update({ devices: [trayDevice({ ready: false })], loggingEnabled: true, selectedDeviceId: first.id, serviceStatus: 'ready' })
    assert.equal(item(doubles.instances[0].menu, 'safe-eject').enabled, false)
    controller.destroy()
    controller.destroy()
    assert.equal(doubles.instances[0].destroyCount, 1)
}

/** @returns {void} Verifies every tray label is selected through the active desktop translator. */
function testLocalizedTray() {
    const doubles = createTrayDoubles()
    const calls = []
    const controller = new TrayController({
        ...doubles,
        actions: { exit() {}, open() {}, scan() {}, setLogging() {}, startOperation() {} },
        icon: {},
        translate(key, params = {}) {
            calls.push({ key, params })
            return `translated:${key}:${params.count ?? ''}:${params.device ?? ''}:${params.status ?? ''}`
        }
    })
    controller.update({ devices: [trayDevice()], loggingEnabled: true, selectedDeviceId: 'rdx:tray-1', serviceStatus: 'ready' })
    const menu = doubles.instances[0].menu
    assert.match(item(menu, 'summary').label, /^translated:tray\.summary:/)
    assert.equal(item(menu, 'open').label, 'translated:tray.open:::')
    assert.equal(item(menu, 'scan').label, 'translated:tray.scan:::')
    assert.match(item(menu, 'safe-eject').label, /^translated:tray\.safeEject:/)
    assert.equal(item(menu, 'logging').label, 'translated:tray.logging:::')
    assert.equal(item(menu, 'exit').label, 'translated:tray.exit:::')
    assert.equal(
        calls.some(({ key }) => key === 'tray.summary'),
        true
    )
    controller.destroy()
}

/** @returns {Promise<void>} Verifies background and tray scans share one in-flight call. */
async function testNonOverlappingScan() {
    let complete
    let scans = 0
    const controller = new AutoScanController({
        intervalMs: 1_000,
        scan: async () => {
            scans += 1
            return new Promise((resolve) => {
                complete = resolve
            })
        }
    })
    assert.equal(controller.isRunning(), false)
    controller.start()
    assert.equal(controller.isRunning(), true)
    const first = controller.scanNow()
    const second = controller.scanNow()
    assert.equal(first, second)
    assert.equal(scans, 1)
    complete({ ok: true })
    assert.deepEqual(await first, { ok: true })
    controller.stop()
}

/** @returns {Promise<void>} Verifies suspend retains one scan until settlement before admitting fresh work. */
async function testSuspendInvalidatesInFlightScan() {
    const resolvers = []
    const published = []
    let scans = 0
    let active = 0
    let maxActive = 0
    const controller = new AutoScanController({
        afterScan: async (_result) => published.push(scans),
        scan: async () => {
            scans += 1
            active += 1
            maxActive = Math.max(maxActive, active)
            return new Promise((resolve) =>
                resolvers.push((result) => {
                    active -= 1
                    resolve(result)
                })
            )
        }
    })
    controller.start()
    const stale = controller.scanNow()
    const stopped = controller.stop()
    controller.start()
    assert.equal(controller.scanNow(), stale)
    assert.equal(scans, 1)
    assert.equal(maxActive, 1)
    resolvers[0]({ ok: true })
    assert.deepEqual(await stale, { ok: false, reason: 'scan-invalidated' })
    await stopped
    assert.deepEqual(published, [])
    const fresh = controller.scanNow()
    assert.equal(scans, 2)
    assert.equal(maxActive, 1)
    resolvers[1]({ ok: true })
    assert.deepEqual(await fresh, { ok: true })
    assert.deepEqual(published, [2])
    await controller.stop()
}

/** @returns {Promise<void>} Verifies suspend invalidation and resume refresh without eject. */
async function testSuspendResumeLifecycle() {
    const calls = []
    const scanner = {
        start() {
            calls.push('scan-start')
        },
        stop() {
            calls.push('scan-stop')
        }
    }
    const lifecycle = new DesktopLifecycleController({
        invalidateSessions() {
            calls.push('invalidate-sessions')
        },
        refresh: async () => calls.push('refresh'),
        scanner
    })
    await lifecycle.onSuspend()
    assert.deepEqual(calls, ['scan-stop', 'invalidate-sessions'])
    assert.doesNotMatch(calls.join(' '), /eject/i)
    await lifecycle.onResume()
    assert.deepEqual(calls, ['scan-stop', 'invalidate-sessions', 'scan-start', 'refresh'])
}

/** @returns {Promise<void>} Verifies resume preserves a disabled Auto Scan preference. */
async function testResumePreservesDisabledPolling() {
    const calls = []
    const lifecycle = new DesktopLifecycleController({
        invalidateSessions() {},
        refresh: async () => calls.push('refresh'),
        scanner: {
            isRunning: () => false,
            start: () => calls.push('scan-start'),
            stop: () => calls.push('scan-stop')
        }
    })
    await lifecycle.onSuspend()
    await lifecycle.onResume()
    assert.deepEqual(calls, ['scan-stop', 'refresh'])
}

/** @returns {Promise<void>} Verifies lifecycle resume forces a new scan after the suspended epoch. */
async function testResumeStartsFreshScan() {
    let scans = 0
    const scanner = new AutoScanController({
        scan: async () => {
            scans += 1
            return { ok: true }
        }
    })
    scanner.start()
    await scanner.scanNow()
    const scansBeforeSuspend = scans
    const lifecycle = new DesktopLifecycleController({
        invalidateSessions() {},
        refresh: () => scanner.scanNow(),
        scanner
    })
    await lifecycle.onSuspend()
    await lifecycle.onResume()
    assert.equal(scans, scansBeforeSuspend + 1)
    scanner.stop()
}

/** @returns {Promise<void>} Verifies suspend is the final publication and resume waits for full invalidation. */
async function testSuspendTransitionBarrier() {
    const calls = []
    let releaseAfterScan
    let releaseInvalidation
    let afterScanStarted
    let invalidationStarted
    const afterScanGate = new Promise((resolve) => {
        releaseAfterScan = resolve
    })
    const invalidationGate = new Promise((resolve) => {
        releaseInvalidation = resolve
    })
    const afterScanAdmission = new Promise((resolve) => {
        afterScanStarted = resolve
    })
    const invalidationAdmission = new Promise((resolve) => {
        invalidationStarted = resolve
    })
    const scanner = new AutoScanController({
        afterScan: async () => {
            calls.push('after-scan-start')
            afterScanStarted()
            await afterScanGate
            calls.push('stale-ready')
        },
        scan: async () => ({ ok: true })
    })
    scanner.start()
    const scan = scanner.scanNow()
    await afterScanAdmission
    const lifecycle = new DesktopLifecycleController({
        async invalidateSessions() {
            calls.push('invalidate-start')
            invalidationStarted()
            await invalidationGate
            calls.push('suspended')
        },
        refresh: async () => calls.push('refresh'),
        scanner: {
            isRunning: () => scanner.isRunning(),
            start: () => {
                calls.push('start')
                scanner.start()
            },
            stop: () => scanner.stop()
        }
    })

    const suspended = lifecycle.onSuspend()
    const resumed = lifecycle.onResume()
    assert.deepEqual(calls, ['after-scan-start'])
    releaseAfterScan()
    await invalidationAdmission
    assert.deepEqual(calls, ['after-scan-start', 'stale-ready', 'invalidate-start'])
    releaseInvalidation()
    await Promise.all([scan, suspended, resumed])
    assert.deepEqual(calls, ['after-scan-start', 'stale-ready', 'invalidate-start', 'suspended', 'start', 'refresh'])
    await scanner.stop()
}

/** @returns {Promise<void>} Verifies unsafe close warns and remains prevented. */
async function testUnsafeCloseWarning() {
    let warned = 0
    let quits = 0
    const lifecycle = new DesktopLifecycleController({
        getShutdownPolicy: () => ({ allowed: false, reason: 'operation-in-progress' }),
        invalidateSessions() {},
        refresh: async () => {},
        requestQuit() {
            quits += 1
        },
        scanner: { start() {}, stop() {} },
        warnUnsafeClose: async () => {
            warned += 1
        }
    })
    const event = {
        prevented: false,
        preventDefault() {
            this.prevented = true
        }
    }
    assert.equal(lifecycle.handleWindowClose(event), false)
    await lifecycle.waitForWarning()
    assert.equal(event.prevented, true)
    assert.equal(warned, 1)
    assert.equal(lifecycle.requestExit(), false)
    await lifecycle.waitForWarning()
    assert.equal(quits, 0)
}

test('tray enables safe eject only for one selected ready capable device', testTrayEjectGate)
test('tray labels use the active desktop translator', testLocalizedTray)
test('tray and automatic scans never overlap', testNonOverlappingScan)
test('suspend retains an in-flight scan before admitting a fresh resume scan', testSuspendInvalidatesInFlightScan)
test('sleep stops polling, invalidates sessions, refreshes on wake, and never ejects', testSuspendResumeLifecycle)
test('resume preserves a disabled automatic scan preference', testResumePreservesDisabledPolling)
test('resume forces a fresh scan after the suspended scan epoch', testResumeStartsFreshScan)
test('suspend finishes stale publication and invalidation before resume', testSuspendTransitionBarrier)
test('unsafe close warns instead of exiting', testUnsafeCloseWarning)

test('unsafe close shares one warning and releases ownership after either dialog failure mode', async () => {
    for (const asynchronous of [false, true]) {
        let warned = 0
        const dialog = Promise.withResolvers()
        const lifecycle = new DesktopLifecycleController({
            getShutdownPolicy: () => ({ allowed: false }),
            invalidateSessions() {},
            refresh: async () => {},
            scanner: { start() {}, stop() {} },
            /** @returns {Promise<void>} Models a failing native warning API. @throws {Error} For synchronous failure coverage. */
            warnUnsafeClose() {
                warned++
                if (asynchronous) return dialog.promise
                throw new Error('controlled warning failure')
            }
        })
        let prevented = 0
        const event = { preventDefault: () => prevented++ }
        assert.equal(lifecycle.handleWindowClose(event), false)
        assert.equal(lifecycle.requestExit(), false)
        const completed = lifecycle.waitForWarning()
        await Promise.resolve()
        assert.equal(warned, 1)
        if (asynchronous) dialog.reject(new Error('controlled async warning failure'))
        await completed
        assert.equal(prevented, 1)

        assert.equal(lifecycle.requestExit(), false)
        await lifecycle.waitForWarning()
        assert.equal(warned, 2)
    }
})

test('native tray handlers contain synchronous and asynchronous action failures', async () => {
    for (const asynchronous of [false, true]) {
        const doubles = createTrayDoubles()
        /** @returns {Promise<never>} Models a failing main-owned menu action. @throws {Error} For synchronous failure coverage. */
        function fail() {
            if (asynchronous) return Promise.reject(new Error('controlled async tray failure'))
            throw new Error('controlled tray failure')
        }
        const controller = new TrayController({ ...doubles, icon: {}, actions: { exit: fail, open: fail, scan: fail, setLogging: fail, startOperation: fail } })
        const device = trayDevice()
        controller.update({ devices: [device], selectedDeviceId: device.id, serviceStatus: 'ready', loggingEnabled: true })
        for (const id of ['open', 'scan', 'safe-eject', 'logging', 'exit']) {
            assert.deepEqual(await item(doubles.instances[0].menu, id).click(), { ok: false, reason: 'service-failure' })
        }
        controller.destroy()
    }
})
