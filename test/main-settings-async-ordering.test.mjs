// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { runInNewContext } from 'node:vm'
import test from 'node:test'

import { AutoScanController } from '../src/main/tray-controller.mjs'

/** @param {object} dependencies - Main-owned settings and scanner test boundaries. @returns {Promise<Function>} Exact production update function without launching Electron. */
async function loadSettingsUpdate(dependencies) {
    // Windows checkouts may use CRLF; the extraction boundary below uses LF.
    const source = (await readFile(new URL('../src/main.mjs', import.meta.url), 'utf8')).replace(/\r\n/g, '\n')
    const start = source.indexOf('async function updateRendererSettings(request) {')
    assert.notEqual(start, -1)
    const end = source.indexOf('\n}\n', start)
    assert.notEqual(end, -1)
    return runInNewContext(`${source.slice(start, end + 2)}\nupdateRendererSettings`, dependencies)
}

test('overlapping Auto Scan disable and enable publish and complete in order while an admitted scan drains', async () => {
    const scan = Promise.withResolvers()
    const pollingStopped = Promise.withResolvers()
    const scanner = new AutoScanController({
        scan: () => scan.promise,
        timers: { setTimeout: () => Symbol('scan-timer'), clearTimeout() {} }
    })
    scanner.start()
    const inFlight = scanner.scanNow()
    let settings = { autoScan: true, eventLogging: true, language: 'en' }
    const published = []
    const completed = []
    const update = await loadSettingsUpdate({
        autoScanController: {
            start: scanner.start.bind(scanner),
            /** @returns {Promise<void>} Exposes the real scanner's synchronous stop admission separately from its pending scan drain. */
            stop() {
                const drained = scanner.stop()
                pollingStopped.resolve()
                return drained
            }
        },
        settingsService: {
            getDesktopState: () => ({ ...settings }),
            /** @param {object} request - Requested persisted values. @returns {Promise<object>} Detached saved settings response. */
            async update(request) {
                settings = { ...settings, ...request }
                return { ok: true, settings: { ...settings } }
            }
        },
        eventPublisher: { publishSettingsEvent: (value) => published.push(value.autoScan) },
        refreshTrayDevices: async () => {},
        serviceRuntime: null
    })

    /** @param {boolean} autoScan - Next setting. @returns {Promise<object>} Records public completion order. */
    async function setAutoScan(autoScan) {
        const result = await update({ autoScan })
        completed.push(result.settings.autoScan)
        return result
    }

    const disabled = setAutoScan(false)
    await pollingStopped.promise
    assert.equal(scanner.isRunning(), false)
    const enabled = setAutoScan(true)
    try {
        await enabled
        assert.equal(scanner.isRunning(), true)
        assert.deepEqual(published, [false, true])
        assert.deepEqual(completed, [false, true])
    } finally {
        scan.resolve({ ok: true })
        await Promise.all([disabled, enabled, inFlight])
        await scanner.stop()
    }
    assert.equal(settings.autoScan, true)
    assert.deepEqual(published, [false, true])
    assert.deepEqual(completed, [false, true])
})
