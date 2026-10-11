// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const mainUrl = new URL('../src/main.mjs', import.meta.url)

/**
 * Verifies startup populates the native inventory once before the first window,
 * independently of the persisted periodic Auto Scan preference.
 * @returns {Promise<void>} Resolves after the startup ordering is proven.
 */
async function testPerformsInitialDiscoveryBeforeWindow() {
    const main = await readFile(mainUrl, 'utf8')
    const startupStart = main.indexOf('const serviceReadiness = await serviceRuntime.start()')
    const startupEnd = main.indexOf('function handleSuspend()', startupStart)
    const startup = main.slice(startupStart, startupEnd)
    const initialScan = startup.indexOf('await autoScanController.scanNow()')
    const createWindow = startup.indexOf('await createWindow()')
    const periodicPreference = startup.indexOf('if (settingsService.getDesktopState().autoScan) autoScanController.start()')

    assert.notEqual(startupStart, -1)
    assert.notEqual(startupEnd, -1)
    assert.notEqual(initialScan, -1)
    assert.notEqual(createWindow, -1)
    assert.notEqual(periodicPreference, -1)
    assert.ok(initialScan < createWindow)
    assert.ok(createWindow < periodicPreference)
}

test('performs initial discovery before the first window even when periodic Auto Scan is disabled', testPerformsInitialDiscoveryBeforeWindow)

test('wires service retry to the existing runtime and refreshes discovery without registration', async () => {
    const main = await readFile(mainUrl, 'utf8')

    assert.match(main, /async function retryHardwareService\(\)/u)
    assert.match(main, /const readiness = await serviceRuntime\.start\(\)/u)
    assert.match(main, /await autoScanController\.scanNow\(\)/u)
    assert.match(main, /retry: retryHardwareService/u)
})
