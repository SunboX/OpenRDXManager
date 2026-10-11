// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { app, BrowserWindow, ipcMain } from 'electron'
import { isTrustedApplicationSender, registerIpcHandlers } from '../src/main/ipc-controller.mjs'
import { windowOptions } from '../src/window-options.mjs'
import { normalizeConsoleMessage, VisualErrorTracker } from './visual-error-tracker.mjs'
import { captureValidatedVisualImage, loadWithPageErrorCapture } from './visual-runtime-capture.mjs'
import { resizeAcceptanceWindow } from './acceptance-window-size.mjs'
import { decodeVisualRasterAnchorCrops } from './visual-raster.mjs'
import { assertVisualRasterAnchorCrops } from './visual-qa-contract.mjs'

const indexPath = fileURLToPath(new URL('../src/index.html', import.meta.url))
const indexUrl = pathToFileURL(indexPath).href
const fixtureUrl = new URL('./manufacturing-fixture.mjs', import.meta.url).href
const evidenceDirectory = process.env.OPENRDX_MANUFACTURING_EVIDENCE_DIRECTORY ?? '/tmp/openrdx-manufacturing-visual'
const trustedWebContents = new Set()
const calls = []
const record = Object.freeze({ backupId: 'record-abcdef-1', deviceId: 'rdx:7810544062', serial: '7810544062', createdAt: 1789128000000, state: 'valid' })
let backups = [record, { ...record, backupId: 'record-abc-3', createdAt: record.createdAt - 60000, serial: null, state: 'erased' }]

/** @returns {object} Synthetic public saved metadata; this script has no native-device service. */
function inventory() {
    return { ok: true, backupSupported: true, restoreSupported: true, backups, page: 0, hasMore: false }
}

const settings = { autoScan: false, eventLogging: false, language: 'en', lastSafeView: 'utilities', updateChecks: false }
const services = {
    settings: {
        /** @returns {Promise<object>} Non-persistent fixture preferences. */
        async get() {
            return { ok: true, settings }
        }
    },
    devices: {
        /** @returns {Promise<object>} Makes the ordinary initial renderer truthfully unavailable before the synthetic fixture mounts. */
        async list() {
            return { ok: false, reason: 'hardware-unavailable' }
        }
    },
    manufacturing: {
        /** @returns {Promise<object>} Records the desktop folder intent without opening external windows during fixture capture. */
        async openFolder() {
            calls.push({ method: 'openFolder', request: {} })
            return { ok: true }
        },
        /** @param {object} request - Production-schema-validated metadata query. @returns {Promise<object>} Synthetic inventory without hardware I/O. */
        async list(request) {
            calls.push({ method: 'list', request })
            return inventory()
        },
        /** @param {object} request - Production-schema-validated target. @returns {Promise<object>} Synthetic verified-backup response. */
        async backup(request) {
            calls.push({ method: 'backup', request })
            backups = [{ ...record, backupId: 'record-abcdef-2', createdAt: record.createdAt + 60000 }, ...backups]
            return inventory()
        },
        /** @param {object} request - Production-schema-validated target and confirmation. @returns {Promise<object>} Synthetic verified restore; no native transport is created. */
        async restore(request) {
            calls.push({ method: 'restore', request })
            return inventory()
        }
    },
    /** @param {object} event - Electron request event. @returns {boolean} Restricts IPC to the owned local main frame. */
    isTrustedSender(event) {
        return isTrustedApplicationSender({ event, rendererUrl: indexUrl, trustedWebContents })
    },
    /** @returns {object[]} Application-owned visual targets. */
    getTrustedWebContents() {
        return [...trustedWebContents]
    }
}

/** @param {Electron.BrowserWindow} window - Protected fixture window. @param {string} method - Exact exported test operation. @param {string|undefined} argument - Optional controlled screenshot region. @returns {Promise<unknown>} Runs the bounded renderer test helper. */
async function invokeFixture(window, method, argument) {
    try {
        return await window.webContents.executeJavaScript(`(async () => { const fixture = await import(${JSON.stringify(fixtureUrl)}); return fixture[${JSON.stringify(method)}](${argument === undefined ? '' : JSON.stringify(argument)}); })()`)
    } catch (error) {
        throw new Error(`Manufacturing fixture ${method} failed: ${error.message}`, { cause: error })
    }
}

/** @returns {Promise<void>} Verifies real Electron rendering and preload/main actions against synthetic service data, writing screenshots outside the repository. */
async function run() {
    await app.whenReady()
    await mkdir(evidenceDirectory, { recursive: true })
    const ipc = registerIpcHandlers({ ipcMain, services })
    const window = new BrowserWindow({ ...windowOptions, show: true })
    const errors = new VisualErrorTracker()
    const captures = []
    trustedWebContents.add(window.webContents)
    /** @param {object} details - Electron's console event. @returns {void} Records every relevant console error. */
    function onConsole(details) {
        const normalized = normalizeConsoleMessage(details, arguments)
        if (normalized !== null) errors.record('consoleErrors', normalized.message)
    }
    /** @param {object} _event - Debugger event. @param {string} method - Protocol method. @param {object} params - Exception details. @returns {void} Records uncaught renderer errors. */
    function onDebug(_event, method, params) {
        if (method === 'Runtime.exceptionThrown') errors.record('pageErrors', params.exceptionDetails?.text ?? 'renderer exception')
    }
    /** @param {object} _event - Electron event. @param {number} code - Error code. @param {string} description - Failure description. @returns {void} Records navigation failures. */
    function onLoadFailure(_event, code, description) {
        errors.record('loadFailures', `${code}:${description}`)
    }
    /** @param {object} _event - Electron event. @param {object} details - Process termination facts. @returns {void} Records unexpected renderer exits. */
    function onGone(_event, details) {
        errors.record('rendererCrashes', details.reason)
    }
    window.webContents.on('console-message', onConsole)
    window.webContents.on('did-fail-load', onLoadFailure)
    window.webContents.on('render-process-gone', onGone)
    /** @param {string} name - Evidence basename. @param {'top'|'bottom'} region - Actual card scroll target. @returns {Promise<void>} Requires live control bounds and matching target pixels before saving evidence. */
    async function capture(name, region) {
        const state = await invokeFixture(window, 'inspectManufacturing', region)
        assert.equal(state.title, 'OpenRDXManager')
        assert.equal(state.url, indexUrl)
        assert.ok(state.bodyTextLength > 500)
        assert.equal(state.fixtureOnly, true)
        assert.equal(state.horizontalOverflow, false)
        assert.deepEqual(state.controlsOverflow, [])
        assert.match(state.panelText, /Every firmware update saves a verified private backup first/)
        const capture = await captureValidatedVisualImage({
            /** @returns {Promise<void>} Invalidates the compositor and waits for local fixture paint. */
            async prepare() {
                window.webContents.invalidate()
                await invokeFixture(window, 'settlePaint')
            },
            /** @returns {Promise<Electron.NativeImage>} Candidate compositor frame. */
            async capture() {
                return window.webContents.capturePage()
            },
            /** @param {Electron.NativeImage} image - Candidate frame. @returns {object} Verified brand and manufacturing heading/confirmation pixels. */
            validate(image) {
                return assertVisualRasterAnchorCrops(decodeVisualRasterAnchorCrops(image, state.rasterAnchors, { width: state.width, height: state.height }))
            }
        })
        const screenshot = join(evidenceDirectory, `${name}.png`)
        await writeFile(screenshot, capture.image.toPNG())
        captures.push({ ...state, screenshot, rasterEvidence: capture.evidence, captureAttempts: capture.attempts })
    }
    try {
        await loadWithPageErrorCapture(window.webContents.debugger, onDebug, () => window.loadFile(indexPath))
        await invokeFixture(window, 'mountManufacturingFixture')
        for (const [width, height] of [
            [1024, 768],
            [1280, 900]
        ]) {
            await resizeAcceptanceWindow(window, width, height)
            await invokeFixture(window, 'settlePaint')
            await capture(`manufacturing-${width}-top`, 'top')
            await capture(`manufacturing-${width}-bottom`, 'bottom')
        }
        const backupRefresh = await invokeFixture(window, 'exerciseBackupRefresh')
        assert.deepEqual(backupRefresh, { cycles: 3, focused: true, enabled: true, selectorMutations: 0 })
        await invokeFixture(window, 'exerciseOpenFolder')
        assert.deepEqual(
            calls.filter((call) => call.method === 'openFolder'),
            [{ method: 'openFolder', request: {} }]
        )
        await invokeFixture(window, 'exerciseBackup')
        await invokeFixture(window, 'prepareRestore')
        await capture('manufacturing-confirmed-restore', 'bottom')
        await invokeFixture(window, 'exerciseRestore')
        await capture('manufacturing-verified-restore', 'bottom')
        await invokeFixture(window, 'prepareIdentityRecovery')
        await capture('manufacturing-confirmed-identity-recovery', 'bottom')
        await invokeFixture(window, 'exerciseRestore')
        assert.deepEqual(
            calls.filter((call) => call.method === 'backup'),
            [{ method: 'backup', request: { deviceId: record.deviceId, deviceRevision: 4 } }]
        )
        assert.deepEqual(
            calls.filter((call) => call.method === 'restore'),
            [
                { method: 'restore', request: { deviceId: record.deviceId, deviceRevision: 4, backupId: record.backupId, confirmationSerial: record.serial, acknowledged: true } },
                { method: 'restore', request: { deviceId: 'rdx:0123456789', deviceRevision: 5, backupId: record.backupId, confirmationSerial: record.serial, acknowledged: true, allowIdentityChange: true } }
            ]
        )
        errors.assertGloballyEmpty()
        await writeFile(join(evidenceDirectory, 'manifest.json'), `${JSON.stringify({ fixtureOnly: true, nativeTransportCreated: false, security: { contextIsolation: true, sandbox: true, nodeIntegration: false }, backupRefresh, calls, captures }, null, 2)}\n`)
        console.log(`Manufacturing Electron acceptance passed: ${evidenceDirectory}`)
    } finally {
        trustedWebContents.delete(window.webContents)
        window.destroy()
        ipc.dispose()
    }
}

/** @returns {Promise<void>} Starts without blocking Electron's ESM readiness event. */
async function runEntrypoint() {
    try {
        await run()
        app.exit(0)
    } catch (error) {
        console.error(error)
        app.exit(1)
    }
}

void runEntrypoint()
