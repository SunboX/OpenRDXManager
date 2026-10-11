// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { applicationMetadata } from '../src/main/application-metadata.mjs'

import { mkdir, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { app, BrowserWindow, ipcMain } from 'electron'
import { registerIpcHandlers, isTrustedApplicationSender } from '../src/main/ipc-controller.mjs'
import { visualWindowOptions } from './visual-window-options.mjs'
import { WindowMenuChannel } from '../src/shared/window-menu.mjs'
import { initializeIsolatedElectronProfile } from './isolated-profile.mjs'

const profile = initializeIsolatedElectronProfile(app)
/** @returns {void} Keeps the isolated app alive until capture cleanup reports its exit status. */
function keepAlive() {}
app.on('window-all-closed', keepAlive)
app.commandLine.appendSwitch('hide-scrollbars')
app.commandLine.appendSwitch('force-prefers-reduced-motion')
const project = fileURLToPath(new URL('..', import.meta.url))
const indexUrl = new URL('../src/index.html', import.meta.url)
const fixtureUrl = new URL('./documentation-fixture.mjs', import.meta.url).href
const output = join(project, 'docs/assets/screenshots')
const trustedWebContents = new Set()
const settings = { autoScan: false, eventLogging: false, language: 'en', updateChecks: false }
const captures = [
    ['status', 'status', null],
    ['encryption', 'encryption', null],
    ['credentials', 'encryption', '.security-section--wide h3'],
    ['credential-actions', 'encryption', '[data-action="change-credential"]'],
    ['automatic-access', 'encryption', '[data-automatic-write-access]'],
    ['protection-reset', 'encryption', '[data-action="reset-protection"]'],
    ['diagnostics', 'tests', null],
    ['write-read-test', 'tests', '[data-test-kind="write-read-test"] h3'],
    ['firmware-update', 'utilities', '[data-feature="firmware"] h3'],
    ['eject', 'utilities', '[data-feature="eject"] h3'],
    ['sata-mode', 'utilities', '[data-feature="sata-mode"] h3'],
    ['volume-label', 'utilities', '[data-feature="volume-label"] h3'],
    ['format', 'destructive-preflight', '[data-format-confirmation]'],
    ['drive-letter', 'windows-utilities', '[data-feature="drive-letter"] h3'],
    ['manufacturing-backup', 'manufacturing', '[data-manufacturing-panel] h3'],
    ['manufacturing-restore', 'manufacturing', '[data-manufacturing-action="restore"]'],
    ['migration-recovery', 'recovery', '[data-recovery-panel] h2'],
    ['firmware-progress', 'critical-active', '[data-feature="firmware"] h3'],
    ['activity-log', 'activity', null],
    ['help', 'help', null],
    ['compatibility', 'compatibility', null],
    ['support', 'support', null],
    ['languages', 'language-de', null],
    ['ai-agent-access', 'status', '[data-mcp-settings] h1'],
    ['discovery', 'no-device', null]
]

/** @returns {Promise<object>} Keeps initial service access and every mutation unavailable. */
async function unavailable() {
    return { ok: false, reason: 'hardware-unavailable' }
}

const services = {
    app: {
        /** @returns {Promise<object>} Reads package-owned metadata without hardware access. */
        async getInfo() {
            return { ok: true, app: { ...applicationMetadata, platform: process.platform } }
        }
    },
    settings: {
        /** @returns {Promise<object>} Reads non-persistent documentation preferences. */
        async get() {
            return { ok: true, settings }
        }
    },
    devices: { list: unavailable, scan: unavailable },
    mcp: { getStatus: mcpStatus },
    /** @param {object} event - Local Electron sender. @returns {boolean} Accepts only the owned local application main frame. */
    isTrustedSender(event) {
        return isTrustedApplicationSender({ event, rendererUrl: indexUrl.href, trustedWebContents })
    },
    /** @returns {object[]} Owned documentation renderer targets. */
    getTrustedWebContents() {
        return [...trustedWebContents]
    }
}

/** @returns {Promise<object>} Returns public disabled MCP preferences without credentials or opening a listener. */
async function mcpStatus() {
    return { ok: true, enabled: false, port: 48170, status: 'disabled', endpoint: null }
}

/**
 * Invokes a bounded documentation helper inside the real protected renderer.
 * @param {Electron.BrowserWindow} window - Owned screenshot window.
 * @param {string} method - Fixture export name.
 * @param {string|null} argument - Controlled scene identifier or feature selector.
 * @returns {Promise<unknown>} Fixture result.
 */
async function invoke(window, method, argument) {
    return window.webContents.executeJavaScript(`(async () => { const fixture = await import(${JSON.stringify(fixtureUrl)}); return fixture[${JSON.stringify(method)}](${JSON.stringify(argument)}); })()`)
}

/** @returns {Promise<void>} Captures documentation previews using fixture data and the real application modules, without native hardware access. */
async function run() {
    await app.whenReady()
    await mkdir(output, { recursive: true })
    const ipc = registerIpcHandlers({ ipcMain, services })
    /** @returns {object[]} macOS has no application-owned menu strip. */
    function listMenus() {
        return []
    }
    ipcMain.handle(WindowMenuChannel.list, listMenus)
    const window = new BrowserWindow({ ...visualWindowOptions, width: 1440, height: 1000 })
    trustedWebContents.add(window.webContents)
    const manifest = []
    try {
        await window.loadFile(fileURLToPath(indexUrl))
        for (const [name, scene, anchor] of captures) {
            await invoke(window, 'mountDocumentationFixture', scene)
            await invoke(window, 'prepareDocumentationForm', name)
            if (name === 'ai-agent-access') await window.webContents.executeJavaScript('document.querySelector("[data-action=open-mcp]").click()')
            const geometry = await invoke(window, 'prepareDocumentationCapture', anchor)
            window.webContents.invalidate()
            await invoke(window, 'settleDocumentationPaint', null)
            if (name === 'help') {
                const about = await window.webContents.executeJavaScript('document.querySelector(".about-card")?.textContent')
                if (!about?.includes(applicationMetadata.version)) throw new Error('Missing application version in Help/About screenshot')
            }
            const image = await window.webContents.capturePage()
            if (image.isEmpty()) throw new Error(`Empty screenshot: ${name}`)
            const png = image.resize({ width: 1440, quality: 'best' }).toPNG()
            await writeFile(join(output, `${name}.png`), png)
            manifest.push({ name, scene, anchor, viewport: geometry.viewport, fixture: true, bytes: png.length })
            console.log(`Captured ${name}`)
            if (name === 'ai-agent-access') await window.webContents.executeJavaScript('document.querySelector("[data-mcp-settings]").close()')
        }
        await writeFile(join(output, 'manifest.json'), `${JSON.stringify({ applicationVersion: applicationMetadata.version, captureDate: new Date().toISOString().slice(0, 10), data: 'Demonstration fixtures, not connected hardware', captures: manifest }, null, 2)}\n`)
    } catch (error) {
        console.error('Documentation capture failed:', error)
        throw error
    } finally {
        window.destroy()
        ipc.dispose()
        ipcMain.removeHandler(WindowMenuChannel.list)
        await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 })
    }
}

/** @returns {Promise<void>} Reports capture failures and exits the isolated Electron process. */
async function finish() {
    try {
        await run()
        app.exit(0)
    } catch (error) {
        console.error(error)
        app.exit(1)
    }
}

void finish()
