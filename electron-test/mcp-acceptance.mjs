// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { app, BrowserWindow, clipboard } from 'electron/main'
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client'
import { installPrivateClipboardFixture } from './mcp-clipboard-fixture.mjs'
import { resizeAcceptanceWindow } from './acceptance-window-size.mjs'

const root = fileURLToPath(new URL('..', import.meta.url))
const output = join(root, 'test-results', 'mcp')
let userData
let previousClipboard = ''
const privateClipboard = process.argv.includes('--mcp-acceptance-private-clipboard')
const restoreClipboard = privateClipboard ? installPrivateClipboardFixture(clipboard) : null
const failures = []
let client
let window
const deadline = setTimeout(() => {
    console.error('MCP Electron acceptance timed out')
    app.exit(1)
}, 45_000)

// This harness imports the real main entry point. Only its application root
// and preferences are isolated; the actual runtime, preload and renderer run.
app.getAppPath = () => root
app.on('web-contents-created', (_event, contents) => {
    contents.on('console-message', (_event, level, message) => {
        if (level >= 3) failures.push(message)
    })
    contents.on('render-process-gone', (_event, details) => failures.push(details.reason))
    contents.on('preload-error', (_event, _path, error) => failures.push(error.message))
})

/** @param {Function} predicate - Bounded readiness observation. @param {string} label - Failure context. @returns {Promise<*>} First truthy result, without assuming a fixed renderer delay. */
async function until(predicate, label) {
    for (let attempt = 0; attempt < 600; attempt++) {
        const value = await predicate()
        if (value) return value
        await delay(50)
    }
    throw new Error(`Readiness failed: ${label}`)
}

/** @returns {Promise<number>} Currently unused loopback port for the isolated UI enablement test. */
async function unusedPort() {
    const listener = createServer()
    const listening = once(listener, 'listening')
    listener.listen(0, '127.0.0.1')
    try {
        await listening
        return listener.address().port
    } finally {
        if (listener.listening) await promisify(listener.close).call(listener)
    }
}

/** @param {string} source - Test-owned renderer expression. @returns {Promise<*>} Result through Electron's actual renderer engine. */
async function evaluate(source) {
    return window.webContents.executeJavaScript(source, true)
}

/** @param {number} width - Window width. @param {number} height - Window height. @returns {Promise<void>} Captures the painted real MCP dialog after verifying it fits. */
async function capture(width, height) {
    await resizeAcceptanceWindow(window, width, height)
    assert.equal(await evaluate(`(() => { const dialog = document.querySelector('[data-mcp-settings]'); const r = dialog.getBoundingClientRect(); return dialog.open && r.left >= 0 && r.top >= 0 && r.right <= innerWidth && r.bottom <= innerHeight && dialog.scrollWidth <= dialog.clientWidth })()`), true)
    await writeFile(join(output, `settings-${width}x${height}.png`), (await window.webContents.capturePage()).toPNG())
}

/** @returns {Promise<void>} Runs the production app without blocking Electron's initial module evaluation and ready event. */
async function verify() {
    userData = await mkdtemp(join(tmpdir(), 'openrdx-mcp-electron-'))
    app.setPath('userData', userData)
    await writeFile(join(userData, 'settings.json'), JSON.stringify({ autoScan: false, eventLogging: true, language: 'en', lastSafeView: 'status', updateChecks: false, windowBounds: null }))
    try {
        await app.whenReady()
        previousClipboard = await clipboard.readText()
        await import('../src/main.mjs')
        window = await until(() => BrowserWindow.getAllWindows()[0], 'main window')
        await until(async () => !window.webContents.isLoading() && (await evaluate('Boolean(window.openRdx?.mcp && document.querySelector("[data-action=open-mcp]"))')), 'preload and MCP button')
        const preferences = window.webContents.getLastWebPreferences()
        assert.equal(preferences.contextIsolation, true)
        assert.equal(preferences.sandbox, true)
        assert.equal(preferences.nodeIntegration, false)
        assert.equal((await evaluate('openRdx.mcp.getStatus()')).status, 'disabled')
        await evaluate('document.querySelector("[data-action=open-mcp]").click()')
        await until(() => evaluate('document.querySelector("[data-mcp-settings]")?.open && !document.querySelector("[data-mcp-action=apply]").disabled'), 'settings dialog')
        const port = await unusedPort()
        await evaluate(`(() => { const enabled = document.querySelector('#mcp-enabled'); enabled.checked = true; enabled.dispatchEvent(new Event('change', {bubbles:true})); const port = document.querySelector('#mcp-port'); port.value = '${port}'; port.dispatchEvent(new Event('input', {bubbles:true})); document.querySelector('[data-mcp-action=apply]').click() })()`)
        const status = await until(async () => {
            const value = await evaluate('openRdx.mcp.getStatus()')
            return value.status === 'listening' && value
        }, 'listening endpoint')
        await until(() => evaluate('!document.querySelector("[data-mcp-action=copy]").disabled'), 'copy configuration')
        await evaluate('document.querySelector("[data-mcp-action=copy]").click()')
        const configuration = await until(async () => {
            try {
                return JSON.parse(await clipboard.readText()).mcpServers.OpenRDXManager
            } catch {
                return null
            }
        }, 'copied agent configuration')
        assert.equal(configuration.env.OPENRDX_MCP_URL, status.endpoint)
        const token = (await readFile(configuration.env.OPENRDX_MCP_TOKEN_FILE, 'utf8')).trim()
        assert.equal((await clipboard.readText()).includes(token), false)
        assert.equal(await evaluate(`document.body.textContent.includes(${JSON.stringify(token)})`), false)
        client = new Client({ name: 'real-electron-acceptance', version: '1' }, { versionNegotiation: { mode: 'auto' } })
        await client.connect(new StreamableHTTPClientTransport(new URL(status.endpoint), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }))
        const tools = await client.listTools()
        assert.ok(tools.tools.some((tool) => tool.name === 'rdx_format'))
        const info = (await client.callTool({ name: 'rdx_app_info', arguments: {} })).structuredContent
        assert.equal(info.ok, true)
        const inventory = (await client.callTool({ name: 'rdx_devices_list', arguments: {} })).structuredContent
        assert.equal(typeof inventory.ok, 'boolean')
        const readiness = (await client.callTool({ name: 'rdx_service_status', arguments: {} })).structuredContent
        assert.equal(readiness.ok, true)
        const capability = JSON.parse((await client.readResource({ uri: 'openrdx://capabilities' })).contents[0].text)
        assert.equal(capability.operations.length, 20)
        const settings = (await client.callTool({ name: 'rdx_settings_get', arguments: {} })).structuredContent
        assert.equal(settings.settings.autoScan, false)
        assert.equal((await client.callTool({ name: 'rdx_settings_update', arguments: { autoScan: false } })).structuredContent.ok, true)
        await mkdir(output, { recursive: true })
        await capture(1024, 768)
        await capture(1440, 900)
        await client.close()
        client = null
        await evaluate('(() => { const enabled = document.querySelector("#mcp-enabled"); enabled.checked = false; enabled.dispatchEvent(new Event("change", {bubbles:true})); document.querySelector("[data-mcp-action=apply]").click() })()')
        await until(async () => (await evaluate('openRdx.mcp.getStatus()')).status === 'disabled', 'disabled endpoint')
        await assert.rejects(fetch(status.endpoint))
        await evaluate('document.querySelector("[data-mcp-action=close]").click()')
        assert.equal(await evaluate('document.querySelector("[data-mcp-settings]").open'), false)
        assert.deepEqual(failures, [])
        const evidence = { tools: tools.tools.length, operations: capability.operations.length, resources: 10, renderer: 'real Electron with production preload/main', enabledViaUI: true, disabledViaUI: true, readOnlyMcpCalls: true, preferenceRoundTrip: true, privateClipboard, hostClipboardTested: !privateClipboard, contextIsolation: true, sandbox: true, nodeIntegration: false, service: { status: readiness.status, hardwareReady: readiness.hardwareReady }, deviceCount: inventory.devices?.length ?? null, deviceMutationTested: false, rendererErrors: failures }
        await writeFile(join(output, 'acceptance.json'), `${JSON.stringify(evidence, null, 2)}\n`)
        console.log(`MCP Electron acceptance passed: tools=${tools.tools.length} operations=${capability.operations.length} service=${readiness.status} devices=${inventory.devices?.length ?? 'unavailable'}`)
        process.exitCode = 0
    } catch (error) {
        console.error(`MCP Electron acceptance failed: ${error.message}`)
        process.exitCode = 1
    } finally {
        clearTimeout(deadline)
        try {
            await client?.close()
        } catch {
            // Keep the original acceptance failure while completing app cleanup.
        }
        await clipboard.writeText(previousClipboard)
        restoreClipboard?.()
        // The production before-quit path closes MCP and the native runtime.
        app.once('will-quit', () => {
            void rm(userData, { recursive: true, force: true })
        })
        app.quit()
    }
}

void verify()
