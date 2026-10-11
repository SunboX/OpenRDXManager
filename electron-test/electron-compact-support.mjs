// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'

import { app, BrowserWindow, ipcMain } from 'electron'

import { isTrustedApplicationSender, registerIpcHandlers } from '../src/main/ipc-controller.mjs'
import { windowOptions } from '../src/window-options.mjs'
import { resizeAcceptanceWindow } from './acceptance-window-size.mjs'

const indexPath = fileURLToPath(new URL('../src/index.html', import.meta.url))
const indexUrl = pathToFileURL(indexPath).href
const fixtureUrl = new URL('./compact-support-fixture.mjs', import.meta.url).href
// Match the visual matrix's deterministic Windows test scale without changing
// the production window's DPI or minimum-size policy.
if (process.platform === 'win32') app.commandLine.appendSwitch('force-device-scale-factor', '2')
const trustedWebContents = new Set()
const services = {
    devices: {
        /**
         * Supplies a truthful ready no-device result to the default renderer mount.
         * @returns {Promise<object>} Strict empty device-list response.
         */
        async list() {
            return { ok: true, devices: [] }
        }
    },
    /**
     * Returns only compact-test renderer targets owned by this process.
     * @returns {object[]} Current trusted web-contents targets.
     */
    getTrustedWebContents() {
        return [...trustedWebContents]
    },
    /**
     * Accepts IPC only from the compact-test window registered below.
     * @param {object} event - Candidate Electron invoke event.
     * @returns {boolean} True only for an owned compact renderer.
     */
    isTrustedSender(event) {
        return isTrustedApplicationSender({ event, rendererUrl: indexUrl, trustedWebContents })
    }
}
const ipcController = registerIpcHandlers({ ipcMain, services })

/**
 * Inspects and activates the bound support control at the production minimum
 * Electron window size, including CSS layout, focusability, and native pointer
 * activation. The historical script name is retained for command compatibility.
 * @returns {Promise<void>} Resolves after every compact runtime assertion passes.
 */
async function verifyCompactSupport() {
    await app.whenReady()
    const window = new BrowserWindow({
        ...windowOptions,
        width: 1024,
        height: 768,
        show: true
    })
    trustedWebContents.add(window.webContents)

    try {
        await window.loadFile(indexPath)
        const preloadContract = await window.webContents.executeJavaScript(`/**
         * Reads only the public shape and frozen state of the real preload API.
         * @returns {object} Serializable preload readiness evidence.
         */
        (function inspectPreloadContract() {
            const api = globalThis.openRdx
            return {
                frozen: Object.isFrozen(api),
                groups: Object.keys(api).sort(),
                groupFrozen: Object.values(api).every(Object.isFrozen),
                hasInvoke: 'invoke' in api,
                hasSendCdb: 'sendCdb' in api
            }
        })()`)

        assert.deepEqual(preloadContract.groups, ['app', 'devices', 'files', 'logs', 'manufacturing', 'mcp', 'operations', 'recovery', 'service', 'settings', 'support', 'updates'])
        assert.equal(preloadContract.frozen, true)
        assert.equal(preloadContract.groupFrozen, true)
        assert.equal(preloadContract.hasInvoke, false)
        assert.equal(preloadContract.hasSendCdb, false)

        const prototypeBoundaryErrors = await window.webContents.executeJavaScript(`/**
         * Exercises prohibited own keys through the actual isolated-world bridge.
         * @returns {Promise<string[]>} Stable error messages for rejected requests.
         */
        (async function inspectPrototypeBoundary() {
            const nullPrototypeRequest = Object.assign(Object.create(null), {
                autoScan: false,
                constructor: 'controlled-constructor'
            })
            const requests = [
                JSON.parse('{"autoScan":false,"__proto__":{"polluted":true}}'),
                nullPrototypeRequest,
                { autoScan: false, nested: { prototype: 'controlled-prototype' } }
            ]
            const errors = []
            for (const request of requests) {
                try {
                    await globalThis.openRdx.settings.update(request)
                    errors.push('accepted')
                } catch (error) {
                    errors.push(String(error?.message ?? error))
                }
            }
            return errors
        })()`)
        assert.deepEqual(prototypeBoundaryErrors, ['OpenRDX request contains a prohibited prototype-control key', 'OpenRDX request contains a prohibited prototype-control key', 'OpenRDX request contains a prohibited prototype-control key'])

        await window.webContents.executeJavaScript(`/**
         * Imports and mounts the bound support fixture in the isolated renderer.
         * @returns {Promise<void>} Resolves after the fixture is mounted.
         */
        (async function mountCompactFixture() {
            const fixture = await import(${JSON.stringify(fixtureUrl)})
            fixture.mountCompactSupportFixture()
        })()`)
        const presentation = await window.webContents.executeJavaScript(`/**
         * Reads CSS-aware support and reason-code presentation evidence.
         * @returns {object} Serializable compact presentation measurements.
         */
        (function inspectCompactSupport() {
            const control = document.querySelector('.topbar [data-intent="open-support"]')
            const rect = control.getBoundingClientRect()
            const unavailableCode = document.querySelector('#intent-open-event-log-topbar-unavailable')
            control.focus()
            return {
                ariaLabel: control.getAttribute('aria-label'),
                centerX: Math.round(rect.left + rect.width / 2),
                centerY: Math.round(rect.top + rect.height / 2),
                disabled: control.disabled,
                display: getComputedStyle(control).display,
                focusKey: document.activeElement?.dataset.focusKey ?? null,
                height: rect.height,
                tabIndex: control.tabIndex,
                unavailableCodeClientRects: unavailableCode.getClientRects().length,
                unavailableCodeDisplay: getComputedStyle(unavailableCode).display,
                unavailableCodeText: unavailableCode.textContent.trim(),
                width: rect.width,
                clientRects: control.getClientRects().length
            }
        })()`)

        assert.deepEqual(window.webContents.getOwnerBrowserWindow()?.getBounds(), {
            x: window.getBounds().x,
            y: window.getBounds().y,
            width: 1024,
            height: 768
        })
        assert.equal(presentation.display === 'none', false)
        assert.equal(presentation.clientRects > 0, true)
        assert.equal(presentation.width > 0, true)
        assert.equal(presentation.height > 0, true)
        assert.equal(presentation.disabled, false)
        assert.equal(presentation.tabIndex, 0)
        assert.equal(presentation.ariaLabel, 'Open support')
        assert.equal(presentation.focusKey, 'topbar:support')
        assert.equal(presentation.unavailableCodeDisplay === 'none', false)
        assert.equal(presentation.unavailableCodeClientRects > 0, true)
        assert.equal(presentation.unavailableCodeText, 'INTENT_OPEN_EVENT_LOG_UNAVAILABLE')

        window.webContents.sendInputEvent({ type: 'mouseDown', x: presentation.centerX, y: presentation.centerY, button: 'left', clickCount: 1 })
        window.webContents.sendInputEvent({ type: 'mouseUp', x: presentation.centerX, y: presentation.centerY, button: 'left', clickCount: 1 })
        await delay(16)
        const calls = await window.webContents.executeJavaScript('globalThis.__openRdxCompactSupportFixture.calls')
        assert.deepEqual(calls, [{ type: 'open-support' }])

        await resizeAcceptanceWindow(window, 1440, 900)
        const desktopOverflow = await window.webContents.executeJavaScript('document.documentElement.scrollWidth - document.documentElement.clientWidth')
        assert.equal(desktopOverflow, 0)

        const desktopScroll = await window.webContents.executeJavaScript(`/**
         * Exercises the desktop scroll owner through real Chromium layout.
         * @returns {object} Serializable scroll geometry after moving the Status workspace.
         */
        (function inspectDesktopScrollOwner() {
            const documentScroller = document.scrollingElement
            const workspace = document.querySelector('.area-panel')
            const workspaceShell = document.querySelector('.main-workspace')
            const topbar = document.querySelector('.topbar')
            const deviceRail = document.querySelector('.device-rail')
            const commandRail = document.querySelector('.command-rail')
            const tabs = document.querySelector('.area-tabs')
            const workspaceRect = workspace.getBoundingClientRect()
            const workspaceShellRect = workspaceShell.getBoundingClientRect()
            const commandRailRect = commandRail.getBoundingClientRect()
            const workspaceStyle = getComputedStyle(workspace)
            const before = {
                commandRailTop: commandRail.getBoundingClientRect().top,
                deviceRailTop: deviceRail.getBoundingClientRect().top,
                tabsTop: tabs.getBoundingClientRect().top,
                topbarTop: topbar.getBoundingClientRect().top
            }
            workspace.scrollTop = 120
            return {
                after: {
                    commandRailTop: commandRail.getBoundingClientRect().top,
                    deviceRailTop: deviceRail.getBoundingClientRect().top,
                    tabsTop: tabs.getBoundingClientRect().top,
                    topbarTop: topbar.getBoundingClientRect().top
                },
                before,
                documentScrollTop: documentScroller.scrollTop,
                documentScrollable: documentScroller.scrollHeight > documentScroller.clientHeight + 1,
                outerBottomGap: Math.round(workspaceShellRect.bottom - workspaceRect.bottom),
                outerRightGap: Math.round(commandRailRect.left - workspaceRect.right),
                workspacePaddingBottom: workspaceStyle.paddingBottom,
                workspacePaddingRight: workspaceStyle.paddingRight,
                workspaceOverflowY: getComputedStyle(workspace).overflowY,
                workspaceScrollTop: workspace.scrollTop,
                workspaceScrollable: workspace.scrollHeight > workspace.clientHeight + 1
            }
        })()`)
        assert.equal(desktopScroll.documentScrollable, false)
        assert.equal(desktopScroll.workspaceOverflowY, 'auto')
        assert.equal(desktopScroll.workspaceScrollable, true)
        assert.equal(desktopScroll.workspaceScrollTop, 120)
        assert.equal(desktopScroll.documentScrollTop, 0)
        assert.equal(desktopScroll.outerBottomGap, 0)
        assert.equal(desktopScroll.outerRightGap, 0)
        assert.equal(desktopScroll.workspacePaddingBottom, '32px')
        assert.equal(desktopScroll.workspacePaddingRight, '24px')
        assert.deepEqual(desktopScroll.after, desktopScroll.before)

        await resizeAcceptanceWindow(window, 1024, 768)
        const compactScroll = await window.webContents.executeJavaScript(`/**
         * Reads the fallback where surrounding rails no longer fit side by side.
         * @returns {object} Serializable document and workspace scroll geometry.
         */
        (function inspectCompactScrollOwner() {
            const documentScroller = document.scrollingElement
            const workspace = document.querySelector('.area-panel')
            return {
                viewportWidth: innerWidth,
                viewportHeight: innerHeight,
                documentHeight: documentScroller.scrollHeight,
                documentScrollable: documentScroller.scrollHeight > documentScroller.clientHeight + 1,
                workspaceOverflowY: getComputedStyle(workspace).overflowY,
                workspaceScrollable: workspace.scrollHeight > workspace.clientHeight + 1
            }
        })()`)
        assert.equal(compactScroll.documentScrollable, true, JSON.stringify(compactScroll))
        assert.notEqual(compactScroll.workspaceOverflowY, 'auto')
        assert.equal(compactScroll.workspaceScrollable, false)
    } finally {
        trustedWebContents.delete(window.webContents)
        ipcController.dispose()
        window.destroy()
    }
}

/**
 * Runs assertions and exits without blocking Electron's initial ready event.
 * @returns {Promise<void>} Resolves after publishing the verification outcome.
 */
async function runVerification() {
    try {
        await verifyCompactSupport()
        app.exit(0)
    } catch (error) {
        console.error(error)
        app.exit(1)
    }
}

void runVerification()
