// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { writeFile, mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { setTimeout as delay } from 'node:timers/promises'
import { app, BrowserWindow } from 'electron'
import { windowOptions } from '../src/window-options.mjs'
import { captureValidatedVisualImage } from './visual-runtime-capture.mjs'
import { decodeVisualRasterAnchorCrops } from './visual-raster.mjs'
import { assertVisualRasterAnchorCrops } from './visual-qa-contract.mjs'
import { initializeIsolatedElectronProfile } from './isolated-profile.mjs'

initializeIsolatedElectronProfile(app)
const directory = process.env.OPENRDX_LINUX_FORMAT_EVIDENCE_DIRECTORY
if (!directory) throw new Error('An explicit evidence directory is required')
const rendererUrl = new URL('../src/renderer/', import.meta.url).href

/** @returns {Promise<void>} Checks the real Linux form in Chromium using fixture data and no hardware bridge. */
async function run() {
    await mkdir(directory, { recursive: true })
    await app.whenReady()
    const window = new BrowserWindow({ ...windowOptions, show: true, webPreferences: { ...windowOptions.webPreferences, preload: undefined, backgroundThrottling: false } })
    try {
        await window.loadFile(fileURLToPath(new URL('../src/index.html', import.meta.url)))
        await window.webContents.executeJavaScript(`
            /** @returns {Promise<void>} Mounts only a synthetic selected cartridge. */
            (async function mountLinuxFormat() {
                const { mountApplication } = await import(${JSON.stringify(`${rendererUrl}app-controller.mjs`)})
                const { createFixtureState } = await import(${JSON.stringify(`${rendererUrl}fixture-state.mjs`)})
                const { createStore } = await import(${JSON.stringify(`${rendererUrl}store.mjs`)})
                globalThis.__formatRequests = []
                globalThis.__formatController = mountApplication(document.querySelector('#app'), {
                    platform: 'linux', store: createStore({ ...createFixtureState({ mode: 'one-device' }), activeArea: 'utilities' }),
                    utilityController: {
                        /** @returns {boolean} Makes only fixture intent submission available. */
                        isAvailable() { return true },
                        /** @param {object} request - Structured fixture intent. @returns {Promise<object>} Records intent without executing an operation. */
                        async start(request) { globalThis.__formatRequests.push(request); return { ok: false, reason: 'hardware-unavailable' } }
                    }
                })
                document.querySelector('[data-feature="format"]').scrollIntoView({ block: 'center' })
            })()
        `)
        await delay(300)
        const evidence = await window.webContents.executeJavaScript(`
            /** @returns {object} Reads visible select labels, default and geometry. */
            (function inspectLinuxFormat() {
                const card = document.querySelector('[data-feature="format"]')
                const select = card.querySelector('[data-utility-filesystem]')
                const bounds = select.getBoundingClientRect()
                /** @param {Element} element - Visible scene element. @param {string} name - Evidence label. @param {string} color - Pixel marker. @returns {object} Required raster anchor. */
                function anchor(element, name, color) {
                    const rect = element.getBoundingClientRect()
                    const marker = document.createElement('span')
                    marker.setAttribute('aria-hidden', 'true')
                    marker.style.cssText = 'position:absolute;z-index:2147483647;top:1px;left:1px;width:3px;height:3px;pointer-events:none;background:' + color
                    element.style.position = 'relative'; element.append(marker)
                    return { name, color: getComputedStyle(element).color, fiducialColor: color, rect: { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom } }
                }
                return { contentSize: { width: innerWidth, height: innerHeight }, rasterAnchors: [anchor(card.querySelector('.utility-guidance'), 'linux-format-guidance', 'rgb(64,255,128)'), anchor(document.querySelector('.brand'), 'brand', 'rgb(255,64,224)')], choices: [...select.options].map(option => ({ value: option.value, label: option.textContent, disabled: option.disabled })), selected: select.value, text: card.textContent, visible: bounds.top >= 0 && bounds.bottom <= innerHeight }
            })()
        `)
        assert.deepEqual(
            evidence.choices.map(({ value }) => value),
            ['ext4', 'ext3', 'ext2', 'xfs', 'btrfs', 'f2fs', 'ntfs', 'exfat', 'fat16', 'fat32']
        )
        assert.equal(evidence.selected, 'ext4')
        assert.equal(evidence.visible, true)
        assert.equal(evidence.choices.find(({ value }) => value === 'fat16').disabled, true)
        const capture = await captureValidatedVisualImage({
            /** @returns {Promise<void>} Requires repaint before checking current pixels. */
            async prepare() {
                window.webContents.invalidate()
                await delay(300)
            },
            /** @returns {Promise<Electron.NativeImage>} Captures the isolated fixture window. */
            async capture() {
                return window.webContents.capturePage()
            },
            /** @param {Electron.NativeImage} image - Candidate frame. @returns {object} Proven current-scene pixels. */
            validate(image) {
                return assertVisualRasterAnchorCrops(decodeVisualRasterAnchorCrops(image, evidence.rasterAnchors, evidence.contentSize))
            }
        })
        await writeFile(join(directory, 'linux-format.png'), capture.image.toPNG())
        await window.webContents.executeJavaScript(`
            /** @returns {void} Changes the actual form and submits a fixture-only Btrfs request. */
            (function submitBtrfs() {
                const select = document.querySelector('[data-utility-filesystem]')
                select.value = 'btrfs'; select.dispatchEvent(new Event('change', { bubbles: true }))
                const confirmation = document.querySelector('[data-format-confirmation]')
                confirmation.value = confirmation.dataset.expectedIdentity
                confirmation.dispatchEvent(new Event('input', { bubbles: true }))
                document.querySelector('[data-action="start-format"]').click()
            })()
        `)
        await delay(100)
        const requests = await window.webContents.executeJavaScript('globalThis.__formatRequests')
        assert.equal(requests.length, 1)
        assert.equal(requests[0].filesystem, 'btrfs')
        await writeFile(join(directory, 'result.json'), JSON.stringify({ fixtureOnly: true, ...evidence, requests }, null, 2))
        console.log(`Linux format Electron acceptance passed: ${directory}`)
    } finally {
        window.destroy()
    }
}

/** @returns {Promise<void>} Lets Electron readiness proceed before acceptance starts. */
async function main() {
    try {
        await run()
        app.exit(0)
    } catch (error) {
        console.error(error)
        app.exit(1)
    }
}
void main()
