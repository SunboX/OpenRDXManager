// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { writeFile } from 'node:fs/promises'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { setTimeout as delay } from 'node:timers/promises'
import { once } from 'node:events'
import { app, BrowserWindow } from 'electron'
import { windowOptions } from '../src/window-options.mjs'
import { resizeAcceptanceWindow } from './acceptance-window-size.mjs'
import { captureValidatedVisualImage } from './visual-runtime-capture.mjs'
import { decodeVisualRasterAnchorCrops } from './visual-raster.mjs'
import { assertVisualRasterAnchorCrops } from './visual-qa-contract.mjs'

const directory = process.env.OPENRDX_INTERLOCK_EVIDENCE_DIRECTORY
if (!directory) throw new Error('An explicit new evidence directory is required')
mkdirSync(directory)
// Isolate Chromium caches from concurrently running acceptance tests and the real app.
app.setPath('userData', join(directory, 'user-data'))
const fixtureUrl = new URL('./visual-fixture.mjs', import.meta.url).href

/** @returns {Promise<void>} Renders the real UI with synthetic data and no native transport or preload. */
async function run() {
    await app.whenReady()
    const window = new BrowserWindow({ ...windowOptions, show: true, webPreferences: { ...windowOptions.webPreferences, preload: undefined } })
    const captures = []
    try {
        await window.loadFile(fileURLToPath(new URL('../src/index.html', import.meta.url)))
        for (const [width, height] of [
            [1024, 768],
            [1280, 900]
        ]) {
            await resizeAcceptanceWindow(window, width, height)
            await window.webContents.executeJavaScript(`
                /** @returns {Promise<void>} Mounts only the isolated no-hardware scene. */
                (async function mountInterlock() {
                    const fixture = await import(${JSON.stringify(fixtureUrl)})
                    await fixture.mountVisualFixture('firmware-power-cycle')
                })()`)
            await delay(300)
            const evidence = await window.webContents.executeJavaScript(`
                /** @returns {object} Reads banner and result text without any device operation. */
                (function inspectInterlock() {
                    /** @param {string} selector - Fixed scene anchor. @param {string} name - Evidence label. @param {string} fiducialColor - Test-only pixel marker. @returns {object} Required visible anchor geometry. */
                    function anchor(selector, name, fiducialColor) {
                        const element = document.querySelector(selector)
                        const rect = element.getBoundingClientRect()
                        if (rect.left < 0 || rect.top < 0 || rect.right > innerWidth || rect.bottom > innerHeight) throw new Error('Interlock anchor is clipped: ' + name)
                        const marker = document.createElement('span')
                        marker.setAttribute('aria-hidden', 'true')
                        marker.style.cssText = 'position:absolute;z-index:2147483647;top:1px;left:1px;width:3px;height:3px;pointer-events:none;background:' + fiducialColor
                        if (getComputedStyle(element).position === 'static') element.style.position = 'relative'
                        element.append(marker)
                        return { name, color: getComputedStyle(element).color, fiducialColor, rect: { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom } }
                    }
                    return {
                        banner: document.querySelector('[data-operation-failure]').textContent,
                        result: document.querySelector('[data-result-status="failed"]').textContent,
                        fixtureOnly: document.querySelector('.fixture-note') !== null,
                        overflow: document.documentElement.scrollWidth > innerWidth,
                        nativeBridgeAbsent: globalThis.openRdx === undefined,
                        contentSize: { width: innerWidth, height: innerHeight },
                        rasterAnchors: [anchor('.brand', 'brand', 'rgb(255, 64, 224)'), anchor('[data-operation-failure] p', 'interlock-guidance', 'rgb(64, 255, 128)')]
                    }
                })()`)
            assert.equal(evidence.fixtureOnly, true)
            assert.equal(evidence.nativeBridgeAbsent, true)
            assert.equal(evidence.overflow, false)
            for (const text of [evidence.banner, evidence.result]) {
                assert.match(text, /safety lock.*manufacturing-data write/)
                assert.match(text, /Disconnect both USB and the power adapter/)
                assert.match(text, /No firmware was written/)
                assert.doesNotMatch(text, /do not disconnect it/)
            }
            const capture = await captureValidatedVisualImage({
                /** @returns {Promise<void>} Requests a repaint with a bounded delay, including on a locked desktop. */
                async prepare() {
                    window.webContents.invalidate()
                    await delay(300)
                },
                /** @returns {Promise<Electron.NativeImage>} Candidate frame, not yet accepted as evidence. */
                async capture() {
                    return window.webContents.capturePage()
                },
                /** @param {Electron.NativeImage} image - Candidate frame. @returns {object} Verified current-scene pixels; rejects stale service-unavailable frames. */
                validate(image) {
                    return assertVisualRasterAnchorCrops(decodeVisualRasterAnchorCrops(image, evidence.rasterAnchors, evidence.contentSize))
                }
            })
            const screenshot = join(directory, `interlock-${width}.png`)
            await writeFile(screenshot, capture.image.toPNG(), { flag: 'wx' })
            captures.push({ width, height, ...evidence, screenshot, rasterEvidence: capture.evidence, captureAttempts: capture.attempts })
        }
        await writeFile(join(directory, 'result.json'), JSON.stringify({ fixtureOnly: true, captures }, null, 2), { flag: 'wx' })
        console.log(`Firmware interlock Electron acceptance passed: ${directory}`)
        if (process.argv.includes('--keep-open')) await once(window, 'closed')
    } finally {
        if (!window.isDestroyed()) window.destroy()
    }
}

/** @returns {Promise<void>} Starts asynchronously so Electron can complete readiness. */
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
