// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { applicationMetadata } from '../src/main/application-metadata.mjs'

import { mkdir, writeFile } from 'node:fs/promises'
import { basename, dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

import { app, BrowserWindow, ipcMain, nativeImage } from 'electron'

import { isTrustedApplicationSender, registerIpcHandlers } from '../src/main/ipc-controller.mjs'
import { registerWindowMenu } from '../src/main/window-menu.mjs'
import { WindowMenuChannel } from '../src/shared/window-menu.mjs'
import { visualWindowOptions } from './visual-window-options.mjs'
import { guardVisualOutput } from './visual-output.mjs'
import { normalizeConsoleMessage, VisualErrorTracker } from './visual-error-tracker.mjs'
import { isVisualAnchorUnoccluded } from './visual-anchor-visibility.mjs'
import { initializeIsolatedElectronProfile } from './isolated-profile.mjs'
import { assertVisualRasterAnchorCrops, assertVisualSnapshot, collectVisualDisabledReasons, createVisualControlKey, createVisualQaMatrix, serializeVisualQaCaptureMetrics, serializeVisualQaManifest } from './visual-qa-contract.mjs'
import { captureValidatedVisualImage, loadWithPageErrorCapture, runWithVisualErrorCursor } from './visual-runtime-capture.mjs'
import { compareVisualImages, decodeVisualRasterAnchorCrops, hasMeaningfulVisualDifference, injectSingleChannelRasterNoise } from './visual-raster.mjs'

initializeIsolatedElectronProfile(app, process.env.OPENRDX_ELECTRON_TEST_PROFILE)
guardVisualOutput(app, { stdout: process.stdout, stderr: process.stderr })

// macOS overlay scrollbar opacity is wall-clock driven and can change capture
// pixels after layout has settled; scroll positions remain manifest evidence.
app.commandLine.appendSwitch('hide-scrollbars')
app.commandLine.appendSwitch('force-prefers-reduced-motion')
// Even a forced 2x scale rounds Windows non-client minimum-height calculations
// up to 769 DIPs on this host. Integer 1x avoids that native-frame rounding;
// exact bounds and painted raster anchors remain mandatory. Production DPI
// behavior and minimum-size/security defaults are not changed.
if (process.platform === 'win32') {
    app.commandLine.appendSwitch('force-device-scale-factor', '1')
}
// Use the same software compositor for QA on every host rather than depending
// on each GPU's antialiasing. Pixel budgets and production GPU behavior remain
// unchanged; settled renderer state is still required before every capture.
app.disableHardwareAcceleration()

const projectDirectory = fileURLToPath(new URL('..', import.meta.url))
const indexPath = fileURLToPath(new URL('../src/index.html', import.meta.url))
const indexUrl = pathToFileURL(indexPath).href
const fixtureUrl = new URL('./visual-fixture.mjs', import.meta.url).href
const evidenceDirectory = process.env.OPENRDX_VISUAL_QA_EVIDENCE_DIRECTORY ?? join(projectDirectory, 'docs', 'evidence', 'phase-4-task-8')
const consoleErrorInjectionPrefix = '--visual-qa-inject-console-error='
const rasterNoiseInjectionPrefix = '--visual-qa-inject-raster-noise='
const rasterCorruptionInjectionPrefix = '--visual-qa-inject-raster-corruption='
let consoleErrorInjection = null
let rasterNoiseInjection = null
let rasterCorruptionInjection = null
for (const argument of process.argv) {
    if (argument.startsWith(consoleErrorInjectionPrefix)) consoleErrorInjection = argument.slice(consoleErrorInjectionPrefix.length)
    if (argument.startsWith(rasterNoiseInjectionPrefix)) rasterNoiseInjection = argument.slice(rasterNoiseInjectionPrefix.length)
    if (argument.startsWith(rasterCorruptionInjectionPrefix)) rasterCorruptionInjection = argument.slice(rasterCorruptionInjectionPrefix.length)
}
if (consoleErrorInjection !== null && !['before-mount', 'during-transition'].includes(consoleErrorInjection)) {
    throw new Error(`Unsupported visual QA console-error injection: ${consoleErrorInjection}`)
}
const trustedWebContents = new Set()
let pendingDeviceList = null

/**
 * Creates a manually controlled promise for the production renderer's initial
 * service list. Holding it proves the visible starting state; resolving it
 * proves the ready/no-device transition through the real preload bridge.
 * @returns {{promise: Promise<object>, resolve: (value: object) => void}} Deferred list response.
 */
function createDeferredDeviceList() {
    const { promise, resolve } = Promise.withResolvers()
    return { promise, resolve }
}

const services = {
    app: {
        /** @returns {Promise<object>} Bounded visual-test application metadata. */
        async getInfo() {
            return { ok: true, app: { ...applicationMetadata, platform: process.platform } }
        }
    },
    devices: {
        /** @returns {Promise<object>} Current controlled service list response. */
        async list() {
            return pendingDeviceList.promise
        },
        /** @returns {Promise<object>} Safe visual-test scan result. */
        async scan() {
            return { ok: false, reason: 'hardware-unavailable' }
        }
    },
    files: {
        /** @returns {Promise<object>} No file token is created during visual QA. */
        async chooseFirmware() {
            return { ok: false, reason: 'feature-unavailable' }
        },
        /** @returns {Promise<object>} No export token is created during visual QA. */
        async chooseExportDestination() {
            return { ok: false, reason: 'feature-unavailable' }
        }
    },
    logs: {
        /** @returns {Promise<object>} Empty local log result. */
        async list() {
            return { ok: true, entries: [] }
        },
        /** @returns {Promise<object>} Safe unavailable mutation result. */
        async setEnabled() {
            return { ok: false, reason: 'feature-unavailable' }
        },
        /** @returns {Promise<object>} No export token is created during visual QA. */
        async export() {
            return { ok: false, reason: 'feature-unavailable' }
        }
    },
    operations: {
        /** @returns {Promise<object>} No hardware operation starts during visual QA. */
        async start() {
            return { ok: false, reason: 'hardware-unavailable' }
        },
        /** @returns {Promise<object>} No operation is cancellable during visual QA. */
        async cancel() {
            return { ok: false, reason: 'operation-not-cancellable' }
        },
        /** @returns {Promise<object>} Fail-closed no-hardware safety context. */
        async getContext() {
            return { serviceMode: 'no-device', hardwareReady: false, activeOperation: null, device: null }
        }
    },
    settings: {
        /** @returns {Promise<object>} Stable Phase 1 settings. */
        async get() {
            return { ok: true, settings: { autoScan: true, eventLogging: true, language: 'en', updateChecks: false } }
        },
        /** @returns {Promise<object>} Stable Phase 1 settings without persistence. */
        async update() {
            return { ok: true, settings: { autoScan: true, eventLogging: true, language: 'en', updateChecks: false } }
        }
    },
    support: {
        /** @returns {Promise<object>} No support file is written during visual QA. */
        async generateSummary() {
            return { ok: false, reason: 'feature-unavailable' }
        }
    },
    updates: {
        /** @returns {Promise<object>} Network checks remain unavailable in visual QA. */
        async check() {
            return { ok: false, reason: 'feature-unavailable' }
        }
    },
    /**
     * Returns current process-owned renderer targets.
     * @returns {object[]} Trusted Electron web contents.
     */
    getTrustedWebContents() {
        return [...trustedWebContents]
    },
    /**
     * Restricts visual-test IPC to the exact local main frame.
     * @param {object} event - Electron invoke event.
     * @returns {boolean} True only for the owned visual-test renderer.
     */
    isTrustedSender(event) {
        return isTrustedApplicationSender({ event, rendererUrl: indexUrl, trustedWebContents })
    }
}

const ipcController = registerIpcHandlers({ ipcMain, services })
// Visual fixtures own no native menus. Keep the real trusted menu boundary so
// preload reads resolve normally and untrusted/popup requests still fail closed.
registerWindowMenu({
    ipcMain,
    BrowserWindow,
    isTrustedSender: services.isTrustedSender,
    Menu: {
        /** @returns {null} No native application menu exists in visual QA. */
        getApplicationMenu() {
            return null
        }
    }
})

/**
 * Waits for one renderer selector without guessing at fixed load timings.
 * @param {Electron.WebContents} webContents - Owned renderer target.
 * @param {string} selector - CSS selector whose presence completes the wait.
 * @returns {Promise<void>} Resolves after the selector appears.
 */
async function waitForSelector(webContents, selector) {
    await webContents.executeJavaScript(`(
        /**
         * Polls for a required application mount without fixed sleeps.
         * @returns {Promise<void>} Resolves when the selector is present.
         */
        async function waitForRequiredSelector() {
        const selector = ${JSON.stringify(selector)}
        const deadline = performance.now() + 5000
        while (document.querySelector(selector) === null) {
            if (performance.now() >= deadline) {
                throw new Error('Timed out waiting for ' + selector)
            }
            await new Promise(requestAnimationFrame.bind(globalThis))
        }
    })()`)
}

/**
 * Allows layout, local fonts, and paint to settle without sleeping for an
 * arbitrary wall-clock duration.
 * @param {Electron.WebContents} webContents - Owned renderer target.
 * @returns {Promise<void>} Resolves after fonts and two animation frames.
 */
async function waitForPaint(webContents) {
    await webContents.executeJavaScript(`
    /** Waits for local fonts and two complete paint frames. @returns {Promise<void>} */
    (async function waitForVisualPaint() {
        await document.fonts.ready
        await new Promise(requestAnimationFrame.bind(globalThis))
        await new Promise(requestAnimationFrame.bind(globalThis))
    })()`)
}

/**
 * Applies one supported outer-window size and verifies Electron honored its
 * production minimum constraints.
 * @param {BrowserWindow} window - Visual QA window.
 * @param {{width: number, height: number}} viewport - Required outer bounds.
 * @returns {Promise<void>} Resolves after layout settles at the exact bounds.
 */
async function setWindowSize(window, viewport) {
    window.setBounds({ x: 40, y: 40, width: viewport.width, height: viewport.height }, false)
    const bounds = window.getBounds()
    assert.equal(bounds.width, viewport.width)
    assert.equal(bounds.height, viewport.height)
    window.webContents.invalidate()
    await waitForPaint(window.webContents)
}

/**
 * Mounts one fixture through the actual renderer modules inside Chromium.
 * @param {Electron.WebContents} webContents - Owned renderer target.
 * @param {string} state - Exact fixture mode.
 * @returns {Promise<void>} Resolves after the requested state is mounted.
 */
async function mountFixture(webContents, state) {
    await webContents.executeJavaScript(`
    /** Loads and mounts only the explicitly selected visual-test fixture. @returns {Promise<void>} */
    (async function mountFixtureState() {
        const fixture = await import(${JSON.stringify(fixtureUrl)})
        await fixture.mountVisualFixture(${JSON.stringify(state)})
    })()`)
    await waitForSelector(webContents, '.application-shell')
    await waitForPaint(webContents)
}

/**
 * Resets inherited scroll positions and brings state-defining evidence into the
 * captured viewport when the relevant control would otherwise be below fold.
 * @param {Electron.WebContents} webContents - Owned renderer target.
 * @param {string} state - Exact visual scene ID.
 * @returns {Promise<void>} Resolves after scroll positioning completes.
 */
async function positionSceneForCapture(webContents, state) {
    const selector = {
        'destructive-preflight': '[data-feature="format"]',
        'disabled-reasons': '#credential-fields-disabled-reason',
        'protected-locked': '.security-access',
        'protected-unlocked': '.security-access',
        'update-unavailable': '[data-support-result="help"]'
    }[state]
    await webContents.executeJavaScript(`
        /** Positions the state-defining visual target without changing application state. @returns {void} */
        (function positionVisualScene() {
            window.scrollTo(0, 0)
            const scrollElements = [...new Set([document.scrollingElement, ...document.querySelectorAll('*')].filter(Boolean))]
            for (const element of scrollElements) {
                element.scrollLeft = 0
                element.scrollTop = 0
            }
            const selector = ${JSON.stringify(selector ?? null)}
            const target = selector === null ? null : document.querySelector(selector)
            if (target !== null) target.scrollIntoView({ block: 'center', inline: 'nearest' })
            window.scrollTo(0, window.scrollY)
            for (const element of scrollElements) element.scrollLeft = 0
        })()`)
}

/**
 * Removes host pointer and DOM-focus state before a screenshot. A synthetic
 * pointer move to inert canvas prevents a physical cursor from leaving a
 * transitioning hover style over the state-defining control.
 * @param {BrowserWindow} window - Visual QA window.
 * @returns {Promise<void>} Resolves after the neutral state has painted.
 */
async function stabilizeInteractionForCapture(window) {
    await window.webContents.executeJavaScript(`
        /** Clears renderer-owned focus before immutable raster capture. @returns {void} */
        (function clearVisualCaptureFocus() {
            const active = document.activeElement
            if (active instanceof HTMLElement) active.blur()
        })()`)
    window.webContents.sendInputEvent({ type: 'mouseMove', x: 1, y: 1, movementX: 0, movementY: 0 })
    await waitForPaint(window.webContents)
}

/**
 * Emits one exact renderer console error only from this separate Electron test
 * entrypoint when a negative integration test selects the matching boundary.
 * @param {Electron.WebContents} webContents - Owned renderer target.
 * @param {'before-mount' | 'during-transition'} injectionPoint - Current operation boundary.
 * @returns {Promise<void>} Resolves after any selected error is emitted.
 */
async function injectConsoleError(webContents, injectionPoint) {
    if (consoleErrorInjection !== injectionPoint) return
    const message = `openrdx-visual-injected-${injectionPoint}`
    await webContents.executeJavaScript(`console.error(${JSON.stringify(message)})`)
    consoleErrorInjection = null
}

/**
 * Exercises exact fixture control paths and keyboard tab behavior before the
 * fixture is remounted for pristine screenshot capture.
 * @param {BrowserWindow} window - Visual QA window.
 * @param {string} state - Current fixture state.
 * @returns {Promise<object|null>} Keyboard evidence for the selected-device state.
 */
async function exerciseFixture(window, state) {
    const webContents = window.webContents
    if (state === 'status') {
        window.focus()
        webContents.focus()
        const windowFocusedAtTraversal = window.isFocused()
        await webContents.executeJavaScript(`
        /** Moves focus to a neutral browser-owned starting position. @returns {void} */
        (function resetFocusForKeyboardTraversal() {
            document.body.tabIndex = -1
            document.body.focus()
            document.body.removeAttribute('tabindex')
        })()`)
        webContents.sendInputEvent({ type: 'keyDown', keyCode: 'Tab' })
        webContents.sendInputEvent({ type: 'keyUp', keyCode: 'Tab' })
        await waitForPaint(webContents)
        const skipLinkEvidence = await webContents.executeJavaScript(`
        /** Reads skip-link focus and focus-ring evidence. @returns {object} */
        (function inspectSkipLinkFocus() {
            const active = document.activeElement
            const style = getComputedStyle(active)
            return {
                focusVisibleMatched: active?.matches(':focus-visible') === true,
                outlineStyle: style.outlineStyle,
                outlineWidth: style.outlineWidth,
                skipLinkFocused: active?.classList.contains('skip-link') === true,
                visibleFocusRing: parseFloat(style.outlineWidth) >= 2 && style.outlineStyle !== 'none'
            }
        })()`)
        webContents.sendInputEvent({ type: 'keyDown', keyCode: 'Tab' })
        webContents.sendInputEvent({ type: 'keyUp', keyCode: 'Tab' })
        webContents.sendInputEvent({ type: 'keyDown', keyCode: 'Tab', modifiers: ['shift'] })
        webContents.sendInputEvent({ type: 'keyUp', keyCode: 'Tab', modifiers: ['shift'] })
        await waitForPaint(webContents)
        const shiftTabReturnedToSkipLink = await webContents.executeJavaScript("document.activeElement?.classList.contains('skip-link') === true")
        await webContents.executeJavaScript('document.querySelector(\'[data-area="status"]\').focus()')
        webContents.sendInputEvent({ type: 'keyDown', keyCode: 'End' })
        webContents.sendInputEvent({ type: 'keyUp', keyCode: 'End' })
        await waitForPaint(webContents)
        const endArea = await webContents.executeJavaScript('document.activeElement?.dataset.area')
        assert.equal(endArea, 'utilities')
        const utilityEvidence = await webContents.executeJavaScript(`
        /** Reads the complete fixture-backed Utilities workspace. @returns {object} Utility rendering evidence. */
        (function inspectUtilityWorkspace() {
            const panel = document.querySelector('[role="tabpanel"]')
            return {
                featureCount: panel?.querySelectorAll('[data-feature]').length ?? 0,
                hardwareNoteVisible: panel?.querySelector('.utilities-hardware-note') !== null,
                viewVisible: panel?.querySelector('[data-utilities-view]') !== null
            }
        })()`)
        assert.deepEqual(utilityEvidence, { featureCount: 7, hardwareNoteVisible: true, viewVisible: true })
        webContents.sendInputEvent({ type: 'keyDown', keyCode: 'Home' })
        webContents.sendInputEvent({ type: 'keyUp', keyCode: 'Home' })
        await waitForPaint(webContents)
        const homeArea = await webContents.executeJavaScript('document.activeElement?.dataset.area')
        assert.equal(homeArea, 'status')
        await webContents.executeJavaScript('document.querySelector(\'[data-operation="status-refresh"]\').click()')
        assert.deepEqual(await webContents.executeJavaScript('globalThis.__openRdxVisualFixture.calls'), [{ type: 'operation', kind: 'status-refresh', deviceId: 'rdx:7810544062', deviceRevision: 4 }])
        return { ...skipLinkEvidence, shiftTabReturnedToSkipLink, endArea, homeArea, windowFocusedAtTraversal }
    }
    const selectors = { 'no-device': '[data-intent="scan"]', 'operation-failure': '[data-intent="retry-operation"]', 'service-unavailable': '[data-intent="retry-service"]' }
    if (state in selectors) {
        await webContents.executeJavaScript(`document.querySelector(${JSON.stringify(selectors[state])}).click()`)
        assert.equal((await webContents.executeJavaScript('globalThis.__openRdxVisualFixture.calls')).length, 1)
        return null
    }
    if (['routine-active', 'critical-active', 'destructive-active'].includes(state)) {
        await webContents.executeJavaScript(`for (const control of document.querySelectorAll('[data-operation], [data-action="manage-device"], [data-action="scan-devices"], [data-setting="auto-scan"]')) control.click()`)
        assert.deepEqual(await webContents.executeJavaScript('globalThis.__openRdxVisualFixture.calls'), [])
    }
    return null
}

/**
 * Reads layout, accessibility, provenance, local-resource, and runtime health
 * evidence from the actual Electron renderer.
 * @param {BrowserWindow} window - Visual QA window.
 * @param {object} entry - Exact capture-plan entry.
 * @param {VisualErrorTracker} errorTracker - Complete process-owned error streams.
 * @param {Readonly<Record<string, number>>} cursor - Cursor captured before the tested operation.
 * @param {object|null} functionalEvidence - Keyboard evidence for the selected-device fixture.
 * @returns {Promise<object>} Serializable fail-closed inspection result.
 */
async function inspectRenderer(window, entry, errorTracker, cursor, functionalEvidence) {
    const browserEvidence = await window.webContents.executeJavaScript(`
    /** Reads deterministic visual evidence from the mounted application. @returns {object} */
    (function inspectVisualState() {
        ${createVisualControlKey.toString()}
        ${collectVisualDisabledReasons.toString()}
        ${isVisualAnchorUnoccluded.toString()}
        /** @param {Element} element - Candidate element. @returns {boolean} True when the element occupies visible layout. */
        function isVisible(element) {
            const style = getComputedStyle(element)
            const rect = element.getBoundingClientRect()
            return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0
        }
        /** @param {Element} element - Candidate element. @returns {boolean} True when the complete rendered box is inside the capture viewport. */
        function isInViewport(element) {
            if (element === null || !isVisible(element)) return false
            const rect = element.getBoundingClientRect()
            return rect.top >= -0.5 && rect.left >= -0.5 && rect.bottom <= window.innerHeight + 0.5 && rect.right <= window.innerWidth + 0.5
        }
        /** @param {Element} element - UI element to identify. @returns {string} Stable bounded label. */
        function describe(element) {
            return element.getAttribute('aria-label') || element.textContent.trim().replace(/\\s+/g, ' ').slice(0, 100) || element.tagName.toLowerCase()
        }
        /** @param {Element} element - Candidate control. @returns {boolean} True when its accessible name is absent. */
        function isUnlabeled(element) {
            if (element.matches('input')) return !element.closest('label')?.textContent.trim() && !element.getAttribute('aria-label')
            return !element.getAttribute('aria-label') && !element.textContent.trim() && !element.getAttribute('title')
        }
        /** @param {Element} element - Candidate control. @returns {boolean} True when disabled. */
        function isDisabled(element) {
            return element.disabled === true
        }
        /** @param {Element} element - Disabled control. @returns {boolean} True when no complete described-by reason exists. */
        function hasMissingDisabledReason(element) {
            return disabledReasons(element).length === 0
        }
        /** @param {Element} element - Visible target. @returns {boolean} True when clipped outside the renderer viewport. */
        function isHorizontallyClipped(element) {
            const rect = element.getBoundingClientRect()
            return rect.left < -0.5 || rect.right > window.innerWidth + 0.5
        }
        /** @param {Element} icon - Visible icon. @returns {boolean} True when its local font emitted a glyph. */
        function hasIconGlyph(icon) {
            return !['none', 'normal', '""'].includes(getComputedStyle(icon, '::before').content)
        }
        /** @param {Element} element - Disabled control. @returns {string[]} Every rendered local reason linked to or surrounding it. */
        function disabledReasons(element) {
            return collectVisualDisabledReasons(element, document, isVisible)
        }
        const controls = [...document.querySelectorAll('button, input, select, a[href]')].filter(isVisible)
        const unlabeledControls = controls.filter(isUnlabeled).map(describe)
        const disabledWithoutReason = controls.filter(isDisabled).filter(hasMissingDisabledReason).map(describe)
        const disabledElements = controls.filter(isDisabled)
        const state = ${JSON.stringify(entry.state)}
        const disabledControls = disabledElements.map(function inventoryDisabledControl(element, index) {
            return {
                key: createVisualControlKey(element, index),
                reasons: disabledReasons(element)
            }
        })
        const disabledReasonTarget = document.querySelector('#credential-fields-disabled-reason')
        const disabledReasonEvidence = state === 'disabled-reasons' ? {
            reasonCount: disabledControls.reduce(function countReasons(total, control) { return total + control.reasons.length }, 0),
            targetInViewport: isInViewport(disabledReasonTarget)
        } : null
        const formatConfirmation = document.querySelector('[data-format-confirmation]')
        const formatAction = document.querySelector('[data-action="start-format"]')
        const destructivePreflightEvidence = state === 'destructive-preflight' ? {
            actionEnabled: formatAction?.disabled === false,
            exactIdentityEntered: typeof formatConfirmation?.dataset.expectedIdentity === 'string' && formatConfirmation.dataset.expectedIdentity.length > 0 && formatConfirmation.value === formatConfirmation.dataset.expectedIdentity,
            noActiveOperation: document.querySelector('[data-operation-status]') === null,
            targetInViewport: isInViewport(document.querySelector('[data-feature="format"]'))
        } : null
        const accessStatus = document.querySelector('.security-access')
        const protectedAccessEvidence = ['protected-locked', 'protected-unlocked'].includes(state) ? {
            disableAccessEnabled: document.querySelector('[data-action="disable-access"]')?.disabled === false,
            enableAccessEnabled: document.querySelector('[data-action="enable-access"]')?.disabled === false,
            reportedState: accessStatus?.classList.contains('security-access--enabled') ? 'enabled' : accessStatus?.classList.contains('security-access--disabled') ? 'disabled' : 'unknown',
            targetInViewport: isInViewport(accessStatus)
        } : null
        const updateResultText = document.querySelector('[data-support-result="help"]')?.textContent.trim() || ''
        const updateUnavailableEvidence = state === 'update-unavailable' ? {
            checkEnabled: document.querySelector('[data-action="check-updates"]')?.disabled === false,
            failureVisible: /update check did not change manager or device state/i.test(updateResultText),
            networkReasonVisible: /update metadata could not be retrieved/i.test(updateResultText),
            targetInViewport: isInViewport(document.querySelector('[data-support-result="help"]'))
        } : null
        const horizontalTargets = [...document.querySelectorAll('.topbar, .device-rail, .main-workspace, .state-workspace, [data-support-overlay], [role="alert"], [data-operation-status], button, input, select')].filter(isVisible)
        const clippedElements = horizontalTargets.filter(isHorizontallyClipped).map(describe)
        const scrollElements = [...new Set([document.scrollingElement, ...document.querySelectorAll('*')].filter(Boolean))]
        /** @param {Element} element - Scroll container. @param {number} index - Stable document order. @returns {string} Bounded scroll-container identity. */
        function describeScrollContainer(element, index) {
            if (element === document.scrollingElement) return 'document'
            const id = element.getAttribute?.('id')
            if (id) return element.tagName.toLowerCase() + '#' + id
            const className = typeof element.className === 'string' ? element.className.trim().replace(/\\s+/g, '.').slice(0, 80) : ''
            return className ? element.tagName.toLowerCase() + '.' + className : element.tagName.toLowerCase() + ':' + index
        }
        const horizontalScrollOffsets = []
        const verticalScrollOffsets = []
        for (const [index, element] of scrollElements.entries()) {
            const label = describeScrollContainer(element, index)
            if (Math.abs(element.scrollLeft) > 0.5) horizontalScrollOffsets.push(label + ':' + element.scrollLeft)
            if (Math.abs(element.scrollTop) > 0.5) verticalScrollOffsets.push(label + ':' + element.scrollTop)
        }
        const topbar = document.querySelector('.topbar')
        const topbarInViewport = isInViewport(topbar) && isInViewport(topbar?.querySelector('.brand')) && isInViewport(topbar?.querySelector('.topbar__actions'))
        /**
         * Captures one DOM anchor whose foreground must appear inside the final
         * screenshot, independently of the layout-only geometry contract.
         * @param {string} name - Stable structural anchor identity.
         * @param {Element|null} element - Visible element expected to paint.
         * @param {string} fiducialColor - Unique QA-only positional marker.
         * @returns {object|null} Serializable anchor geometry and sRGB color.
         */
        function captureRasterAnchor(name, element, fiducialColor) {
            if (!isInViewport(element) || !isVisualAnchorUnoccluded(element, document)) return null
            const marker = document.createElement('span')
            marker.dataset.visualQaFiducial = name
            marker.setAttribute('aria-hidden', 'true')
            marker.style.cssText = 'position:absolute;z-index:2147483647;top:1px;left:1px;width:3px;height:3px;pointer-events:none;background:' + fiducialColor
            if (getComputedStyle(element).position === 'static') element.style.position = 'relative'
            element.append(marker)
            const rect = element.getBoundingClientRect()
            return {
                name,
                color: getComputedStyle(element).color,
                fiducialColor,
                rect: { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom, width: rect.width, height: rect.height }
            }
        }
        /**
         * Finds the first visible element for one structural screenshot slot.
         * @param {string} selectors - Ordered CSS selector list.
         * @returns {Element|null} First complete viewport-visible match.
         */
        function findRasterAnchorElement(selectors) {
            return [...document.querySelectorAll(selectors)].find((element) => isInViewport(element) && isVisualAnchorUnoccluded(element, document)) ?? null
        }
        const supportOverlay = document.querySelector('[data-support-overlay]')
        const rasterAnchors = (isInViewport(supportOverlay)
            ? [
                  captureRasterAnchor('overlay-heading', findRasterAnchorElement('[data-support-overlay] .eyebrow, [data-support-overlay] h1, [data-support-overlay] h2, [data-support-overlay] h3'), 'rgb(255, 64, 224)'),
                  captureRasterAnchor('overlay-control', findRasterAnchorElement('[data-support-overlay] button, [data-support-overlay] select, [data-support-overlay] input'), 'rgb(64, 255, 128)'),
                  captureRasterAnchor('overlay-result', findRasterAnchorElement('[data-support-overlay] [data-support-result], [data-support-overlay] [role="status"], [data-support-overlay] p'), 'rgb(64, 128, 255)')
              ]
            : [
                  captureRasterAnchor('brand', document.querySelector('.brand'), 'rgb(255, 0, 255)'),
                  captureRasterAnchor('device-rail-heading', document.querySelector('.device-rail .eyebrow'), 'rgb(127, 255, 0)'),
                  captureRasterAnchor('device-rail-toggle', document.querySelector('.device-rail__toggle i'), 'rgb(0, 127, 255)'),
                  captureRasterAnchor('main-heading', findRasterAnchorElement('.main-workspace h1, .main-workspace h2, .main-workspace h3, .main-workspace .eyebrow, .state-workspace h1'), 'rgb(255, 255, 0)'),
                  captureRasterAnchor('command-rail-heading', document.querySelector('.command-rail .eyebrow'), 'rgb(255, 0, 127)')
              ]).filter(Boolean)
        const bodyText = document.body.textContent
        const unexpectedEnabledControls = []
        const contradictoryCopy = []
        if (['routine-active', 'critical-active', 'destructive-active'].includes(state)) {
            for (const element of document.querySelectorAll('[data-operation], [data-action="manage-device"], [data-action="scan-devices"], [data-setting="auto-scan"], [role="tab"]:not([aria-selected="true"])')) {
                if (!element.disabled) unexpectedEnabledControls.push(describe(element))
            }
            if (document.querySelector('[data-operation-status] progress') === null) contradictoryCopy.push('active-progress-missing')
        }
        if (state === 'service-unavailable') {
            if (!document.querySelector('[role="alert"]')?.textContent.includes('service-unavailable')) contradictoryCopy.push('missing-service-error')
            for (const element of document.querySelectorAll('[data-setting="auto-scan"], [data-action="scan-devices"], [data-operation]')) {
                if (!element.disabled) unexpectedEnabledControls.push(describe(element))
            }
        }
        if (state === 'operation-failure') {
            const failure = document.querySelector('[data-operation-failure]')?.textContent || ''
            if (!failure.includes('transport-timeout') || !failure.includes('support-visual-01')) contradictoryCopy.push('missing-failure-provenance')
        }
        if (state === 'status' && (!bodyText.includes('RDX QuikStor USB3+ External') || !bodyText.includes('hardware unverified'))) contradictoryCopy.push('missing-fixture-device-provenance')
        if (state === 'no-device' && (document.querySelector('[data-action="manage-device"]') || !bodyText.includes('No RDX drives detected'))) contradictoryCopy.push('invented-or-missing-empty-state')
        if (state === 'starting-runtime' && !document.querySelector('[data-service-pending="starting"]')) contradictoryCopy.push('missing-starting-state')
        if (state === 'ready-no-device-runtime') {
            for (const element of document.querySelectorAll('[data-action="scan-devices"], [data-setting="auto-scan"], [data-operation]')) {
                if (!element.disabled) unexpectedEnabledControls.push(describe(element))
            }
            if (!bodyText.includes('Hardware unavailable') || !bodyText.includes('hardware-unavailable') || document.querySelector('[data-action="manage-device"]')) contradictoryCopy.push('ready-no-device-hardware-claim')
        }
        const fixtureState = ${JSON.stringify(entry.fixture)}
        if (fixtureState && document.querySelector('.fixture-note') === null) contradictoryCopy.push('fixture-provenance-missing')
        if (!fixtureState && document.querySelector('.fixture-note, .fixture-chip') !== null) contradictoryCopy.push('runtime-shows-fixture-provenance')
        if (fixtureState && /Service-reported|Validated service snapshot/.test(bodyText)) contradictoryCopy.push('fixture-and-service-provenance')
        const resourceUrls = [location.href]
        for (const resource of performance.getEntriesByType('resource')) resourceUrls.push(resource.name)
        const icons = [...document.querySelectorAll('.ph, .ph-fill, .ph-duotone')].filter(isVisible)
        const serviceStatus = document.querySelector('[data-service-status], [data-service-pending]')
        /** @returns {string} Stable visible feature surface ID. */
        function visibleSurface() {
            if (document.querySelector('[data-activity-view]')) return 'activity'
            if (document.querySelector('[data-compatibility-view]')) return 'compatibility'
            const help = document.querySelector('[data-help-view]')
            if (help) return help.dataset.helpView === 'support' ? 'support' : 'help'
            if (document.querySelector('[data-service-pending="starting"]')) return 'starting'
            if (document.querySelector('[role="alert"] #service-error-title')) return 'service-unavailable'
            if (document.querySelector('[data-encryption-view]')) return 'encryption'
            if (document.querySelector('[data-tests-view]')) return 'tests'
            if (document.querySelector('[data-utilities-view]')) return 'utilities'
            if (document.querySelector('#status-heading')) return 'status'
            if (document.querySelector('#empty-state-title')) return 'no-device'
            return 'unknown'
        }
        return {
            state,
            surface: visibleSurface(),
            language: globalThis.__openRdxVisualFixture?.language || 'en',
            viewport: { name: ${JSON.stringify(entry.viewport.name)}, width: window.innerWidth, height: window.innerHeight },
            documentOverflowX: Math.max(0, document.documentElement.scrollWidth - document.documentElement.clientWidth),
            bodyOverflowX: Math.max(0, document.body.scrollWidth - document.body.clientWidth),
            clippedElements,
            horizontalScrollOffsets,
            verticalScrollOffsets,
            topbarInViewport,
            rasterAnchors,
            unlabeledControls,
            disabledWithoutReason,
            disabledControlCount: disabledElements.length,
            disabledControls,
            disabledReasonEvidence,
            destructivePreflightEvidence,
            protectedAccessEvidence,
            updateUnavailableEvidence,
            unexpectedEnabledControls,
            contradictoryCopy,
            resourceUrls,
            computedFonts: [getComputedStyle(document.body).fontFamily, getComputedStyle(document.querySelector('h1, .brand')).fontFamily],
            iconGlyphCount: icons.filter(hasIconGlyph).length,
            csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content || '',
            serviceStatusVisible: serviceStatus !== null && isVisible(serviceStatus)
        }
    })()`)
    browserEvidence.windowBounds = window.getBounds()
    const [contentWidth, contentHeight] = window.getContentSize()
    browserEvidence.contentSize = { width: contentWidth, height: contentHeight }
    return {
        ...browserEvidence,
        keyboardEvidence: functionalEvidence,
        ...errorTracker.delta(cursor)
    }
}

/**
 * Captures and validates one exact matrix entry.
 * @param {BrowserWindow} window - Visual QA window.
 * @param {object} entry - Exact capture-plan entry.
 * @param {VisualErrorTracker} errorTracker - Complete process-owned error streams.
 * @param {Readonly<Record<string, number>>} cursor - Pre-operation error cursor.
 * @param {object|null} [functionalEvidence=null] - Keyboard evidence for the selected-device fixture.
 * @returns {Promise<object>} Validated inspection result with artifact name.
 */
async function captureEntry(window, entry, errorTracker, cursor, functionalEvidence = null) {
    await setWindowSize(window, entry.viewport)
    await positionSceneForCapture(window.webContents, entry.state)
    await stabilizeInteractionForCapture(window)
    const inspection = await inspectRenderer(window, entry, errorTracker, cursor, functionalEvidence)
    let candidateImage
    let capture
    try {
        assertVisualSnapshot(inspection, entry)
        errorTracker.assertEmptySince(cursor, `${entry.state}/${entry.viewport.name}`)
        capture = await captureValidatedVisualImage({
            /** @returns {Promise<Electron.NativeImage>} One candidate compositor frame. */
            async capture() {
                const image = await window.webContents.capturePage()
                candidateImage = entry.screenshot === rasterCorruptionInjection ? createFiducialFreeCorruptedCapture(image, entry.viewport.name) : image
                return candidateImage
            },
            /** @returns {Promise<void>} Invalidates and settles one candidate repaint. */
            async prepare() {
                window.webContents.invalidate()
                await waitForPaint(window.webContents)
            },
            /** @param {Electron.NativeImage} image - Candidate frame. @returns {object} Painted structural-anchor evidence. */
            validate(image) {
                return assertVisualRasterAnchorCrops(decodeVisualRasterAnchorCrops(image, inspection.rasterAnchors, inspection.contentSize))
            }
        })
    } catch (error) {
        // Capture only this isolated fixture's failed pixels/inspection so a
        // real paint/layout failure remains diagnosable without weakening it.
        if (!candidateImage) candidateImage = await window.webContents.capturePage()
        if (candidateImage && !candidateImage.isEmpty()) await writeFile(join(evidenceDirectory, `failed-${entry.screenshot}`), candidateImage.toPNG())
        await writeFile(join(evidenceDirectory, `failed-${entry.screenshot}.json`), JSON.stringify(inspection, null, 2))
        throw new Error(`Visual QA failed at ${entry.state}/${entry.viewport.name}: ${error.message}`, { cause: error })
    }
    const image = capture.image
    inspection.rasterEvidence = { ...capture.evidence, captureAttempts: capture.attempts }
    errorTracker.assertEmptySince(cursor, `${entry.state}/${entry.viewport.name} capture`)
    await writeVisualScreenshot(join(evidenceDirectory, entry.screenshot), image, entry.screenshot === rasterNoiseInjection, async () => {
        window.webContents.invalidate()
        await waitForPaint(window.webContents)
        const confirmationImage = await window.webContents.capturePage()
        assertVisualRasterAnchorCrops(decodeVisualRasterAnchorCrops(confirmationImage, inspection.rasterAnchors, inspection.contentSize))
        errorTracker.assertEmptySince(cursor, `${entry.state}/${entry.viewport.name} confirmation capture`)
        return confirmationImage
    })
    return { screenshot: entry.screenshot, inspection }
}

/**
 * Substitutes a same-size historical shell raster without QA fiducials to
 * simulate a stale compositor layer that still contains plausible themed
 * foreground pixels and valid dimensions.
 * @param {Electron.NativeImage} image - Complete freshly captured image.
 * @param {string} viewportName - Exact capture-plan viewport name.
 * @returns {Electron.NativeImage} Intentionally corrupted same-size image.
 */
function createFiducialFreeCorruptedCapture(image, viewportName) {
    const size = image.getSize()
    assert.ok(viewportName === 'minimum' || viewportName === 'expanded')
    const suffix = viewportName === 'expanded' ? 'expanded-1440x900' : 'minimum-1024x768'
    // Historical evidence was captured at a different DPI. Keep this negative
    // fixture dimension-valid so missing painted anchors cause its rejection.
    const corrupted = nativeImage.createFromPath(join(projectDirectory, 'docs', 'evidence', 'phase-1-task-8', `one-device-${suffix}.png`)).resize(size)
    assert.deepEqual(corrupted.getSize(), size)
    return corrupted
}

/**
 * Replaces screenshot evidence unless like-for-like physical sRGB rasters
 * differ only within the contract's tightly bounded compositor-noise budget.
 * @param {string} screenshotPath - Tracked screenshot destination.
 * @param {Electron.NativeImage} image - Freshly captured renderer image.
 * @param {boolean} injectRasterNoise - Whether to exercise the bounded noise path.
 * @param {() => Promise<Electron.NativeImage>} confirmReplacement - Captures a second painted frame only when the first contains meaningful drift.
 * @returns {Promise<void>} Resolves after preserving or replacing evidence.
 */
async function writeVisualScreenshot(screenshotPath, image, injectRasterNoise, confirmReplacement) {
    const trackedImage = nativeImage.createFromPath(screenshotPath)
    let replacementImage = image
    if (!trackedImage.isEmpty()) {
        const comparison = compareVisualImages(trackedImage, image)
        let freshRaster = comparison.freshRaster
        if (injectRasterNoise && !comparison.meaningfulDifference) {
            freshRaster = injectSingleChannelRasterNoise(comparison.trackedRaster, comparison.freshRaster)
        }
        if (!hasMeaningfulVisualDifference(comparison.trackedRaster, freshRaster)) {
            if (injectRasterNoise) console.log(`OpenRDXManager visual QA preserved injected raster noise: ${basename(screenshotPath)}`)
            return
        }
        const confirmedImage = await confirmReplacement()
        const confirmedComparison = compareVisualImages(trackedImage, confirmedImage)
        if (!confirmedComparison.meaningfulDifference) return
        // Preserve exact before/after pixels for diagnosing drift without
        // changing the comparison decision or replacing evidence prematurely.
        const driftDirectory = process.env.OPENRDX_VISUAL_QA_DIAGNOSTICS_DIRECTORY ?? join(dirname(screenshotPath), 'raster-drift')
        await mkdir(driftDirectory, { recursive: true })
        const driftName = `${process.pid}-${basename(screenshotPath)}`
        await writeFile(join(driftDirectory, `tracked-${driftName}`), trackedImage.toPNG())
        await writeFile(join(driftDirectory, `candidate-${driftName}`), image.toPNG())
        await writeFile(join(driftDirectory, `confirmed-${driftName}`), confirmedImage.toPNG())
        if (hasMeaningfulVisualDifference(comparison.freshRaster, confirmedComparison.freshRaster)) {
            throw new Error(`Visual QA screenshot remained unstable after confirmation: ${basename(screenshotPath)}`)
        }
        replacementImage = confirmedImage
        console.log(`OpenRDXManager visual QA replaced changed raster: ${basename(screenshotPath)}`)
    }
    await writeFile(screenshotPath, replacementImage.toPNG())
}

/**
 * Runs the complete deterministic visual and functional verification matrix.
 * @returns {Promise<void>} Resolves after evidence and manifest are written.
 */
async function runVisualQa() {
    await app.whenReady()
    await mkdir(evidenceDirectory, { recursive: true })
    pendingDeviceList = createDeferredDeviceList()
    const window = new BrowserWindow(visualWindowOptions)
    trustedWebContents.add(window.webContents)
    const errorTracker = new VisualErrorTracker()
    const debuggerSession = window.webContents.debugger

    /**
     * Records renderer errors from Electron 44's details-first event while
     * retaining a positional fallback without declaring deprecated parameters.
     * @param {object} details - Current Electron console message details or legacy event.
     * @returns {void}
     */
    function handleConsoleMessage(details) {
        const normalized = normalizeConsoleMessage(details, arguments)
        if (normalized !== null) errorTracker.record('consoleErrors', normalized.message)
    }
    /** @param {object} _event - Electron event. @param {number} code - Load error code. @param {string} description - Safe load description. @param {string} url - Failed URL. @param {boolean} isMainFrame - Main-frame flag. @returns {void} Records load failures. */
    function handleLoadFailure(_event, code, description, url, isMainFrame) {
        errorTracker.record('loadFailures', `${isMainFrame ? 'main' : 'sub'}:${code}:${description}:${url}`)
    }
    /** @param {object} _event - Electron event. @param {object} details - Renderer termination details. @returns {void} Records unexpected renderer exits. */
    function handleRendererGone(_event, details) {
        errorTracker.record('rendererCrashes', `${details.reason}:${details.exitCode}`)
    }
    /**
     * Records uncaught exceptions and unhandled rejections reported by the
     * renderer's DevTools Runtime domain.
     * @param {object} _event - Electron debugger event.
     * @param {string} method - DevTools protocol event name.
     * @param {object} parameters - DevTools protocol event payload.
     * @returns {void}
     */
    function handleDebuggerMessage(_event, method, parameters) {
        if (method !== 'Runtime.exceptionThrown') return
        const details = parameters?.exceptionDetails
        const message = details?.exception?.description || details?.text || 'Unspecified renderer exception'
        errorTracker.record('pageErrors', message)
    }
    window.webContents.on('console-message', handleConsoleMessage)
    window.webContents.on('did-fail-load', handleLoadFailure)
    window.webContents.on('render-process-gone', handleRendererGone)
    const results = []
    const matrix = createVisualQaMatrix()
    if (rasterNoiseInjection !== null) {
        let supportedInjection = false
        for (const entry of matrix) {
            if (entry.screenshot === rasterNoiseInjection) supportedInjection = true
        }
        assert.equal(supportedInjection, true, `Unsupported visual QA raster-noise injection: ${rasterNoiseInjection}`)
    }
    try {
        /** Loads the initial local renderer while Runtime exception capture activates. @returns {Promise<void>} */
        async function loadInitialRenderer() {
            /** Navigates the process-owned window to the local renderer. @returns {Promise<void>} */
            async function navigateToRenderer() {
                await window.loadFile(indexPath)
            }
            await loadWithPageErrorCapture(debuggerSession, handleDebuggerMessage, navigateToRenderer)
        }
        const { cursor: initialLoadCursor } = await runWithVisualErrorCursor(errorTracker, loadInitialRenderer)
        await waitForSelector(window.webContents, '[data-service-pending="starting"]')
        errorTracker.assertEmptySince(initialLoadCursor, 'initial renderer load')
        // A transition-error probe targets the real preload/service transition;
        // the complete unrelated fixture matrix is exercised by positive runs.
        const fixtureEntries = consoleErrorInjection === 'during-transition' ? [] : matrix.filter(({ fixture }) => fixture)
        for (const entry of fixtureEntries) {
            // Mount and exercise at the final capture size so Chromium cannot
            // retain sticky compositor layers from the preceding viewport.
            await setWindowSize(window, entry.viewport)
            /** Mounts, exercises, and restores one fixture under a single pre-operation cursor. @returns {Promise<object|null>} */
            async function exerciseAndRestoreFixture() {
                await injectConsoleError(window.webContents, 'before-mount')
                await mountFixture(window.webContents, entry.state)
                const evidence = await exerciseFixture(window, entry.state)
                await mountFixture(window.webContents, entry.state)
                return evidence
            }
            const { cursor: fixtureCursor, value: functionalEvidence } = await runWithVisualErrorCursor(errorTracker, exerciseAndRestoreFixture)
            results.push(await captureEntry(window, entry, errorTracker, fixtureCursor, functionalEvidence))
        }

        pendingDeviceList = createDeferredDeviceList()
        /** Reloads the production renderer for real-runtime state capture. @returns {Promise<void>} */
        async function reloadRuntimeRenderer() {
            await window.webContents.reload()
        }
        const { cursor: runtimeLoadCursor } = await runWithVisualErrorCursor(errorTracker, reloadRuntimeRenderer)
        await waitForSelector(window.webContents, '[data-service-pending="starting"]')
        for (const entry of matrix.filter(({ state }) => state === 'starting-runtime')) {
            results.push(await captureEntry(window, entry, errorTracker, runtimeLoadCursor))
        }
        errorTracker.assertEmptySince(runtimeLoadCursor, 'real-runtime renderer load and starting captures')

        /** Resolves the controlled service boundary into terminal no-device readiness. @returns {Promise<void>} */
        async function transitionToReadyNoDevice() {
            pendingDeviceList.resolve({ ok: true, status: 'ready', mode: 'no-device', privileged: false, hardwareReady: false, hardwareVerified: false, platformCapability: { state: 'transport-unavailable', reason: 'native-service-not-implemented' }, epoch: 1, listRevision: 0, devices: [] })
            await injectConsoleError(window.webContents, 'during-transition')
        }
        const { cursor: transitionCursor } = await runWithVisualErrorCursor(errorTracker, transitionToReadyNoDevice)
        await waitForSelector(window.webContents, '[data-service-status="ready"]')
        await waitForPaint(window.webContents)
        for (const entry of matrix.filter(({ state }) => state === 'ready-no-device-runtime')) {
            results.push(await captureEntry(window, entry, errorTracker, transitionCursor))
        }
        errorTracker.assertEmptySince(transitionCursor, 'ready/no-device transition and captures')

        assert.equal(results.length, matrix.length)
        errorTracker.assertGloballyEmpty()
        await writeFile(join(evidenceDirectory, 'visual-qa-results.json'), serializeVisualQaManifest(results))
        await writeFile(join(evidenceDirectory, 'visual-qa-capture-metrics.json'), serializeVisualQaCaptureMetrics(results))
    } finally {
        window.webContents.removeListener('console-message', handleConsoleMessage)
        window.webContents.removeListener('did-fail-load', handleLoadFailure)
        window.webContents.removeListener('render-process-gone', handleRendererGone)
        debuggerSession.removeListener('message', handleDebuggerMessage)
        if (debuggerSession.isAttached()) debuggerSession.detach()
        trustedWebContents.delete(window.webContents)
        ipcController.dispose()
        ipcMain.removeHandler(WindowMenuChannel.list)
        ipcMain.removeHandler(WindowMenuChannel.open)
        window.destroy()
    }
}

/** @returns {Promise<void>} Runs visual QA and reports its outcome without blocking Electron readiness. */
async function runVisualQaEntrypoint() {
    try {
        await runVisualQa()
        console.log(`OpenRDXManager visual QA passed: ${createVisualQaMatrix().length} screenshots in ${evidenceDirectory}`)
        app.exit(0)
    } catch (error) {
        console.error(error)
        app.exit(1)
    }
}

void runVisualQaEntrypoint()
