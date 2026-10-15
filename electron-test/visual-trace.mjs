// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const traceStarted = performance.now()

/**
 * Reports an optional timestamped boundary in this owned visual process.
 * The trace changes no renderer state and is absent unless explicitly enabled.
 * @param {string} phase - Bounded test operation about to start or just completed.
 * @returns {void} Writes only diagnostic stderr, never manifest evidence.
 */
export function traceVisualPhase(phase) {
    // A quiet probe keeps the pending-paint snapshot without per-boundary I/O.
    if (process.env.OPENRDX_VISUAL_QA_TRACE === '1' && process.env.OPENRDX_VISUAL_QA_TRACE_QUIET !== '1') console.error(`visual-phase: ${phase} elapsedMs=${Math.round(performance.now() - traceStarted)} pid=${process.pid}`)
}

/**
 * Observes one slow paint wait without changing the window, DOM or its awaits.
 * @param {Electron.WebContents} webContents - Owned isolated visual renderer.
 * @param {Electron.BrowserWindow|null} window - Owned window for fixed public-state diagnostics.
 * @returns {() => void} Cancels the optional diagnostic timer after the wait ends.
 */
export function observeVisualPaintWait(webContents, window) {
    if (process.env.OPENRDX_VISUAL_QA_TRACE !== '1') {
        /** @returns {void} Leaves tracing disabled without scheduling or observing renderer work. */
        return function stopDisabledPaintObservation() {}
    }
    /** @returns {Promise<void>} Reads fixed progress fields from the owned renderer once. */
    async function readPendingPaint() {
        try {
            const windowState = { visible: window?.isVisible() ?? null, minimized: window?.isMinimized() ?? null, focused: window?.isFocused() ?? null, backgroundThrottling: webContents.getBackgroundThrottling() }
            const state = await webContents.executeJavaScript(`
                /** @returns {object} Fixed read-only state while a paint promise remains pending. */
                (function readVisualPaintProgress() {
                    return { phase: globalThis.__openRdxVisualPaintTrace?.phase ?? null, readyState: document.readyState, fontStatus: document.fonts.status, visibility: document.visibilityState }
                })()`)
            traceVisualPhase(`paint:pending-state:${JSON.stringify(state)}`)
            const directory = process.env.OPENRDX_VISUAL_QA_DIAGNOSTICS_DIRECTORY
            if (directory) {
                await mkdir(directory, { recursive: true })
                await writeFile(join(directory, `paint-pending-${process.pid}.json`), JSON.stringify({ ...state, window: windowState, elapsedMs: Math.round(performance.now() - traceStarted), pid: process.pid }, null, 2))
            }
        } catch (error) {
            traceVisualPhase(`paint:pending-read-failed:${error.name}`)
        }
    }
    const timer = setTimeout(readPendingPaint, 1000)
    timer.unref()
    /** @returns {void} Stops only this wait's unused diagnostic timer. */
    return function stopObservingPaint() {
        clearTimeout(timer)
    }
}
