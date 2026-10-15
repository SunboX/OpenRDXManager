// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Keeps the owned QA renderer's existing background-paint policy after loads.
 * Register before the first navigation; dispose before destroying the window.
 * @param {Electron.WebContents} webContents - Secure process-owned QA renderer.
 * @param {import('./visual-error-tracker.mjs').VisualErrorTracker} errorTracker - Existing fail-closed load error stream.
 * @returns {() => void} Removes only this registration's exact load listener.
 */
export function registerVisualBackgroundPolicy(webContents, errorTracker) {
    /** @returns {void} Reapplies the configured QA policy after each loaded document. */
    function handleDidFinishLoad() {
        try {
            // Reload can leave a hidden renderer's first RAF pending even while
            // the getter remains false. Reapply the existing QA policy to the
            // newly loaded native view; do not change production preferences.
            webContents.setBackgroundThrottling(false)
        } catch (error) {
            errorTracker.record('loadFailures', `visual background policy: ${error instanceof Error ? error.message : String(error)}`)
        }
    }
    webContents.on('did-finish-load', handleDidFinishLoad)
    /** @returns {void} Releases this owned listener without changing unrelated observers. */
    return function disposeVisualBackgroundPolicy() {
        webContents.removeListener('did-finish-load', handleDidFinishLoad)
    }
}
