// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { setTimeout as delay } from 'node:timers/promises'

/**
 * Waits for actual Chromium resize readback, not merely two frames at the old
 * Windows client size. The exact requested dimensions remain mandatory.
 * @param {object} window - Owned acceptance BrowserWindow.
 * @param {number} width - Exact test viewport width.
 * @param {number} height - Exact test viewport height.
 * @param {object} [options] - Bounded test scheduling overrides.
 * @param {number} [options.maxAttempts=150] - Maximum observed resize attempts.
 * @param {Function} [options.wait=delay] - Asynchronous delay between observations.
 * @returns {Promise<void>} Resolves only after exact viewport and paint readback.
 */
export async function resizeAcceptanceWindow(window, width, height, { maxAttempts = 150, wait = delay } = {}) {
    window.setContentSize(width, height)
    let actual
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        actual = await window.webContents.executeJavaScript('({ width: innerWidth, height: innerHeight })')
        if (actual.width === width && actual.height === height) {
            await window.webContents.executeJavaScript('new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)))')
            actual = await window.webContents.executeJavaScript('({ width: innerWidth, height: innerHeight })')
            if (actual.width === width && actual.height === height) return
        }
        if (attempt + 1 < maxAttempts) await wait(20)
    }
    throw new Error(`Acceptance viewport did not resize to ${width}x${height}: ${JSON.stringify(actual)}`)
}
