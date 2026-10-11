// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Waits for local fonts and two complete paint frames in the isolated renderer.
 * This function is serialized by the harness and uses only browser APIs.
 * @returns {Promise<void>} Resolves after fonts and layout have settled.
 */
export async function waitForRendererVisualPaint() {
    // New locale text can request additional Unicode subsets only when layout
    // runs; do not await the already resolved font cycle from the prior scene.
    document.documentElement.getBoundingClientRect()
    await document.fonts.ready
    await new Promise(requestAnimationFrame.bind(globalThis))
    await new Promise(requestAnimationFrame.bind(globalThis))
}
