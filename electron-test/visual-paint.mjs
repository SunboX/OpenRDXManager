// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Waits for local fonts and two complete paint frames in the isolated renderer.
 * This function is serialized by the harness and uses only browser APIs.
 * @param {boolean} [trace=false] - Records optional test-only progress without changing the awaited work.
 * @returns {Promise<void>} Resolves after fonts and layout have settled.
 */
export async function waitForRendererVisualPaint(trace = false) {
    const progress = trace ? (globalThis.__openRdxVisualPaintTrace = { phase: 'layout' }) : null
    // New locale text can request additional Unicode subsets only when layout
    // runs; do not await the already resolved font cycle from the prior scene.
    document.documentElement.getBoundingClientRect()
    if (progress) progress.phase = 'await-fonts'
    await document.fonts.ready
    if (progress) progress.phase = 'await-raf-1'
    await new Promise(requestAnimationFrame.bind(globalThis))
    if (progress) progress.phase = 'await-raf-2'
    await new Promise(requestAnimationFrame.bind(globalThis))
    if (progress) progress.phase = 'done'
}
