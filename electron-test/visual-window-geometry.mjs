// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

const titlebarInsetsByWindow = new WeakMap()

/**
 * Waits for the renderer viewport before asking Cocoa to publish overlay layout.
 * @param {{width: number, height: number}} expected - Exact native content size.
 * @returns {Promise<void>} Resolves on matching bounds or fails after five seconds.
 */
export async function waitForRendererViewport(expected) {
    const deadline = performance.now() + 5000
    while (innerWidth !== expected.width || innerHeight !== expected.height) {
        if (performance.now() >= deadline) throw new Error('Timed out waiting for resized renderer viewport')
        await new Promise(requestAnimationFrame.bind(globalThis))
    }
}

/**
 * Waits for the native overlay and its CSS title to match the resized content
 * viewport. Electron can deliver the viewport resize before overlay geometry.
 * This function is serialized into the isolated renderer and uses only DOM APIs.
 * @param {{width: number, height: number, titlebarInsets: {left: number, right: number}|null}} expected - Target CSS bounds and measured control reservation.
 * @returns {Promise<void>} Resolves on exact geometry or throws after five seconds.
 */
export async function waitForRendererWindowGeometry(expected) {
    const deadline = performance.now() + 5000
    let observed
    while (true) {
        const overlay = navigator.windowControlsOverlay
        const safe = overlay?.getTitlebarAreaRect()
        const title = document.querySelector('.window-titlebar__title')?.getBoundingClientRect()
        observed = { width: innerWidth, height: innerHeight, overlay: safe ? { x: safe.x, width: safe.width } : null, title: title ? { left: title.left, width: title.width } : null }
        const insets = expected.titlebarInsets
        const expectedTitleWidth = insets === null ? expected.width : expected.width - insets.left - insets.right
        const overlayReady = insets === null || (overlay.visible && safe.x === insets.left && safe.width === expectedTitleWidth && title?.left === safe.x && title?.width === safe.width)
        if (innerWidth === expected.width && innerHeight === expected.height && overlayReady) return
        if (performance.now() >= deadline) throw new Error(`Timed out waiting for native window geometry: ${JSON.stringify({ expected, observed })}`)
        await new Promise(requestAnimationFrame.bind(globalThis))
    }
}

/**
 * Resizes a QA window and awaits its actual native content/overlay geometry.
 * Native control insets are measured once before any QA resizing, so a stale
 * overlay after a resize cannot be mistaken for the target geometry.
 * @param {Electron.BrowserWindow} window - Owned secure visual QA window.
 * @param {{width: number, height: number}} viewport - Supported outer bounds.
 * @param {string} [platform=process.platform] - Native QA host; injected in unit fixtures.
 * @returns {Promise<void>} Resolves after the native overlay and DOM title agree.
 */
export async function resizeVisualWindow(window, viewport, platform = process.platform) {
    if (!titlebarInsetsByWindow.has(window)) {
        const initial = await window.webContents.executeJavaScript(`
            /** Reads the initial native control reservation. @returns {object|null} Insets for the visible overlay. */
            (function readNativeTitlebarInsets() {
                const overlay = navigator.windowControlsOverlay
                if (!overlay?.visible) return null
                const safe = overlay.getTitlebarAreaRect()
                return { left: safe.x, right: innerWidth - safe.x - safe.width }
            })()`)
        titlebarInsetsByWindow.set(window, initial)
    }
    window.setBounds({ x: 40, y: 40, width: viewport.width, height: viewport.height }, false)
    const content = window.getContentBounds()
    const expected = { width: content.width, height: content.height, titlebarInsets: titlebarInsetsByWindow.get(window) }
    await window.webContents.executeJavaScript(`(${waitForRendererViewport.toString()})(${JSON.stringify(expected)})`)
    if (platform === 'darwin' && expected.titlebarInsets !== null) {
        // Electron 44's Cocoa resize notification can precede content-view size
        // propagation. Reaffirming the existing visibility explicitly publishes
        // native overlay layout after the viewport settles, without changing
        // controls. Final API/CSS assertions below remain exact.
        // A measured visible overlay already establishes visible controls;
        // Electron exposes a setter but no public visibility getter.
        window.setWindowButtonVisibility(true)
    }
    await window.webContents.executeJavaScript(`(${waitForRendererWindowGeometry.toString()})(${JSON.stringify(expected)})`)
}

/**
 * Settles the native viewport before replacing the renderer's overlay cache.
 * Reloading at the previous expanded size can leave Chromium's overlay API
 * stale after the following shrink even while CSS and content bounds update.
 * @param {Electron.BrowserWindow} window - Owned secure visual QA window.
 * @param {{width: number, height: number}} viewport - First real-runtime capture size.
 * @param {string} [platform=process.platform] - Native QA host; injected in unit fixtures.
 * @returns {Promise<void>} Resolves after strict resize validation and reload request.
 */
export async function reloadVisualRuntimeAtViewport(window, viewport, platform = process.platform) {
    await resizeVisualWindow(window, viewport, platform)
    await window.webContents.reload()
}
