// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { app, BrowserWindow, Menu, nativeTheme } from 'electron/main'
import { resizeAcceptanceWindow } from './acceptance-window-size.mjs'
import { normalizeConsoleMessage } from './visual-error-tracker.mjs'

const root = fileURLToPath(new URL('..', import.meta.url))

/**
 * Waits for production startup and layout without issuing device operations.
 * @param {Function} predicate - Async readiness observation.
 * @returns {Promise<*>} First truthy result.
 * @throws {Error} When the bounded readiness deadline expires.
 */
async function until(predicate) {
    for (let attempt = 0; attempt < 400; attempt++) {
        const value = await predicate()
        if (value) return value
        await delay(50)
    }
    throw new Error('Window chrome did not become ready')
}

/** @returns {Promise<void>} Inspects the real application chrome in an isolated desktop session. */
async function verify() {
    const deadline = setTimeout(() => app.exit(1), 60_000)
    try {
        const output = await mkdtemp(join(tmpdir(), 'openrdx-window-chrome-'))
        app.setPath('userData', join(output, 'preferences'))
        app.getAppPath = () => root
        const consoleErrors = []
        /** @param {object} event - Electron creation event. @param {Electron.WebContents} contents - Owned renderer. @returns {void} Observes errors without changing renderer privileges. */
        function observeRendererErrors(event, contents) {
            /** @param {object} details - Electron console message. @returns {void} Retains error-level evidence across all window transitions. */
            function recordConsoleError(details) {
                const error = normalizeConsoleMessage(details, arguments)
                if (error) consoleErrors.push(error.message)
            }
            contents.on('console-message', recordConsoleError)
        }
        app.on('web-contents-created', observeRendererErrors)
        await import('../src/main.mjs')
        const window = await until(async () => {
            const candidate = BrowserWindow.getAllWindows()[0]
            if (!candidate || candidate.webContents.isLoading()) return null
            return (await candidate.webContents.executeJavaScript('Boolean(document.querySelector("#app > .application-shell"))')) && candidate
        })
        assert.equal(nativeTheme.themeSource, 'dark')
        assert.equal(window.webContents.getTitle(), 'OpenRDXManager')
        assert.equal(window.webContents.getURL(), pathToFileURL(join(root, 'src', 'index.html')).href)
        assert.equal(nativeTheme.shouldUseDarkColors, true)
        assert.equal(window.isMenuBarVisible(), false)
        assert.ok(Menu.getApplicationMenu()?.items.length > 0)
        if (process.platform !== 'darwin') {
            await until(() => window.webContents.executeJavaScript('document.querySelectorAll(".window-menubar button").length >= 4'))
            const submenu = Menu.getApplicationMenu().items.find((item) => item.submenu).submenu
            const shown = once(submenu, 'menu-will-show')
            await window.webContents.executeJavaScript('document.querySelector(".window-menubar button").click()')
            await shown
            submenu.closePopup(window)
            await until(() => window.webContents.executeJavaScript('document.querySelector(".window-menubar button").getAttribute("aria-expanded") === "false"'))
        }
        const evidence = []
        for (const [mode, width, height] of [
            ['wide', 1280, 800],
            // Windows rounds the 768-DIP native minimum to 769 at fractional DPI.
            // Keep the narrow-width case above that platform minimum.
            ['narrow', 1024, 800],
            ['minimum', 1024, 769],
            // Adjacent client sizes exercise fractional physical-pixel rounding
            // around the user's restored window, rather than only round sizes.
            ['resize-a', 1099, 779],
            ['resize-b', 1100, 780],
            ['resize-c', 1101, 781],
            ['resize-d', 1102, 782],
            ['resize-e', 1103, 783],
            ['continuous-resize', 1103, 783],
            ['maximized', null, null],
            ['restored', 1024, 769]
        ]) {
            window.show()
            window.focus()
            if (mode === 'maximized') {
                const maximized = once(window, 'maximize')
                window.maximize()
                await maximized
                assert.equal(window.isMaximized(), true)
                const bounds = window.getContentBounds()
                await until(() => window.webContents.executeJavaScript(`innerWidth === ${bounds.width} && innerHeight === ${bounds.height}`))
            } else {
                if (window.isMaximized()) {
                    const restored = once(window, 'unmaximize')
                    window.unmaximize()
                    await restored
                }
                if (mode === 'continuous-resize') {
                    for (let step = 0; step < 60; step++) {
                        window.setContentSize(1024 + (step % 30) * 10, 780 + (step % 20))
                        await delay(16)
                    }
                }
                await resizeAcceptanceWindow(window, width, height)
            }
            const expectedFrameInset = process.platform !== 'win32' ? 0 : mode === 'maximized' ? 2 : 0.5
            await until(() => window.webContents.executeJavaScript(`getComputedStyle(document.querySelector('#app'), '::after').right === '${expectedFrameInset}px'`))
            const layout = await window.webContents.executeJavaScript(`(async () => {
            await document.fonts.ready;
            await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
            const bar = document.querySelector('.window-titlebar');
            const title = document.querySelector('.window-titlebar__title');
            const style = getComputedStyle(bar);
            const titleRect = title.getBoundingClientRect();
            const controls = navigator.windowControlsOverlay;
            const safe = controls?.getTitlebarAreaRect();
            const frame = getComputedStyle(document.querySelector('#app'), '::after');
            return {
                width: innerWidth, height: innerHeight,
                pixelRatio: devicePixelRatio,
                backgroundImage: getComputedStyle(document.body).backgroundImage,
                scanlines: getComputedStyle(document.body, '::after').backgroundImage,
                frame: { top: parseFloat(frame.top), right: parseFloat(frame.right), bottom: parseFloat(frame.bottom), left: parseFloat(frame.left), width: parseFloat(frame.borderRightWidth), hitTesting: frame.pointerEvents },
                dark: matchMedia('(prefers-color-scheme: dark)').matches,
                background: style.backgroundColor, drag: style.webkitAppRegion,
                barHeight: bar.getBoundingClientRect().height,
                menuHeight: document.querySelector('.window-menubar').getBoundingClientRect().height,
                menuBackground: getComputedStyle(document.querySelector('.window-menubar')).backgroundColor,
                titleLeft: titleRect.left, titleRight: titleRect.right,
                overlayVisible: controls?.visible ?? false,
                safe: safe ? { x: safe.x, width: safe.width } : null,
                dashboardTop: document.querySelector('#app').getBoundingClientRect().top,
                /** @returns {object} Painted shell and workspace bounds in CSS pixels. */
                shell: (() => {
                    const element = document.querySelector('.application-shell');
                    const rect = element.getBoundingClientRect();
                    const style = getComputedStyle(element);
                    const workspace = element.querySelector('.shell-grid, .state-workspace').getBoundingClientRect();
                    return { right: rect.right, bottom: rect.bottom, borderRight: parseFloat(style.borderRightWidth), borderBottom: parseFloat(style.borderBottomWidth), workspaceRight: workspace.right, workspaceBottom: workspace.bottom };
                })(),
                horizontalOverflow: document.documentElement.scrollWidth > innerWidth,
                documentHeight: document.documentElement.scrollHeight,
                clientWidth: document.documentElement.clientWidth,
                nodeIntegration: typeof globalThis.require !== 'undefined'
            };
        })()`)
            assert.equal(layout.dark, true)
            // Performance tuning must retain both glows and the scanline overlay.
            assert.equal((layout.backgroundImage.match(/radial-gradient/g) ?? []).length, 2)
            assert.match(layout.scanlines, /repeating-linear-gradient/)
            assert.equal(layout.background, 'rgb(8, 20, 34)')
            assert.equal(layout.drag, 'drag')
            assert.ok(layout.barHeight >= 30 && layout.barHeight <= 40)
            assert.equal(layout.dashboardTop, layout.barHeight + layout.menuHeight)
            assert.equal(layout.menuBackground, 'rgb(8, 20, 34)')
            assert.equal(layout.horizontalOverflow, false)
            assert.ok(layout.documentHeight <= layout.height + 0.5, 'Desktop scrolling must stay inside the shell')
            assert.ok(layout.clientWidth >= layout.width - 0.5, 'No outer scrollbar gutter may separate the frame from the window')
            // Chromium may round a 1px rule down to a physical pixel at fractional DPI.
            assert.ok(layout.shell.borderRight > 0 && layout.shell.borderRight <= 1)
            assert.ok(layout.shell.borderBottom > 0 && layout.shell.borderBottom <= 1)
            // innerWidth/Height round fractional CSS viewport dimensions to integers.
            assert.ok(layout.shell.right <= layout.width + 0.5, 'Shell must remain inside the viewport')
            assert.ok(layout.shell.bottom <= layout.height + 0.5, 'Shell must remain inside the viewport')
            assert.equal(layout.frame.right, expectedFrameInset)
            assert.equal(layout.frame.bottom, expectedFrameInset)
            assert.equal(layout.frame.left, expectedFrameInset)
            assert.equal(layout.frame.top, layout.dashboardTop)
            assert.equal(layout.frame.hitTesting, 'none')
            assert.ok(layout.frame.width > 0)
            // Layout rectangles and computed CSS widths have different serialization precision.
            assert.ok(layout.shell.workspaceRight <= layout.shell.right - layout.shell.borderRight + 0.01, `Workspace must not paint over the right border: ${JSON.stringify(layout.shell)}`)
            assert.ok(layout.shell.workspaceBottom <= layout.shell.bottom - layout.shell.borderBottom + 0.01, `Workspace must not paint over the bottom border: ${JSON.stringify(layout.shell)}`)
            assert.equal(layout.nodeIntegration, false)
            assert.equal(layout.overlayVisible, true)
            assert.ok(layout.titleLeft >= layout.safe.x)
            assert.ok(layout.titleRight <= layout.safe.x + layout.safe.width + 1)
            // Native resize and preload style notifications can precede the
            // compositor's submitted frame even after renderer animation frames.
            await delay(150)
            const image = await window.webContents.capturePage()
            await writeFile(join(output, `window-${mode}.png`), image.toPNG())
            const bitmap = image.toBitmap()
            const raster = image.getSize()
            // Sample inside the frame, away from the client pixels Windows clips
            // at maximized resize edges. Scaling derives from actual capture size.
            for (const [x, y] of [
                [Math.floor(raster.width - ((layout.frame.right + layout.frame.width / 2) * raster.width) / layout.shell.right), Math.floor(raster.height / 2)],
                [Math.floor(raster.width / 2), Math.floor(raster.height - ((layout.frame.bottom + layout.frame.width / 2) * raster.height) / layout.shell.bottom)]
            ]) {
                const offset = (y * raster.width + x) * 4
                assert.ok(bitmap[offset + 1] > bitmap[offset + 2] + 30, `Turquoise border must be painted at ${x},${y} (${mode}, ${JSON.stringify(layout.frame)}): ${output}`)
            }
            // Force long content at the user's restored size: removing the outer
            // scrollbar must not make content below the fold unreachable.
            if (mode === 'restored') {
                const overflow = await window.webContents.executeJavaScript(`(async () => {
                    const workspace = document.querySelector('.application-shell > .state-workspace, .shell-grid');
                    const probe = document.createElement('div');
                    probe.style.minHeight = '1600px';
                    probe.style.gridColumn = '1 / -1';
                    workspace.append(probe);
                    try {
                        await new Promise(resolve => requestAnimationFrame(resolve));
                        workspace.scrollTop = workspace.scrollHeight;
                        return { height: innerHeight, documentHeight: document.documentElement.scrollHeight, scrollTop: workspace.scrollTop, workspaceHeight: workspace.clientHeight, scrollHeight: workspace.scrollHeight, overflow: getComputedStyle(workspace).overflowY, probeHeight: probe.getBoundingClientRect().height };
                    } finally {
                        probe.remove();
                        workspace.scrollTop = 0;
                    }
                })()`)
                assert.ok(overflow.documentHeight <= overflow.height + 0.5, 'Long content must not reintroduce document scrolling')
                assert.ok(overflow.scrollTop > 0, `Long restored-window content must remain reachable by workspace scrolling: ${JSON.stringify(overflow)}`)
            }
            evidence.push({ mode, gpu: app.getGPUFeatureStatus(), ...layout })
        }
        assert.deepEqual(consoleErrors, [], 'Window transitions must not emit renderer console errors')
        await writeFile(join(output, 'evidence.json'), JSON.stringify(evidence, null, 2))
        console.log(`Window chrome Electron acceptance passed: ${output}`)
        clearTimeout(deadline)
        app.quit()
    } catch (error) {
        console.error(error)
        clearTimeout(deadline)
        app.exit(1)
    }
}

// Electron finishes evaluating the entry module before emitting app readiness.
void verify()
