// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { windowFrameChannel } from '../shared/window-frame.mjs'

/** Keeps Windows-only frame painting synchronized with the native window state. */
export class WindowFrameController {
    #window
    #contents
    #publish
    #dispose

    /**
     * @param {Electron.BrowserWindow} window - Main-owned local application window.
     * @param {string} [platform] - Host platform, injectable for deterministic tests.
     * @returns {WindowFrameController} Registers read-only notifications on Windows.
     */
    constructor(window, platform = process.platform) {
        this.#window = window
        this.#publish = this.publish.bind(this)
        this.#dispose = this.dispose.bind(this)
        if (platform !== 'win32') return
        // BrowserWindow.webContents itself becomes inaccessible after 'closed'.
        // Retain the EventEmitter reference while the native window is alive.
        this.#contents = window.webContents
        for (const event of ['maximize', 'unmaximize', 'enter-full-screen', 'leave-full-screen']) window.on(event, this.#publish)
        // A reload replaces the isolated preload, so replay the current native state.
        this.#contents.on('did-finish-load', this.#publish)
        window.once('closed', this.#dispose)
    }

    /** @returns {void} Publishes only a closed state enum; never performs a device operation. */
    publish() {
        const window = this.#window
        if (window.isDestroyed() || this.#contents?.isDestroyed() !== false) return
        const state = window.isMaximized() && !window.isFullScreen() ? 'maximized' : 'restored'
        this.#contents.send(windowFrameChannel, state)
    }

    /** @returns {void} Detaches exactly the listeners owned by this controller. */
    dispose() {
        const window = this.#window
        for (const event of ['maximize', 'unmaximize', 'enter-full-screen', 'leave-full-screen']) window.removeListener(event, this.#publish)
        this.#contents?.removeListener('did-finish-load', this.#publish)
        window.removeListener('closed', this.#dispose)
    }
}
