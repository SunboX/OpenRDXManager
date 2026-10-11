// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { windowFrameChannel } from './shared/window-frame.mjs'

/**
 * Reflects a bounded, main-owned native state in the isolated preload's DOM.
 * @param {object} dependencies - Document and fixed Electron event transport.
 * @param {Document} dependencies.document - Local application document.
 * @param {object} dependencies.transport - Private ipcRenderer, never exposed to page code.
 * @returns {Function} Removes the owned listeners when this document is unloaded.
 */
export function mountWindowFrame({ document, transport }) {
    // Only main's Windows controller opts into native-edge compensation.
    // Other platforms receive no notification and retain their flush frame.
    let state = null
    /** @returns {void} Applies the latest notification, including one received before DOM readiness. */
    function apply() {
        if (state !== null) document.documentElement?.setAttribute('data-window-frame', state)
    }
    /** @param {object} _event - Private Electron event. @param {unknown} value - Closed frame enum. @returns {void} Ignores malformed payloads without exposing native controls. */
    function receive(_event, value) {
        if (value !== 'restored' && value !== 'maximized') return
        state = value
        apply()
    }
    /** @returns {void} Releases only this document's listeners. */
    function dispose() {
        transport.removeListener(windowFrameChannel, receive)
        document.removeEventListener('DOMContentLoaded', apply)
    }
    transport.on(windowFrameChannel, receive)
    document.addEventListener('DOMContentLoaded', apply, { once: true })
    apply()
    return dispose
}
