// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { contextBridge, ipcRenderer } from 'electron'

import { createPreloadApi } from './preload-api.mjs'
import { mountWindowMenu } from './preload-window-menu.mjs'
import { mountWindowFrame } from './preload-window-frame.mjs'
import { IpcChannel } from './shared/ipc-contract.mjs'

contextBridge.exposeInMainWorld('openRdx', createPreloadApi(ipcRenderer))
const disposeWindowFrame = mountWindowFrame({ document, transport: ipcRenderer })
window.addEventListener('unload', disposeWindowFrame, { once: true })

/**
 * Reports renderer mounting over a fixed internal channel only after the local
 * module renderer has populated the application root. This does not add a
 * callable method or channel selector to the public preload API.
 * @returns {boolean} True after reporting a successfully mounted shell.
 */
function reportMountedRenderer() {
    if (document.querySelector('#app > .application-shell') !== null) {
        ipcRenderer.send(IpcChannel.APP_RENDERER_MOUNTED)
        return true
    }
    return false
}

/** @returns {void} Waits only for the local asynchronous settings bootstrap to mount its shell. */
function observeRendererMount() {
    if (reportMountedRenderer()) return
    const root = document.querySelector('#app')
    if (root === null) return
    const observer = new MutationObserver(() => {
        if (reportMountedRenderer()) observer.disconnect()
    })
    observer.observe(root, { childList: true })
}

window.addEventListener('DOMContentLoaded', observeRendererMount, { once: true })
/** @returns {Promise<void>} Mounts the application menus through the isolated preload. */
async function mountNativeMenuStrip() {
    await mountWindowMenu({ document, transport: ipcRenderer })
}
window.addEventListener('DOMContentLoaded', mountNativeMenuStrip, { once: true })
