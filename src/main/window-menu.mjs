// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { WindowMenuChannel } from '../shared/window-menu.mjs'

/**
 * Registers a bounded native-menu boundary for the isolated title-bar preload.
 * @param {object} dependencies - Electron APIs and the existing local sender policy.
 * @param {string} [dependencies.platform] - Host platform, injectable for tests.
 * @returns {void} Registers two private handlers without exposing native menu creation.
 */
export function registerWindowMenu({ ipcMain, Menu, BrowserWindow, isTrustedSender, platform = process.platform }) {
    /** @param {object} event - Invoke sender. @returns {boolean} Fails closed for detached or untrusted renderers. */
    function trusted(event) {
        try {
            return isTrustedSender(event) === true
        } catch {
            return false
        }
    }
    /** @param {object} event - Trusted preload sender. @returns {Promise<object[]>} Visible native top-level labels, without callbacks or submenus. */
    async function list(event) {
        if (!trusted(event) || platform === 'darwin') return []
        return (Menu.getApplicationMenu()?.items ?? []).flatMap((item, index) =>
            item.submenu && item.visible !== false
                ? [
                      {
                          index,
                          label: item.label
                              .replace(/&&/gu, '\u0000')
                              .replace(/&/gu, '')
                              .replace(/\u0000/gu, '&'),
                          enabled: item.enabled !== false
                      }
                  ]
                : []
        )
    }
    /** @param {object} event - Trusted preload sender. @param {unknown} request - Bounded menu index and popup anchor. @returns {Promise<object>} Completion after the native popup closes. */
    async function open(event, request) {
        if (!trusted(event) || platform === 'darwin' || !request || typeof request !== 'object') return { ok: false }
        if (Object.keys(request).length !== 3 || !['index', 'x', 'y'].every((key) => Number.isSafeInteger(request[key]) && request[key] >= 0)) return { ok: false }
        const item = Menu.getApplicationMenu()?.items[request.index]
        const window = BrowserWindow.fromWebContents(event.sender)
        if (!item?.submenu || item.enabled === false || item.visible === false || !window || window.isDestroyed()) return { ok: false }
        const bounds = window.getContentBounds()
        if (request.x >= bounds.width || request.y >= bounds.height) return { ok: false }
        try {
            // Adapt Electron's native popup callback once, retaining menu roles and accelerators.
            await new Promise((resolve) => item.submenu.popup({ window, x: request.x, y: request.y, callback: resolve }))
            return { ok: true }
        } catch {
            return { ok: false }
        }
    }
    ipcMain.handle(WindowMenuChannel.list, list)
    ipcMain.handle(WindowMenuChannel.open, open)
}
