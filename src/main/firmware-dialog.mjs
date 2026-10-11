// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Opens the firmware chooser as a modal child of the current application window.
 * @param {{BrowserWindow: object, dialog: object}} dependencies - Main-owned Electron APIs.
 * @param {object} options - Bounded firmware chooser options.
 * @returns {Promise<object>} Native selection result; no device operation is dispatched.
 * @throws {Error} When there is no live application window or the dialog fails.
 */
export async function showFirmwareOpenDialog({ BrowserWindow, dialog }, options) {
    const focused = BrowserWindow.getFocusedWindow()
    const window = focused && !focused.isDestroyed() ? focused : BrowserWindow.getAllWindows().find((candidate) => !candidate.isDestroyed())
    if (!window) throw new Error('firmware-dialog-window-unavailable')
    // Parenting keeps GTK/portal and macOS dialogs attached to the visible app.
    if (window.isMinimized()) window.restore()
    window.show()
    window.focus()
    return await dialog.showOpenDialog(window, options)
}
