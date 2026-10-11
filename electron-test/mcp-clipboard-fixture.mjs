// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Isolates the text-only clipboard surface for unattended acceptance tests.
 * Production main/preload copy actions still run, but no host clipboard is read
 * or replaced. Other clipboard formats are deliberately outside this fixture.
 * @param {object} clipboard - Electron's main-process clipboard API.
 * @returns {Function} Idempotent restoration of the original method identities.
 */
export function installPrivateClipboardFixture(clipboard) {
    if (typeof clipboard?.readText !== 'function' || typeof clipboard?.writeText !== 'function') throw new TypeError('invalid-acceptance-clipboard')
    const originalRead = clipboard.readText
    const originalWrite = clipboard.writeText
    let text = ''
    let restored = false
    /** @returns {string} Only text written during this fixture session. */
    function readText() {
        return text
    }
    /** @param {string} value - Test-owned copied configuration. @returns {void} Stores no host clipboard data. */
    function writeText(value) {
        if (typeof value !== 'string') throw new TypeError('invalid-acceptance-clipboard-text')
        text = value
    }
    clipboard.readText = readText
    try {
        clipboard.writeText = writeText
    } catch (error) {
        clipboard.readText = originalRead
        throw error
    }
    /** @returns {void} Releases fixture text and restores the real API without calling it. */
    return function restoreClipboard() {
        if (restored) return
        restored = true
        text = ''
        clipboard.readText = originalRead
        clipboard.writeText = originalWrite
    }
}
