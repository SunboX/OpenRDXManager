// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createRequire } from 'node:module'
import { win32 } from 'node:path'

const require = createRequire(import.meta.url)

/**
 * Resolves the same fixed Windows known-folder location as the native backup store.
 * @param {string} addonPath - Main-owned compiled native addon, never renderer input.
 * @param {Function} [loadAddon] - Test dependency for the native query.
 * @returns {string} Absolute local backup path for main-process folder opening only.
 * @throws {Error} If the native query is unavailable or returns an invalid path.
 */
export function windowsManufacturingDirectory(addonPath, loadAddon = require) {
    const directory = loadAddon(addonPath).manufacturingBackupDirectory()
    if (typeof directory !== 'string' || !/^[A-Za-z]:\\/u.test(directory) || !win32.isAbsolute(directory) || !directory.endsWith('\\OpenRDXManager\\manufacturing-backups')) throw new Error('manufacturing-folder-unavailable')
    return directory
}
