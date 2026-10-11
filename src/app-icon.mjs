// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const iconDirectory = fileURLToPath(new URL('../resources/icons/', import.meta.url))

export const linuxDesktopEntryId = 'io.openrdx.OpenRDXManager'

export const appIconPaths = Object.freeze({
    darwin: join(iconDirectory, 'app-icon.icns'),
    linux: join(iconDirectory, 'app-icon.png'),
    win32: join(iconDirectory, 'app-icon.ico')
})

/**
 * Resolves the native application icon for one supported Electron platform.
 * @param {string} platform - Node.js platform identifier.
 * @returns {string} Absolute platform-native icon path.
 * @throws {TypeError} When the platform has no shipped icon contract.
 */
export function getAppIconPath(platform) {
    const path = appIconPaths[platform]
    if (path === undefined) throw new TypeError('app-icon-platform-unsupported')
    return path
}
