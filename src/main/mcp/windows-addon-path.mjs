// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import path from 'node:path'

/**
 * Resolves only the app-owned native credential addon. External Node has no
 * Electron resourcesPath, but the unpacked ASAR root identifies the trusted
 * sibling resources directory. Credential/client inputs never select a DLL.
 * @param {string} applicationRoot - Root derived from this module's own file URL.
 * @param {string|undefined} resourcesPath - Electron-owned resources directory when present.
 * @param {typeof path} [paths=path] - Native paths; injected for Windows tests.
 * @returns {string} Fixed absolute native addon path.
 */
export function resolveWindowsMcpAddonPath(applicationRoot, resourcesPath, paths = path) {
    const root = paths.resolve(applicationRoot)
    if (paths.basename(root) === 'app.asar.unpacked') return paths.join(paths.dirname(root), 'native', 'windows', 'openrdx-windows-client.node')
    if (root.endsWith('.asar') && typeof resourcesPath === 'string') return paths.join(resourcesPath, 'native', 'windows', 'openrdx-windows-client.node')
    return paths.join(root, 'out', 'native', 'windows', 'openrdx-windows-client.node')
}
