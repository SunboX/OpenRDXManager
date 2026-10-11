// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import path from 'node:path'

/**
 * Resolves the shipped stdio bridge for an external Node.js client. Node cannot
 * load Electron ASAR archives, so installers expose the bridge and its imports
 * in the sibling unpacked tree. Source and legacy directory bundles stay local.
 * @param {string} applicationPath - Trusted Electron app.getAppPath() result.
 * @param {typeof path} [paths=path] - Native path implementation; injected for cross-platform tests.
 * @returns {string} Absolute ordinary-file bridge entrypoint.
 * @throws {TypeError} When the application root is relative or malformed.
 */
export function resolveMcpBridgePath(applicationPath, paths = path) {
    if (typeof applicationPath !== 'string' || applicationPath.includes('\0') || !paths.isAbsolute(applicationPath)) throw new TypeError('mcp-application-path-invalid')
    const root = applicationPath.endsWith('.asar') ? `${applicationPath}.unpacked` : applicationPath
    return paths.join(root, 'scripts', 'mcp-stdio.mjs')
}
