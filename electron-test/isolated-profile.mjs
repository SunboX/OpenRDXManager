// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { mkdirSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { isAbsolute, join } from 'node:path'

/**
 * Selects a disposable Electron profile before main-module evaluation finishes.
 * This boundary must be synchronous: awaiting app readiness here deadlocks ESM
 * startup, and changing paths after readiness can reuse the real app's caches.
 * The parent test owns cleanup of the supplied directory after Electron exits.
 * @param {object} app - Electron app or a synchronous test double.
 * @param {string|undefined} directory - Optional parent-owned absolute profile path.
 * @returns {string} Unique profile path, never the production user-data directory.
 * @throws {Error} If the path is relative or profile initialization fails.
 */
export function initializeIsolatedElectronProfile(app, directory) {
    if (directory !== undefined && !isAbsolute(directory)) throw new Error('Electron test profile must be an absolute path')
    const profile = directory ?? mkdtempSync(join(tmpdir(), 'openrdx-electron-profile-'))
    mkdirSync(profile, { recursive: true })
    app.setPath('userData', profile)
    app.setPath('sessionData', profile)
    return profile
}
