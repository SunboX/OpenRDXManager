// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { symlink } from 'node:fs/promises'

/** Creates a real link or records precisely the unavailable Windows privilege.
 * @param {object} context - Owner of this one symlink-only test/subtest.
 * @param {string} target - Disposable fixture target.
 * @param {string} path - Disposable fixture link.
 * @returns {Promise<boolean>} Whether the real-link assertions can run.
 */
export async function createSymlinkFixture(context, target, path) {
    try {
        await symlink(target, path)
        return true
    } catch (error) {
        if (process.platform !== 'win32' || error.code !== 'EPERM') throw error
        context.skip('Windows file-symlink privilege unavailable; native junction/hardlink checks run separately')
        return false
    }
}
