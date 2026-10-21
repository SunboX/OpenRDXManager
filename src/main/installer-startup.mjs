// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFile, writeFile } from 'node:fs/promises'
import { setTimeout } from 'node:timers/promises'

/**
 * Delays UI and service startup while the installer enrolls this process's user.
 * The signal grants no trust: normal native service authentication still runs.
 * @param {string} path - Installer-owned completion file.
 * @param {object} options - Injectable filesystem, delay and bounded poll count.
 * @returns {Promise<void>} Resolves only on successful installer completion.
 * @throws {Error} On failed setup, inaccessible signal or timeout.
 */
export async function waitForInstallerResult(path, { read = readFile, acknowledge = writeFile, sleep = setTimeout, attempts = 720 } = {}) {
    for (let attempt = 0; attempt < attempts; attempt += 1) {
        try {
            const result = await read(path, 'utf8')
            if (result === 'ready') {
                await acknowledge(`${path}.ack`, 'received', { flag: 'r+' })
                return
            }
            if (result === 'failed') throw new Error('Installer setup failed')
            // File creation and its short write are separate installer operations.
            if (result !== '') throw new Error('Invalid installer result')
        } catch (error) {
            if (error.code !== 'ENOENT') throw error
        }
        await sleep(250)
    }
    throw new Error('Installer setup timed out')
}
