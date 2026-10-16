// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createLogFileSecurity } from '../../src/main/log-file-security.mjs'

/**
 * Gates terminal appends while retaining the real logger and POSIX filesystem.
 * @returns {{fileSecurity: object, terminalWriteStarted: Promise<object>, release: () => void}} Explicit terminal persistence boundary; release also permits cleanup after assertion failure.
 */
export function createTerminalRuntimeLog() {
    // The owning runtime fixture explicitly uses darwin on every CI host;
    // retain its pre-existing POSIX storage semantics, including on Windows.
    const storage = createLogFileSecurity({ platform: 'darwin' })
    const entered = Promise.withResolvers()
    const gate = Promise.withResolvers()
    return {
        terminalWriteStarted: entered.promise,
        release: gate.resolve,
        fileSecurity: {
            prepareDirectory: storage.prepareDirectory.bind(storage),
            openRead: storage.openRead.bind(storage),
            removeFile: storage.removeFile.bind(storage),
            renameFile: storage.renameFile.bind(storage),
            /** @param {string} path - Logger-owned append path. @returns {Promise<object>} Real handle with an explicitly gated terminal append. */
            async openAppend(path) {
                const handle = await storage.openAppend(path)
                return {
                    stat: handle.stat.bind(handle),
                    read: handle.read.bind(handle),
                    close: handle.close.bind(handle),
                    /** @param {string} line - Sanitized JSONL record. @param {object} options - Native append options. @returns {Promise<void>} Resolves after the gate and real append; preserves filesystem errors. */
                    async writeFile(line, options) {
                        const record = JSON.parse(line)
                        if (record.event === 'operation-lifecycle' && ['succeeded', 'failed', 'cancelled'].includes(record.details.state)) {
                            entered.resolve(record)
                            await gate.promise
                        }
                        await handle.writeFile(line, options)
                    }
                }
            }
        }
    }
}
