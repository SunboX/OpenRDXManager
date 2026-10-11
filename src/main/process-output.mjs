// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Keeps a detached launcher's closed console pipe from terminating the desktop.
 * Other stream errors retain their normal exception behavior. This does not
 * handle application exceptions or change the native service protocol streams.
 * @param {NodeJS.WriteStream[]} streams - Main-process console output streams.
 * @returns {void} Installs handlers for the lifetime of this main process.
 */
export function containBrokenConsolePipes(streams = [process.stdout, process.stderr]) {
    for (const stream of new Set(streams)) {
        stream.on('error', handleConsoleError)
    }
}

/**
 * Contains only a pipe that its consumer has closed.
 * @param {Error & {code?: string}} error - Writable output failure.
 * @returns {void} Leaves EPIPE contained so active device operations can finish.
 * @throws {Error} For every other output failure.
 */
function handleConsoleError(error) {
    if (error.code !== 'EPIPE') throw error
}
