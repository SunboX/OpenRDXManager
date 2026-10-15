// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execute = promisify(execFile)

/**
 * Owns one visual-test runtime directly, without npm or a command shell.
 * @param {string} executable - Electron executable or finite process-test fixture.
 * @param {string[]} args - Exact runtime arguments.
 * @param {{cwd?: string, env?: object, timeoutMs?: number}} [options] - Runtime environment and test deadline.
 * @returns {Promise<{stdout: string, stderr: string}>} Captured output after the child closes.
 * @throws {Error} For launch failure, timeout or an unsuccessful runtime exit.
 */
export async function runVisualProcess(executable, args, { cwd, env, timeoutMs = 180_000 } = {}) {
    // npm catches SIGTERM and waits for its script, so its timeout can outlive
    // the deadline or even resolve successfully with incomplete captured output.
    // Own the real runtime and terminate only that child at the same deadline.
    const pending = execute(executable, args, { cwd, env, timeout: timeoutMs, killSignal: 'SIGKILL', windowsHide: true, maxBuffer: 5 * 1024 * 1024 })
    const closed = new Promise((resolve) => pending.child.once('close', resolve))
    try {
        return await pending
    } finally {
        // A signal being sent is insufficient evidence of termination. Retain
        // the child until Node observes close and has reaped the direct process.
        await closed
    }
}
