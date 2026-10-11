// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const execute = promisify(execFile)
const aclScript = fileURLToPath(new URL('./windows-log-acl.ps1', import.meta.url))

/**
 * Gives an isolated Windows fixture the current desktop user's owner SID.
 * Elevated runners otherwise create Administrators-owned files; production
 * storage correctly refuses those as belonging to another security principal.
 * @param {string} path - Existing isolated test file or directory.
 * @param {{privateAccess?: boolean}} [options] - Optionally create an explicit user-only DACL for a fixture that production must leave untouched.
 * @returns {Promise<void>} Completes after ownership is set; no-op on other hosts.
 */
export async function ownWindowsFixture(path, { privateAccess = false } = {}) {
    if (process.platform !== 'win32') return
    await execute('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['-NoProfile', '-File', aclScript, path, privateAccess ? 'private-as-user' : 'own-as-user'], { windowsHide: true, timeout: 10_000 })
}
