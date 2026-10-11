// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { spawnSync } from 'node:child_process'

/**
 * Refreshes the administrator credential used only by the subsequently
 * spawned debug helper. Electron and its renderer remain unprivileged.
 * @returns {void} Exits nonzero when authorization is unavailable or refused.
 */
function authorizeDevelopmentService() {
    if (!['darwin', 'linux'].includes(process.platform)) return
    const result = spawnSync('/usr/bin/sudo', ['-v'], { stdio: 'inherit' })
    if (result.error !== undefined || result.status !== 0) {
        process.stderr.write('OpenRDXManager: development hardware-service authorization failed.\n')
        process.exitCode = 1
    }
}

authorizeDevelopmentService()
