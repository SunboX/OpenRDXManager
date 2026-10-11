// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { promisify } from 'node:util'

const execute = promisify(execFile)

/**
 * Launches the actual packaged app against an isolated profile, with no service installation.
 * Runtime success proves renderer mounting and bounded unavailable/ready service reporting,
 * not physical hardware operation or operating-system signing trust.
 * @returns {Promise<void>} Resolves only after the packaged smoke marker is observed.
 * @throws {Error} For launch failure, timeout or missing smoke evidence.
 */
async function verifyPackagedApplication() {
    const arm = process.arch === 'arm64'
    const directory = resolve('dist/installers')
    const executable =
        process.platform === 'linux' && process.argv.includes('--installed')
            ? '/opt/OpenRDXManager/OpenRDXManager'
            : {
                  darwin: join(directory, arm ? 'mac-arm64' : 'mac', 'OpenRDXManager.app', 'Contents/MacOS/OpenRDXManager'),
                  win32: join(directory, arm ? 'win-arm64-unpacked' : 'win-unpacked', 'OpenRDXManager.exe'),
                  linux: join(directory, arm ? 'linux-arm64-unpacked' : 'linux-unpacked', 'OpenRDXManager')
              }[process.platform]
    if (!executable) throw new Error('unsupported-packaged-platform')
    const profile = await mkdtemp(join(tmpdir(), 'openrdx-packaged-smoke-'))
    const environment = { ...process.env }
    delete environment.ELECTRON_RUN_AS_NODE
    try {
        const result = await execute(executable, ['--smoke-test', `--user-data-dir=${profile}`], { env: environment, timeout: 60_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true })
        const output = `${result.stdout}${result.stderr}`
        if (!output.includes('OpenRDXManager smoke test passed: renderer=mounted')) throw new Error(`packaged-smoke-marker-missing: ${output}`)
        console.log(output.trim())
    } finally {
        await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 })
    }
}

await verifyPackagedApplication()
