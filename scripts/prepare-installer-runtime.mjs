// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { chmod, copyFile, mkdir } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { buildMacOsServiceManagementAddon } from './build-macos-service-management.mjs'
import { buildWindowsClientAddon } from './build-windows-client-addon.mjs'

const execute = promisify(execFile)
const root = fileURLToPath(new URL('..', import.meta.url))

/**
 * Compiles release-mode helpers on the native host, retaining existing service policy.
 * No service registration, elevation or hardware operation occurs during packaging.
 * @returns {Promise<void>} Resolves after all required native files are staged.
 * @throws {Error} If compilation, addon creation or staging fails.
 */
async function prepareInstallerRuntime() {
    const folder = { darwin: 'macos', win32: 'windows', linux: 'linux' }[process.platform]
    if (!folder) throw new Error('unsupported-installer-platform')
    const suffix = process.platform === 'win32' ? '.exe' : ''
    const destination = join(root, 'out', 'native', folder)
    const target = join(root, 'out', 'installer-native')
    await execute('cargo', ['build', '--release', '--locked', '--manifest-path', join(root, 'native/rdx-service/Cargo.toml'), '--target-dir', target, '--bin', 'openrdx-hardware', '--bin', 'rdxctl'], { cwd: root, maxBuffer: 32 * 1024 * 1024 })
    await mkdir(destination, { recursive: true })
    for (const binary of ['openrdx-hardware', 'rdxctl']) {
        const output = join(destination, `${binary}${suffix}`)
        await copyFile(join(target, 'release', `${binary}${suffix}`), output)
        if (process.platform !== 'win32') await chmod(output, 0o755)
    }
    if (process.platform === 'darwin') {
        await buildMacOsServiceManagementAddon({ outputPath: join(destination, 'openrdx-service-management.node'), projectRoot: root })
    }
    if (process.platform === 'win32') {
        await buildWindowsClientAddon()
        const provisionerTarget = join(root, 'out', 'installer-provisioner')
        await execute('cargo', ['build', '--release', '--locked', '--manifest-path', join(root, 'native/rdx-service/windows-native/Cargo.toml'), '--target-dir', provisionerTarget, '--bin', 'openrdx-service-acl'], { cwd: root, maxBuffer: 32 * 1024 * 1024 })
        await copyFile(join(provisionerTarget, 'release', 'openrdx-service-acl.exe'), join(destination, 'openrdx-service-acl.exe'))
    }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) await prepareInstallerRuntime()
