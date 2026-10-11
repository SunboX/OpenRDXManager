// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { copyFile, lstat, mkdir, rename, rm } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'

const execFileAsync = promisify(execFile)
const require = createRequire(import.meta.url)
const projectRoot = fileURLToPath(new URL('..', import.meta.url))

/**
 * Returns fixed source, build, and staging paths for the direct Windows client.
 * @param {{root?: string}} [options] - Absolute project root override for tests.
 * @returns {{addonRoot: string, artifactPath: string, runtimePath: string}} Controlled paths.
 */
export function getWindowsClientAddonBuildPaths({ root = projectRoot } = {}) {
    if (!isAbsolute(root)) throw new TypeError('windows-client-project-root-invalid')
    const normalized = resolve(root)
    const addonRoot = join(normalized, 'native', 'windows-client-addon')
    return {
        addonRoot,
        artifactPath: join(addonRoot, 'build', 'Release', 'openrdx_windows_client.node'),
        runtimePath: join(normalized, 'out', 'native', 'windows', 'openrdx-windows-client.node')
    }
}

/** @param {string} path - Expected regular file. @returns {Promise<void>} Rejects links and non-files. */
async function requireRegularFile(path) {
    const metadata = await lstat(path)
    if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error('windows-client-artifact-invalid')
}

/**
 * Builds and atomically stages the handle-free Windows N-API client.
 * Non-Windows hosts return without attempting an unverifiable host build.
 * @param {{platform?: string, root?: string}} [options] - Controlled host and root.
 * @returns {Promise<{runtimePath: string, skipped: boolean}>} Stage result.
 */
export async function buildWindowsClientAddon({ platform = process.platform, root = projectRoot } = {}) {
    const paths = getWindowsClientAddonBuildPaths({ root })
    if (platform !== 'win32') return { runtimePath: paths.runtimePath, skipped: true }
    await requireRegularFile(join(paths.addonRoot, 'binding.gyp'))
    await requireRegularFile(join(paths.addonRoot, 'openrdx_windows_client.cc'))
    const nodeGyp = require.resolve('node-gyp/bin/node-gyp.js')
    await execFileAsync(process.execPath, [nodeGyp, 'rebuild', '--release'], {
        cwd: paths.addonRoot,
        windowsHide: true,
        maxBuffer: 16 * 1024 * 1024
    })
    await requireRegularFile(paths.artifactPath)
    await mkdir(dirname(paths.runtimePath), { recursive: true, mode: 0o700 })
    const temporary = `${paths.runtimePath}.stage-${process.pid}`
    await rm(temporary, { force: true })
    try {
        await copyFile(paths.artifactPath, temporary)
        await requireRegularFile(temporary)
        await rename(temporary, paths.runtimePath)
    } finally {
        await rm(temporary, { force: true })
    }
    return { runtimePath: paths.runtimePath, skipped: false }
}

/** @returns {boolean} True only for direct CLI execution. */
function isDirectInvocation() {
    return process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)
}

/** @returns {Promise<void>} Runs the bounded staging command. */
async function runCommand() {
    try {
        await buildWindowsClientAddon()
    } catch {
        process.stderr.write('windows-client-build-failed\n')
        process.exitCode = 1
    }
}

if (isDirectInvocation()) await runCommand()
