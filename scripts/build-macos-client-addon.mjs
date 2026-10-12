// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { copyFile, lstat, mkdir, rename, rm } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import { validateSigningBuildEnvironment } from './signing-build-policy.mjs'

const execFileAsync = promisify(execFile)
const require = createRequire(import.meta.url)
const projectRoot = fileURLToPath(new URL('..', import.meta.url))

/**
 * Returns fixed source, build, and staging paths for the direct macOS client.
 * @param {{root?: string}} [options] - Absolute project root override for tests.
 * @returns {{addonRoot: string, artifactPath: string, runtimePath: string}} Controlled paths.
 */
export function getMacOsClientAddonBuildPaths({ root = projectRoot } = {}) {
    if (!isAbsolute(root)) throw new TypeError('macos-client-project-root-invalid')
    const normalized = resolve(root)
    const addonRoot = join(normalized, 'native', 'macos-client-addon')
    return {
        addonRoot,
        artifactPath: join(addonRoot, 'build', 'Release', 'openrdx_macos_client.node'),
        runtimePath: join(normalized, 'out', 'native', 'macos', 'openrdx-macos-client.node')
    }
}

/** @param {string} path - Expected regular file. @returns {Promise<void>} Rejects links and non-files. */
async function requireRegularFile(path) {
    const metadata = await lstat(path)
    if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error('macos-client-artifact-invalid')
}

/**
 * Builds and atomically stages the handle-free macOS N-API client.
 * Non-macOS hosts return without attempting an unverifiable host build.
 * @param {{platform?: string, root?: string, environment?: NodeJS.ProcessEnv}} [options] - Controlled host, root, and compile-time signing authority.
 * @returns {Promise<{runtimePath: string, skipped: boolean}>} Stage result.
 */
export async function buildMacOsClientAddon({ platform = process.platform, root = projectRoot, environment: buildEnvironment = process.env } = {}) {
    const team = getMacOsClientCompiledTeam(buildEnvironment)
    const paths = getMacOsClientAddonBuildPaths({ root })
    if (platform !== 'darwin') return { runtimePath: paths.runtimePath, skipped: true }
    await requireRegularFile(join(paths.addonRoot, 'binding.gyp'))
    await requireRegularFile(join(paths.addonRoot, 'openrdx_macos_client.cc'))
    const sdk = await execFileAsync('/usr/bin/xcrun', ['--sdk', 'macosx', '--show-sdk-path'])
    const environment = { ...buildEnvironment, SDKROOT: buildEnvironment.SDKROOT ?? sdk.stdout.trim() }
    await execFileAsync('cargo', ['build', '--release', '--locked', '--manifest-path', join(paths.addonRoot, 'Cargo.toml'), '--target-dir', join(paths.addonRoot, 'build', 'trust')], { env: environment, maxBuffer: 16 * 1024 * 1024 })
    const nodeGyp = require.resolve('node-gyp/bin/node-gyp.js')
    await execFileAsync(process.execPath, [nodeGyp, 'configure', '--release', `--openrdx_macos_team_id=${team}`], {
        cwd: paths.addonRoot,
        env: environment,
        maxBuffer: 16 * 1024 * 1024
    })
    await execFileAsync(process.execPath, [nodeGyp, 'build', '--release'], { cwd: paths.addonRoot, env: environment, maxBuffer: 16 * 1024 * 1024 })
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

/**
 * Validate canonical and legacy build-time Team ID aliases before native build.
 * Empty authority selects local-only builds; malformed/mismatched values deny.
 * @param {NodeJS.ProcessEnv} environment - Build configuration, never runtime enrollment.
 * @returns {string} Canonical compiled team or empty local-only authority.
 */
export function getMacOsClientCompiledTeam(environment) {
    if (environment === null || typeof environment !== 'object') throw new TypeError('macos-client-build-environment-invalid')
    validateSigningBuildEnvironment(environment)
    return environment.OPENRDX_MACOS_TEAM_ID ?? environment.OPENRDX_MANAGER_TEAM_ID ?? ''
}

/** @returns {boolean} True only for direct CLI execution. */
function isDirectInvocation() {
    return process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)
}

/** @returns {Promise<void>} Runs the bounded staging command. */
async function runCommand() {
    try {
        await buildMacOsClientAddon()
    } catch {
        process.stderr.write('macos-client-build-failed\n')
        process.exitCode = 1
    }
}

if (isDirectInvocation()) await runCommand()
