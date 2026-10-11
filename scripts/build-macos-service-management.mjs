// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { lstat, mkdir, rename, rm } from 'node:fs/promises'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'

const execFileAsync = promisify(execFile)
const defaultProjectRoot = fileURLToPath(new URL('..', import.meta.url))

/**
 * Verifies one existing regular source file without following a final symlink.
 * @param {string} path - Fixed source path.
 * @returns {Promise<void>} Resolves for one regular non-link file.
 * @throws {Error} When the source is absent or unsafe.
 */
async function verifySourceFile(path) {
    const metadata = await lstat(path)
    if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error('macos-service-management-source-invalid')
}

/**
 * Builds the fixed macOS ServiceManagement N-API addon.
 * @param {{outputPath: string, projectRoot?: string, execFileImpl?: Function, nodeIncludePath?: string}} options - Controlled build inputs.
 * @returns {Promise<string>} Absolute published addon path.
 * @throws {TypeError|Error} For unsupported hosts, paths, sources, or compiler failures.
 */
export async function buildMacOsServiceManagementAddon(options) {
    const projectRoot = resolve(options?.projectRoot ?? defaultProjectRoot)
    const outputPath = options?.outputPath
    if (typeof outputPath !== 'string' || !isAbsolute(outputPath) || outputPath === projectRoot || !outputPath.endsWith('/openrdx-service-management.node')) {
        throw new TypeError('macos-service-management-output-invalid')
    }
    if (process.platform !== 'darwin') throw new Error('macos-service-management-unsupported-platform')
    const sourcePath = join(projectRoot, 'native', 'service-management', 'macos', 'openrdx_service_management.mm')
    const nodeIncludePath = resolve(options.nodeIncludePath ?? join(dirname(process.execPath), '..', 'include', 'node'))
    await verifySourceFile(sourcePath)
    await verifySourceFile(join(nodeIncludePath, 'node_api.h'))
    const outputDirectory = dirname(outputPath)
    await mkdir(outputDirectory, { recursive: true, mode: 0o700 })
    const temporaryPath = join(outputDirectory, `.openrdx-service-management-${randomUUID()}.node`)
    const execFileImpl = options.execFileImpl ?? execFileAsync
    try {
        await execFileImpl('/usr/bin/xcrun', ['--sdk', 'macosx', 'clang++', '-std=c++20', '-fobjc-arc', '-mmacosx-version-min=13.0', '-bundle', '-undefined', 'dynamic_lookup', '-I', nodeIncludePath, '-framework', 'Foundation', '-framework', 'ServiceManagement', sourcePath, '-o', temporaryPath], { maxBuffer: 16 * 1024 * 1024 })
        await rename(temporaryPath, outputPath)
        return outputPath
    } finally {
        await rm(temporaryPath, { force: true })
    }
}

/** @returns {Promise<void>} Builds the development runtime addon at the fixed path. */
async function main() {
    if (process.platform !== 'darwin') return
    await buildMacOsServiceManagementAddon({ outputPath: join(defaultProjectRoot, 'out', 'native', 'macos', 'openrdx-service-management.node') })
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    await main()
}
