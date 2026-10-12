// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { createRequire } from 'node:module'
import { copyFile, lstat, mkdir, mkdtemp, rename, rm } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'

const execute = promisify(execFile)
const require = createRequire(import.meta.url)
const { UUID } = require('builder-util-runtime')
const { getMakeNsisPath } = require('app-builder-lib/out/toolsets/windows.js')
const { nsisEscapeString } = require('app-builder-lib/out/targets/nsis/nsisScriptGenerator.js')
const project = fileURLToPath(new URL('..', import.meta.url))
const builderNamespace = UUID.parse('50e065bc-3134-11e6-9bab-38c9862bdaf3')

/**
 * Matches electron-builder's uninstall registry identity for this fixed application.
 * @param {{appId: string, guid?: string}} options Build metadata; no runtime overrides.
 * @returns {{guid: string, installKey: string, uninstallKey: string}} Fixed registry keys.
 * @throws {Error} For unrelated applications or malformed explicit GUIDs.
 */
export function windowsRemoverIdentity({ appId, guid }) {
    if (appId !== 'com.openrdx.manager' || (guid !== undefined && !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/iu.test(guid))) throw new Error('windows-remover-identity-invalid')
    const identity = guid ?? UUID.v5(appId, builderNamespace)
    return { guid: identity, installKey: `Software\\${identity}`, uninstallKey: `Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${identity}` }
}

/**
 * Compiles a normal NSIS entrypoint, avoiding the uninstaller's pre-hook self-copy.
 * Stages final bytes before runtime inventory so both NSIS and ZIP pin the remover.
 * @param {{root: string, appId: string, version: string, guid?: string, projectRoot?: string, resolveCompiler?: Function, compile?: Function}} options Controlled packaging context and injected build operations.
 * @returns {Promise<string>} Final remover path.
 * @throws {Error} On compilation, invalid output, or atomic publication failure.
 */
export async function buildWindowsRemover({ root, appId, version, guid, projectRoot = project, resolveCompiler = () => getMakeNsisPath('1.2.1'), compile = execute }) {
    const identity = windowsRemoverIdentity({ appId, guid })
    if (!/^\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$/iu.test(version)) throw new Error('windows-remover-version-invalid')
    const outputDirectory = join(projectRoot, 'out')
    await mkdir(outputDirectory, { recursive: true })
    await mkdir(root, { recursive: true })
    const scratch = await mkdtemp(join(outputDirectory, 'windows-remover-'))
    const output = join(scratch, 'remover.exe')
    const destination = join(root, 'Uninstall OpenRDXManager.exe')
    const temporary = join(root, `.openrdx-remover-${scratch.split(/[\\/]/u).at(-1)}.tmp`)
    try {
        const tool = await resolveCompiler()
        // A .cmd wrapper cannot be executed directly by Node on Windows. Use
        // its checksum-pinned real compiler and the same bundle's data directory.
        const compiler = process.platform === 'win32' ? join(dirname(tool.path), 'windows', 'makensis.exe') : tool.path
        const values = { OUTPUT_FILE: output, BUILD_RESOURCES_DIR: join(projectRoot, 'resources/installer'), APP_GUID: identity.guid, VERSION: version }
        const args = ['-V2', ...Object.entries(values).map(([name, value]) => `-D${name}=${nsisEscapeString(value)}`), join(projectRoot, 'resources/installer/windows-remover.nsi')]
        await compile(compiler, args, { env: { ...process.env, ...tool.env, ...(process.platform === 'win32' ? { NSISDIR: join(dirname(tool.path), 'windows') } : {}) }, maxBuffer: 16 * 1024 * 1024, windowsHide: true })
        const metadata = await lstat(output)
        if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size === 0) throw new Error('windows-remover-output-invalid')
        await copyFile(output, temporary)
        await rename(temporary, destination)
        return destination
    } finally {
        await rm(temporary, { force: true })
        await rm(scratch, { recursive: true, force: true })
    }
}
