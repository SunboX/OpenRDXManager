// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { lstat, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { promisify } from 'node:util'
import { resolveMcpBridgePath } from '../src/main/mcp/bridge-path.mjs'
import { resolveWindowsMcpAddonPath } from '../src/main/mcp/windows-addon-path.mjs'

const execute = promisify(execFile)

/**
 * Imports the shipped MCP bridge through ordinary Node, proving ASAR unpacking
 * and transitive SDK availability. The entrypoint is checked but never executed;
 * no endpoint, credentials or device operation is started. Windows additionally
 * loads the app-owned N-API addon without constructing its storage object.
 * @param {string} resourcesDirectory - Trusted packaged resources directory.
 * @param {object} [options] - Host defaults and isolated process-test injection.
 * @param {string} [options.platform=process.platform] - Packaged host platform.
 * @param {Function} [options.executeImpl=execute] - External Node process runner.
 * @returns {Promise<string>} Successful external Node evidence marker.
 * @throws {Error} For missing ordinary files, failed imports or missing exports.
 */
export async function verifyPackagedMcpBridge(resourcesDirectory, { platform = process.platform, executeImpl = execute } = {}) {
    const entrypoint = resolveMcpBridgePath(join(resourcesDirectory, 'app.asar'))
    if (!(await lstat(entrypoint)).isFile()) throw new Error('packaged-mcp-entrypoint-not-regular-file')
    const applicationRoot = dirname(dirname(entrypoint))
    const moduleUrl = pathToFileURL(join(applicationRoot, 'src', 'main', 'mcp', 'stdio-bridge.mjs')).href
    const windowsCheck =
        platform === 'win32'
            ? `
const require = createRequire(import.meta.url)
const addon = require(${JSON.stringify(resolveWindowsMcpAddonPath(applicationRoot, undefined))})
if (typeof addon.createMcpStorage !== 'function') throw new Error('packaged-mcp-native-export-missing')
`
            : ''
    const source = `
import { createRequire } from 'node:module'
const bridge = await import(${JSON.stringify(moduleUrl)})
if (typeof bridge.startStdioBridge !== 'function') throw new Error('packaged-mcp-bridge-export-missing')
${windowsCheck}
console.log('OpenRDXManager packaged MCP bridge passed: external-node=true')
`
    const result = await executeImpl(process.execPath, ['--input-type=module', '-e', source], { timeout: 30_000, maxBuffer: 1024 * 1024, windowsHide: true })
    if (!result.stdout.includes('OpenRDXManager packaged MCP bridge passed: external-node=true')) throw new Error('packaged-mcp-import-marker-missing')
    return result.stdout.trim()
}

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
        const resources = process.platform === 'darwin' ? join(dirname(dirname(executable)), 'Resources') : join(dirname(executable), 'resources')
        console.log(await verifyPackagedMcpBridge(resources))
    } finally {
        await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 })
    }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) await verifyPackagedApplication()
