// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { lstat } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { promisify } from 'node:util'
import { FuseV1Options, FuseVersion, getCurrentFuseWire } from '@electron/fuses'
import { resolveMcpBridgePath } from '../src/main/mcp/bridge-path.mjs'
import { resolveWindowsMcpAddonPath } from '../src/main/mcp/windows-addon-path.mjs'
import { withPackagedSmokeProfile } from './packaged-smoke-diagnostics.mjs'

export { withPackagedSmokeProfile } from './packaged-smoke-diagnostics.mjs'

const execute = promisify(execFile)

/**
 * Keeps the external watchdog above each installed Windows/macOS auth smoke gate.
 * @param {{platform: string, installed: boolean, requireService: boolean}} options - Verifier-owned launch state.
 * @returns {number} Fixed watchdog; all other verification stays at 60 seconds.
 */
export function resolvePackagedSmokeProcessTimeout(options) {
    if (options.installed !== true || options.requireService !== true) return 60_000
    return options.platform === 'win32' ? 135_000 : options.platform === 'darwin' ? 90_000 : 60_000
}

/**
 * Selects the exact installer-owned path or native build output.
 * @param {{platform?: string, arch?: string, installed?: boolean}} [options] - Verification host and installation state.
 * @returns {string} Native executable path matching the service identity contract.
 * @throws {Error} For an unsupported platform or architecture.
 */
export function resolvePackagedExecutable({ platform = process.platform, arch = process.arch, installed = false } = {}) {
    if (!['arm64', 'x64'].includes(arch)) throw new Error('unsupported-packaged-architecture')
    const directory = resolve('dist/installers')
    const executable = installed
        ? { darwin: '/Applications/OpenRDXManager.app/Contents/MacOS/OpenRDXManager', win32: 'C:\\Program Files\\OpenRDXManager\\OpenRDXManager.exe', linux: '/opt/OpenRDXManager/OpenRDXManager' }[platform]
        : {
              darwin: join(directory, arch === 'arm64' ? 'mac-arm64' : 'mac', 'OpenRDXManager.app', 'Contents/MacOS/OpenRDXManager'),
              win32: join(directory, arch === 'arm64' ? 'win-arm64-unpacked' : 'win-unpacked', 'OpenRDXManager.exe'),
              linux: join(directory, arch === 'arm64' ? 'linux-arm64-unpacked' : 'linux-unpacked', 'OpenRDXManager')
          }[platform]
    if (!executable) throw new Error('unsupported-packaged-platform')
    return executable
}

/**
 * Reads the shipped Electron binary rather than trusting build configuration.
 * @param {string} executable - Final packaged/installed Electron executable.
 * @returns {Promise<void>} Resolves only for disabled startup bypasses and enabled ASAR integrity.
 * @throws {Error} For absent, unsupported or unsafe fuse states.
 */
export async function verifyPackagedElectronFuses(executable) {
    const wire = await getCurrentFuseWire(executable)
    if (wire.version !== FuseVersion.V1) throw new Error('packaged-electron-fuse-version-invalid')
    for (const option of [FuseV1Options.RunAsNode, FuseV1Options.EnableNodeOptionsEnvironmentVariable, FuseV1Options.EnableNodeCliInspectArguments]) {
        if (wire[option] !== 48) throw new Error(`packaged-electron-fuse-invalid: ${FuseV1Options[option]}`)
    }
    for (const option of [FuseV1Options.EnableEmbeddedAsarIntegrityValidation, FuseV1Options.OnlyLoadAppFromAsar]) {
        if (wire[option] !== 49) throw new Error(`packaged-electron-fuse-invalid: ${FuseV1Options[option]}`)
    }
}

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
 * Launches the actual packaged app against an isolated profile. This verifier
 * never installs services; --installed --require-service demands an already
 * enrolled installation and its authenticated privileged native handshake.
 * Runtime success proves renderer mounting and bounded unavailable/ready service reporting,
 * not physical hardware operation or operating-system signing trust.
 * @returns {Promise<void>} Resolves only after the packaged smoke marker is observed.
 * @throws {Error} For launch failure, timeout or missing smoke evidence.
 */
async function verifyPackagedApplication() {
    const installed = process.argv.includes('--installed')
    const requireService = process.argv.includes('--require-service')
    if (requireService && !installed) throw new Error('service-acceptance-requires-installed-runtime')
    const executable = resolvePackagedExecutable({ installed })
    if (process.platform !== 'linux') await verifyPackagedElectronFuses(executable)
    const environment = { ...process.env }
    delete environment.ELECTRON_RUN_AS_NODE
    await withPackagedSmokeProfile(
        async (profile) => {
            const result = await execute(executable, [requireService ? '--service-auth-test' : '--smoke-test', `--user-data-dir=${profile}`], { env: environment, timeout: resolvePackagedSmokeProcessTimeout({ platform: process.platform, installed, requireService }), maxBuffer: 8 * 1024 * 1024, windowsHide: true })
            const output = `${result.stdout}${result.stderr}`
            if (!output.includes('OpenRDXManager smoke test passed: renderer=mounted')) throw new Error(`packaged-smoke-marker-missing: ${output}`)
            if (requireService && !output.includes(`OpenRDXManager installed service authentication passed: platform=${process.platform}`)) throw new Error(`installed-service-authentication-marker-missing: ${output}`)
            console.log(output.trim())
            const resources = process.platform === 'darwin' ? join(dirname(dirname(executable)), 'Resources') : join(dirname(executable), 'resources')
            console.log(await verifyPackagedMcpBridge(resources))
        },
        { installed, requireService }
    )
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) await verifyPackagedApplication()
