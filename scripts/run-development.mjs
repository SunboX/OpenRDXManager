// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { constants, homedir } from 'node:os'
import { delimiter, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { assertSupportedNode } from './prepare-development-runtime.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const projectRoot = fileURLToPath(new URL('..', import.meta.url))
const require = createRequire(join(projectRoot, 'package.json'))

/**
 * Selects a usable Node and npm before any dependency or build command runs.
 * An older shell can use the version already installed by nvm for this project.
 * @param {object} [options] - Host runtime inputs and injectable filesystem/probe operations.
 * @param {string} [options.nodeVersion] - Active Node version without a leading v.
 * @param {string} [options.execPath] - Active Node executable.
 * @param {object} [options.environment] - Parent environment; never modified.
 * @param {string} [options.platform] - Node host platform.
 * @param {string} [options.homeDirectory] - Home used for the default nvm location.
 * @param {Function} [options.fileExists] - Synchronous file existence check.
 * @param {Function} [options.probeNode] - Synchronous Node version probe.
 * @returns {{execPath: string, npmCli: string, version: string, environment: object}} Selected child runtime.
 * @throws {Error} When no supported installed Node or npm CLI can be found.
 */
export function resolveDevelopmentNode({ nodeVersion = process.versions.node, execPath = process.execPath, environment = process.env, platform = process.platform, homeDirectory = homedir(), fileExists = existsSync, probeNode = spawnSync } = {}) {
    let executable = execPath
    let version = nodeVersion
    try {
        assertSupportedNode(version)
    } catch {
        const selected = readFileSync(join(projectRoot, '.nvmrc'), 'utf8').trim().replace(/^v/u, '')
        if (!/^\d+\.\d+\.\d+$/u.test(selected)) throw new Error('The project .nvmrc must select an exact Node version.')
        const roots = [environment.NVM_DIR, join(homeDirectory, '.nvm')].filter(Boolean)
        const candidates = roots.map((root) => join(root, 'versions', 'node', `v${selected}`, 'bin', 'node'))
        if (platform === 'win32' && environment.NVM_HOME) candidates.unshift(join(environment.NVM_HOME, `v${selected}`, 'node.exe'))
        executable = undefined
        for (const candidate of new Set(candidates)) {
            if (!fileExists(candidate)) continue
            const result = probeNode(candidate, ['--version'], { encoding: 'utf8', timeout: 5_000, maxBuffer: 1024, windowsHide: true })
            if (result.error || result.status !== 0 || result.stdout?.trim() !== `v${selected}`) continue
            assertSupportedNode(selected)
            executable = candidate
            version = selected
            break
        }
        if (!executable) throw new Error(`Node.js ${nodeVersion} is too old and the project Node is not installed. Run "nvm install ${selected}" once, then retry npm start.`)
    }

    const binaryDirectory = dirname(executable)
    const npmCandidates = [join(binaryDirectory, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'), join(binaryDirectory, 'node_modules', 'npm', 'bin', 'npm-cli.js'), environment.npm_execpath].filter(Boolean)
    const npmCli = npmCandidates.find((candidate) => fileExists(candidate))
    if (!npmCli) throw new Error('The selected Node installation has no npm CLI. Reinstall that Node version with npm included.')

    // npm hooks are separate processes: changing PATH only inside prestart
    // cannot select Node for later hooks. Every child receives this environment.
    const childEnvironment = { ...environment, npm_execpath: npmCli, npm_node_execpath: executable }
    const pathKey = Object.keys(environment).find((key) => key.toLowerCase() === 'path') ?? 'PATH'
    for (const key of Object.keys(childEnvironment)) {
        if (key.toLowerCase() === 'path') delete childEnvironment[key]
    }
    childEnvironment[pathKey] = [binaryDirectory, environment[pathKey]].filter(Boolean).join(delimiter)
    return { execPath: executable, npmCli, version, platform, environment: childEnvironment }
}

/**
 * Runs a development command with terminal input and propagates its exit status.
 * @param {object} runtime - Selected Node executable and child environment.
 * @param {string[]} args - Node CLI arguments; passed without shell interpolation.
 * @param {Function} runCommand - Synchronous subprocess runner.
 * @returns {number} Child exit code, including signal termination.
 * @throws {Error} When the operating system cannot start the command.
 */
function runNodeCommand(runtime, args, runCommand) {
    const result = runCommand(runtime.execPath, args, { cwd: projectRoot, env: runtime.environment, stdio: 'inherit' })
    if (result.error) throw result.error
    return result.status ?? (result.signal ? 128 + (constants.signals[result.signal] ?? 0) : 1)
}

/**
 * Adds the explicitly opted-in Windows rasterization override without changing
 * application styling or forcing it onto untested drivers. Chromium's enabling
 * switch overrides rasterization eligibility, so it must not be a global default.
 * @param {object} runtime - Selected platform and unchanged parent environment.
 * @param {string[]} args - Explicit Electron options; software-rendering choices win.
 * @returns {string[]} Fresh argument array, preserving every caller-supplied option.
 */
export function resolveDevelopmentElectronArgs(runtime, args) {
    const result = [...args]
    const softwareOptions = ['--disable-gpu', '--disable-gpu-compositing', '--disable-gpu-rasterization']
    const hasOverride = args.some((argument) => [...softwareOptions, '--enable-gpu-rasterization'].includes(argument.split('=')[0]))
    if (runtime.platform === 'win32' && runtime.environment.OPENRDX_WINDOWS_GPU_RASTERIZATION === '1' && !hasOverride) result.push('--enable-gpu-rasterization')
    return result
}

/**
 * Builds, authorizes, and launches under one selected runtime. Smoke launches
 * retain their existing unprivileged readiness check without authorizing a helper.
 * @param {object} [options] - Selected runtime, Electron arguments, and subprocess runner.
 * @param {object} [options.runtime] - Runtime selected before starting any build.
 * @param {string[]} [options.args] - Arguments forwarded verbatim to Electron.
 * @param {Function} [options.runCommand] - Synchronous subprocess runner.
 * @returns {number} First failed step's status or the Electron exit status.
 * @throws {Error} When runtime selection or process creation fails.
 */
export function runDevelopment({ runtime = resolveDevelopmentNode(), args = [], runCommand = spawnSync } = {}) {
    const buildStatus = runNodeCommand(runtime, [runtime.npmCli, 'run', 'build:runtime'], runCommand)
    if (buildStatus !== 0) return buildStatus
    if (!args.includes('--smoke-test')) {
        const authorizationStatus = runNodeCommand(runtime, [join(projectRoot, 'scripts', 'authorize-development-service.mjs')], runCommand)
        if (authorizationStatus !== 0) return authorizationStatus
    }
    // Resolve Electron only after the build hook has repaired missing packages.
    const electronArgs = resolveDevelopmentElectronArgs(runtime, args)
    if (runtime.platform === 'win32') {
        // This is the requested GUI, not a background build helper. SW_HIDE
        // can suppress its first native window even though Electron is running.
        const result = runCommand(join(projectRoot, 'out', 'windows-runtime', 'OpenRDXManager.exe'), [projectRoot, ...electronArgs], { cwd: projectRoot, env: runtime.environment, stdio: 'inherit', windowsHide: false })
        if (result.error) throw result.error
        return result.status ?? 1
    }
    return runNodeCommand(runtime, [require.resolve('electron/cli.js'), projectRoot, ...electronArgs], runCommand)
}

if (process.argv[1] === scriptPath) {
    try {
        const runtime = resolveDevelopmentNode()
        if (runtime.execPath !== process.execPath) console.info(`OpenRDXManager: using Node.js ${runtime.version} for this launch (shell: ${process.versions.node}).`)
        process.exitCode = runDevelopment({ runtime, args: process.argv.slice(2) })
    } catch (error) {
        console.error(`OpenRDXManager: ${error.message}`)
        process.exitCode = 1
    }
}
