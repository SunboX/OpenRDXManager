// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptPath = fileURLToPath(import.meta.url)
const projectRoot = fileURLToPath(new URL('..', import.meta.url))

/**
 * Checks the package's stable Node version floor before loading dependencies.
 * @param {string} version - Active Node version without the leading v.
 * @returns {void} Returns for a supported runtime.
 * @throws {Error} When Node is too old or the version contract is invalid.
 */
export function assertSupportedNode(version) {
    const { engines } = JSON.parse(readFileSync(join(projectRoot, 'package.json'), 'utf8'))
    const minimum = /^>=(\d+)\.(\d+)\.(\d+)$/u.exec(engines.node)?.slice(1).map(Number)
    const current = /^(\d+)\.(\d+)\.(\d+)$/u.exec(version)?.slice(1).map(Number)
    const difference = minimum && current ? current.findIndex((part, index) => part !== minimum[index]) : -1
    if (!minimum || !current || (difference !== -1 && current[difference] < minimum[difference])) {
        const selected = readFileSync(join(projectRoot, '.nvmrc'), 'utf8').trim()
        throw new Error(`Node.js ${engines.node} is required (running ${version}). Run "nvm install && nvm use" to select ${selected}, then retry.`)
    }
}

/**
 * Executes both native dependencies without opening a window or starting a service.
 * This runs in a disposable child so a repair cannot reuse cached package modules.
 * @returns {void} Returns only when esbuild and the installed Electron can run here.
 * @throws {Error} For absent, incompatible, or unusable native executables.
 */
function probeDevelopmentDependencies() {
    const require = createRequire(join(projectRoot, 'package.json'))
    require('esbuild').transformSync('export const ready = true', { loader: 'js' })

    // Read Electron's metadata directly: requiring its entry point can download
    // a binary as a side effect, before the controlled locked reinstall below.
    const electronRoot = dirname(require.resolve('electron/package.json'))
    const expectedPath = { darwin: 'Electron.app/Contents/MacOS/Electron', linux: 'electron', win32: 'electron.exe' }[process.platform]
    if (!expectedPath || readFileSync(join(electronRoot, 'path.txt'), 'utf8').trim() !== expectedPath) {
        throw new Error(`Electron executable is not installed for ${process.platform}-${process.arch}`)
    }
    const executable = join(process.env.ELECTRON_OVERRIDE_DIST_PATH ?? join(electronRoot, 'dist'), expectedPath)
    const result = spawnSync(executable, ['-p', 'JSON.stringify({platform:process.platform,arch:process.arch,version:process.versions.electron})'], {
        cwd: projectRoot,
        encoding: 'utf8',
        env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
        timeout: 10_000,
        maxBuffer: 1024 * 1024,
        windowsHide: true
    })
    if (result.error || result.status !== 0) {
        throw new Error(`Electron executable cannot run on ${process.platform}-${process.arch} (${result.error?.code ?? result.signal ?? result.status})`)
    }
    const runtime = JSON.parse(result.stdout.trim())
    const { version } = JSON.parse(readFileSync(join(electronRoot, 'package.json'), 'utf8'))
    if (runtime.platform !== process.platform || runtime.arch !== process.arch || runtime.version !== version) {
        throw new Error('Electron executable has the wrong architecture, platform, or version')
    }
}

/**
 * Repairs copied or incomplete development dependencies once using the lockfile.
 * Healthy installs remain untouched. Build hooks continue only after a fresh probe.
 * @param {object} [options] - Runtime inputs and injectable process runner for tests.
 * @param {string} [options.nodeVersion] - Active Node version.
 * @param {string} [options.npmCli] - npm's own CLI path from the invoking npm script.
 * @param {Function} [options.runCommand] - Synchronous subprocess runner.
 * @param {Function} [options.log] - Progress message sink.
 * @returns {void} Returns when the development dependencies are usable.
 * @throws {Error} For unsupported Node, failed installation, or a failed second probe.
 */
export function prepareDevelopmentRuntime({ nodeVersion = process.versions.node, npmCli = process.env.npm_execpath, runCommand = spawnSync, log = console.info } = {}) {
    assertSupportedNode(nodeVersion)
    const probeOptions = { cwd: projectRoot, encoding: 'utf8', timeout: 20_000, maxBuffer: 1024 * 1024, windowsHide: true }
    const before = runCommand(process.execPath, [scriptPath, '--probe'], probeOptions)
    if (!before.error && before.status === 0) return
    if (!npmCli) throw new Error('Run this preparation through "npm run build:preload" so the active npm CLI is available.')

    log(`OpenRDXManager: Reinstalling locked dependencies for ${process.platform}-${process.arch} because the native runtime check failed.`)
    const installation = runCommand(process.execPath, [npmCli, 'ci', '--include=dev', '--include=optional'], {
        cwd: projectRoot,
        stdio: 'inherit',
        // A development launch always needs this host, even if the parent shell
        // still contains platform overrides from a previous cross-platform build.
        env: { ...process.env, npm_config_os: process.platform, npm_config_cpu: process.arch, npm_config_platform: process.platform, npm_config_arch: process.arch, ELECTRON_INSTALL_PLATFORM: process.platform, ELECTRON_INSTALL_ARCH: process.arch },
        windowsHide: true
    })
    if (installation.error || installation.status !== 0) {
        throw new Error('npm ci failed. Resolve the installation error above, then retry the build.')
    }
    const after = runCommand(process.execPath, [scriptPath, '--probe'], probeOptions)
    if (after.error || after.status !== 0) {
        throw new Error(`Native development dependencies are still unavailable after npm ci. ${after.stderr?.trim() || after.error?.message || 'Check the installed runtime and host libraries.'}`)
    }
}

if (process.argv[1] === scriptPath) {
    try {
        if (process.argv[2] === '--probe') probeDevelopmentDependencies()
        else prepareDevelopmentRuntime()
    } catch (error) {
        console.error(`OpenRDXManager: ${error.message}`)
        process.exitCode = 1
    }
}
