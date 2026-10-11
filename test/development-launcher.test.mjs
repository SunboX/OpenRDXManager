// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { delimiter, dirname, join } from 'node:path'
import test from 'node:test'

const launcherUrl = new URL('../scripts/run-development.mjs', import.meta.url)

/** @returns {Promise<object>} Launcher utilities without starting the application. */
async function loadLauncher() {
    return import(launcherUrl)
}

/** @returns {object} Isolated macOS nvm runtime inputs with an older active shell. */
function oldShellFixture() {
    const nvmDirectory = '/test home/nvm'
    const executable = join(nvmDirectory, 'versions', 'node', 'v22.16.0', 'bin', 'node')
    const npmCli = join(dirname(executable), '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js')
    return {
        nodeVersion: '20.17.0',
        execPath: '/old-node/bin/node',
        environment: { NVM_DIR: nvmDirectory, PATH: '/old-node/bin:/usr/bin', npm_execpath: '/old-npm/npm-cli.js' },
        platform: 'darwin',
        homeDirectory: '/test home',
        fileExists: (path) => path === executable || path === npmCli,
        probeNode: () => ({ status: 0, stdout: 'v22.16.0\n' }),
        executable,
        npmCli
    }
}

test('development launcher owns startup preparation and smoke preparation under the selected Node', async () => {
    const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))
    assert.equal(packageJson.scripts.start, 'node scripts/run-development.mjs')
    assert.equal(packageJson.scripts.smoke, 'node scripts/run-development.mjs --smoke-test')
    assert.equal(packageJson.scripts.prestart, undefined)
    assert.equal(packageJson.scripts.presmoke, undefined)
})

test('development launcher replaces an inherited Node 20 with the installed project Node and npm', async () => {
    const { resolveDevelopmentNode } = await loadLauncher()
    const fixture = oldShellFixture()
    const originalEnvironment = { ...fixture.environment }
    const runtime = resolveDevelopmentNode(fixture)
    assert.equal(runtime.execPath, fixture.executable)
    assert.equal(runtime.npmCli, fixture.npmCli)
    assert.equal(runtime.environment.PATH.split(delimiter)[0], dirname(fixture.executable))
    assert.equal(runtime.environment.npm_node_execpath, fixture.executable)
    assert.deepEqual(fixture.environment, originalEnvironment)
})

test('development launcher retains an already-supported Node without requiring nvm', async () => {
    const { resolveDevelopmentNode } = await loadLauncher()
    const runtime = resolveDevelopmentNode({
        ...oldShellFixture(),
        nodeVersion: '24.0.0',
        execPath: '/current/bin/node',
        environment: { PATH: '/current/bin:/usr/bin', npm_execpath: '/current/npm-cli.js' },
        fileExists: (path) => path === '/current/npm-cli.js',
        probeNode: () => assert.fail('supported runtime must not search other Node versions')
    })
    assert.equal(runtime.execPath, '/current/bin/node')
})

test('development launcher rejects a missing or mislabelled project Node before starting npm', async () => {
    const { resolveDevelopmentNode } = await loadLauncher()
    for (const overrides of [{ fileExists: () => false }, { probeNode: () => ({ status: 0, stdout: 'v20.17.0\n' }) }, { probeNode: () => ({ status: null, error: new Error('cannot execute') }) }]) {
        assert.throws(() => resolveDevelopmentNode({ ...oldShellFixture(), ...overrides }), /nvm install 22\.16\.0/)
    }
})

test('development launcher runs build, authorization, and Electron with the selected Node', async () => {
    const { runDevelopment, resolveDevelopmentNode } = await loadLauncher()
    const runtime = resolveDevelopmentNode(oldShellFixture())
    const calls = []
    const status = runDevelopment({
        runtime,
        args: ['--some-argument=value with spaces'],
        runCommand(command, args, options) {
            calls.push({ command, args, options })
            return { status: 0 }
        }
    })
    assert.equal(status, 0)
    assert.equal(calls.length, 3)
    assert.deepEqual(calls[0].args, [runtime.npmCli, 'run', 'build:runtime'])
    assert.match(calls[1].args[0], /authorize-development-service\.mjs$/)
    assert.match(calls[2].args[0], /electron[/\\]cli\.js$/)
    assert.equal(calls[2].args.at(-1), '--some-argument=value with spaces')
    for (const call of calls) {
        assert.equal(call.command, runtime.execPath)
        assert.equal(call.options.env, runtime.environment)
        assert.equal(call.options.stdio, 'inherit')
        assert.equal(call.options.shell, undefined)
    }
})

test('development launcher smoke mode builds and launches without hardware authorization', async () => {
    const { runDevelopment, resolveDevelopmentNode } = await loadLauncher()
    const calls = []
    const status = runDevelopment({
        runtime: resolveDevelopmentNode(oldShellFixture()),
        args: ['--smoke-test'],
        runCommand(command, args) {
            calls.push(args)
            return { status: 0 }
        }
    })
    assert.equal(status, 0)
    assert.equal(calls.length, 2)
    assert.equal(calls[1].at(-1), '--smoke-test')
})

test('development launcher stops immediately on build or authorization failure', async () => {
    const { runDevelopment, resolveDevelopmentNode } = await loadLauncher()
    for (const failedStep of [1, 2]) {
        let calls = 0
        const status = runDevelopment({
            runtime: resolveDevelopmentNode(oldShellFixture()),
            runCommand() {
                calls += 1
                return { status: calls === failedStep ? 7 : 0 }
            }
        })
        assert.equal(status, 7)
        assert.equal(calls, failedStep)
    }
})

test('Windows development and smoke launches use the branded executable without hiding its GUI', async () => {
    const { runDevelopment, resolveDevelopmentNode } = await loadLauncher()
    const runtime = resolveDevelopmentNode({ ...oldShellFixture(), platform: 'win32' })
    for (const args of [[], ['--smoke-test']]) {
        const calls = []
        assert.equal(
            runDevelopment({
                runtime,
                args,
                runCommand(command, forwarded, options) {
                    calls.push({ command, forwarded, options })
                    return { status: 0 }
                }
            }),
            0
        )
        const launch = calls.at(-1)
        assert.match(launch.command, /windows-runtime[/\\]OpenRDXManager\.exe$/)
        assert.equal(launch.forwarded[0], launch.options.cwd)
        assert.deepEqual(launch.forwarded.slice(1), args)
        assert.equal(launch.options.env, runtime.environment)
        assert.equal(launch.options.windowsHide, false)
    }
})

test('GPU rasterization is an explicit Windows development opt-in, with software overrides retained', async () => {
    const { resolveDevelopmentElectronArgs } = await loadLauncher()
    for (const platform of ['win32', 'darwin', 'linux']) {
        for (const value of [undefined, '0', 'true', '1']) {
            const runtime = { platform, environment: { OPENRDX_WINDOWS_GPU_RASTERIZATION: value } }
            const args = ['--smoke-test']
            const expected = platform === 'win32' && value === '1' ? [...args, '--enable-gpu-rasterization'] : args
            assert.deepEqual(resolveDevelopmentElectronArgs(runtime, args), expected)
            assert.deepEqual(args, ['--smoke-test'])
            assert.equal(runtime.environment.OPENRDX_WINDOWS_GPU_RASTERIZATION, value)
        }
    }
    const runtime = { platform: 'win32', environment: { OPENRDX_WINDOWS_GPU_RASTERIZATION: '1' } }
    for (const option of ['--disable-gpu', '--disable-gpu-compositing', '--disable-gpu-rasterization', '--enable-gpu-rasterization']) {
        for (const argument of [option, `${option}=true`]) assert.deepEqual(resolveDevelopmentElectronArgs(runtime, [argument]), [argument])
    }
})

test('Windows GPU opt-in reaches the GUI only, not build or service authorization commands', async () => {
    const { runDevelopment, resolveDevelopmentNode } = await loadLauncher()
    const fixture = oldShellFixture()
    const runtime = resolveDevelopmentNode({ ...fixture, platform: 'win32', environment: { ...fixture.environment, OPENRDX_WINDOWS_GPU_RASTERIZATION: '1' } })
    for (const args of [[], ['--smoke-test']]) {
        const calls = []
        assert.equal(
            runDevelopment({
                runtime,
                args,
                runCommand(command, forwarded) {
                    calls.push(forwarded)
                    return { status: 0 }
                }
            }),
            0
        )
        assert.deepEqual(calls.at(-1).slice(1), [...args, '--enable-gpu-rasterization'])
        assert.ok(calls.slice(0, -1).every((forwarded) => !forwarded.includes('--enable-gpu-rasterization')))
    }
})
