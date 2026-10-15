// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const packageUrl = new URL('../package.json', import.meta.url)
const preparationUrl = new URL('../scripts/prepare-development-runtime.mjs', import.meta.url)

/**
 * Loads the preparation utility without requiring installed native packages.
 * @returns {Promise<Function>} Development preparation entry point.
 */
async function loadPreparation() {
    return (await import(preparationUrl)).prepareDevelopmentRuntime
}

test('preload builds prepare host dependencies before importing esbuild', async () => {
    const packageJson = JSON.parse(await readFile(packageUrl, 'utf8'))
    assert.equal(packageJson.scripts['prebuild:preload'], 'node scripts/prepare-development-runtime.mjs')
})

test('full tests prepare preload and native dependencies before directly owned visual processes start', async () => {
    const packageJson = JSON.parse(await readFile(packageUrl, 'utf8'))
    assert.equal(packageJson.scripts.pretest, 'npm run build:preload && npm run build:native-service')
    const visualTest = await readFile(new URL('./visual-qa-electron.test.mjs', import.meta.url), 'utf8')
    const visualRunner = await readFile(new URL('./helpers/visual-process.mjs', import.meta.url), 'utf8')
    assert.match(visualTest, /runVisualProcess\(electronPath, \[visualQaPath, \.\.\.visualArguments\]/u)
    assert.doesNotMatch(visualTest, /npmArguments|npm-cli\.js|['"]npm(?:\.cmd)?['"]/u)
    assert.match(visualRunner, /execute\(executable, args, \{ cwd, env, timeout: timeoutMs, killSignal: 'SIGKILL'/u)
})

test('dependency installation downloads the Electron executable before a runtime probe', async () => {
    const packageJson = JSON.parse(await readFile(packageUrl, 'utf8'))
    assert.equal(packageJson.scripts.postinstall, 'install-electron')
})

test('healthy native dependencies do not trigger an installation', async () => {
    const prepare = await loadPreparation()
    const calls = []
    prepare({
        nodeVersion: '22.16.0',
        runCommand(command, args) {
            calls.push({ command, args })
            return { status: 0 }
        }
    })
    assert.equal(calls.length, 1)
    assert.equal(calls[0].args.at(-1), '--probe')
})

test('incompatible native dependencies are reinstalled from the lock and checked again', async () => {
    const prepare = await loadPreparation()
    const calls = []
    const messages = []
    const outcomes = [{ status: 1 }, { status: 0 }, { status: 0 }]
    prepare({
        nodeVersion: '22.16.0',
        npmCli: '/npm with spaces/npm-cli.js',
        log: (message) => messages.push(message),
        runCommand(command, args, options) {
            calls.push({ command, args, options })
            return outcomes.shift()
        }
    })
    assert.equal(calls.length, 3)
    assert.equal(calls[1].command, process.execPath)
    assert.deepEqual(calls[1].args, ['/npm with spaces/npm-cli.js', 'ci', '--include=dev', '--include=optional'])
    assert.equal(calls[1].options.shell, undefined)
    assert.equal(calls[1].options.env.npm_config_arch, process.arch)
    assert.equal(calls[1].options.env.ELECTRON_INSTALL_PLATFORM, process.platform)
    assert.equal(calls[2].args.at(-1), '--probe')
    assert.match(messages.join('\n'), /Reinstalling locked dependencies/)
})

test('an unsupported Node version stops before any probe or dependency changes', async () => {
    const prepare = await loadPreparation()
    for (const nodeVersion of ['20.17.0', '22.11.0', 'invalid']) {
        assert.throws(() => prepare({ nodeVersion, runCommand: () => assert.fail('must not spawn with unsupported Node') }), /Node\.js >=22\.12\.0.*nvm install.*nvm use/s)
    }
})

test('the minimum supported Node and newer releases are accepted', async () => {
    const prepare = await loadPreparation()
    for (const nodeVersion of ['22.12.0', '22.16.0', '24.0.0']) {
        assert.doesNotThrow(() => prepare({ nodeVersion, runCommand: () => ({ status: 0 }) }))
    }
})

test('a failed dependency installation stops without attempting the build or retrying', async () => {
    const prepare = await loadPreparation()
    let calls = 0
    assert.throws(
        () =>
            prepare({
                nodeVersion: '22.16.0',
                npmCli: '/npm-cli.js',
                log() {},
                runCommand() {
                    calls += 1
                    return { status: 1 }
                }
            }),
        /npm ci failed/
    )
    assert.equal(calls, 2)
})

test('a still-incompatible installation fails with the probe reason after exactly one repair', async () => {
    const prepare = await loadPreparation()
    let calls = 0
    assert.throws(
        () =>
            prepare({
                nodeVersion: '22.16.0',
                npmCli: '/npm-cli.js',
                log() {},
                runCommand() {
                    calls += 1
                    return calls === 2 ? { status: 0 } : { status: 1, stderr: 'Electron executable has the wrong architecture' }
                }
            }),
        /still unavailable.*Electron executable has the wrong architecture/s
    )
    assert.equal(calls, 3)
})

test('missing npm invocation does not attempt a shell fallback or delete dependencies', async () => {
    const prepare = await loadPreparation()
    let calls = 0
    assert.throws(
        () =>
            prepare({
                nodeVersion: '22.16.0',
                npmCli: '',
                runCommand() {
                    calls += 1
                    return { status: 1 }
                }
            }),
        /npm run build:preload/
    )
    assert.equal(calls, 1)
})
