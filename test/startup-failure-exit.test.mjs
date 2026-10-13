// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createRequire } from 'node:module'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import { StartupFailureExitController } from '../src/main/startup-failure-exit.mjs'

const execute = promisify(execFile)
const require = createRequire(import.meta.url)
const fixture = fileURLToPath(new URL('../electron-test/startup-failure-exit-acceptance.mjs', import.meta.url))

/**
 * Launch the isolated lifecycle fixture with a real Electron process.
 * @param {string} scenario - Fixed ownership/normal-exit fixture.
 * @returns {Promise<{code: number, output: string}>} Actual exit status and lifecycle evidence.
 */
async function runElectronFixture(scenario) {
    const env = { ...process.env }
    delete env.ELECTRON_RUN_AS_NODE
    try {
        const result = await execute(require('electron'), [fixture, scenario], { env, timeout: 15_000, maxBuffer: 1024 * 1024 })
        return { code: 0, output: result.stdout + result.stderr }
    } catch (error) {
        if (!Number.isInteger(error.code)) throw error
        return { code: error.code, output: (error.stdout ?? '') + (error.stderr ?? '') }
    }
}

for (const scenario of ['failure', 'blocked', 'normal']) {
    test(`startup failure lifecycle preserves Electron status after ${scenario} guarded teardown`, { skip: process.platform !== 'darwin' }, async () => {
        const result = await runElectronFixture(scenario)
        assert.match(result.output, /teardown-pending-observed/u)
        assert.match(result.output, /runtime-stop-confirmed/u)
        if (scenario === 'blocked') assert.match(result.output, /ownership-blocked/u)
        assert.equal(result.code, scenario === 'normal' ? 0 : 1, result.output)
    })
}

test('startup failure final exit refuses absent or unconfirmed ownership policy', () => {
    for (const policy of [undefined, null, { allowed: false }, { allowed: 'true' }]) {
        let quits = 0
        let exits = 0
        let prevented = false
        const controller = new StartupFailureExitController({
            app: { quit: () => quits++, exit: () => exits++ },
            getShutdownPolicy: () => policy
        })
        controller.requestFailure()
        controller.handleWillQuit({
            preventDefault: () => {
                prevented = true
            }
        })
        assert.equal(quits, 1)
        assert.equal(prevented, true)
        assert.equal(exits, 0)
    }
})

test('startup failure final exit contains failed ownership lookup', () => {
    let exits = 0
    let prevented = false
    const controller = new StartupFailureExitController({
        app: { quit() {}, exit: () => exits++ },
        /** @returns {never} Models an unavailable coordinator ownership result. */
        getShutdownPolicy() {
            throw new Error('unconfirmed ownership')
        }
    })
    controller.requestFailure()
    controller.handleWillQuit({
        preventDefault: () => {
            prevented = true
        }
    })
    assert.equal(prevented, true)
    assert.equal(exits, 0)
})
