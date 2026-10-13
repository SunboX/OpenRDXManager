// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { setTimeout as delay } from 'node:timers/promises'
import { app } from 'electron/main'
import { ShutdownController } from '../src/main/shutdown-controller.mjs'
import { StartupFailureExitController } from '../src/main/startup-failure-exit.mjs'

/**
 * Exercise real Electron quit status with an isolated ownership/teardown fixture.
 * No application service, physical device, privileged endpoint or window is opened.
 * @returns {Promise<void>} Releases the approved fixture teardown before quitting.
 */
async function run() {
    await app.whenReady()
    const scenario = process.argv.at(-1)
    let allowed = scenario !== 'blocked'
    let admissionClosed = false
    let stops = 0
    const stopped = Promise.withResolvers()
    const coordinator = {
        /** @returns {object} Current fixture ownership policy. */
        getShutdownPolicy() {
            return { allowed }
        },
        /** @returns {boolean} Closes fixture admission only after approval. */
        beginShutdown() {
            if (!allowed || admissionClosed) return false
            admissionClosed = true
            return true
        }
    }
    const shutdown = new ShutdownController({
        app,
        coordinator,
        runtime: {
            /** @returns {Promise<void>} Holds teardown until the test confirms release. */
            async stop() {
                stops++
                await stopped.promise
                console.log('startup-exit-fixture runtime-stop-confirmed')
            }
        }
    })
    const failure = new StartupFailureExitController({ app, getShutdownPolicy: coordinator.getShutdownPolicy })
    /** @param {object} event - Preventable Electron event. @returns {void} Applies the actual guarded shutdown controller. */
    function beforeQuit(event) {
        shutdown.handleBeforeQuit(event)
    }
    /** @param {object} event - Final approved Electron quit event. @returns {void} Preserves failure status. */
    function willQuit(event) {
        failure.handleWillQuit(event)
    }
    app.on('before-quit', beforeQuit)
    app.on('will-quit', willQuit)
    if (scenario === 'normal') app.quit()
    else failure.requestFailure()
    await delay(50)
    if (scenario === 'blocked') {
        assert.equal(stops, 0)
        assert.equal(admissionClosed, false)
        console.log('startup-exit-fixture ownership-blocked')
        allowed = true
        failure.requestFailure()
        await delay(50)
    }
    assert.equal(stops, 1)
    assert.equal(admissionClosed, true)
    console.log('startup-exit-fixture teardown-pending-observed')
    stopped.resolve()
    await shutdown.waitForShutdown()
}

/** @returns {Promise<void>} Contains fixture errors without affecting an actual Manager runtime. */
async function main() {
    try {
        await run()
    } catch (error) {
        console.error(error)
        app.exit(2)
    }
}

void main()
