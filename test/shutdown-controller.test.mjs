// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { ShutdownController } from '../src/main/shutdown-controller.mjs'

/** @returns {object} Preventable Electron-style event with observation. */
function createEvent() {
    return {
        prevented: false,
        preventDefault() {
            this.prevented = true
        }
    }
}

test('blocks window close and initial quit while an operation owns the coordinator', async () => {
    let active = true
    let stops = 0
    let quits = 0
    const controller = new ShutdownController({
        app: {
            quit() {
                quits += 1
            }
        },
        coordinator: { getShutdownPolicy: () => (active ? { allowed: false, reason: 'operation-in-progress' } : { allowed: true }) },
        runtime: {
            async stop() {
                stops += 1
            }
        }
    })
    const closeEvent = createEvent()
    const quitEvent = createEvent()

    controller.handleWindowClose(closeEvent)
    controller.handleBeforeQuit(quitEvent)
    await controller.waitForShutdown()

    assert.equal(closeEvent.prevented, true)
    assert.equal(quitEvent.prevented, true)
    assert.equal(stops, 0)
    assert.equal(quits, 0)

    active = false
    const allowedQuit = createEvent()
    controller.handleBeforeQuit(allowedQuit)
    await controller.waitForShutdown()
    assert.equal(allowedQuit.prevented, true)
    assert.equal(stops, 1)
    assert.equal(quits, 1)

    const reentered = createEvent()
    controller.handleBeforeQuit(reentered)
    assert.equal(reentered.prevented, false)
})

test('coalesces repeated quit requests and bounds a stuck runtime stop', async () => {
    let quits = 0
    const controller = new ShutdownController({
        app: {
            quit() {
                quits += 1
            }
        },
        coordinator: { getShutdownPolicy: () => ({ allowed: true }) },
        runtime: { stop: () => new Promise(() => {}) },
        timeoutMs: 1
    })
    const first = createEvent()
    const second = createEvent()

    controller.handleBeforeQuit(first)
    controller.handleBeforeQuit(second)
    await controller.waitForShutdown()

    assert.equal(first.prevented, true)
    assert.equal(second.prevented, true)
    assert.equal(quits, 1)
})

test('publishes shutdown ownership before a synchronous teardown reenters quit and fails', async () => {
    let stops = 0
    let quits = 0
    const reentrant = createEvent()
    const controller = new ShutdownController({
        app: { quit: () => quits++ },
        coordinator: { getShutdownPolicy: () => ({ allowed: true }) },
        runtime: {
            /** @returns {never} Models a synchronous native teardown failure after quit reentry. */
            stop() {
                stops++
                controller.handleBeforeQuit(reentrant)
                throw new Error('controlled teardown failure')
            }
        }
    })

    controller.handleBeforeQuit(createEvent())
    await controller.waitForShutdown()
    assert.equal(stops, 1)
    assert.equal(quits, 1)
    assert.equal(reentrant.prevented, true)
})

test('contains a rejected runtime stop after the bounded shutdown has already completed', async () => {
    const stopped = Promise.withResolvers()
    let quits = 0
    const controller = new ShutdownController({
        app: { quit: () => quits++ },
        coordinator: { getShutdownPolicy: () => ({ allowed: true }) },
        runtime: { stop: () => stopped.promise },
        timeoutMs: 1
    })

    controller.handleBeforeQuit(createEvent())
    await controller.waitForShutdown()
    stopped.reject(new Error('late teardown failure'))
    await controller.waitForShutdown()
    assert.equal(quits, 1)
})
