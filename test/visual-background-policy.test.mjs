// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { test } from 'node:test'

import { registerVisualBackgroundPolicy } from '../electron-test/visual-background-policy.mjs'
import { VisualErrorTracker } from '../electron-test/visual-error-tracker.mjs'

test('each completed QA document reapplies false even when the existing getter is already false', () => {
    const webContents = new EventEmitter()
    const calls = []
    /** @returns {boolean} Reports the already configured policy, which is insufficient to restore native painting. */
    webContents.getBackgroundThrottling = function getBackgroundThrottling() {
        return false
    }
    /** @param {boolean} value - Existing QA policy to reapply. @returns {void} Records the actual setter invocation. */
    webContents.setBackgroundThrottling = function setBackgroundThrottling(value) {
        calls.push(value)
    }
    const tracker = new VisualErrorTracker()
    const dispose = registerVisualBackgroundPolicy(webContents, tracker)
    assert.deepEqual(calls, [])
    webContents.emit('did-start-loading')
    assert.deepEqual(calls, [])
    webContents.emit('did-finish-load')
    webContents.emit('did-finish-load')
    assert.deepEqual(calls, [false, false])
    tracker.assertGloballyEmpty()
    dispose()
})

test('policy failures are recorded without an uncaught listener exception and block the next paint boundary', () => {
    const webContents = new EventEmitter()
    /** @returns {void} Models a native setter failure without an exception dialog. */
    webContents.setBackgroundThrottling = function setBackgroundThrottling() {
        throw new Error('controlled policy failure')
    }
    const tracker = new VisualErrorTracker()
    const dispose = registerVisualBackgroundPolicy(webContents, tracker)
    const cursor = tracker.capture()
    assert.doesNotThrow(() => webContents.emit('did-finish-load'))
    let paintStarted = false
    assert.throws(() => {
        tracker.assertEmptySince(cursor, 'real-runtime renderer load')
        paintStarted = true
    }, /loadFailures: .*controlled policy failure/)
    assert.equal(paintStarted, false)
    dispose()
})

test('disposing the policy removes only its own exact listener and prevents later setter calls', () => {
    const webContents = new EventEmitter()
    let setterCalls = 0
    let unrelatedCalls = 0
    /** @returns {void} Records an unrelated lifecycle observer. */
    function unrelatedLoadObserver() {
        unrelatedCalls += 1
    }
    /** @returns {void} Records native setter calls. */
    webContents.setBackgroundThrottling = function setBackgroundThrottling() {
        setterCalls += 1
    }
    webContents.on('did-finish-load', unrelatedLoadObserver)
    const dispose = registerVisualBackgroundPolicy(webContents, new VisualErrorTracker())
    assert.equal(webContents.listenerCount('did-finish-load'), 2)
    webContents.emit('did-finish-load')
    dispose()
    dispose()
    assert.deepEqual(webContents.listeners('did-finish-load'), [unrelatedLoadObserver])
    webContents.emit('did-finish-load')
    assert.equal(setterCalls, 1)
    assert.equal(unrelatedCalls, 2)
})
