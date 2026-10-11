// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'

import { guardVisualOutput } from '../electron-test/visual-output.mjs'
import { visualWindowOptions } from '../electron-test/visual-window-options.mjs'
import { windowOptions } from '../src/window-options.mjs'

test('visual QA keeps painting in the background without changing production window security', () => {
    assert.equal(visualWindowOptions.webPreferences.backgroundThrottling, false)
    assert.equal(windowOptions.webPreferences.backgroundThrottling, undefined)
    const { backgroundThrottling, ...securityPreferences } = visualWindowOptions.webPreferences
    assert.deepEqual(securityPreferences, windowOptions.webPreferences)
    assert.equal(visualWindowOptions.minHeight, windowOptions.minHeight)
    assert.equal(visualWindowOptions.minWidth, windowOptions.minWidth)
    assert.equal(Object.isFrozen(visualWindowOptions.webPreferences), true)
})

for (const streamName of ['stdout', 'stderr']) {
    test(`visual QA exits unsuccessfully when ${streamName} closes instead of opening an exception dialog`, () => {
        const exits = []
        const streams = { stdout: new EventEmitter(), stderr: new EventEmitter() }
        guardVisualOutput(
            {
                /** @param {number} code - Exit status. @returns {void} Records fixture termination. */
                exit(code) {
                    exits.push(code)
                }
            },
            streams
        )
        streams[streamName].emit('error', Object.assign(new Error('broken pipe'), { code: 'EPIPE' }))
        assert.deepEqual(exits, [1])
    })
}
