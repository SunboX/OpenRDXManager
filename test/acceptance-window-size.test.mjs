// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { resizeAcceptanceWindow } from '../electron-test/acceptance-window-size.mjs'

/** @param {object[]} observations - Controlled renderer sizes. @returns {object} No native window or hardware is created. */
function windowFixture(observations) {
    const calls = []
    return {
        calls,
        /** @param {...number} size - Requested test dimensions. @returns {void} Records the resize intent. */
        setContentSize(...size) {
            calls.push(size)
        },
        webContents: {
            /** @param {string} source - Closed viewport/paint observation. @returns {Promise<object|undefined>} Next controlled observation. */
            async executeJavaScript(source) {
                if (source.startsWith('new Promise')) return
                return observations.length > 1 ? observations.shift() : observations[0]
            }
        }
    }
}

test('acceptance resize waits through stale Windows frames and requires post-paint readback', async () => {
    const oldSize = { width: 1440, height: 900 }
    const wanted = { width: 1024, height: 768 }
    const window = windowFixture([oldSize, wanted, oldSize, wanted, wanted])
    let waits = 0
    await resizeAcceptanceWindow(window, 1024, 768, { maxAttempts: 3, wait: async () => waits++ })
    assert.deepEqual(window.calls, [[1024, 768]])
    assert.equal(waits, 2)
})

test('acceptance resize fails after bounded observations if the viewport never changes', async () => {
    const window = windowFixture([{ width: 1440, height: 900 }])
    let waits = 0
    await assert.rejects(resizeAcceptanceWindow(window, 1024, 768, { maxAttempts: 2, wait: async () => waits++ }), /did not resize to 1024x768/)
    assert.equal(waits, 1)
})
