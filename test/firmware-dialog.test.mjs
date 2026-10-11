// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { showFirmwareOpenDialog } from '../src/main/firmware-dialog.mjs'

/** @param {object} [state] - Window state. @returns {object} Live window and recorded visibility actions. */
function windowFixture(state = {}) {
    const calls = []
    return {
        calls,
        isDestroyed: () => state.destroyed === true,
        isMinimized: () => state.minimized === true,
        restore: () => calls.push('restore'),
        show: () => calls.push('show'),
        focus: () => calls.push('focus')
    }
}

for (const minimized of [false, true]) {
    test(`firmware chooser is modal to the focused app window (minimized=${minimized})`, async () => {
        const window = windowFixture({ minimized })
        const options = { properties: ['openFile'] }
        const selection = { canceled: true, filePaths: [] }
        const result = await showFirmwareOpenDialog(
            {
                BrowserWindow: { getFocusedWindow: () => window, getAllWindows: () => [] },
                dialog: {
                    /** @param {object} parent - Modal owner. @param {object} settings - Picker settings. @returns {Promise<object>} Cancelled selection. */
                    async showOpenDialog(parent, settings) {
                        assert.equal(parent, window)
                        assert.equal(settings, options)
                        assert.deepEqual(window.calls, minimized ? ['restore', 'show', 'focus'] : ['show', 'focus'])
                        return selection
                    }
                }
            },
            options
        )
        assert.equal(result, selection)
    })
}

test('firmware chooser selects a live owner if focus is absent or stale', async () => {
    const destroyed = windowFixture({ destroyed: true })
    const live = windowFixture()
    for (const focused of [null, destroyed]) {
        const result = await showFirmwareOpenDialog(
            {
                BrowserWindow: { getFocusedWindow: () => focused, getAllWindows: () => [destroyed, live] },
                dialog: {
                    /** @param {object} parent - Modal owner. @returns {Promise<object>} Native result. */
                    async showOpenDialog(parent) {
                        assert.equal(parent, live)
                        return { canceled: true }
                    }
                }
            },
            {}
        )
        assert.equal(result.canceled, true)
    }
    assert.deepEqual(destroyed.calls, [])
})

test('firmware chooser reports a missing owner instead of opening an invisible dialog', async () => {
    await assert.rejects(
        showFirmwareOpenDialog(
            {
                BrowserWindow: { getFocusedWindow: () => null, getAllWindows: () => [] },
                dialog: { showOpenDialog: () => assert.fail('An unparented chooser must never open') }
            },
            {}
        ),
        /firmware-dialog-window-unavailable/
    )
})
