// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { runInNewContext } from 'node:vm'
import { test } from 'node:test'

import { waitForRendererWindowGeometry } from '../electron-test/visual-window-geometry.mjs'

/**
 * Runs the renderer wait against delayed native overlay/CSS updates.
 * @param {object[]} frames - Observable states after successive animation frames.
 * @param {object} expected - Exact content bounds and measured native control insets.
 * @returns {Promise<number>} Number of animation frames needed before settling.
 */
async function settleGeometry(frames, expected) {
    let frame = 0
    const context = {
        expected,
        performance: { now: () => frame * 1000 },
        get innerWidth() {
            return frames[Math.min(frame, frames.length - 1)].width
        },
        get innerHeight() {
            return 900
        },
        navigator: { windowControlsOverlay: { visible: true, getTitlebarAreaRect: () => frames[Math.min(frame, frames.length - 1)].overlay } },
        document: { querySelector: () => ({ getBoundingClientRect: () => frames[Math.min(frame, frames.length - 1)].title }) },
        requestAnimationFrame(callback) {
            frame += 1
            callback()
        }
    }
    await runInNewContext(`(${waitForRendererWindowGeometry.toString()})(expected)`, context)
    return frame
}

test('native overlay and CSS title must catch up after the content viewport resizes', async () => {
    const stale = { width: 1440, overlay: { x: 78, width: 946 }, title: { left: 78, width: 946 } }
    const overlayReady = { width: 1440, overlay: { x: 78, width: 1362 }, title: { left: 78, width: 946 } }
    const ready = { ...overlayReady, title: { left: 78, width: 1362 } }
    assert.equal(await settleGeometry([stale, stale, overlayReady, ready], { width: 1440, height: 900, titlebarInsets: { left: 78, right: 0 } }), 3)
})

test('right-side native controls retain their measured reserved area', async () => {
    const ready = { width: 1440, overlay: { x: 0, width: 1302 }, title: { left: 0, width: 1302 } }
    assert.equal(await settleGeometry([ready], { width: 1440, height: 900, titlebarInsets: { left: 0, right: 138 } }), 0)
})

test('a native overlay that never reaches the target size fails explicitly', async () => {
    const stale = { width: 1440, overlay: { x: 78, width: 946 }, title: { left: 78, width: 946 } }
    await assert.rejects(settleGeometry([stale], { width: 1440, height: 900, titlebarInsets: { left: 78, right: 0 } }), /Timed out waiting for native window geometry/u)
})
