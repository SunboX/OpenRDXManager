// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { runInNewContext } from 'node:vm'
import { test } from 'node:test'

import { waitForRendererVisualPaint } from '../electron-test/visual-paint.mjs'

/**
 * Verifies a locale change's newly requested font completes before paint.
 * @returns {Promise<void>} Resolves after delayed subset loading and two frames.
 */
async function verifyNewFontReadiness() {
    const fontLoad = Promise.withResolvers()
    let layoutFlushed = false
    let paintFrames = 0
    const context = {
        document: {
            documentElement: {
                /** Discovers font subsets required by newly mounted text. @returns {object} Unused viewport box. */
                getBoundingClientRect() {
                    layoutFlushed = true
                    return {}
                }
            },
            fonts: {
                /** @returns {Promise<void>} Current font-loading cycle, updated during layout. */
                get ready() {
                    return layoutFlushed ? fontLoad.promise : Promise.resolve()
                }
            }
        },
        /** @param {Function} callback - Frame observer. @returns {void} Completes one test frame. */
        requestAnimationFrame(callback) {
            paintFrames += 1
            callback()
        }
    }
    const painted = runInNewContext(`(${waitForRendererVisualPaint.toString()})()`, context)
    // Let an incorrectly captured, previously resolved FontFaceSet.ready
    // advance through both frame promises before releasing the new subset.
    for (let turn = 0; turn < 4; turn += 1) await Promise.resolve()
    assert.equal(paintFrames, 0, 'Capture must wait for the font cycle discovered by the new locale layout')
    fontLoad.resolve()
    await painted
    assert.equal(layoutFlushed, true)
    assert.equal(paintFrames, 2)
}

test('visual paint awaits the new locale font-loading cycle before capturing frames', verifyNewFontReadiness)
