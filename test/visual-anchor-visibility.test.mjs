// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { isVisualAnchorUnoccluded } from '../electron-test/visual-anchor-visibility.mjs'

/** Creates geometric visibility with independently controlled painted ownership.
 * @returns {object} Visible heading and child glyph element.
 */
function fixture() {
    const glyph = {}
    const element = {
        getBoundingClientRect: () => ({ left: 100, top: 130, width: 180, height: 24 }),
        contains: (candidate) => candidate === glyph
    }
    return { element, glyph }
}

test('visual anchors accept visible self or descendant pixels at both sampled points', () => {
    const { element, glyph } = fixture()
    const points = []
    assert.equal(
        isVisualAnchorUnoccluded(element, {
            elementFromPoint: (x, y) => {
                points.push([x, y])
                return points.length === 1 ? element : glyph
            }
        }),
        true
    )
    assert.deepEqual(points, [
        [102, 132],
        [190, 142]
    ])
})

test('a viewport-visible heading clipped by its scroll container is not a painted anchor', () => {
    const { element } = fixture()
    const scrollContainer = {}
    assert.equal(isVisualAnchorUnoccluded(element, { elementFromPoint: (_x, y) => (y < 145 ? scrollContainer : element) }), false)
})

test('visual anchors reject overlapping siblings, missing pixels and empty elements', () => {
    const { element } = fixture()
    for (const hit of [{}, null]) assert.equal(isVisualAnchorUnoccluded(element, { elementFromPoint: () => hit }), false)
    assert.equal(isVisualAnchorUnoccluded(null, {}), false)
    assert.equal(isVisualAnchorUnoccluded({ getBoundingClientRect: () => ({ width: 0, height: 5 }) }, {}), false)
})
