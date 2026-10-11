// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { persistValidatedVisualImage } from '../electron-test/visual-runtime-capture.mjs'

for (const selection of ['preserved baseline', 'confirmed replacement']) {
    test(`raster evidence describes the exact saved ${selection}`, async () => {
        const fresh = { pixels: 101 }
        const saved = { pixels: selection === 'preserved baseline' ? 100 : 102 }
        const capture = { image: fresh, evidence: { matchingPixels: 101 }, attempts: 2 }
        const persisted = await persistValidatedVisualImage(
            capture,
            async (image) => {
                assert.equal(image, fresh)
                return saved
            },
            (image) => ({ matchingPixels: image.pixels })
        )
        assert.equal(persisted.image, saved)
        assert.deepEqual(persisted.evidence, { matchingPixels: saved.pixels })
        assert.equal(persisted.attempts, 2)
        assert.equal(capture.evidence.matchingPixels, 101)
    })
}

test('saved image anchor validation stays mandatory even after a fresh capture passed', async () => {
    const capture = { image: 'fresh', evidence: { valid: true }, attempts: 1 }
    await assert.rejects(
        persistValidatedVisualImage(
            capture,
            async () => 'saved-invalid',
            (image) => {
                assert.equal(image, 'saved-invalid')
                throw new Error('saved-anchor-missing')
            }
        ),
        /saved-anchor-missing/u
    )
})
