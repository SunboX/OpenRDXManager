// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { englishCatalog } from '../src/locales/en.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'
import { createCompatibilityModel } from '../src/renderer/views/compatibility-view.mjs'
import { renderStatusView } from '../src/renderer/views/status-view.mjs'

const translator = createTranslator(englishCatalog, englishCatalog)

for (const [raw, expected] of [
    ['0106', '1.06'],
    ['0110', '1.10'],
    ['1006', '10.06'],
    ['0283', '2.83'],
    ['0001', '0001'],
    ['1.06', '1.06'],
    ['A106', 'A106']
]) {
    test(`firmware revision ${raw} displays as ${expected} without changing device identity`, () => {
        const state = structuredClone(createFixtureState({ mode: 'one-device' }))
        const device = state.devices[0]
        device.drive.firmwareRevision = raw
        device.drive.details.firmwareRevision = { availability: 'reported', value: raw }
        const before = structuredClone(device)
        const dom = new JSDOM(renderStatusView(device, { translator }))
        try {
            const row = [...dom.window.document.querySelectorAll('#drive-data-heading + dl .data-row')].find((item) => item.querySelector('dt').textContent === 'Firmware revision')
            assert.equal(row.querySelector('dd').textContent, expected)
            assert.equal(createCompatibilityModel(state, 'darwin').device.firmware, expected)
            assert.deepEqual(device, before)
        } finally {
            dom.window.close()
        }
    })
}

test('unavailable firmware revision retains its explanation', () => {
    const state = structuredClone(createFixtureState({ mode: 'one-device' }))
    const device = state.devices[0]
    delete device.drive.firmwareRevision
    device.drive.details.firmwareRevision = { availability: 'unavailable', reason: 'field-decoder-unavailable' }
    const dom = new JSDOM(renderStatusView(device, { translator }))
    try {
        const row = [...dom.window.document.querySelectorAll('#drive-data-heading + dl .data-row')].find((item) => item.querySelector('dt').textContent === 'Firmware revision')
        assert.equal(row.querySelector('dd').textContent, 'Not available in OpenRDXManager')
        assert.equal(createCompatibilityModel(state, 'darwin').device.firmware, 'field-decoder-unavailable')
    } finally {
        dom.window.close()
    }
})
