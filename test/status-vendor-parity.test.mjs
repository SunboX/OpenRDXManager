// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { englishCatalog } from '../src/locales/en.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'
import { renderShell } from '../src/renderer/views/shell-view.mjs'
import { renderStatusView } from '../src/renderer/views/status-view.mjs'

const translator = createTranslator(englishCatalog, englishCatalog)

/** @returns {object} Creates typed vendor telemetry with no encryption probe result. */
function vendorState() {
    const state = structuredClone(createFixtureState({ mode: 'one-device' }))
    state.provenance = 'service'
    const device = state.devices[0]
    device.drive.details.policy = { availability: 'unavailable', reason: 'field-decoder-unavailable' }
    Object.assign(device.media.details, {
        status: { availability: 'reported', value: 'Good' },
        loadCount: { availability: 'reported', value: 21 },
        bytesRead: { availability: 'reported', value: 2_170_000_000 },
        bytesWritten: { availability: 'reported', value: 95_000_000 },
        writeProtected: { availability: 'reported', value: false },
        encrypted: { availability: 'unavailable', reason: 'not-reported' }
    })
    return state
}

test('vendor telemetry and known write protection remain visible without encryption telemetry', () => {
    for (const writeProtected of [false, true]) {
        const device = vendorState().devices[0]
        device.media.details.writeProtected.value = writeProtected
        const dom = new JSDOM(renderStatusView(device, { translator }))
        try {
            const document = dom.window.document
            const card = document.querySelector('.metric-card:last-child')
            assert.equal(card.querySelector('strong').textContent, writeProtected ? 'Write protected' : 'Read / write')
            assert.equal(card.querySelector('small').textContent, 'Write protection')
            assert.match(document.querySelector('#cartridge-data-heading + dl').textContent, /21/)
            assert.match(document.querySelector('#cartridge-data-heading + dl').textContent, /2.17 GB/)
            assert.match(document.querySelector('#cartridge-data-heading + dl').textContent, /95.0 MB/)
            assert.equal(document.querySelectorAll('.metric-card')[1].querySelector('strong').textContent, 'Good')
        } finally {
            dom.window.close()
        }
    }
})

test('the real shell identifies Windows drive policy as inapplicable on macOS and Linux', () => {
    for (const platform of ['darwin', 'linux']) {
        const dom = new JSDOM(renderShell(vendorState(), { translator, platform }))
        try {
            const policy = [...dom.window.document.querySelectorAll('.data-row')].find((row) => row.querySelector('dt').textContent === 'Drive policy')
            assert.equal(policy.querySelector('dd').textContent, 'Windows-only setting')
        } finally {
            dom.window.close()
        }
    }
})

test('a reported encryption state keeps priority over ordinary write access', () => {
    const device = vendorState().devices[0]
    device.media.details.encrypted = { availability: 'reported', value: true }
    const dom = new JSDOM(renderStatusView(device, { translator }))
    try {
        const card = dom.window.document.querySelector('.metric-card:last-child')
        assert.equal(card.querySelector('strong').textContent, 'Encrypted')
        assert.equal(card.querySelector('small').textContent, 'Read / write')
    } finally {
        dom.window.close()
    }
})
