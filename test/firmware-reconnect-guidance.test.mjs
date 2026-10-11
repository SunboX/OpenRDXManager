// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { getCatalog } from '../src/locales/catalogs.mjs'
import { createTranslator, supportedLanguageCodes } from '../src/renderer/i18n.mjs'

/** @returns {void} Shows localized VM reattachment help only while firmware reconnects. */
function testReconnectGuidance() {
    for (const language of supportedLanguageCodes) {
        for (const stage of ['firmware-writing', 'device-reconnecting', 'firmware-readback']) {
            const fixture = createFixtureState({ mode: 'busy' })
            const store = createStore({ ...fixture, activeOperation: { ...fixture.activeOperation, stage } })
            const dom = new JSDOM('<!doctype html><div id="app"></div>')
            const catalog = getCatalog(language)
            const controller = mountApplication(dom.window.document.querySelector('#app'), { store, translator: createTranslator(catalog, getCatalog('en')) })
            try {
                const guidance = dom.window.document.querySelector('[data-firmware-reconnect-guidance]')
                if (stage === 'device-reconnecting') {
                    assert.equal(guidance?.textContent, catalog['utilities.firmware.reconnectingGuidance'], language)
                    assert.equal(guidance.closest('[data-operation-status]').getAttribute('role'), 'status', language)
                    assert.equal(dom.window.document.querySelector('[data-operation-success]'), null, language)
                    store.dispatch({ type: 'device/list-replaced', devices: [], epoch: 1, listRevision: 2 })
                    assert.equal(dom.window.document.querySelector('[data-firmware-reconnect-guidance]')?.textContent, catalog['utilities.firmware.reconnectingGuidance'], language)
                } else {
                    assert.equal(guidance, null, `${language}: ${stage}`)
                }
            } finally {
                controller.destroy()
                dom.window.close()
            }
        }
    }
}

test('firmware reconnect guidance is localized and confined to the verification wait', testReconnectGuidance)
