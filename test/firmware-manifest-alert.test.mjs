// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { JSDOM } from 'jsdom'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { createUtilityOperationController } from '../src/renderer/workflows/utility-operation-controller.mjs'
import { getCatalog } from '../src/locales/catalogs.mjs'
import { createTranslator, supportedLanguageCodes } from '../src/renderer/i18n.mjs'

/** @returns {Promise<void>} Every language retains actionable selection alerts without accepting an operation. */
async function testMissingManifestAlert() {
    for (const language of supportedLanguageCodes) {
        const dom = new JSDOM('<!doctype html><div id="app"></div>')
        const fixture = createFixtureState({ mode: 'one-device' })
        const store = createStore({ ...fixture, devices: [{ ...fixture.devices[0], media: null, mediaState: 'no-media' }] })
        let starts = 0
        const api = {
            files: { chooseFirmware: async () => ({ ok: false, reason: 'firmware-openrdx-manifest-missing' }) },
            operations: {
                start: async () => {
                    starts += 1
                    return { ok: true, operationId: 'op:unexpected' }
                }
            }
        }
        const catalog = getCatalog(language)
        const controller = mountApplication(dom.window.document.querySelector('#app'), { store, translator: createTranslator(catalog, getCatalog('en')), utilityController: createUtilityOperationController(api) })
        try {
            const document = dom.window.document
            document.querySelector('[role="tab"][data-area="utilities"]').click()
            document.querySelector('[data-action="start-firmware"]').click()
            await delay(0)
            store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
            store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
            const alert = document.querySelector('[data-utility-feedback]')
            assert.equal(alert.getAttribute('role'), 'alert', language)
            assert.equal(alert.getAttribute('aria-live'), 'assertive', language)
            assert.equal(alert.dataset.feedbackState, 'failed', language)
            assert.equal(alert.closest('[data-feature]').dataset.feature, 'firmware', language)
            assert.ok(alert.textContent.includes(catalog['reason.firmwareOpenRdxManifestMissing']), language)
            assert.match(alert.textContent, /OpenRDX-v1-11\.bin.*OpenRDX-v1-11\.json/)
            assert.equal(starts, 0, language)
            assert.equal(store.getState().activeOperation, null, language)
            document.querySelector('[data-action="start-firmware"]').click()
            assert.equal(document.querySelector('[data-utility-feedback]').getAttribute('role'), 'status', language)
            assert.equal(document.querySelector('[data-utility-feedback]').dataset.feedbackState, 'pending', language)
            await delay(0)
        } finally {
            controller.destroy()
            dom.window.close()
        }
    }
}

test('missing firmware JSON shows a persistent localized alert before admission', testMissingManifestAlert)
