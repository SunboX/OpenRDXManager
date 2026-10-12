// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { englishCatalog } from '../src/locales/en.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'
import { renderShell } from '../src/renderer/views/shell-view.mjs'
import { createDashboardDom } from './helpers/renderer-dom.mjs'
import { createStore } from '../src/renderer/store.mjs'

const translator = createTranslator(englishCatalog)

/** @param {object} setup - Closed setup state. @param {string} [platform='darwin'] - Presentation platform. @returns {Document} Rendered real shell. */
function renderSetup(setup, platform = 'darwin') {
    const fixture = createFixtureState({ mode: 'no-device' })
    const state = { ...fixture, provenance: 'service', privilegedServiceSetup: setup, service: { ...fixture.service, status: 'unavailable' } }
    return new JSDOM(renderShell(state, { platform, translator, intentAvailability: { 'hardware-service-register': true, 'retry-service': true, 'hardware-service-check': true } })).window.document
}

for (const state of ['installer-required', 'repair-required']) {
    test(`${state} directs macOS to PKG without a service registration action`, () => {
        const document = renderSetup({ state })
        assert.match(document.querySelector('main').textContent, /PKG/)
        assert.equal(document.querySelector('[data-action="register-hardware-service"]'), null)
        assert.equal(document.querySelector('[data-action="open-hardware-approval"]'), null)
        assert.equal(document.querySelector('[data-action="check-hardware-setup"]')?.disabled, false)
    })
}

test('Windows service failure explains rerunning the installer with the dock connected', () => {
    const document = renderSetup({ state: 'not-applicable' }, 'win32')
    assert.match(document.querySelector('main').textContent, /EXE installer again/)
    assert.match(document.querySelector('main').textContent, /connected/)
    assert.equal(document.querySelector('[data-action="register-hardware-service"]'), null)
})

test('renderer store accepts installer guidance but rejects invented setup readiness', () => {
    const store = createStore(createFixtureState({ mode: 'no-device' }))
    store.dispatch({ type: 'service/setup', setup: { state: 'repair-required' } })
    assert.deepEqual(store.getState().privilegedServiceSetup, { state: 'repair-required' })
    store.dispatch({ type: 'service/setup', setup: { state: 'file-exists' } })
    assert.deepEqual(store.getState().privilegedServiceSetup, { state: 'repair-required' })
})

test('Check again refreshes local setup proof without registering a service', async (context) => {
    const fixture = createFixtureState({ mode: 'no-device' })
    const state = { ...fixture, provenance: 'service', privilegedServiceSetup: { state: 'repair-required' }, service: { ...fixture.service, status: 'unavailable' } }
    const mounted = createDashboardDom(state, {
        platform: 'darwin',
        supportApi: {
            service: {
                getSetup: async () => ({ ok: true, state: 'enabled' }),
                register: async () => {
                    throw new Error('must-not-register')
                }
            }
        }
    })
    context.after(() => {
        mounted.controller.destroy()
        mounted.dom.window.close()
    })
    const button = mounted.root.querySelector('[data-action="check-hardware-setup"]')
    assert.equal(button?.disabled, false)
    button.click()
    await new Promise((resolve) => setImmediate(resolve))
    assert.deepEqual(mounted.store.getState().privilegedServiceSetup, { state: 'enabled' })
    assert.equal(mounted.root.querySelector('[data-hardware-setup]'), null)
})
