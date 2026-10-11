// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { englishCatalog } from '../src/locales/en.mjs'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { renderShell } from '../src/renderer/views/shell-view.mjs'

const translator = createTranslator(englishCatalog, englishCatalog)

/** @returns {void} Verifies the shipped Encryption tab renders its real workspace instead of the future placeholder. */
function testProductionShellRendersEncryptionWorkspace() {
    const dom = new JSDOM('<!doctype html><html><body></body></html>')
    const state = { ...createFixtureState({ mode: 'one-device' }), activeArea: 'encryption' }
    const markup = renderShell(state, { activeArea: 'encryption', document: dom.window.document, intentAvailability: {}, translator })
    dom.window.document.body.innerHTML = markup

    assert.notEqual(dom.window.document.querySelector('[data-encryption-view]'), null)
    assert.equal(dom.window.document.querySelector('#panel-encryption .future-workspace'), null)
    assert.match(dom.window.document.querySelector('[data-encryption-view]').textContent, /Encryption & Access Control/)
}

/** @returns {void} Verifies serialized and callback-owned Encryption views receive the active translator. */
function testEncryptionTranslatorHandoff() {
    const dom = new JSDOM('<!doctype html><html><body><div id="app"></div></body></html>', { pretendToBeVisual: true })
    const fixture = createFixtureState({ mode: 'one-device' })
    const device = { ...fixture.devices[0], media: null }
    const state = { ...fixture, activeArea: 'encryption', devices: [device] }
    const translated = (key) => `localized:${key}`
    const markup = renderShell(state, { activeArea: 'encryption', document: dom.window.document, intentAvailability: {}, translator: translated })
    assert.match(markup, /localized:encryption\.title/)
    assert.match(markup, /localized:encryption\.noCartridge/)

    const controller = mountApplication(dom.window.document.querySelector('#app'), {
        store: createStore(state),
        translator: translated
    })
    assert.match(dom.window.document.querySelector('[data-encryption-view]').textContent, /localized:encryption\.title/)
    assert.match(dom.window.document.querySelector('[data-encryption-view]').textContent, /localized:encryption\.noCartridge/)
    controller.destroy()
    dom.window.close()
}

/** @returns {Promise<void>} Verifies production callbacks own workflow transitions and transient intent dispatch. */
async function testProductionEncryptionWorkflowContract() {
    const dom = new JSDOM('<!doctype html><html><body><div id="app"></div></body></html>', { pretendToBeVisual: true, url: 'file:///openrdxmanager/src/index.html' })
    const root = dom.window.document.querySelector('#app')
    const state = { ...createFixtureState({ mode: 'one-device' }), activeArea: 'encryption' }
    const store = createStore(state)
    const starts = []
    const securityController = {
        /** @returns {boolean} Exposes the controlled future service boundary. */
        isAvailable() {
            return true
        },
        /** @param {object} intent - Structured security intent. @param {Uint8Array|null} credential - Transient bytes. @returns {Promise<object>} Accepted fixture result. */
        async start(intent, credential) {
            starts.push({ credential: credential === null ? null : new TextDecoder().decode(credential), intent })
            return { ok: true, operationId: 'security-op-1' }
        }
    }
    const securityStateProvider = {
        /** @param {object} _state - Store state. @param {object} device - Selected device. @param {object|null} workflow - Local workflow. @returns {object} Strict complete test security model. */
        getModel(_state, device, workflow) {
            return {
                access: 'enabled',
                automaticAuthentication: {},
                credentials: [],
                device: { drive: device.drive, id: device.id, label: `${device.product} · ${device.media.serial}`, media: device.media, revision: device.revision },
                evidence: { 'configure-basic': { state: 'available' } },
                mode: 'none',
                resetWithoutPassword: false,
                workflow
            }
        }
    }
    const controller = mountApplication(root, { securityController, securityStateProvider, store })
    const panel = root.querySelector('#panel-encryption')
    panel.scrollTop = 400
    store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
    store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
    assert.equal(root.querySelector('#panel-encryption'), panel)
    assert.equal(panel.scrollTop, 400)

    root.querySelector('[data-action="configure-basic"]').click()
    assert.notEqual(root.querySelector('[data-security-workflow-form="configure-basic"]'), null)
    root.querySelector('[data-workflow-password]').value = 'Transient-Draft-42!'
    store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
    assert.equal(root.querySelector('[data-workflow-password]').value, '', 'Refreshing callbacks must still clear transient password inputs')
    assert.equal(root.querySelector('#panel-encryption'), panel)
    root.querySelector('[data-workflow-password]').value = 'Review-Passphrase-42!'
    root.querySelector('[data-workflow-password-confirmation]').value = 'Review-Passphrase-42!'
    root.querySelector('[data-security-workflow-form="configure-basic"]').dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }))
    assert.notEqual(root.querySelector('[data-exact-device-confirmation]'), null)

    root.querySelector('[data-workflow-password]').value = 'Review-Passphrase-42!'
    root.querySelector('[data-workflow-password-confirmation]').value = 'Review-Passphrase-42!'
    const exactInput = root.querySelector('[data-exact-device-confirmation] input[type="text"]')
    exactInput.value = state.devices[0].media.serial
    exactInput.dispatchEvent(new dom.window.Event('input', { bubbles: true }))
    root.querySelector('[data-confirmation-confirm]').click()
    await Promise.resolve()

    assert.equal(starts.length, 1)
    assert.equal(starts[0].credential, 'Review-Passphrase-42!')
    assert.equal(starts[0].intent.operation, 'configure-basic')
    assert.notEqual(root.querySelector('[data-progress-timeline]'), null)
    controller.destroy()
}

test('production shell renders the real Encryption workspace', testProductionShellRendersEncryptionWorkspace)
test('production Encryption preserves the active translator through live mounting', testEncryptionTranslatorHandoff)
test('production Encryption callbacks own workflow and transient intent lifecycle', testProductionEncryptionWorkflowContract)
