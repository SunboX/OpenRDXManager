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
import { getFirmwarePreflightFailureReasonKey } from '../src/renderer/firmware-failure-reasons.mjs'

/** @returns {void} Keeps terminal firmware evidence visible after discovery removes its target. */
function retainDisconnectedFirmwareFailure() {
    for (const replacementPresent of [false, true]) {
        const fixture = createFixtureState({ mode: 'operation-failed' })
        const store = createStore({
            ...fixture,
            discovery: { ...fixture.discovery, epoch: 1, listRevision: 1 },
            lastOperation: {
                ...fixture.lastOperation,
                kind: 'firmware-update',
                error: { ...fixture.lastOperation.error, code: 'firmware-reconnect-failed', stage: 'firmware-readback', retryable: true }
            }
        })
        const dom = new JSDOM('<!doctype html><div id="app"></div>')
        const controller = mountApplication(dom.window.document.querySelector('#app'), { store })
        try {
            const previous = dom.window.document.querySelector('[data-operation-failure]').textContent
            const devices = replacementPresent ? [{ ...fixture.devices[0], id: 'rdx:replacement' }] : []
            store.dispatch({ type: 'device/list-replaced', devices, epoch: 1, listRevision: 2 })
            assert.equal(store.getState().selectedDeviceId, null)
            const failure = dom.window.document.querySelector('[data-operation-failure][role="alert"]')
            assert.notEqual(failure, null)
            assert.equal(failure.textContent.includes('firmware-reconnect-failed'), true)
            assert.equal(failure.textContent.includes(fixture.lastOperation.error.supportCorrelationId), true)
            assert.match(previous, /Firmware update did not complete/)
            assert.match(failure.textContent, /Firmware update did not complete/)
            assert.doesNotMatch(failure.textContent, /No firmware was written/)
            assert.equal(dom.window.document.querySelector('[data-action="retry-operation"]').disabled, true)
            assert.equal(dom.window.document.querySelectorAll('main').length, 1)
            assert.equal(dom.window.document.querySelector('[data-operation-success]'), null)
            assert.equal(dom.window.document.querySelectorAll('[data-operation-failure]').length, 1)
            assert.match(dom.window.document.querySelector('main').textContent, replacementPresent ? /Select an RDX drive/ : /No RDX drives detected/)
        } finally {
            controller.destroy()
            dom.window.close()
        }
    }
}

test('firmware failure survives removal without offering a retry on a replacement dock', retainDisconnectedFirmwareFailure)

/** @returns {void} Separates unverified post-transfer reconnection from stale request admission. */
function reconnectFailureExplainsUnverifiedFirmware() {
    for (const language of supportedLanguageCodes) {
        const fixture = createFixtureState({ mode: 'operation-failed' })
        const operation = { ...fixture.lastOperation, kind: 'firmware-update', error: { ...fixture.lastOperation.error, code: 'firmware-reconnect-failed', stage: 'device-reconnecting', retryable: false, dispatchCertainty: 'completion-unknown' } }
        const store = createStore({ ...fixture, activeArea: 'utilities', lastOperation: operation })
        const dom = new JSDOM('<!doctype html><div id="app"></div>')
        const catalog = getCatalog(language)
        const controller = mountApplication(dom.window.document.querySelector('#app'), { store, translator: createTranslator(catalog, getCatalog('en')) })
        try {
            const text = dom.window.document.querySelector('[data-operation-failure]').textContent
            assert.ok(text.includes(catalog['reason.firmwareReconnectFailed']), language)
            assert.ok(text.includes('firmware-reconnect-failed'), language)
            assert.equal(text.includes(catalog['operation.failureDescription.firmwareBeforeTransfer']), false, language)
            assert.equal(dom.window.document.querySelector('[data-operation-success]'), null, language)
            for (const stage of ['queued', 'firmware-validating', 'device-reconnecting', 'firmware-readback']) {
                assert.equal(getFirmwarePreflightFailureReasonKey({ ...operation, error: { ...operation.error, stage } }), undefined, stage)
            }
        } finally {
            controller.destroy()
            dom.window.close()
        }
    }
}

test('firmware reconnect failures explain verification and never assert no firmware was written', reconnectFailureExplainsUnverifiedFirmware)
