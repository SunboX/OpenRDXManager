// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createStore } from '../src/renderer/store.mjs'

test('utility admission feedback uses the active translator and preserves raw operation identity', async () => {
    const dom = new JSDOM('<div id="app"></div>', { pretendToBeVisual: true, url: 'file:///openrdxmanager/src/index.html' })
    const state = { ...createFixtureState({ mode: 'one-device' }), activeArea: 'utilities' }
    let finish
    const controller = mountApplication(dom.window.document.querySelector('#app'), {
        store: createStore(state),
        translator: (key, params = {}) => `localized:${key}:${params.operationId ?? params.reason ?? ''}`,
        utilityController: {
            isAvailable: () => true,
            start: () =>
                new Promise((resolve) => {
                    finish = resolve
                })
        }
    })
    const action = dom.window.document.querySelector('[data-action="eject-safe"]')
    action.click()
    assert.equal(dom.window.document.querySelector('[data-utility-feedback]').textContent, 'localized:utilities.feedback.submitting:')
    finish({ ok: true, operationId: 'op:raw-utility-42' })
    await new Promise((resolve) => setImmediate(resolve))
    assert.equal(dom.window.document.querySelector('[data-utility-feedback]').textContent, 'localized:utilities.feedback.accepted:op:raw-utility-42')
    controller.destroy()
    dom.window.close()
})

test('app-controlled failures translate allowlisted reason codes without exposing protocol tokens', async () => {
    const dom = new JSDOM('<div id="app"></div>', { pretendToBeVisual: true, url: 'file:///openrdxmanager/src/index.html' })
    const state = { ...createFixtureState({ mode: 'one-device' }), activeArea: 'utilities' }
    const controller = mountApplication(dom.window.document.querySelector('#app'), {
        store: createStore(state),
        translator: (key, params = {}) => `localized:${key}:${params.reason ?? ''}`,
        utilityController: {
            isAvailable: () => true,
            start: async () => ({ ok: false, reason: 'firmware-selection-cancelled' })
        }
    })
    dom.window.document.querySelector('[data-action="eject-safe"]').click()
    await new Promise((resolve) => setImmediate(resolve))
    const feedback = dom.window.document.querySelector('[data-utility-feedback]').textContent
    assert.equal(feedback, 'localized:utilities.feedback.failed:localized:reason.firmwareSelectionCancelled:')
    assert.doesNotMatch(feedback, /firmware-selection-cancelled/)
    controller.destroy()
    dom.window.close()
})
