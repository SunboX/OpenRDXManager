// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'
import { getCatalog } from '../src/locales/catalogs.mjs'

/** @returns {void} Verifies private-record failures explain the cause without false no-write claims. */
function manufacturingFailuresRetainTheirMutationBoundary() {
    const catalog = getCatalog('en')
    for (const [suffix, key] of [
        ['unreadable', 'Unreadable'],
        ['invalid', 'Invalid'],
        ['changed', 'Changed'],
        ['backup-unavailable', 'BackupUnavailable']
    ]) {
        for (const stage of ['firmware-validating', 'firmware-finalizing', 'firmware-readback']) {
            const fixture = createFixtureState({ mode: 'operation-failed' })
            const error = { ...fixture.lastOperation.error, code: `firmware-manufacturing-${suffix}`, stage, retryable: false }
            const store = createStore({ ...fixture, activeArea: 'utilities', lastOperation: { ...fixture.lastOperation, kind: 'firmware-update', error } })
            const dom = new JSDOM('<!doctype html><div id="app"></div>')
            const controller = mountApplication(dom.window.document.querySelector('#app'), { store, translator: createTranslator(catalog, catalog) })
            try {
                const reason = catalog[`reason.firmwareManufacturing${key}`]
                assert.equal(typeof reason, 'string')
                for (const selector of ['[data-operation-failure]', '[data-result-status="failed"]']) {
                    const text = dom.window.document.querySelector(selector).textContent
                    assert.ok(text.includes(reason), `${suffix}:${stage}:${selector}`)
                    assert.equal(text.includes(catalog['operation.failureDescription.firmwareBeforeTransfer']), stage === 'firmware-validating')
                }
                assert.equal(dom.window.document.querySelector('[data-operation-success]'), null)
            } finally {
                controller.destroy()
                dom.window.close()
            }
        }
    }
}

test('manufacturing failures give actionable reasons and preserve the no-write boundary', manufacturingFailuresRetainTheirMutationBoundary)
