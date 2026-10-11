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
import { createRendererIntentAdapter } from '../src/renderer/intent-adapter.mjs'

const GUIDANCE = Object.freeze({
    'firmware-capturing': 'capturing',
    'firmware-compatibility-setup': 'compatibilitySetup',
    'firmware-staging': 'staging',
    'firmware-awaiting-bootloader': 'awaitingBootloader',
    'firmware-programming-bootstrap': 'programmingBootstrap',
    'firmware-awaiting-bootstrap': 'awaitingBootstrap',
    'firmware-restoring-identity': 'restoringIdentity'
})

/** @returns {void} Proves that every locale distinguishes both authorized power cycles from transfers. */
function installationGuidanceIsLocalizedAndPersistent() {
    for (const language of supportedLanguageCodes) {
        const catalog = getCatalog(language)
        for (const [stage, suffix] of Object.entries(GUIDANCE)) {
            const fixture = createFixtureState({ mode: 'busy' })
            for (const presence of ['present', 'absent', 'reconciling']) {
                const absent = presence !== 'present'
                const store = createStore({ ...fixture, service: presence === 'reconciling' ? { ...fixture.service, status: 'reconciling' } : fixture.service, activeArea: 'utilities', settings: { ...fixture.settings, language }, devices: absent ? [] : fixture.devices, selectedDeviceId: absent ? null : fixture.selectedDeviceId, activeOperation: { ...fixture.activeOperation, stage, cancellationState: stage === 'firmware-capturing' ? 'cancellable' : 'closed' } })
                const dom = new JSDOM('<!doctype html><div id="app"></div>')
                const controller = mountApplication(dom.window.document.querySelector('#app'), { store, translator: createTranslator(catalog, getCatalog('en')) })
                try {
                    const prompt = dom.window.document.querySelector('[data-firmware-installation-guidance]')
                    const key = `utilities.firmware.installation.${suffix}`
                    assert.equal(typeof catalog[key], 'string', `${language}:${key}`)
                    assert.equal(prompt?.textContent, catalog[key], `${language}:${stage}:absent=${absent}`)
                    assert.equal(dom.window.document.querySelector('[data-operation-success]'), null)
                    assert.ok(dom.window.document.querySelector('#operation-lock-reason'))
                    const continuation = dom.window.document.querySelector('[data-action="continue-firmware-installation"]')
                    assert.equal(continuation !== null, suffix.startsWith('awaiting'))
                    if (continuation !== null) {
                        assert.equal(continuation.textContent, catalog['utilities.firmware.continue.action'])
                        assert.equal(continuation.disabled, true, 'no delegate must remain unavailable')
                    }
                    if (language === 'en' && suffix.startsWith('awaiting')) {
                        assert.match(prompt.textContent, /Disconnect.*reconnect.*same USB port/)
                        assert.match(prompt.textContent, /J7 open/)
                        assert.match(prompt.textContent, suffix === 'awaitingBootloader' ? /first power cycle/i : /second power cycle/i)
                    }
                } finally {
                    controller.destroy()
                    dom.window.close()
                }
            }
        }
        assert.notEqual(catalog['utilities.firmware.installation.awaitingBootloader'], catalog['utilities.firmware.installation.awaitingBootstrap'])
    }
}

test('first-install guidance distinguishes both power cycles and survives device disappearance in all locales', installationGuidanceIsLocalizedAndPersistent)

/** @returns {void} Checks actionable migration failures and limits no-write assurances to exact capture boundaries. */
function migrationFailuresKeepTheirMutationBoundary() {
    const cases = [
        ['capture-invalid', 'CaptureInvalid', 'firmware-capturing', true],
        ['recovery-unavailable', 'RecoveryUnavailable', 'firmware-validating', true],
        ['staging-failed', 'StagingFailed', 'firmware-staging', false],
        ['bootloader-unavailable', 'BootloaderUnavailable', 'firmware-awaiting-bootloader', false],
        ['programming-failed', 'ProgrammingFailed', 'firmware-programming-bootstrap', false],
        ['readback-mismatch', 'ReadbackMismatch', 'firmware-restoring-identity', false],
        ['capture-invalid', 'CaptureInvalid', 'firmware-staging', false],
        ['recovery-unavailable', 'RecoveryUnavailable', 'firmware-programming-bootstrap', false]
    ]
    for (const language of supportedLanguageCodes) {
        const catalog = getCatalog(language)
        for (const [suffix, keySuffix, stage, noWrite] of cases) {
            const fixture = createFixtureState({ mode: 'operation-failed' })
            const error = { ...fixture.lastOperation.error, code: `firmware-migration-${suffix}`, stage, retryable: false }
            const store = createStore({ ...fixture, activeArea: 'utilities', lastOperation: { ...fixture.lastOperation, kind: 'firmware-update', error } })
            const dom = new JSDOM('<!doctype html><div id="app"></div>')
            const controller = mountApplication(dom.window.document.querySelector('#app'), { store, translator: createTranslator(catalog, getCatalog('en')) })
            try {
                for (const selector of ['[data-operation-failure]', '[data-result-status="failed"]']) {
                    const text = dom.window.document.querySelector(selector).textContent
                    assert.ok(text.includes(catalog[`reason.firmwareMigration${keySuffix}`]), `${language}:${suffix}:${selector}`)
                    assert.equal(text.includes(catalog['operation.failureDescription.firmwareBeforeTransfer']), noWrite, `${language}:${suffix}:${stage}`)
                }
                assert.equal(dom.window.document.querySelector('[data-operation-success]'), null)
            } finally {
                controller.destroy()
                dom.window.close()
            }
        }
    }
}

test('migration failures explain recovery without unproven no-write or success claims in all locales', migrationFailuresKeepTheirMutationBoundary)

test('each power cycle requires its own operator click and disables duplicate submissions', async () => {
    const fixture = createFixtureState({ mode: 'busy' })
    const operationId = 'op:continue-ui'
    const store = createStore({ ...fixture, activeOperation: { ...fixture.activeOperation, id: operationId, stage: 'firmware-awaiting-bootloader', cancellationState: 'closed' } })
    const calls = []
    const response = Promise.withResolvers()
    const intentAdapter = createRendererIntentAdapter({
        supportedIntents: ['operation-continue'],
        invoke: async (request) => {
            calls.push(request)
            return response.promise
        }
    })
    const dom = new JSDOM('<!doctype html><div id="app"></div>')
    const controller = mountApplication(dom.window.document.querySelector('#app'), { store, intentAdapter })
    const button = () => dom.window.document.querySelector('[data-action="continue-firmware-installation"]')
    try {
        assert.equal(calls.length, 0, 'rendering a waiting stage cannot resume native work')
        assert.equal(button().disabled, false)
        button().click()
        button().click()
        assert.equal(calls.length, 1)
        assert.deepEqual(calls[0], { type: 'operation-continue', operationId: operationId, stage: 'firmware-awaiting-bootloader' })
        assert.equal(button().disabled, true)
        response.resolve({ ok: true, operationId: operationId })
        await new Promise(setImmediate)
        assert.equal(button().disabled, true)
        store.dispatch({ type: 'operation/progress', operationId: operationId, stage: 'firmware-programming-bootstrap', progress: 0.6, cancellationState: 'closed' })
        assert.equal(button(), null)
        store.dispatch({ type: 'operation/progress', operationId: operationId, stage: 'firmware-awaiting-bootstrap', progress: 0.7, cancellationState: 'closed' })
        assert.equal(button().disabled, false)
        assert.equal(calls.length, 1, 'second reconnection needs another explicit operator action')
        button().click()
        await new Promise(setImmediate)
        assert.equal(calls.length, 2)
        assert.equal(calls[1].stage, 'firmware-awaiting-bootstrap')
        assert.equal(button().disabled, true)
        assert.notEqual(store.getState().activeOperation, null)
        assert.equal(dom.window.document.querySelector('[data-operation-success]'), null)
    } finally {
        controller.destroy()
        dom.window.close()
    }
})
