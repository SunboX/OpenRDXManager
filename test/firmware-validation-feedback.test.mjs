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

/** @returns {void} Confirms that pre-transfer rejection never implies a partial flash. */
function testFirmwareFailureStageGuidance() {
    for (const stage of ['queued', 'firmware-writing']) {
        const fixture = createFixtureState({ mode: 'operation-failed' })
        const store = createStore({ ...fixture, lastOperation: { ...fixture.lastOperation, kind: 'firmware-update', error: { ...fixture.lastOperation.error, code: 'firmware-image-invalid', stage } } })
        const dom = new JSDOM('<!doctype html><div id="app"></div>')
        const controller = mountApplication(dom.window.document.querySelector('#app'), { store })
        try {
            const message = dom.window.document.querySelector('[data-operation-failure]').textContent
            assert.equal(message.includes('No firmware was written'), stage === 'queued')
            assert.equal(message.includes('Keep the dock powered'), stage === 'firmware-writing')
        } finally {
            controller.destroy()
            dom.window.close()
        }
    }
}

test('firmware failure guidance distinguishes validation from transfer', testFirmwareFailureStageGuidance)

/** @returns {void} Renders each sanitized transport cause without claiming that transfer never began. */
function testFirmwareTransportFailureGuidance() {
    const cases = [
        ['firmware-transfer-incomplete', 'reason.firmwareTransferIncomplete'],
        ['firmware-device-rejected', 'reason.firmwareDeviceRejected'],
        ['firmware-command-unsupported', 'reason.firmwareCommandUnsupported'],
        ['firmware-command-invalid', 'reason.firmwareCommandInvalid'],
        ['firmware-device-not-ready', 'reason.firmwareDeviceNotReady'],
        ['firmware-hardware-failure', 'reason.firmwareHardwareFailure'],
        ['firmware-write-protected', 'reason.firmwareWriteProtected'],
        ['firmware-unit-attention', 'reason.firmwareUnitAttention'],
        ['firmware-transport-unavailable', 'reason.firmwareTransportUnavailable'],
        ['firmware-transport-invalid', 'reason.firmwareTransportInvalid'],
        ['firmware-signature-error', 'reason.firmwareSignatureError']
    ]
    for (const language of supportedLanguageCodes) {
        const catalog = getCatalog(language)
        for (const [code, reasonKey] of cases) {
            const fixture = createFixtureState({ mode: 'operation-failed' })
            const error = { ...fixture.lastOperation.error, code, stage: 'firmware-writing', retryable: false }
            const store = createStore({ ...fixture, activeArea: 'utilities', lastOperation: { ...fixture.lastOperation, kind: 'firmware-update', error } })
            const dom = new JSDOM('<!doctype html><div id="app"></div>')
            const controller = mountApplication(dom.window.document.querySelector('#app'), { store, translator: createTranslator(catalog, getCatalog('en')) })
            try {
                for (const selector of ['[data-operation-failure]', '[data-result-status="failed"]']) {
                    const message = dom.window.document.querySelector(selector).textContent
                    assert.ok(message.includes(catalog[reasonKey]), `${language}:${code}:${selector}`)
                    assert.equal(message.includes(catalog['operation.failureDescription.firmwareBeforeTransfer']), false)
                }
            } finally {
                controller.destroy()
                dom.window.close()
            }
        }
    }
}

test('firmware transport failures show their exact localized cause', testFirmwareTransportFailureGuidance)

/** @returns {void} Renders concrete manifest recovery guidance through every active locale. */
function testManifestFailureGuidance() {
    const cases = [
        ['firmware-openrdx-manifest-missing', 'reason.firmwareOpenRdxManifestMissing', /matching OpenRDX release \.json file is missing/],
        ['firmware-openrdx-manifest-malformed', 'reason.firmwareOpenRdxManifestMalformed', /not valid JSON/],
        ['firmware-openrdx-manifest-filename-mismatch', 'reason.firmwareOpenRdxManifestFilenameMismatch', /filename does not match/],
        ['firmware-openrdx-manifest-hash-mismatch', 'reason.firmwareOpenRdxManifestHashMismatch', /SHA-256 checksums do not match/],
        ['firmware-openrdx-manifest-invalid', 'reason.firmwareOpenRdxManifestInvalid', /cannot be read safely or contains invalid release metadata/]
    ]
    for (const language of supportedLanguageCodes) {
        for (const [code, reasonKey, expected] of cases) {
            const fixture = createFixtureState({ mode: 'operation-failed' })
            const store = createStore({ ...fixture, lastOperation: { ...fixture.lastOperation, kind: 'firmware-update', error: { ...fixture.lastOperation.error, code, stage: 'queued' } } })
            const dom = new JSDOM('<!doctype html><div id="app"></div>')
            const catalog = getCatalog(language)
            const controller = mountApplication(dom.window.document.querySelector('#app'), { store, translator: createTranslator(catalog, getCatalog('en')) })
            try {
                const message = dom.window.document.querySelector('[data-operation-failure]').textContent
                assert.equal(typeof catalog[reasonKey], 'string', `${language}:${code} has its own translation`)
                assert.ok(message.includes(catalog[reasonKey]), `${language}:${code} explains the cause`)
                if (language === 'en') {
                    assert.match(message, expected)
                    assert.match(message, /No firmware was written/)
                    if (code.endsWith('-missing')) {
                        assert.match(message, /OpenRDX-v1-11\.bin.*OpenRDX-v1-11\.json/)
                        assert.match(message, /same folder.*original, matching names/)
                        assert.match(message, /Then select the \.bin file again/)
                    }
                    if (code.endsWith('-filename-mismatch')) assert.match(message, /OpenRDX-v1-07\.bin.*OpenRDX-v1-07\.json/)
                }
            } finally {
                controller.destroy()
                dom.window.close()
            }
        }
    }
}

test('manifest failures show their actionable localized cause in the terminal error', testManifestFailureGuidance)

/** @returns {void} Identifies a current Manager installation limitation without implying an impossible hardware upgrade or partial write. */
function testUnsupportedInstallationGuidance() {
    for (const language of supportedLanguageCodes) {
        const fixture = createFixtureState({ mode: 'operation-failed' })
        const error = { ...fixture.lastOperation.error, code: 'firmware-openrdx-installation-unsupported', stage: 'firmware-validating', retryable: false }
        const store = createStore({ ...fixture, activeArea: 'utilities', lastOperation: { ...fixture.lastOperation, kind: 'firmware-update', error } })
        const dom = new JSDOM('<!doctype html><div id="app"></div>')
        const catalog = getCatalog(language)
        const controller = mountApplication(dom.window.document.querySelector('#app'), { store, translator: createTranslator(catalog, getCatalog('en')) })
        try {
            const reason = catalog['reason.firmwareOpenRdxInstallationUnsupported']
            const noWrite = catalog['operation.failureDescription.firmwareBeforeTransfer']
            assert.equal(typeof reason, 'string', `${language}: localized Manager limitation`)
            assert.equal(typeof noWrite, 'string', `${language}: localized no-write assurance`)
            for (const selector of ['[data-operation-failure]', '[data-result-status="failed"]']) {
                const message = dom.window.document.querySelector(selector).textContent
                assert.ok(message.includes(reason), `${language}:${selector} identifies Manager limitation`)
                assert.ok(message.includes(noWrite), `${language}:${selector} identifies pre-transfer rejection`)
                if (language === 'en') {
                    assert.match(message, /This version of OpenRDXManager cannot install OpenRDX on the firmware currently reported by this dock/)
                    assert.match(message, /No firmware was written/)
                    assert.doesNotMatch(message, /downgrade|physically impossible|Keep the dock powered/)
                }
            }
            if (language === 'en') {
                assert.doesNotMatch(dom.window.document.querySelector('#app').textContent, /downgraded to an older unsigned image/)
                assert.match(dom.window.document.querySelector('#app').textContent, /authentication result for the selected installation route/)
            }
            assert.equal(dom.window.document.querySelector('[data-action="retry-operation"]'), null)
        } finally {
            controller.destroy()
            dom.window.close()
        }
    }
}

test('unsupported OpenRDX installation explains the current Manager limitation in banner and Utilities', testUnsupportedInstallationGuidance)

/** @returns {void} Restricts no-write assurance to the allowlisted pre-transfer cause and stage. */
function testInstallationFailureStageBoundary() {
    for (const [code, stage] of [
        ['firmware-openrdx-installation-unsupported', 'firmware-writing'],
        ['host-operation-failed', 'firmware-validating'],
        ['firmware-openrdx-manifest-missing', 'firmware-validating']
    ]) {
        const fixture = createFixtureState({ mode: 'operation-failed' })
        const store = createStore({ ...fixture, activeArea: 'utilities', lastOperation: { ...fixture.lastOperation, kind: 'firmware-update', error: { ...fixture.lastOperation.error, code, stage } } })
        const dom = new JSDOM('<!doctype html><div id="app"></div>')
        const controller = mountApplication(dom.window.document.querySelector('#app'), { store })
        try {
            for (const selector of ['[data-operation-failure]', '[data-result-status="failed"]']) assert.doesNotMatch(dom.window.document.querySelector(selector).textContent, /No firmware was written/)
        } finally {
            controller.destroy()
            dom.window.close()
        }
    }
}

test('unrelated firmware failures do not acquire a no-write assurance', testInstallationFailureStageBoundary)

/** @returns {void} Shows reboot guidance only for the proven pre-transfer interlock. */
function testReceiverInterlockGuidance() {
    for (const language of supportedLanguageCodes) {
        for (const stage of ['firmware-validating', 'firmware-writing']) {
            const fixture = createFixtureState({ mode: 'operation-failed' })
            const error = { ...fixture.lastOperation.error, code: 'firmware-power-cycle-required', stage, retryable: false }
            const store = createStore({ ...fixture, activeArea: 'utilities', lastOperation: { ...fixture.lastOperation, kind: 'firmware-update', error } })
            const dom = new JSDOM('<!doctype html><div id="app"></div>')
            const catalog = getCatalog(language)
            const controller = mountApplication(dom.window.document.querySelector('#app'), { store, translator: createTranslator(catalog, getCatalog('en')) })
            try {
                assert.equal(typeof catalog['reason.firmwarePowerCycleRequired'], 'string')
                assert.equal(typeof catalog['reason.firmwareReceiverReadinessUnknown'], 'string')
                for (const selector of ['[data-operation-failure]', '[data-result-status="failed"]']) {
                    const message = dom.window.document.querySelector(selector).textContent
                    assert.equal(message.includes(catalog['reason.firmwarePowerCycleRequired']), stage === 'firmware-validating')
                    assert.equal(message.includes(catalog['operation.failureDescription.firmwareBeforeTransfer']), stage === 'firmware-validating')
                }
                assert.equal(dom.window.document.querySelector('[data-action="retry-operation"]'), null)
            } finally {
                controller.destroy()
                dom.window.close()
            }
        }
    }
}

test('receiver interlock shows stage-bounded power-cycle guidance in every locale', testReceiverInterlockGuidance)
