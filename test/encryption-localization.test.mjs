// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { createAutomaticAuthOperation, createAutomaticAuthWorkflow } from '../src/renderer/workflows/automatic-auth-workflow.mjs'
import { createPasswordOperation, estimatePasswordStrength } from '../src/renderer/workflows/password-workflow.mjs'
import { createProtectionOperation, createProtectionWorkflow } from '../src/renderer/workflows/protection-workflow.mjs'
import { SECURITY_MUTATORS } from '../src/renderer/security-evidence-registry.mjs'
import { renderEncryptionView } from '../src/renderer/views/encryption-view.mjs'

/** @returns {{dom: JSDOM, document: Document}} Isolated Encryption DOM. */
function createDom() {
    const dom = new JSDOM('<!doctype html><html><body></body></html>', {
        pretendToBeVisual: true,
        url: 'file:///openrdxmanager/src/index.html'
    })
    return { dom, document: dom.window.document }
}

/**
 * Returns a conspicuous translator whose output proves the exact message key
 * and bounded parameters reached the visible presentation boundary.
 * @param {string} key - Requested bundled message key.
 * @param {object} [params={}] - Bounded interpolation parameters.
 * @returns {string} Sentinel translation.
 */
function sentinelTranslator(key, params = {}) {
    const entries = Object.entries(params).sort(([left], [right]) => left.localeCompare(right))
    const suffix = entries.length === 0 ? '' : `:${entries.map(([name, value]) => `${name}=${value}`).join(',')}`
    return `§${key}${suffix}§`
}

/** @returns {object} Strict selected-device fixture with all Encryption mutators available. */
function localizedFixture() {
    const evidence = {}
    for (const operation of SECURITY_MUTATORS) evidence[operation] = { state: 'available' }
    return {
        access: 'enabled',
        automaticAuthentication: {
            associated: false,
            associationCount: 1,
            driveCredentialExists: false,
            slot: null,
            writeAllowed: false
        },
        credentials: [
            {
                name: 'Archivleser',
                permissions: { manage: false, read: true, write: false },
                role: 'additional',
                slot: 1
            }
        ],
        device: {
            drive: { details: { connectionType: { availability: 'reported', value: 'SATA III' } } },
            id: 'rdx-fixture-001',
            label: 'RDX QuikStor · RAW-DEVICE-001',
            media: { id: 'media-fixture-001', serial: 'RAW-MEDIA-001' },
            revision: 9
        },
        evidence,
        mode: 'basic',
        resetWithoutPassword: false
    }
}

/** @returns {object} Strict SATA III device fixture for workflow model assertions. */
function strictDevice() {
    return localizedFixture().device
}

test('Encryption view translates visible copy and preserves raw device values', () => {
    const { document } = createDom()
    const model = localizedFixture()
    model.workflow = createProtectionOperation({ device: model.device, operation: 'remove-basic' })

    const view = renderEncryptionView(model, { document, translator: sentinelTranslator })
    const copy = view.textContent

    for (const key of ['encryption.title', 'encryption.protection.currentState', 'encryption.access.enabled.title', 'encryption.credentials.caption', 'encryption.automatic.writeDisabled', 'encryption.action.removeBasic.label', 'encryption.workflow.description.default', 'encryption.workflow.consequence.removeBasic', 'operation.confirmCriticalTitle', 'reason.protectionAlreadyConfigured']) {
        assert.match(copy, new RegExp(`§${key}(?::|\\§)`))
    }
    for (const untranslated of ['Encryption & Access Control', 'Cartridge access enabled', 'Passwords & permissions', 'Ready after confirmation.', 'The current authenticated session will close.', 'protection-is-already-configured']) {
        assert.doesNotMatch(copy, new RegExp(untranslated.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&')))
    }
    assert.match(copy, /RDX QuikStor · RAW-DEVICE-001/)
    assert.match(copy, /Archivleser/)
    assert.match(copy, /RAW-MEDIA-001/)

    const preview = view.querySelector('[data-password-preview]')
    const strength = view.querySelector('[data-password-strength]')
    preview.value = 'Tr0ub4dor&Correct-Horse'
    preview.dispatchEvent(new document.defaultView.Event('input', { bubbles: true }))
    assert.equal(strength.textContent, '§encryption.password.strength.veryGood§')
})

test('Encryption capability reasons use an allowlist and never expose unknown raw reason text', () => {
    const { document } = createDom()
    const model = localizedFixture()
    model.evidence['configure-basic'] = { reason: 'RAW-UNTRUSTED-REASON', state: 'unsupported-product' }

    const copy = renderEncryptionView(model, { document, translator: sentinelTranslator }).textContent

    assert.match(copy, /§reason.generic§/)
    assert.doesNotMatch(copy, /RAW-UNTRUSTED-REASON/)
})

test('English Encryption capability reasons compose without doubled punctuation', () => {
    const { document } = createDom()
    const copy = renderEncryptionView(localizedFixture(), { document }).textContent

    assert.doesNotMatch(copy, /\.\. This action/)
})

test('Encryption workflow models carry message keys instead of fixed English presentation', () => {
    const protection = createProtectionWorkflow({ evidence: {}, mode: 'none', resetWithoutPassword: true }, sentinelTranslator)
    const automatic = createAutomaticAuthWorkflow({ writeAllowed: false }, sentinelTranslator)
    const protectionOperation = createProtectionOperation({ access: 'enabled', currentMode: 'none', device: strictDevice(), mediaPresent: true, operation: 'configure-aes' })
    const passwordOperation = createPasswordOperation({ device: strictDevice(), operation: 'disable-access' })
    const automaticOperation = createAutomaticAuthOperation({ association: { driveCredentialExists: false }, device: strictDevice(), operation: 'add-automatic-association' })

    assert.equal(protection.basic.description, '§encryption.protection.basic.description§')
    assert.equal(protection.resetPolicy.consequence, '§encryption.protection.reset.consequence§')
    assert.equal(automatic.writeGuidance, '§encryption.automatic.writeDisabled§')
    assert.equal(protectionOperation.stages[0].labelKey, 'encryption.stage.updateSecurity')
    assert.equal(passwordOperation.confirmation.consequenceKey, 'encryption.workflow.consequence.disableAccess')
    assert.equal(automaticOperation.stages[0].labelKey, 'encryption.stage.createAssociation')
    assert.equal(Object.hasOwn(passwordOperation.confirmation, 'consequence'), false)
})

test('Encryption running banner localizes the allowlisted active stage without exposing its raw ID', () => {
    const { document } = createDom()
    const model = localizedFixture()
    const workflow = createProtectionOperation({ access: 'enabled', currentMode: 'none', device: model.device, mediaPresent: true, operation: 'configure-aes' })
    const activeStage = workflow.stages[0]
    model.workflow = { ...workflow, phase: 'running', progress: { activeStage: activeStage.id, value: 0.25 } }

    const view = renderEncryptionView(model, { document, translator: sentinelTranslator })
    const banner = view.querySelector('[data-operation-lock]').textContent

    assert.match(banner, new RegExp(`§${activeStage.labelKey}§`))
    assert.doesNotMatch(banner, new RegExp(activeStage.id.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&')))
})

test('every disabled Encryption input references a visible localized rationale', () => {
    const { document } = createDom()
    const lockedModel = localizedFixture()
    lockedModel.access = 'disabled'
    const lockedView = renderEncryptionView(lockedModel, { document, translator: sentinelTranslator })
    const lockedInputs = [...lockedView.querySelectorAll('input:disabled')]

    assert.equal(lockedInputs.length, 7)
    for (const input of lockedInputs) {
        const reasonId = input.getAttribute('aria-describedby')
        assert.equal(typeof reasonId, 'string')
        assert.notEqual(reasonId, '')
        const reason = lockedView.querySelector(`#${reasonId}`)
        assert.ok(reason)
        assert.notEqual(reason.textContent, '')
    }
    assert.match(lockedView.textContent, /§encryption\.controls\.credentialsDisabledReason§/)
    assert.match(lockedView.textContent, /§encryption\.controls\.readRequiredReason§/)
    assert.match(lockedView.textContent, /§encryption\.controls\.automaticWriteDisabledReason:reason=§reason\.authenticatedAccessRequired§§/)

    const unlockedView = renderEncryptionView(localizedFixture(), { document, translator: sentinelTranslator })
    const alwaysRead = unlockedView.querySelector('[data-permission-input="read"]')
    assert.equal(alwaysRead.disabled, true)
    assert.equal(alwaysRead.getAttribute('aria-describedby'), 'credential-read-required-reason')
    assert.equal(unlockedView.querySelector('#credential-read-required-reason').textContent, '§encryption.controls.readRequiredReason§')
})

test('password strength estimator returns locale-neutral rating tokens', () => {
    assert.equal(estimatePasswordStrength('abc'), 'poor')
    assert.equal(estimatePasswordStrength('abcdefgh'), 'weak')
    assert.equal(estimatePasswordStrength('Abcdefgh1'), 'better')
    assert.equal(estimatePasswordStrength('Abcdefgh1!'), 'good')
    assert.equal(estimatePasswordStrength('Tr0ub4dor&Correct-Horse'), 'very-good')
})
