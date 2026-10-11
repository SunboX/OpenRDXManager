// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { setImmediate } from 'node:timers/promises'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { renderEncryptionView } from '../src/renderer/views/encryption-view.mjs'
import { createPasswordOperation, transitionPasswordOperation } from '../src/renderer/workflows/password-workflow.mjs'

/** @param {object} [options={}] - Workflow boundary callbacks. @returns {object} Mounted exact-confirmation workflow and its local controls. */
function createConfirmationView(options = {}) {
    const dom = new JSDOM('<!doctype html><html><body></body></html>', { pretendToBeVisual: true })
    const document = dom.window.document
    const device = {
        id: 'rdx-confirmation-fixture',
        revision: 7,
        media: { id: 'media-confirmation-fixture', serial: 'MEDIA-EXACT-001' }
    }
    const workflow = transitionPasswordOperation(createPasswordOperation({ device, operation: 'enable-access' }), { credentialValid: true, type: 'submit' })
    const view = renderEncryptionView({ access: 'disabled', credentials: [], device, evidence: { 'enable-access': { state: 'available' } }, mode: 'basic', workflow }, { document, ...options })
    document.body.append(view)
    const password = view.querySelector('[data-workflow-password]')
    password.value = 'Transient-Credential-42!'
    const identity = view.querySelector('[data-exact-device-confirmation] input')
    identity.value = 'MEDIA-EXACT-001'
    identity.dispatchEvent(new dom.window.Event('input', { bubbles: true }))
    return { dom, document, identity, password, view }
}

/** @returns {Promise<void>} Verifies the async result is emitted once after modal teardown and credentials are bounded by intent completion. */
async function testConfirmedIntentLifecycle() {
    const pending = Promise.withResolvers()
    const events = []
    const intents = []
    let credentialBytes
    let fixture
    fixture = createConfirmationView({
        /** @param {object} event - Confirmed workflow transition. @returns {void} Records the visible modal state at transition time. */
        onWorkflowEvent(event) {
            events.push({ event, dialogPresent: fixture.document.querySelector('[data-exact-device-confirmation]') !== null })
        },
        /** @param {object} intent - Strict operation intent. @param {Uint8Array} bytes - Transient credential bytes. @returns {Promise<void>} Controlled completion boundary. */
        async onIntent(intent, bytes) {
            intents.push(intent)
            credentialBytes = bytes
            await pending.promise
        }
    })
    try {
        const confirm = fixture.view.querySelector('[data-confirmation-confirm]')
        confirm.click()
        confirm.click()
        await setImmediate()

        assert.deepEqual(events, [{ event: { identity: 'MEDIA-EXACT-001', type: 'confirm' }, dialogPresent: false }])
        assert.deepEqual(intents, [{ operation: 'enable-access', device: { id: 'rdx-confirmation-fixture', revision: 7 }, media: { id: 'media-confirmation-fixture', identity: 'MEDIA-EXACT-001' }, credential: { slot: null } }])
        assert.equal(new TextDecoder().decode(credentialBytes), 'Transient-Credential-42!')
        assert.equal(fixture.password.value, '')
        pending.resolve()
        await setImmediate()
        assert.equal(
            credentialBytes.every((byte) => byte === 0),
            true
        )
    } finally {
        pending.resolve()
        fixture.dom.window.close()
    }
}

/** @returns {Promise<void>} Verifies cancellation and synchronous view replacement cannot dispatch a stale confirmation. */
async function testDismissedOrDetachedConfirmation() {
    for (const action of ['cancel', 'remove-after-confirm', 'remove-before-confirm']) {
        const events = []
        const intents = []
        const fixture = createConfirmationView({
            /** @param {object} event - Workflow transition. @returns {void} Records any unwanted confirmation. */
            onWorkflowEvent(event) {
                events.push(event)
            },
            /** @param {object} intent - Operation intent. @returns {void} Records any unwanted dispatch. */
            onIntent(intent) {
                intents.push(intent)
            }
        })
        try {
            const confirm = fixture.view.querySelector('[data-confirmation-confirm]')
            if (action === 'cancel') fixture.view.querySelector('[data-confirmation-cancel]').click()
            if (action === 'remove-before-confirm') fixture.view.remove()
            confirm.click()
            if (action === 'remove-after-confirm') fixture.view.remove()
            await setImmediate()

            assert.deepEqual(events, [], action)
            assert.deepEqual(intents, [], action)
            assert.equal(fixture.password.value, '', action)
        } finally {
            fixture.dom.window.close()
        }
    }
}

/** @returns {Promise<void>} Verifies rejected intent delivery reports a bounded failure after credential zeroization. */
async function testRejectedConfirmedIntent() {
    const errors = []
    let credentialBytes
    const fixture = createConfirmationView({
        /** @param {object} _intent - Confirmed operation intent. @param {Uint8Array} bytes - Credential buffer inspected after failure. @returns {Promise<void>} Simulated transport rejection. */
        async onIntent(_intent, bytes) {
            credentialBytes = bytes
            throw new Error('Private transport error details')
        },
        /** @param {string} reason - Stable failure reason. @returns {void} Records error presentation after cleanup. */
        onWorkflowError(reason) {
            errors.push({ reason, zeroed: credentialBytes.every((byte) => byte === 0) })
        }
    })
    try {
        fixture.view.querySelector('[data-confirmation-confirm]').click()
        await setImmediate()

        assert.deepEqual(errors, [{ reason: 'security-service-failure', zeroed: true }])
        assert.equal(fixture.password.value, '')
        assert.equal(fixture.document.querySelector('[data-exact-device-confirmation]'), null)
    } finally {
        fixture.dom.window.close()
    }
}

test('confirmed Encryption intent follows dialog teardown and zeroizes credentials after completion', testConfirmedIntentLifecycle)
test('cancelled or detached Encryption confirmations emit no workflow or operation', testDismissedOrDetachedConfirmation)
test('rejected Encryption intent reports a bounded failure after credential zeroization', testRejectedConfirmedIntent)
