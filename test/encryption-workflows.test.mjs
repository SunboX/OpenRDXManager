// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { buildAutomaticAuthIntent, createAutomaticAuthOperation, createAutomaticAuthWorkflow, transitionAutomaticAuthOperation } from '../src/renderer/workflows/automatic-auth-workflow.mjs'
import { SECURITY_MUTATOR_EVIDENCE, SECURITY_MUTATORS } from '../src/renderer/security-evidence-registry.mjs'
import { buildPasswordIntent, createPasswordOperation, estimatePasswordStrength, transitionPasswordOperation, validateCredentialDraft, withTransientCredentialBytes } from '../src/renderer/workflows/password-workflow.mjs'
import { buildProtectionIntent, createProtectionOperation, createProtectionWorkflow, resolveSecurityCapability, transitionProtectionOperation } from '../src/renderer/workflows/protection-workflow.mjs'
import { renderEncryptionView } from '../src/renderer/views/encryption-view.mjs'

/** @returns {{dom: JSDOM, document: Document}} Isolated encryption workflow DOM. */
function createDom() {
    const dom = new JSDOM('<!doctype html><html><body></body></html>', {
        pretendToBeVisual: true,
        url: 'file:///openrdxmanager/src/index.html'
    })
    return { dom, document: dom.window.document }
}

/** @param {Uint8Array} bytes - Transient fixture bytes. @returns {boolean} True when every byte is zero. */
function isZeroed(bytes) {
    for (const byte of bytes) {
        if (byte !== 0) return false
    }
    return true
}

/** @returns {object} Base evidence registry with every mutator blocked. */
function incompleteEvidence() {
    return structuredClone(SECURITY_MUTATOR_EVIDENCE)
}

/** @returns {object} Read-only authenticated credential fixture. */
function readOnlyCredentialFixture() {
    return {
        access: 'disabled',
        credentials: [
            {
                name: 'Archive reader',
                permissions: { manage: false, read: true, write: false },
                role: 'additional',
                slot: 1
            }
        ],
        device: strictDeviceFixture('SATA III'),
        evidence: {
            ...incompleteEvidence(),
            'enable-access': { state: 'available' }
        },
        mode: 'basic',
        resetWithoutPassword: false
    }
}

/** @returns {object} AES configuration fixture with the media-layout boundary. */
function aesEvidenceIncompleteFixture() {
    return {
        access: 'enabled',
        credentials: [],
        device: strictDeviceFixture('USB 3'),
        evidence: incompleteEvidence(),
        mode: 'none',
        resetWithoutPassword: false
    }
}

/** @param {string} connectionType - Reported strict connection type. @returns {object} Minimal strict renderer device fixture. */
function strictDeviceFixture(connectionType) {
    return {
        id: 'rdx-fixture-001',
        label: 'RDX QuikStor · FIXTURE-001',
        revision: 7,
        drive: { details: { connectionType: { availability: 'reported', value: connectionType } } },
        media: { id: 'media-fixture-001', serial: 'MEDIA-FIXTURE-001' }
    }
}

/** @returns {void} Verifies read permission does not silently imply write permission. */
function testReadOnlyCredential() {
    const { document } = createDom()
    const view = renderEncryptionView(readOnlyCredentialFixture(), { document })

    assert.equal(view.querySelector('[data-action="enable-access"]').disabled, false)
    assert.equal(view.querySelector('[data-permission="read"]').textContent.trim(), 'Allowed')
    assert.equal(view.querySelector('[data-permission="write"]').textContent.trim(), 'Not allowed')
    assert.equal(view.querySelector('[data-permission="manage"]').textContent.trim(), 'Not allowed')
    assert.equal(view.querySelector('[data-action="change-credential"]').disabled, true)
}

/** @returns {void} Verifies AES never appears runnable without compatible media evidence. */
function testAesEvidenceBoundary() {
    const { document } = createDom()
    const view = renderEncryptionView(aesEvidenceIncompleteFixture(), { document })

    assert.match(view.textContent, /Compatible AES media layout is not yet proven/)
    assert.equal(view.querySelector('[data-action="configure-aes"]').disabled, true)
    assert.match(view.querySelector('[data-action-reason="configure-aes"]').textContent, /compatible AES media layout and security-write behavior are not proven/i)
}

/** @returns {void} Verifies documented Basic and reset consequences remain explicit. */
function testProtectionWarnings() {
    const workflow = createProtectionWorkflow({ evidence: incompleteEvidence(), mode: 'none', resetWithoutPassword: true })

    assert.match(workflow.basic.warning, /does not encrypt/i)
    assert.match(workflow.passwordLossWarning, /cannot be recovered/i)
    assert.match(workflow.resetPolicy.consequence, /erase all protection configuration/i)
    assert.equal(workflow.basic.capability.state, 'evidence-incomplete')
    assert.equal(workflow.aes.capability.state, 'evidence-incomplete')
}

/** @returns {void} Verifies the password scale and bounded credential rules. */
function testCredentialValidation() {
    assert.equal(estimatePasswordStrength('abc'), 'poor')
    assert.equal(estimatePasswordStrength('abcdefgh'), 'weak')
    assert.equal(estimatePasswordStrength('Abcdefgh1'), 'better')
    assert.equal(estimatePasswordStrength('Abcdefgh1!'), 'good')
    assert.equal(estimatePasswordStrength('Tr0ub4dor&Correct-Horse'), 'very-good')

    assert.deepEqual(validateCredentialDraft({ confirmation: 'new-fixture', existingNames: ['Archive reader'], name: 'archive READER', password: 'new-fixture', slotCount: 2 }), { valid: false, errors: ['credential-name-not-unique'] })
    assert.deepEqual(validateCredentialDraft({ confirmation: 'new-fixture', existingNames: [], name: 'A'.repeat(198), password: 'new-fixture', slotCount: 2 }), { valid: false, errors: ['credential-name-too-long'] })
    assert.deepEqual(validateCredentialDraft({ confirmation: 'different', existingNames: [], name: 'Backup', password: 'new-fixture', slotCount: 2 }), { valid: false, errors: ['credential-confirmation-mismatch'] })
    assert.deepEqual(validateCredentialDraft({ confirmation: 'new-fixture', existingNames: [], name: 'Backup', password: 'new-fixture', slotCount: 8 }), { valid: false, errors: ['credential-slots-full'] })
}

/** @returns {Promise<void>} Verifies bytes exist only during the bounded action and are then zeroed. */
async function testTransientCredentialZeroization() {
    let observed
    let retained
    /** @param {Uint8Array} bytes - Success-path transient bytes. @returns {Promise<object>} Fixture terminal. */
    async function acceptCredential(bytes) {
        retained = bytes
        observed = new TextDecoder().decode(bytes)
        return { status: 'terminal' }
    }
    const result = await withTransientCredentialBytes('fixture-only-password', acceptCredential)

    assert.equal(observed, 'fixture-only-password')
    assert.deepEqual(result, { status: 'terminal' })
    assert.equal(isZeroed(retained), true)

    let failedRetained
    /** @param {Uint8Array} bytes - Failure-path transient bytes. @returns {Promise<never>} Rejected terminal. */
    async function rejectCredential(bytes) {
        failedRetained = bytes
        throw new Error('fixture terminal failure')
    }
    await assert.rejects(withTransientCredentialBytes('another-fixture', rejectCredential), /fixture terminal failure/)
    assert.equal(isZeroed(failedRetained), true)
}

/** @returns {void} Verifies the eight-slot and temporary-slot UX. */
function testEightSlotModel() {
    const { document } = createDom()
    const credentials = [{ name: 'Master Password', permissions: { manage: true, read: true, write: true }, role: 'master', slot: 0 }]
    for (let slot = 1; slot < 8; slot += 1) {
        credentials.push({ name: `Credential ${slot}`, permissions: { manage: false, read: true, write: slot % 2 === 0 }, role: 'additional', slot })
    }
    const view = renderEncryptionView(
        {
            access: 'enabled',
            credentials,
            device: strictDeviceFixture('SATA III'),
            evidence: { ...incompleteEvidence(), 'create-credential': { state: 'available' }, 'change-credential': { state: 'available' } },
            mode: 'basic',
            resetWithoutPassword: false
        },
        { document }
    )

    assert.equal(view.querySelectorAll('[data-credential-slot]').length, 8)
    assert.match(view.textContent, /one master credential and seven additional slots/i)
    assert.match(view.textContent, /temporary free slot/i)
    assert.equal(view.querySelector('[data-action="create-credential"]').disabled, true)
    assert.equal(view.querySelector('[data-action="change-credential"]').disabled, true)
}

/** @returns {void} Verifies SATA III association scope and delete/reinsert guidance. */
function testAutomaticAuthentication() {
    const available = createAutomaticAuthWorkflow({ access: 'enabled', associated: true, associationCount: 2, associationSlot: 2, connectionType: { availability: 'reported', value: 'SATA III' }, driveCredentialExists: true, evidence: { 'add-automatic-association': { state: 'available' }, 'delete-automatic-association': { state: 'available' }, 'delete-drive-automatic-credential': { state: 'available' } }, mediaPresent: true, protectionMode: 'basic', slotCount: 3, writeAllowed: false })
    assert.equal(available.add.disabled, true)
    assert.equal(available.delete.disabled, false)
    assert.match(available.limit, /seven SATA III drives/i)
    assert.match(available.writeGuidance, /delete.*add it again/i)
    assert.match(available.reinsertGuidance, /eject and reinsert/i)
    assert.match(available.driveDeleteConsequence, /every cartridge associated with this drive/i)
    assert.match(available.associationDeleteConsequence, /only this cartridge/i)

    const unavailable = createAutomaticAuthWorkflow({ access: 'enabled', associated: false, associationCount: 0, connectionType: { availability: 'reported', value: 'USB 3' }, driveCredentialExists: false, evidence: { ...incompleteEvidence(), 'add-automatic-association': { state: 'available' } }, mediaPresent: true, protectionMode: 'basic', slotCount: 1, writeAllowed: true })
    assert.equal(unavailable.add.disabled, true)
    assert.equal(unavailable.add.capability.state, 'unsupported-product')
}

/** @returns {void} Verifies the complete bounded credential/protection form surface. */
function testSecurityFormControls() {
    const { document } = createDom()
    const view = renderEncryptionView(aesEvidenceIncompleteFixture(), { document })

    const protectionValues = []
    for (const input of view.querySelectorAll('[data-protection-option]')) protectionValues.push(input.value)
    assert.deepEqual(protectionValues, ['basic', 'aes'])
    assert.equal(view.querySelector('[data-credential-name]').maxLength, 197)
    assert.equal(view.querySelector('[data-credential-password]').maxLength, 1024)
    assert.equal(view.querySelector('[data-credential-password]').type, 'password')
    assert.equal(view.querySelector('[data-credential-confirmation]').type, 'password')
    assert.equal(view.querySelector('[data-permission-input="read"]').checked, true)
    assert.equal(view.querySelector('[data-permission-input="read"]').disabled, true)
    assert.equal(view.querySelector('[data-permission-input="write"]').disabled, false)
    assert.equal(view.querySelector('[data-permission-input="manage"]').disabled, false)
    assert.notEqual(view.querySelector('[data-reset-without-password]'), null)
    assert.notEqual(view.querySelector('[data-automatic-write-access]'), null)
    assert.notEqual(view.querySelector('[data-action="delete-drive-automatic-credential"]'), null)
}

/** @returns {void} Verifies every incomplete mutation renders disabled with its exact reason. */
function testAllMutatorsFailClosed() {
    const { document } = createDom()
    const view = renderEncryptionView(aesEvidenceIncompleteFixture(), { document })
    const actions = view.querySelectorAll('[data-security-mutator]')

    assert.equal(actions.length >= 10, true)
    for (const action of actions) {
        assert.equal(action.disabled, true, `${action.dataset.action} must fail closed`)
        const reason = view.querySelector(`[data-action-reason="${action.dataset.action}"]`)
        assert.notEqual(reason, null)
        assert.equal(reason.textContent.trim().length > 0, true)
    }
}

/** @returns {Promise<void>} Verifies the complete workflow receives its local responsive surface. */
async function testEncryptionWorkflowStyles() {
    const { document } = createDom()
    const style = document.createElement('style')
    style.textContent = `${await readFile(new URL('../src/styles/tokens.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/base.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/operation-components.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/security-workflows.css', import.meta.url), 'utf8')}`
    document.head.append(style)
    const view = renderEncryptionView(readOnlyCredentialFixture(), { document })
    document.body.append(view)

    assert.equal(document.defaultView.getComputedStyle(view).display, 'grid')
    assert.equal(document.defaultView.getComputedStyle(view.querySelector('.security-section')).display, 'grid')
    const warningStyle = document.defaultView.getComputedStyle(view.querySelector('.security-warning--plaintext'))
    assert.equal(warningStyle.paddingTop, '10px')
    assert.equal(warningStyle.paddingRight, '12px')
}

/** @returns {Promise<void>} Verifies generated JSON and the renderer's embedded registry cannot drift. */
async function testCanonicalRendererEvidenceRegistry() {
    const registry = JSON.parse(await readFile(new URL('./fixtures/security-selector-fixtures.json', import.meta.url), 'utf8'))

    assert.deepEqual(Object.keys(registry.mutators), [...SECURITY_MUTATORS].sort())
    assert.deepEqual(registry.mutators, SECURITY_MUTATOR_EVIDENCE)
    assert.equal(SECURITY_MUTATORS.length, 13)
    assert.equal(resolveSecurityCapability({ 'enable-access': { reason: 'tampered-runtime-reason', state: 'evidence-incomplete' } }, 'enable-access').reason, registry.mutators['enable-access'].reason)
}

/** @returns {void} Verifies AES setup/removal model exact filesystem and destructive confirmation state. */
function testProtectionOperationStateMachine() {
    let operation = createProtectionOperation({
        access: 'enabled',
        currentMode: 'none',
        device: strictDeviceFixture('USB 3'),
        mediaPresent: true,
        operation: 'configure-aes'
    })
    assert.equal(operation.phase, 'input')
    assert.deepEqual(operation.filesystemChoices, ['ntfs', 'exfat'])
    operation = transitionProtectionOperation(operation, {
        type: 'submit',
        credentialValid: true,
        draft: { filesystem: 'exfat', resetWithoutPassword: false }
    })
    assert.equal(operation.phase, 'confirmation')
    assert.equal(operation.confirmation.expected, 'MEDIA-FIXTURE-001')
    assert.equal(operation.confirmation.risk, 'destructive')
    const intent = buildProtectionIntent(operation)
    assert.deepEqual(intent, {
        operation: 'configure-aes',
        device: { id: 'rdx-fixture-001', revision: 7 },
        media: { id: 'media-fixture-001', identity: 'MEDIA-FIXTURE-001' },
        protection: {
            filesystem: 'exfat',
            mode: 'aes',
            resetWithoutPassword: false
        },
        credential: {
            name: 'Master Password',
            permissions: { manage: true, read: true, write: true },
            role: 'master',
            slot: 0
        }
    })
    assert.equal(Object.hasOwn(intent, 'password'), false)

    let removal = createProtectionOperation({ device: strictDeviceFixture('USB 3'), operation: 'remove-aes' })
    removal = transitionProtectionOperation(removal, { type: 'submit', draft: { filesystem: 'ntfs' } })
    assert.equal(removal.phase, 'confirmation')
    assert.equal(buildProtectionIntent(removal).protection.filesystem, 'ntfs')
}

/** @returns {void} Verifies enable and row-specific credential workflows emit bounded structured intents. */
function testPasswordOperationStateMachine() {
    let enable = createPasswordOperation({ device: strictDeviceFixture('USB 3'), operation: 'enable-access' })
    assert.equal(enable.phase, 'input-password')
    enable = transitionPasswordOperation(enable, { type: 'submit', credentialValid: true })
    assert.equal(enable.phase, 'confirmation')
    assert.deepEqual(buildPasswordIntent(enable), {
        operation: 'enable-access',
        device: { id: 'rdx-fixture-001', revision: 7 },
        media: { id: 'media-fixture-001', identity: 'MEDIA-FIXTURE-001' },
        credential: { slot: null }
    })

    let change = createPasswordOperation({ device: strictDeviceFixture('USB 3'), operation: 'change-credential', target: { name: 'Audit reader', role: 'additional', slot: 3 } })
    change = transitionPasswordOperation(change, {
        type: 'submit',
        credentialValid: true,
        draft: { name: 'Audit reader 2', permissions: { manage: false, read: true, write: false } }
    })
    assert.equal(change.phase, 'confirmation')
    assert.deepEqual(buildPasswordIntent(change).credential, {
        name: 'Audit reader 2',
        permissions: { manage: false, read: true, write: false },
        role: 'additional',
        slot: 3,
        temporarySlotRequired: true
    })
}

/** @returns {void} Verifies disabled access gates all management and each row owns structured controls. */
function testAuthenticatedManagementAndRowActions() {
    const { document } = createDom()
    const actions = []
    const fixture = readOnlyCredentialFixture()
    fixture.evidence = Object.fromEntries(SECURITY_MUTATORS.map((operation) => [operation, { state: 'available' }]))
    fixture.credentials.push({ name: 'Writer', permissions: { manage: false, read: true, write: true }, role: 'additional', slot: 2 })
    const view = renderEncryptionView(fixture, { document, onAction: (intent) => actions.push(intent) })

    assert.equal(view.querySelector('[data-credential-name]').disabled, true)
    assert.equal(view.querySelector('[data-permission-input="write"]').disabled, true)
    assert.equal(view.querySelector('[data-action="remove-basic"]').disabled, true)
    assert.equal(view.querySelectorAll('[data-row-change]').length, 2)
    assert.equal(view.querySelectorAll('[data-row-delete]').length, 2)
    assert.equal(view.querySelector('[data-row-change][data-slot="1"]').disabled, true)

    const enabledView = renderEncryptionView({ ...fixture, access: 'enabled' }, { document, onAction: (intent) => actions.push(intent) })
    enabledView.querySelector('[data-row-change][data-slot="2"]').click()
    assert.deepEqual(actions.at(-1), {
        operation: 'change-credential',
        device: { id: 'rdx-fixture-001', revision: 7 },
        media: { id: 'media-fixture-001', identity: 'MEDIA-FIXTURE-001' },
        credential: { name: 'Writer', role: 'additional', slot: 2 }
    })
}

/** @returns {void} Verifies complete input, confirmation, progress, and result workflow surfaces. */
function testGuidedWorkflowSurfaces() {
    const { document } = createDom()
    const input = renderEncryptionView({ ...aesEvidenceIncompleteFixture(), workflow: createPasswordOperation({ device: strictDeviceFixture('USB 3'), operation: 'enable-access' }) }, { document })
    assert.notEqual(input.querySelector('[data-operation-drawer]'), null)
    assert.equal(input.querySelector('[data-workflow-password]').type, 'password')

    let configuration = createProtectionOperation({ access: 'enabled', currentMode: 'none', device: strictDeviceFixture('USB 3'), mediaPresent: true, operation: 'configure-aes' })
    configuration = transitionProtectionOperation(configuration, { type: 'submit', credentialValid: true, draft: { filesystem: 'ntfs', resetWithoutPassword: true } })
    const confirmation = renderEncryptionView({ ...aesEvidenceIncompleteFixture(), workflow: configuration }, { document })
    assert.notEqual(confirmation.querySelector('[data-exact-device-confirmation]'), null)
    assert.match(confirmation.textContent, /NTFS/i)

    const running = renderEncryptionView({ ...aesEvidenceIncompleteFixture(), workflow: { ...configuration, phase: 'running', progress: { activeStage: 'format', value: 0.6 } } }, { document })
    assert.notEqual(running.querySelector('[data-progress-timeline]'), null)
    const result = renderEncryptionView({ ...aesEvidenceIncompleteFixture(), workflow: { ...configuration, phase: 'result', result: { status: 'failed', summary: 'Fixture failure' } } }, { document })
    assert.equal(result.querySelector('[data-result-status]').dataset.resultStatus, 'failed')

    const automatic = renderEncryptionView(
        {
            ...aesEvidenceIncompleteFixture(),
            workflow: createAutomaticAuthOperation({ association: { driveCredentialExists: false }, device: strictDeviceFixture('SATA III'), operation: 'add-automatic-association' })
        },
        { document }
    )
    assert.notEqual(automatic.querySelector('[data-workflow-automatic-write]'), null)
}

/** @returns {void} Verifies guided new-password forms own a live five-level strength scale. */
function testGuidedPasswordStrengthScale() {
    const { dom, document } = createDom()
    const workflows = [createProtectionOperation({ access: 'enabled', currentMode: 'none', device: strictDeviceFixture('USB 3'), mediaPresent: true, operation: 'configure-basic' }), createPasswordOperation({ device: strictDeviceFixture('USB 3'), operation: 'create-credential' })]
    for (const workflow of workflows) {
        const view = renderEncryptionView({ ...aesEvidenceIncompleteFixture(), workflow }, { document })
        const password = view.querySelector('[data-workflow-password]')
        const meter = view.querySelector('[data-workflow-password-strength]')
        const label = view.querySelector('[data-workflow-password-strength-label]')
        assert.equal(meter.min, 1)
        assert.equal(meter.max, 5)
        assert.equal(meter.value, 1)
        assert.equal(label.textContent, 'Poor')
        password.value = 'Long-Cyberpunk-Password-42!'
        password.dispatchEvent(new dom.window.Event('input', { bubbles: true }))
        assert.equal(meter.value, 5)
        assert.equal(label.textContent, 'Very Good')
    }
}

/** @returns {void} Verifies protected, unauthenticated, and missing-media setup states remain blocked once evidence becomes available. */
function testStrictProtectionSetupGates() {
    const { document } = createDom()
    const evidence = { ...incompleteEvidence(), 'configure-aes': { state: 'available' }, 'configure-basic': { state: 'available' } }
    const protectedView = renderEncryptionView({ ...aesEvidenceIncompleteFixture(), evidence, mode: 'basic' }, { document })
    assert.equal(protectedView.querySelector('[data-action="configure-basic"]').disabled, true)
    assert.match(protectedView.querySelector('[data-action-reason="configure-basic"]').textContent, /protection is already configured/i)

    const unauthenticatedView = renderEncryptionView({ ...aesEvidenceIncompleteFixture(), access: 'disabled', evidence, mode: 'none' }, { document })
    assert.equal(unauthenticatedView.querySelector('[data-action="configure-aes"]').disabled, true)
    assert.match(unauthenticatedView.querySelector('[data-action-reason="configure-aes"]').textContent, /access.*required/i)

    assert.throws(() => createProtectionOperation({ access: 'enabled', currentMode: 'basic', device: strictDeviceFixture('USB 3'), mediaPresent: true, operation: 'configure-basic' }), /unprotected/i)
    assert.throws(() => createProtectionOperation({ access: 'disabled', currentMode: 'none', device: strictDeviceFixture('USB 3'), mediaPresent: true, operation: 'configure-aes' }), /access/i)
}

/** @returns {void} Verifies strict SATA III and fully reported lifecycle prerequisites. */
function testStrictAutomaticAuthenticationGates() {
    const base = {
        access: 'enabled',
        associated: false,
        associationCount: 2,
        driveCredentialExists: false,
        evidence: {
            'add-automatic-association': { state: 'available' },
            'delete-automatic-association': { state: 'available' },
            'delete-drive-automatic-credential': { state: 'available' }
        },
        mediaPresent: true,
        protectionMode: 'basic',
        slotCount: 3,
        connectionType: { availability: 'reported', value: 'SATA III' }
    }
    assert.equal(createAutomaticAuthWorkflow(base).add.disabled, false)
    assert.match(createAutomaticAuthWorkflow({ ...base, connectionType: { availability: 'unavailable', reason: 'not-reported' } }).add.reason, /connection-type-not-reported/)
    assert.match(createAutomaticAuthWorkflow({ ...base, protectionMode: 'none' }).add.reason, /protected-cartridge-required/)
    assert.match(createAutomaticAuthWorkflow({ ...base, access: 'disabled' }).add.reason, /authenticated-access-required/)
    assert.match(createAutomaticAuthWorkflow({ ...base, driveCredentialExists: undefined }).add.reason, /drive-credential-state-not-reported/)
    assert.match(createAutomaticAuthWorkflow({ ...base, associationCount: 7 }).add.reason, /seven-drive-association-limit-reached/)
    assert.match(createAutomaticAuthWorkflow({ ...base, associated: true, associationSlot: 8 }).delete.reason, /slot-not-reported-or-out-of-bounds/)
    assert.match(createAutomaticAuthWorkflow({ ...base, driveCredentialExists: false }).driveDelete.reason, /drive-automatic-credential-not-present/)
    assert.equal(createAutomaticAuthWorkflow({ ...base, driveCredentialExists: true }).driveDelete.disabled, false)
}

/** @returns {void} Verifies automatic association mutations use guided structured states. */
function testAutomaticAuthenticationStateMachine() {
    let add = createAutomaticAuthOperation({
        association: { driveCredentialExists: false },
        device: strictDeviceFixture('SATA III'),
        operation: 'add-automatic-association'
    })
    assert.equal(add.phase, 'input')
    add = transitionAutomaticAuthOperation(add, { draft: { allowWrite: false }, type: 'submit' })
    assert.equal(add.phase, 'confirmation')
    assert.deepEqual(buildAutomaticAuthIntent(add), {
        operation: 'add-automatic-association',
        device: { id: 'rdx-fixture-001', revision: 7 },
        media: { id: 'media-fixture-001', identity: 'MEDIA-FIXTURE-001' },
        association: { allowWrite: false, cartridgeSlot: null, driveCredentialExists: false, scope: 'cartridge-drive-pair' }
    })

    let remove = createAutomaticAuthOperation({
        association: { driveCredentialExists: true, slot: 4 },
        device: strictDeviceFixture('SATA III'),
        operation: 'delete-automatic-association'
    })
    remove = transitionAutomaticAuthOperation(remove, { identity: 'MEDIA-FIXTURE-001', type: 'confirm' })
    assert.equal(remove.phase, 'running')
    assert.equal(buildAutomaticAuthIntent(remove).association.cartridgeSlot, 4)
    assert.throws(() => createAutomaticAuthOperation({ association: { driveCredentialExists: true, slot: 8 }, device: strictDeviceFixture('SATA III'), operation: 'delete-automatic-association' }), /slot/i)
}

/** @returns {void} Verifies disabled row controls point to one stable visible reason. */
function testCredentialRowReasonAccessibility() {
    const { document } = createDom()
    const fixture = readOnlyCredentialFixture()
    fixture.evidence = { ...incompleteEvidence(), 'change-credential': { state: 'available' }, 'delete-credential': { state: 'available' } }
    const view = renderEncryptionView(fixture, { document })
    const button = view.querySelector('[data-row-change][data-slot="1"]')
    const reasonId = button.getAttribute('aria-describedby')

    assert.equal(reasonId, 'credential-slot-1-change-reason')
    assert.equal(view.querySelectorAll(`#${reasonId}`).length, 1)
    assert.match(view.querySelector(`#${reasonId}`).textContent, /enable cartridge access/i)
}

test('read-only credential disables writes but allows access enable', testReadOnlyCredential)
test('AES configure stays blocked without proven compatible media format', testAesEvidenceBoundary)
test('Basic protection and reset UX preserve plaintext and loss warnings', testProtectionWarnings)
test('password strength, unique names, confirmation, and credential bounds validate locally', testCredentialValidation)
test('credential bytes are zeroized after success and failure terminals', testTransientCredentialZeroization)
test('one master plus seven slots enforces creation and temporary change space', testEightSlotModel)
test('automatic SATA III association models limits, delete scope, write option, and reinsertion', testAutomaticAuthentication)
test('protection and credential forms expose every bounded documented choice', testSecurityFormControls)
test('every evidence-incomplete security mutator stays disabled with its exact reason', testAllMutatorsFailClosed)
test('encryption workflow uses its bundled responsive cyberpunk surface', testEncryptionWorkflowStyles)
test('renderer consumes the generated canonical 13-operation evidence registry', testCanonicalRendererEvidenceRegistry)
test('protection setup and removal use structured guided state machines', testProtectionOperationStateMachine)
test('enable access and credential changes produce bounded structured intents', testPasswordOperationStateMachine)
test('disabled access gates management and credential rows own change/delete actions', testAuthenticatedManagementAndRowActions)
test('security workflows render input, exact confirmation, progress, and result surfaces', testGuidedWorkflowSurfaces)
test('guided new-password forms expose a live five-level strength scale', testGuidedPasswordStrengthScale)
test('protection setup remains gated by media, access, and unprotected mode', testStrictProtectionSetupGates)
test('automatic authentication requires strict reported SATA III and complete lifecycle state', testStrictAutomaticAuthenticationGates)
test('automatic authentication mutations use structured guided state machines', testAutomaticAuthenticationStateMachine)
test('disabled credential row controls own stable described-by reasons', testCredentialRowReasonAccessibility)
