// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createComponentIcon, getComponentContext, renderCapabilityState } from '../components/capability-state.mjs'
import { requestExactDeviceConfirmation } from '../components/confirmation-dialog.mjs'
import { renderOperationDrawer } from '../components/operation-drawer.mjs'
import { buildAutomaticAuthIntent, createAutomaticAuthWorkflow } from '../workflows/automatic-auth-workflow.mjs'
import { buildPasswordIntent, credentialChangePreflight, estimatePasswordStrength, MAX_CREDENTIAL_SLOTS, validateCredentialDraft, withTransientCredentialBytes } from '../workflows/password-workflow.mjs'
import { buildProtectionIntent, createProtectionWorkflow, resolveSecurityCapability } from '../workflows/protection-workflow.mjs'

const ACTION_LABEL_KEYS = Object.freeze({
    'add-automatic-association': 'encryption.action.addAutomaticAssociation.label',
    'change-credential': 'encryption.action.changeCredential.label',
    'configure-aes': 'encryption.action.configureAes.label',
    'configure-basic': 'encryption.action.configureBasic.label',
    'create-credential': 'encryption.action.createCredential.label',
    'delete-automatic-association': 'encryption.action.deleteAutomaticAssociation.label',
    'delete-drive-automatic-credential': 'encryption.action.deleteDriveAutomaticCredential.label',
    'delete-credential': 'encryption.action.deleteCredential.label',
    'disable-access': 'encryption.action.disableAccess.label',
    'enable-access': 'encryption.action.enableAccess.label',
    'remove-aes': 'encryption.action.removeAes.label',
    'remove-basic': 'encryption.action.removeBasic.label',
    'reset-protection': 'encryption.action.resetProtection.label'
})
const ENCRYPTION_STAGE_KEYS = new Set(['encryption.stage.authenticateCredential', 'encryption.stage.createAssociation', 'encryption.stage.deleteCartridgeAssociation', 'encryption.stage.deleteDriveCredential', 'encryption.stage.formatCartridge', 'encryption.stage.recreatePartition', 'encryption.stage.refreshAccess', 'encryption.stage.refreshCartridge', 'encryption.stage.refreshVerify', 'encryption.stage.reinsertVerify', 'encryption.stage.removePreviousCredential', 'encryption.stage.updateSecurity', 'encryption.stage.verifyTemporaryReplacement'])
const REASON_MESSAGE_KEYS = Object.freeze({
    'access-state-not-reported': 'reason.accessStateNotReported',
    'aes-protection-is-not-configured': 'reason.aesProtectionNotConfigured',
    'all-eight-credential-slots-are-occupied': 'reason.allCredentialSlotsOccupied',
    'association-count-not-reported': 'reason.associationCountNotReported',
    'association-state-not-reported': 'reason.associationStateNotReported',
    'authenticated-access-required': 'reason.authenticatedAccessRequired',
    'automatic-association-not-present': 'reason.automaticAssociationNotPresent',
    'automatic-association-slot-not-reported-or-out-of-bounds': 'reason.automaticAssociationSlotInvalid',
    'automatic-authentication-requires-sata-iii': 'reason.automaticAuthenticationRequiresSataIii',
    'basic-protection-is-not-configured': 'reason.basicProtectionNotConfigured',
    'cartridge-access-is-already-disabled': 'reason.cartridgeAccessAlreadyDisabled',
    'cartridge-access-is-already-enabled': 'reason.cartridgeAccessAlreadyEnabled',
    'cartridge-required': 'reason.cartridgeRequired',
    'cartridge-required-for-protection-setup': 'reason.cartridgeRequiredForProtectionSetup',
    'cartridge-state-not-reported': 'reason.cartridgeStateNotReported',
    'changing-a-credential-requires-one-temporary-free-slot': 'reason.temporarySlotRequired',
    'compatible-aes-media-layout-and-security-write-unproven': 'reason.compatibleAesLayoutUnproven',
    'credential-slot-state-not-reported': 'reason.credentialSlotStateNotReported',
    'drive-already-associated-with-cartridge': 'reason.driveAlreadyAssociated',
    'drive-automatic-credential-not-present': 'reason.driveAutomaticCredentialNotPresent',
    'drive-credential-delete-selector-semantics-unproven': 'reason.driveCredentialDeleteUnproven',
    'drive-credential-state-not-reported': 'reason.driveCredentialStateNotReported',
    'drive-generated-secret-selector-semantics-unproven': 'reason.driveGeneratedSecretUnproven',
    'drive-vs-cartridge-delete-selectors-unproven': 'reason.driveVsCartridgeDeleteUnproven',
    'enable-cartridge-access-before-managing-credentials': 'reason.enableAccessBeforeManagingCredentials',
    'enable-cartridge-access-before-removing-protection': 'reason.enableAccessBeforeRemovingProtection',
    'enabled-cartridge-access-is-required-for-protection-setup': 'reason.enabledAccessRequiredForProtectionSetup',
    'passwordless-reset-is-prohibited-by-cartridge-policy': 'reason.passwordlessResetProhibited',
    'protected-cartridge-required': 'reason.protectedCartridgeRequired',
    'protection-is-already-configured': 'reason.protectionAlreadyConfigured',
    'protection-state-not-reported': 'reason.protectionStateNotReported',
    'reset-selector-and-policy-flags-unproven': 'reason.resetSelectorPolicyUnproven',
    'sata-iii-connection-type-not-reported': 'reason.sataIiiConnectionTypeNotReported',
    'select-a-credential-row': 'reason.selectCredentialRow',
    'selected-device-identity-unavailable': 'reason.selectedDeviceIdentityUnavailable',
    'selector-and-authentication-descriptor-semantics-unproven': 'reason.selectorAuthenticationUnproven',
    'selector-and-delete-descriptor-semantics-unproven': 'reason.selectorDeleteUnproven',
    'selector-and-remove-descriptor-semantics-unproven': 'reason.selectorRemoveUnproven',
    'selector-and-session-close-descriptor-semantics-unproven': 'reason.selectorSessionCloseUnproven',
    'selector-flags-and-aggregate-semantics-unproven': 'reason.selectorFlagsAggregateUnproven',
    'seven-drive-association-limit-reached': 'reason.sevenDriveAssociationLimitReached',
    'temporary-free-slot-required': 'reason.temporarySlotRequired',
    'temporary-slot-transaction-selectors-unproven': 'reason.temporarySlotTransactionUnproven',
    'unknown-security-operation': 'reason.unknownSecurityOperation'
})

/** @param {unknown} reason - Stable internal reason code. @param {(key: string, params?: object) => string} translator - Active translator. @returns {string} Localized allowlisted reason without echoing unknown values. */
function translateCapabilityReason(reason, translator) {
    const key = typeof reason === 'string' ? REASON_MESSAGE_KEYS[reason] : undefined
    return translator(key ?? 'reason.generic')
}

/**
 * Appends a heading and optional icon to a workflow section.
 * @param {Document} document - Owning document.
 * @param {HTMLElement} parent - Section receiving the heading.
 * @param {string} title - Visible section title.
 * @param {string} icon - Bundled Phosphor icon class.
 * @returns {void} Completes after appending the heading.
 */
function appendSectionHeading(document, parent, title, icon) {
    const heading = document.createElement('header')
    heading.className = 'security-section__heading'
    heading.append(createComponentIcon(document, icon, 'ph-duotone'))
    const text = document.createElement('h3')
    text.textContent = title
    heading.append(text)
    parent.append(heading)
}

/**
 * Creates one visible explanatory paragraph.
 * @param {Document} document - Owning document.
 * @param {string} text - Trusted bundled copy.
 * @param {string} [className='security-copy'] - Presentation class.
 * @returns {HTMLParagraphElement} Paragraph node.
 */
function paragraph(document, text, className = 'security-copy') {
    const node = document.createElement('p')
    node.className = className
    node.textContent = text
    return node
}

/**
 * Creates a labeled local input without attaching it to a submission target.
 * @param {Document} document - Owning document.
 * @param {string} labelText - Visible input label.
 * @param {object} attributes - Bounded HTML input properties.
 * @returns {{field: HTMLLabelElement, input: HTMLInputElement}} Labeled local control.
 */
function labeledInput(document, labelText, attributes) {
    const field = document.createElement('label')
    field.className = 'security-field'
    const label = document.createElement('span')
    label.textContent = labelText
    const input = document.createElement('input')
    for (const [name, value] of Object.entries(attributes)) {
        if (name === 'dataset') {
            for (const [dataName, dataValue] of Object.entries(value)) input.dataset[dataName] = dataValue
        } else input[name] = value
    }
    field.append(label, input)
    return { field, input }
}

/**
 * Creates one documented checkbox option with a visible label.
 * @param {Document} document - Owning document.
 * @param {string} labelText - Visible option text.
 * @param {object} attributes - Input properties and data attributes.
 * @returns {{field: HTMLLabelElement, input: HTMLInputElement}} Checkbox and label.
 */
function checkbox(document, labelText, attributes) {
    const control = labeledInput(document, labelText, { ...attributes, type: 'checkbox' })
    control.field.classList.add('security-checkbox')
    control.field.prepend(control.input)
    return control
}

/**
 * Appends one visible explanation and associates it with each disabled input.
 * @param {HTMLElement} parent - Container receiving the explanation.
 * @param {string} id - Stable explanation ID.
 * @param {string} text - Localized visible rationale.
 * @param {HTMLInputElement[]} inputs - Inputs governed by this rationale.
 * @returns {void} Completes after associating disabled controls.
 */
function appendDisabledInputReason(parent, id, text, inputs) {
    const disabledInputs = inputs.filter((input) => input.disabled)
    if (disabledInputs.length === 0) return
    const reason = paragraph(parent.ownerDocument, text, 'security-guidance security-control-reason')
    reason.id = id
    for (const input of disabledInputs) input.setAttribute('aria-describedby', id)
    parent.append(reason)
}

/**
 * Returns an evidence decision with an optional UI/state prerequisite layered
 * on top. Evidence remains the first gate so UI prerequisites cannot disguise
 * an incomplete native contract as available.
 * @param {object} evidence - Renderer evidence mapping.
 * @param {string} action - Stable mutator name.
 * @param {{state: string, reason: string}|null} blocker - Optional documented prerequisite.
 * @returns {{state: string, reason: string}} Effective capability.
 */
function effectiveCapability(evidence, action, blocker = null) {
    const capability = resolveSecurityCapability(evidence, action)
    if (capability.state !== 'available') return capability
    if (blocker !== null) return Object.freeze(blocker)
    return capability
}

/**
 * Projects only strict path-free device/media identity into a renderer intent.
 * @param {object} model - Current selected-device security model.
 * @param {string} operation - Stable high-level operation key.
 * @param {object} [fields={}] - Operation-specific structured fields.
 * @returns {object|null} Bounded intent or null when identity is incomplete.
 */
function createSecurityIntent(model, operation, fields = {}) {
    const device = model?.device
    if (typeof device?.id !== 'string' || !Number.isInteger(device?.revision) || typeof device?.media?.id !== 'string') return null
    const identity = typeof device.media.serial === 'string' && device.media.serial.length > 0 ? device.media.serial : device.media.id
    return Object.freeze({
        operation,
        device: Object.freeze({ id: device.id, revision: device.revision }),
        media: Object.freeze({ id: device.media.id, identity }),
        ...fields
    })
}

/**
 * Renders one evidence/prerequisite-gated security action using the shared
 * capability component and annotates its stable action/reason relationship.
 * @param {Document} document - Owning document.
 * @param {HTMLElement} parent - Parent receiving the capability card.
 * @param {object} capability - Effective capability decision.
 * @param {object|null} intent - Structured high-level security intent.
 * @param {string} description - Visible workflow explanation.
 * @param {object} options - View callback dependencies.
 * @returns {HTMLElement} Rendered capability card.
 */
function appendAction(document, parent, capability, intent, action, description, options) {
    const effective = intent === null && capability.state === 'available' ? { reason: 'selected-device-identity-unavailable', state: 'wrong-media-state' } : capability
    /** @returns {void} Emits only a validated structured high-level intent. */
    function handleAction() {
        if (intent !== null && typeof options.onAction === 'function') options.onAction(intent)
    }
    const card = renderCapabilityState(
        {
            action: { labelKey: ACTION_LABEL_KEYS[action] },
            description,
            reason: translateCapabilityReason(effective.reason, options.translator),
            state: effective.state,
            titleKey: ACTION_LABEL_KEYS[action]
        },
        { document, onAction: handleAction, translator: options.translator }
    )
    card.classList.add('security-action')
    const button = card.querySelector('[data-capability-action]')
    button.dataset.action = action
    button.dataset.securityMutator = ''
    const reason = card.querySelector('[data-capability-reason]')
    reason.dataset.actionReason = action
    parent.append(card)
    return card
}

/**
 * Renders the current access/session state and mutually exclusive enable/disable actions.
 * @param {Document} document - Owning document.
 * @param {HTMLElement} parent - View section.
 * @param {object} model - Current security view model.
 * @param {object} options - View callback dependencies.
 * @returns {void} Completes after access controls are appended.
 */
function renderAccess(document, parent, model, options) {
    const t = options.translator
    const enabled = model.access === 'enabled'
    const reported = enabled || model.access === 'disabled'
    const status = document.createElement('div')
    status.className = `security-access security-access--${enabled ? 'enabled' : 'disabled'}`
    status.dataset.accessStatus = reported ? model.access : 'unknown'
    status.append(createComponentIcon(document, enabled ? 'ph-check-circle' : reported ? 'ph-x-circle' : 'ph-question', 'ph-duotone'))
    const statusCopy = document.createElement('div')
    const title = document.createElement('strong')
    title.textContent = t(enabled ? 'encryption.access.enabled.title' : reported ? 'encryption.access.disabled.title' : 'encryption.access.unknown.title')
    statusCopy.append(title, paragraph(document, t(enabled ? 'encryption.access.enabled.description' : reported ? 'encryption.access.disabled.description' : 'encryption.access.unknown.description')))
    status.append(statusCopy)
    parent.append(status)

    appendAction(document, parent, effectiveCapability(model.evidence, 'enable-access', enabled ? { reason: 'cartridge-access-is-already-enabled', state: 'wrong-media-state' } : reported ? null : { reason: 'access-state-not-reported', state: 'wrong-media-state' }), createSecurityIntent(model, 'enable-access', { credential: Object.freeze({ slot: null }) }), 'enable-access', t('encryption.action.enableAccess.description'), options)
    appendAction(document, parent, effectiveCapability(model.evidence, 'disable-access', enabled ? null : { reason: reported ? 'cartridge-access-is-already-disabled' : 'access-state-not-reported', state: 'wrong-media-state' }), createSecurityIntent(model, 'disable-access'), 'disable-access', t('encryption.action.disableAccess.description'), options)
}

/**
 * Renders one credential slot with explicit permissions and management semantics.
 * @param {Document} document - Owning document.
 * @param {object} credential - Renderer-safe slot metadata.
 * @param {object} model - Current security model.
 * @param {object} options - View callbacks.
 * @returns {HTMLTableRowElement} Credential row.
 */
function renderCredentialRow(document, credential, model, options) {
    const t = options.translator
    const row = document.createElement('tr')
    row.dataset.credentialSlot = String(credential.slot)
    const values = [`#${Number.isInteger(credential.slot) ? credential.slot + 1 : '?'}`, typeof credential.name === 'string' ? credential.name : t('encryption.credentials.unnamed'), t(credential.role === 'master' ? 'encryption.credentials.role.master' : credential.role === 'automatic' ? 'encryption.credentials.role.automatic' : 'encryption.credentials.role.additional')]
    for (const value of values) {
        const cell = document.createElement('td')
        cell.textContent = value
        row.append(cell)
    }
    for (const permission of ['read', 'write', 'manage']) {
        const cell = document.createElement('td')
        cell.dataset.permission = permission
        cell.textContent = t(credential.permissions?.[permission] === true ? 'encryption.credentials.permission.allowed' : 'encryption.credentials.permission.notAllowed')
        row.append(cell)
    }
    const actions = document.createElement('td')
    actions.className = 'security-row-actions'
    const accessBlocker = model.access === 'enabled' ? null : { reason: 'enable-cartridge-access-before-managing-credentials', state: 'authentication-required' }
    appendCredentialRowAction(document, actions, credential, model, options, 'change')
    appendCredentialRowAction(document, actions, credential, model, options, 'delete', accessBlocker)
    row.append(actions)
    return row
}

/**
 * Adds one row-specific change or delete button with its own visible reason.
 * @param {Document} document - Owning document.
 * @param {HTMLElement} parent - Row action cell.
 * @param {object} credential - Exact renderer-safe credential row.
 * @param {object} model - Current security state.
 * @param {object} options - View callbacks.
 * @param {'change'|'delete'} kind - Row operation kind.
 * @param {object|null} [explicitBlocker=null] - Optional prerequisite.
 * @returns {void} Completes after appending the bounded row action.
 */
function appendCredentialRowAction(document, parent, credential, model, options, kind, explicitBlocker = null) {
    const t = options.translator
    const operation = kind === 'change' ? 'change-credential' : credential.role === 'master' ? (model.mode === 'aes' ? 'remove-aes' : 'remove-basic') : 'delete-credential'
    const temporarySlotBlocker = kind === 'change' && Array.isArray(model.credentials) && model.credentials.length >= MAX_CREDENTIAL_SLOTS ? { reason: 'changing-a-credential-requires-one-temporary-free-slot', state: 'slot-limit-reached' } : null
    const accessBlocker = model.access === 'enabled' ? explicitBlocker || temporarySlotBlocker : { reason: 'enable-cartridge-access-before-managing-credentials', state: 'authentication-required' }
    const capability = effectiveCapability(model.evidence, operation, accessBlocker)
    const intent = createSecurityIntent(model, operation, {
        credential: Object.freeze({ name: credential.name, role: credential.role, slot: credential.slot })
    })
    const button = document.createElement('button')
    button.className = 'button button--secondary security-row-action'
    button.type = 'button'
    button.dataset[kind === 'change' ? 'rowChange' : 'rowDelete'] = ''
    button.dataset.action = operation
    button.dataset.slot = String(credential.slot)
    button.disabled = capability.state !== 'available' || intent === null
    button.append(createComponentIcon(document, kind === 'change' ? 'ph-pencil-simple' : 'ph-trash'))
    button.append(document.createTextNode(t(kind === 'change' ? 'encryption.credentials.row.change' : credential.role === 'master' ? 'encryption.credentials.row.removeProtection' : 'encryption.credentials.row.delete')))
    /** @returns {void} Emits the exact row identity without password data. */
    function handleRowAction() {
        if (intent !== null && typeof options.onAction === 'function') options.onAction(intent)
    }
    button.addEventListener('click', handleRowAction)
    const reason = document.createElement('small')
    reason.id = `credential-slot-${credential.slot}-${kind}-reason`
    reason.dataset.rowActionReason = operation
    reason.textContent = button.disabled ? translateCapabilityReason(capability.reason || 'selected-device-identity-unavailable', t) : t('encryption.credentials.readyAfterConfirmation')
    if (button.disabled) button.setAttribute('aria-describedby', reason.id)
    parent.append(button, reason)
}

/**
 * Renders the eight-slot credential table, strength preview, and gated mutators.
 * @param {Document} document - Owning document.
 * @param {HTMLElement} parent - Credential section.
 * @param {object} model - Current security view model.
 * @param {object} options - View callback dependencies.
 * @returns {void} Completes after rendering credential management.
 */
function renderCredentials(document, parent, model, options) {
    const t = options.translator
    const credentials = Array.isArray(model.credentials) ? model.credentials.slice(0, MAX_CREDENTIAL_SLOTS) : []
    parent.append(paragraph(document, t('encryption.credentials.description')))
    const table = document.createElement('table')
    table.className = 'security-credentials'
    const caption = document.createElement('caption')
    caption.textContent = t('encryption.credentials.caption', { count: credentials.length, maximum: MAX_CREDENTIAL_SLOTS })
    table.append(caption)
    const head = document.createElement('thead')
    const headRow = document.createElement('tr')
    for (const key of ['slot', 'name', 'type', 'read', 'write', 'manage', 'actions']) {
        const cell = document.createElement('th')
        cell.scope = 'col'
        cell.textContent = t(`encryption.credentials.column.${key}`)
        headRow.append(cell)
    }
    head.append(headRow)
    table.append(head)
    const body = document.createElement('tbody')
    for (const credential of credentials) body.append(renderCredentialRow(document, credential, model, options))
    if (credentials.length === 0) {
        const empty = document.createElement('tr')
        const cell = document.createElement('td')
        cell.colSpan = 7
        cell.textContent = t('encryption.credentials.empty')
        empty.append(cell)
        body.append(empty)
    }
    table.append(body)
    parent.append(table)

    const preview = document.createElement('fieldset')
    preview.className = 'security-password-preview'
    const legend = document.createElement('legend')
    legend.textContent = t('encryption.credentials.newConfiguration')
    const nameControl = labeledInput(document, t('encryption.credentials.passwordName'), {
        autocomplete: 'off',
        dataset: { credentialName: '' },
        disabled: model.access !== 'enabled',
        maxLength: 197,
        type: 'text'
    })
    const passwordControl = labeledInput(document, t('encryption.credentials.newPassword'), {
        autocomplete: 'new-password',
        dataset: { credentialPassword: '', passwordPreview: '' },
        disabled: model.access !== 'enabled',
        maxLength: 1024,
        type: 'password'
    })
    const confirmationControl = labeledInput(document, t('encryption.credentials.confirmNewPassword'), {
        autocomplete: 'new-password',
        dataset: { credentialConfirmation: '' },
        disabled: model.access !== 'enabled',
        maxLength: 1024,
        type: 'password'
    })
    const output = document.createElement('output')
    output.dataset.passwordStrength = ''
    output.textContent = t('encryption.password.strength.poor')
    /** @returns {void} Updates only the local five-level guidance output. */
    function handlePasswordInput() {
        output.textContent = t(passwordStrengthMessageKey(estimatePasswordStrength(passwordControl.input.value)))
    }
    passwordControl.input.addEventListener('input', handlePasswordInput)
    const permissions = document.createElement('div')
    permissions.className = 'security-permission-options'
    const readPermission = checkbox(document, t('encryption.permissions.read'), {
        checked: true,
        dataset: { permissionInput: 'read' },
        disabled: true
    })
    const writePermission = checkbox(document, t('encryption.permissions.write'), {
        checked: true,
        dataset: { permissionInput: 'write' },
        disabled: model.access !== 'enabled'
    })
    const managePermission = checkbox(document, t('encryption.permissions.manage'), {
        checked: false,
        dataset: { permissionInput: 'manage' },
        disabled: model.access !== 'enabled'
    })
    permissions.append(readPermission.field, writePermission.field, managePermission.field)
    preview.append(legend, nameControl.field, passwordControl.field, confirmationControl.field, output, permissions)
    appendDisabledInputReason(preview, 'credential-fields-disabled-reason', t('encryption.controls.credentialsDisabledReason'), [nameControl.input, passwordControl.input, confirmationControl.input, writePermission.input, managePermission.input])
    appendDisabledInputReason(preview, 'credential-read-required-reason', t('encryption.controls.readRequiredReason'), [readPermission.input])
    parent.append(preview)
    parent.append(paragraph(document, t('encryption.credentials.changeWarning'), 'security-warning'))

    const accessBlocker = model.access === 'enabled' ? null : { reason: 'enable-cartridge-access-before-managing-credentials', state: 'authentication-required' }
    const fullBlocker = credentials.length >= MAX_CREDENTIAL_SLOTS ? { reason: 'all-eight-credential-slots-are-occupied', state: 'wrong-media-state' } : null
    const changePreflight = credentialChangePreflight(credentials.length)
    appendAction(document, parent, effectiveCapability(model.evidence, 'create-credential', accessBlocker ?? fullBlocker), createSecurityIntent(model, 'create-credential', { credential: Object.freeze({ permissions: Object.freeze({ manage: false, read: true, write: true }), role: 'additional', slot: null }) }), 'create-credential', t('encryption.action.createCredential.description'), options)
    appendAction(document, parent, effectiveCapability(model.evidence, 'change-credential', accessBlocker ?? (changePreflight.available ? { reason: 'select-a-credential-row', state: 'wrong-media-state' } : { reason: changePreflight.reason, state: 'wrong-media-state' })), null, 'change-credential', t('encryption.action.changeCredential.description'), options)
    appendAction(document, parent, effectiveCapability(model.evidence, 'delete-credential', accessBlocker ?? { reason: 'select-a-credential-row', state: 'wrong-media-state' }), null, 'delete-credential', t('encryption.action.deleteCredential.description'), options)
}

/**
 * Renders one externally owned password/protection workflow through the shared
 * drawer, exact-confirmation, progress, and result components.
 * @param {Document} document - Owning document.
 * @param {HTMLElement} view - Encryption workspace container.
 * @param {object} model - Complete security view model.
 * @param {object} options - Workflow callbacks.
 * @returns {void} Completes after appending the guided surface.
 */
function renderGuidedWorkflow(document, view, model, options) {
    const t = options.translator
    const workflow = model.workflow
    if (typeof workflow?.operation !== 'string' || typeof workflow?.phase !== 'string') return
    const running = workflow.phase === 'running'
    const result = workflow.phase === 'result'
    const drawer = renderOperationDrawer(
        {
            activeOperation: running
                ? {
                      kindLabel: ACTION_LABEL_KEYS[workflow.operation] === undefined ? workflow.operation : t(ACTION_LABEL_KEYS[workflow.operation]),
                      progress: workflow.progress?.value,
                      stage: workflow.progress?.activeStage,
                      stageLabel: localizeWorkflowStage(workflow, t),
                      stages: workflow.stages
                  }
                : undefined,
            closeSafe: !running,
            description: workflowDescription(workflow, t),
            deviceIdentity: workflow.media?.identity,
            result: result ? workflow.result : undefined,
            risk: workflow.risk,
            title: ACTION_LABEL_KEYS[workflow.operation] === undefined ? workflow.operation : t(ACTION_LABEL_KEYS[workflow.operation])
        },
        { document, onClose: options.onWorkflowClose, translator: t }
    )
    drawer.classList.add('security-workflow-drawer')
    if (['input', 'input-password', 'input-credential', 'confirmation'].includes(workflow.phase)) {
        drawer.append(renderWorkflowFields(document, workflow, model, options))
    }
    view.append(drawer)
    if (workflow.phase === 'confirmation') appendExactWorkflowConfirmation(document, view, drawer, workflow, model, options)
}

/**
 * Resolves the active workflow stage only through the fixed Encryption stage
 * message allowlist. Raw native or injected stage identifiers remain internal.
 * @param {object} workflow - Controller-owned guided workflow.
 * @param {(key: string, params?: object) => string} translator - Active locale translator.
 * @returns {string} Localized stage label or safe starting fallback.
 */
function localizeWorkflowStage(workflow, translator) {
    const activeStage = workflow?.progress?.activeStage
    const stage = Array.isArray(workflow?.stages) ? workflow.stages.find((candidate) => candidate?.id === activeStage) : undefined
    return typeof stage?.labelKey === 'string' && ENCRYPTION_STAGE_KEYS.has(stage.labelKey) ? translator(stage.labelKey) : translator('operation.startingStage')
}

/** @param {object} workflow - Current guided state. @param {(key: string, params?: object) => string} t - Active translator. @returns {string} Visible workflow-specific explanation. */
function workflowDescription(workflow, t) {
    if (workflow.phase === 'running') return t('encryption.workflow.description.running')
    if (workflow.phase === 'result') return t('encryption.workflow.description.result')
    const operationKey = {
        'add-automatic-association': 'addAutomaticAssociation',
        'configure-aes': 'configureAes',
        'configure-basic': 'configureBasic',
        'delete-automatic-association': 'deleteAutomaticAssociation',
        'delete-drive-automatic-credential': 'deleteDriveAutomaticCredential',
        'enable-access': 'enableAccess',
        'remove-aes': 'removeAes'
    }[workflow.operation]
    return t(operationKey === undefined ? 'encryption.workflow.description.default' : `encryption.workflow.description.${operationKey}`)
}

/**
 * Renders current non-secret workflow fields plus transient password controls.
 * @param {Document} document - Owning document.
 * @param {object} workflow - Current guided state.
 * @param {object} model - Complete security model.
 * @param {object} options - Workflow callbacks.
 * @returns {HTMLElement} Workflow fieldset.
 */
function renderWorkflowFields(document, workflow, model, options) {
    const t = options.translator
    const form = document.createElement('form')
    form.className = 'security-guided-form'
    form.dataset.securityWorkflowForm = workflow.operation
    const fields = document.createElement('fieldset')
    const legend = document.createElement('legend')
    legend.textContent = t(workflow.phase === 'confirmation' ? 'encryption.workflow.confirmedSettings' : 'encryption.workflow.settings')
    fields.append(legend)
    let nameControl = null
    if (['create-credential', 'change-credential'].includes(workflow.operation)) {
        nameControl = labeledInput(document, t('encryption.workflow.credentialName'), {
            autocomplete: 'off',
            dataset: { workflowCredentialName: '' },
            maxLength: 197,
            type: 'text',
            value: workflow.draft?.name ?? ''
        })
        fields.append(nameControl.field)
    }
    let passwordControl = null
    let confirmationControl = null
    if (workflowRequiresPassword(workflow.operation)) {
        passwordControl = labeledInput(document, t(workflow.operation.startsWith('configure-') ? 'encryption.workflow.masterPassword' : 'encryption.workflow.password'), {
            autocomplete: workflow.operation === 'enable-access' ? 'current-password' : 'new-password',
            dataset: { workflowPassword: '' },
            maxLength: 1024,
            type: 'password'
        })
        fields.append(passwordControl.field)
        if (workflow.operation !== 'enable-access') {
            confirmationControl = labeledInput(document, t('encryption.workflow.confirmPassword'), {
                autocomplete: 'new-password',
                dataset: { workflowPasswordConfirmation: '' },
                maxLength: 1024,
                type: 'password'
            })
            fields.append(confirmationControl.field)
            const strength = createGuidedStrengthScale(document, t)
            fields.append(strength.container)
            /** @returns {void} Updates only the local non-secret guidance scale. */
            function handleGuidedPasswordInput() {
                const label = estimatePasswordStrength(passwordControl.input.value)
                strength.meter.value = passwordStrengthValue(label)
                strength.label.textContent = t(passwordStrengthMessageKey(label))
            }
            passwordControl.input.addEventListener('input', handleGuidedPasswordInput)
        }
    }
    if (Array.isArray(workflow.filesystemChoices) && workflow.filesystemChoices.length > 0) {
        const filesystems = document.createElement('div')
        filesystems.className = 'security-filesystem-options'
        for (const filesystem of workflow.filesystemChoices) {
            const option = labeledInput(document, filesystem.toUpperCase(), {
                checked: workflow.draft?.filesystem === filesystem || (workflow.draft?.filesystem === null && filesystem === 'ntfs'),
                dataset: { workflowFilesystem: '' },
                name: `filesystem-${workflow.operation}`,
                type: 'radio',
                value: filesystem
            })
            option.field.classList.add('security-checkbox')
            option.field.prepend(option.input)
            filesystems.append(option.field)
        }
        fields.append(filesystems)
    }
    if (workflow.operation.startsWith('configure-')) {
        fields.append(
            checkbox(document, t('encryption.workflow.allowResetWithoutPassword'), {
                checked: workflow.draft?.resetWithoutPassword === true,
                dataset: { workflowResetPolicy: '' }
            }).field
        )
    }
    if (workflow.operation === 'add-automatic-association') {
        fields.append(
            checkbox(document, t('encryption.automatic.allowWrite'), {
                checked: workflow.draft?.allowWrite !== false,
                dataset: { workflowAutomaticWrite: '' }
            }).field
        )
    }
    if (['create-credential', 'change-credential'].includes(workflow.operation)) {
        const permissions = document.createElement('div')
        permissions.className = 'security-permission-options'
        const readPermission = checkbox(document, t('encryption.permissions.read'), { checked: true, dataset: { workflowPermission: 'read' }, disabled: true })
        permissions.append(readPermission.field, checkbox(document, t('encryption.permissions.write'), { checked: workflow.draft?.permissions?.write !== false, dataset: { workflowPermission: 'write' } }).field, checkbox(document, t('encryption.permissions.manage'), { checked: workflow.draft?.permissions?.manage === true, dataset: { workflowPermission: 'manage' } }).field)
        appendDisabledInputReason(permissions, 'workflow-read-required-reason', t('encryption.controls.readRequiredReason'), [readPermission.input])
        fields.append(permissions)
    }
    if (workflow.phase !== 'confirmation') {
        const advance = document.createElement('button')
        advance.className = 'button button--primary'
        advance.type = 'submit'
        advance.dataset.workflowContinue = ''
        advance.textContent = t('encryption.workflow.reviewExactConfirmation')
        fields.append(advance)
    } else {
        fields.append(paragraph(document, typeof workflow.confirmation?.consequenceKey === 'string' ? t(workflow.confirmation.consequenceKey, workflow.confirmation.consequenceParams) : t('encryption.workflow.reviewConsequence'), 'security-warning security-warning--danger'))
        if (workflow.draft?.filesystem !== null && typeof workflow.draft?.filesystem === 'string') fields.append(paragraph(document, t('encryption.workflow.selectedFilesystem', { filesystem: workflow.draft.filesystem.toUpperCase() }), 'security-guidance'))
    }
    form.append(fields)

    /** @param {SubmitEvent} event - Local guided-form submission. @returns {void} Emits no password string. */
    function handleSubmit(event) {
        event.preventDefault()
        const password = passwordControl?.input.value ?? ''
        const confirmation = confirmationControl?.input.value ?? password
        const draft = collectWorkflowDraft(form, workflow, nameControl?.input.value ?? '')
        let credentialValid = !workflowRequiresPassword(workflow.operation) || (password.length > 0 && password === confirmation)
        if (credentialValid && ['create-credential', 'change-credential'].includes(workflow.operation)) {
            const existingNames = []
            for (const credential of Array.isArray(model.credentials) ? model.credentials : []) {
                if (credential.slot !== workflow.credentialTarget?.slot) existingNames.push(credential.name)
            }
            credentialValid = validateCredentialDraft({ confirmation, existingNames, name: draft.name, password, slotCount: workflow.operation === 'create-credential' ? model.credentials?.length : undefined }).valid
        }
        if (typeof options.onWorkflowEvent === 'function') options.onWorkflowEvent({ credentialValid, draft, type: 'submit' })
        if (passwordControl !== null) passwordControl.input.value = ''
        if (confirmationControl !== null) confirmationControl.input.value = ''
    }
    form.addEventListener('submit', handleSubmit)
    return form
}

/** @param {Document} document - Owning document. @param {(key: string, params?: object) => string} t - Active translator. @returns {{container: HTMLElement, label: HTMLOutputElement, meter: HTMLMeterElement}} Five-level strength scale. */
function createGuidedStrengthScale(document, t) {
    const container = document.createElement('div')
    container.className = 'security-guided-strength'
    const title = document.createElement('span')
    title.textContent = t('encryption.password.strength.title')
    const meter = document.createElement('meter')
    meter.dataset.workflowPasswordStrength = ''
    meter.min = 1
    meter.max = 5
    meter.value = 1
    const label = document.createElement('output')
    label.dataset.workflowPasswordStrengthLabel = ''
    label.textContent = t('encryption.password.strength.poor')
    container.append(title, meter, label)
    return { container, label, meter }
}

/** @param {'poor'|'weak'|'better'|'good'|'very-good'} label - Locale-neutral strength rating. @returns {number} One-based five-level value. */
function passwordStrengthValue(label) {
    if (label === 'very-good') return 5
    if (label === 'good') return 4
    if (label === 'better') return 3
    if (label === 'weak') return 2
    return 1
}

/** @param {'poor'|'weak'|'better'|'good'|'very-good'} label - Locale-neutral strength rating. @returns {string} Bundled message key for the rating. */
function passwordStrengthMessageKey(label) {
    if (label === 'very-good') return 'encryption.password.strength.veryGood'
    if (label === 'good') return 'encryption.password.strength.good'
    if (label === 'better') return 'encryption.password.strength.better'
    if (label === 'weak') return 'encryption.password.strength.weak'
    return 'encryption.password.strength.poor'
}

/** @param {HTMLFormElement} form - Current workflow form. @param {object} workflow - Guided state. @param {string} name - Candidate credential name. @returns {object} Non-secret draft. */
function collectWorkflowDraft(form, workflow, name) {
    const filesystem = form.querySelector('[data-workflow-filesystem]:checked')?.value ?? workflow.draft?.filesystem ?? null
    return Object.freeze({
        filesystem,
        allowWrite: form.querySelector('[data-workflow-automatic-write]')?.checked === true,
        name,
        permissions: Object.freeze({
            manage: form.querySelector('[data-workflow-permission="manage"]')?.checked === true,
            read: true,
            write: form.querySelector('[data-workflow-permission="write"]')?.checked === true
        }),
        resetWithoutPassword: form.querySelector('[data-workflow-reset-policy]')?.checked === true
    })
}

/**
 * Mounts exact identity confirmation and awaits its terminal result before
 * emitting an intent with credentials bounded by the async operation lifetime.
 * @param {Document} document - Owning document.
 * @param {HTMLElement} view - Confirmation mount container.
 * @param {HTMLElement} drawer - Drawer containing transient credential fields.
 * @param {object} workflow - Confirmed workflow state.
 * @param {object} model - Current evidence model.
 * @param {object} options - Workflow callbacks.
 * @returns {void} Completes after mounting the dialog.
 */
function appendExactWorkflowConfirmation(document, view, drawer, workflow, model, options) {
    const t = options.translator
    const controller = requestExactDeviceConfirmation(
        {
            deviceLabel: model.device?.label ?? workflow.media?.identity,
            expected: workflow.confirmation.expected,
            operationLabel: ACTION_LABEL_KEYS[workflow.operation] === undefined ? workflow.operation : t(ACTION_LABEL_KEYS[workflow.operation]),
            risk: workflow.confirmation.risk
        },
        { container: view, document, translator: t }
    )
    const capability = resolveSecurityCapability(model.evidence, workflow.operation)
    if (capability.state !== 'available') {
        controller.input.disabled = true
        controller.confirmButton.disabled = true
        drawer.append(paragraph(document, t('encryption.workflow.evidenceIncomplete', { reason: translateCapabilityReason(capability.reason, t) }), 'security-warning'))
    }

    /** @returns {Promise<void>} Consumes one dialog result, ignores removed workflows, and completes credential cleanup on every terminal path. */
    async function completeConfirmation() {
        try {
            const result = await controller.closed
            // Rendering can replace the selected workflow before this promise resumes.
            if (!result.confirmed || !view.isConnected || !view.contains(drawer) || capability.state !== 'available') return
            await emitConfirmedWorkflowIntent(result.identity, drawer, workflow, options)
        } catch {
            if (typeof options.onWorkflowError === 'function') options.onWorkflowError('security-service-failure')
        } finally {
            clearWorkflowCredentialInputs(drawer)
        }
    }
    void completeConfirmation()
}

/** @param {HTMLElement} drawer - Local transient form container. @returns {void} Clears credential controls after confirmation, cancellation, or stale-view dismissal. */
function clearWorkflowCredentialInputs(drawer) {
    for (const input of drawer.querySelectorAll('[data-workflow-password], [data-workflow-password-confirmation]')) input.value = ''
}

/** @param {string} identity - Confirmed identity. @param {HTMLElement} drawer - Transient form container. @param {object} workflow - Confirmed state. @param {object} options - Callbacks. @returns {Promise<void>} Resolves after zeroization and callbacks. */
async function emitConfirmedWorkflowIntent(identity, drawer, workflow, options) {
    const password = drawer.querySelector('[data-workflow-password]')?.value ?? ''
    const confirmation = drawer.querySelector('[data-workflow-password-confirmation]')?.value ?? password
    clearWorkflowCredentialInputs(drawer)
    if (workflowRequiresPassword(workflow.operation) && (password.length === 0 || password !== confirmation)) {
        if (typeof options.onWorkflowError === 'function') options.onWorkflowError('credential-input-invalid')
        return
    }
    if (typeof options.onWorkflowEvent === 'function') options.onWorkflowEvent({ identity, type: 'confirm' })
    if (typeof options.onIntent !== 'function') return
    let intent
    if (workflow.operation.includes('automatic-association') || workflow.operation === 'delete-drive-automatic-credential') intent = buildAutomaticAuthIntent(workflow)
    else if (workflow.operation.includes('credential') || ['enable-access', 'disable-access'].includes(workflow.operation)) intent = buildPasswordIntent(workflow)
    else intent = buildProtectionIntent(workflow)
    if (!workflowRequiresPassword(workflow.operation)) {
        await options.onIntent(intent, null)
        return
    }
    /** @param {Uint8Array} bytes - Transient UTF-8 credential. @returns {Promise<unknown>|unknown} Intent callback result. */
    function emitWithCredential(bytes) {
        return options.onIntent(intent, bytes)
    }
    await withTransientCredentialBytes(password, emitWithCredential)
}

/** @param {string} operation - Workflow operation key. @returns {boolean} Whether the final confirmation requires transient password input. */
function workflowRequiresPassword(operation) {
    return ['enable-access', 'configure-basic', 'configure-aes', 'create-credential', 'change-credential'].includes(operation)
}

/**
 * Renders all documented protection, session, credential, reset, and automatic
 * authentication states. Password values remain in local input controls and
 * are never included in emitted high-level action intents.
 * @param {object} model - Renderer-safe selected cartridge security state.
 * @param {{document?: Document, translator?: (key: string, params?: object) => string, onAction?: (intent: object) => void, onIntent?: (intent: object, credentialBytes: Uint8Array|null) => Promise<unknown>|unknown, onWorkflowClose?: (event: Event) => void, onWorkflowError?: (reason: string) => void, onWorkflowEvent?: (event: object) => void}} [options={}] - DOM, localization, and bounded workflow callbacks.
 * @returns {HTMLElement} Complete Encryption workspace.
 */
export function renderEncryptionView(model = {}, options = {}) {
    const { document, translator } = getComponentContext(options)
    const localizedOptions = { ...options, translator }
    const protection = createProtectionWorkflow(model, translator)
    const automatic = createAutomaticAuthWorkflow(
        {
            access: model.access,
            associated: model.automaticAuthentication?.associated,
            associationCount: model.automaticAuthentication?.associationCount,
            associationSlot: model.automaticAuthentication?.slot,
            connectionType: model.device?.drive?.details?.connectionType,
            driveCredentialExists: model.automaticAuthentication?.driveCredentialExists,
            evidence: model.evidence,
            mediaPresent: model.device?.media === null ? false : model.device?.media === undefined ? undefined : true,
            protectionMode: model.mode,
            slotCount: Array.isArray(model.credentials) ? model.credentials.length : undefined,
            writeAllowed: model.automaticAuthentication?.writeAllowed
        },
        translator
    )
    const view = document.createElement('section')
    view.className = 'encryption-workspace'
    view.dataset.encryptionView = ''

    const header = document.createElement('header')
    header.className = 'encryption-workspace__header'
    const title = document.createElement('div')
    title.append(createComponentIcon(document, 'ph-shield-checkered', 'ph-duotone'))
    const titleCopy = document.createElement('div')
    const eyebrow = document.createElement('span')
    eyebrow.className = 'eyebrow'
    eyebrow.textContent = translator('encryption.eyebrow')
    const heading = document.createElement('h2')
    heading.textContent = translator('encryption.title')
    titleCopy.append(eyebrow, heading)
    title.append(titleCopy)
    header.append(title)
    if (typeof model.device?.label === 'string') header.append(paragraph(document, model.device.label, 'security-device-identity'))
    view.append(header)

    const mode = document.createElement('section')
    mode.className = 'security-section security-protection-modes'
    appendSectionHeading(document, mode, translator('encryption.section.protectionMode'), 'ph-lock-key-open')
    const protectionState = translator(protection.currentMode === 'none' ? 'encryption.protection.state.none' : protection.currentMode === 'aes' ? 'encryption.protection.state.aes' : protection.currentMode === 'basic' ? 'encryption.protection.state.basic' : 'encryption.protection.state.unknown')
    mode.append(paragraph(document, translator('encryption.protection.currentState', { state: protectionState })))
    mode.append(paragraph(document, protection.basic.warning, 'security-warning security-warning--plaintext'))
    mode.append(paragraph(document, protection.passwordLossWarning, 'security-warning security-warning--danger'))
    const protectionOptions = document.createElement('fieldset')
    protectionOptions.className = 'security-protection-options'
    const protectionLegend = document.createElement('legend')
    protectionLegend.textContent = translator('encryption.protection.chooseType')
    protectionOptions.append(protectionLegend)
    for (const [value, labelText] of [
        ['basic', translator('encryption.protection.basic.option')],
        ['aes', translator('encryption.protection.aes.option')]
    ]) {
        const option = labeledInput(document, labelText, {
            checked: protection.currentMode === value,
            dataset: { protectionOption: '' },
            name: 'protection-mode',
            type: 'radio',
            value
        })
        option.field.classList.add('security-checkbox')
        option.field.prepend(option.input)
        protectionOptions.append(option.field)
    }
    const resetOption = checkbox(document, translator('encryption.protection.reset.allowWithoutPassword'), {
        checked: protection.resetPolicy.allowed,
        dataset: { resetWithoutPassword: '' }
    })
    protectionOptions.append(resetOption.field)
    mode.append(protectionOptions)
    const setupBlocker = protection.currentMode !== 'none' ? { reason: protection.currentMode === 'unknown' ? 'protection-state-not-reported' : 'protection-is-already-configured', state: 'wrong-media-state' } : model.device?.media === null || model.device?.media === undefined ? { reason: 'cartridge-required-for-protection-setup', state: 'wrong-media-state' } : model.access !== 'enabled' ? { reason: 'enabled-cartridge-access-is-required-for-protection-setup', state: 'authentication-required' } : null
    appendAction(document, mode, effectiveCapability(model.evidence, 'configure-basic', setupBlocker), createSecurityIntent(model, 'configure-basic', { protection: Object.freeze({ filesystem: null, mode: 'basic' }) }), 'configure-basic', protection.basic.description, localizedOptions)
    appendAction(document, mode, effectiveCapability(model.evidence, 'configure-aes', setupBlocker), createSecurityIntent(model, 'configure-aes', { protection: Object.freeze({ filesystem: null, mode: 'aes' }) }), 'configure-aes', protection.aes.description, localizedOptions)
    view.append(mode)

    const access = document.createElement('section')
    access.className = 'security-section'
    appendSectionHeading(document, access, translator('encryption.section.accessSession'), 'ph-key')
    renderAccess(document, access, model, localizedOptions)
    view.append(access)

    const credentials = document.createElement('section')
    credentials.className = 'security-section security-section--wide'
    appendSectionHeading(document, credentials, translator('encryption.section.credentials'), 'ph-users-three')
    renderCredentials(document, credentials, model, localizedOptions)
    view.append(credentials)

    const automaticSection = document.createElement('section')
    automaticSection.className = 'security-section'
    appendSectionHeading(document, automaticSection, translator('encryption.section.automaticAuthentication'), 'ph-arrows-clockwise')
    automaticSection.append(paragraph(document, automatic.limit), paragraph(document, automatic.writeGuidance), paragraph(document, automatic.associationDeleteConsequence), paragraph(document, automatic.driveDeleteConsequence, 'security-warning'), paragraph(document, automatic.reinsertGuidance, 'security-guidance'))
    const automaticWrite = checkbox(document, translator('encryption.automatic.allowWrite'), {
        checked: automatic.writeAllowed,
        dataset: { automaticWriteAccess: '' },
        disabled: automatic.add.disabled
    })
    automaticSection.append(automaticWrite.field)
    appendDisabledInputReason(automaticSection, 'automatic-write-disabled-reason', translator('encryption.controls.automaticWriteDisabledReason', { reason: translateCapabilityReason(automatic.add.capability.reason, translator) }), [automaticWrite.input])
    appendAction(document, automaticSection, automatic.add.capability, createSecurityIntent(model, 'add-automatic-association', { association: Object.freeze({ allowWrite: automatic.writeAllowed, cartridgeSlot: null, driveCredentialExists: model.automaticAuthentication?.driveCredentialExists }) }), 'add-automatic-association', translator('encryption.action.addAutomaticAssociation.description'), localizedOptions)
    appendAction(document, automaticSection, automatic.delete.capability, createSecurityIntent(model, 'delete-automatic-association', { association: Object.freeze({ cartridgeSlot: model.automaticAuthentication?.slot ?? null, scope: 'cartridge-drive-pair' }) }), 'delete-automatic-association', translator('encryption.action.deleteAutomaticAssociation.description'), localizedOptions)
    appendAction(document, automaticSection, automatic.driveDelete.capability, createSecurityIntent(model, 'delete-drive-automatic-credential', { association: Object.freeze({ scope: 'drive-all-cartridges' }) }), 'delete-drive-automatic-credential', translator('encryption.action.deleteDriveAutomaticCredential.description'), localizedOptions)
    view.append(automaticSection)

    const removal = document.createElement('section')
    removal.className = 'security-section security-section--danger'
    appendSectionHeading(document, removal, translator('encryption.section.removalReset'), 'ph-warning-octagon')
    removal.append(paragraph(document, protection.resetPolicy.consequence, 'security-warning security-warning--danger'))
    removal.append(paragraph(document, translator(model.resetWithoutPassword === undefined ? 'encryption.protection.reset.stateUnknown' : protection.resetPolicy.allowed ? 'encryption.protection.reset.stateAllowed' : 'encryption.protection.reset.stateProhibited')))
    const authenticatedBlocker = model.access === 'enabled' ? null : { reason: 'enable-cartridge-access-before-removing-protection', state: 'authentication-required' }
    appendAction(document, removal, effectiveCapability(model.evidence, 'remove-basic', authenticatedBlocker ?? (protection.currentMode === 'basic' ? null : { reason: 'basic-protection-is-not-configured', state: 'wrong-media-state' })), createSecurityIntent(model, 'remove-basic', { protection: Object.freeze({ filesystem: null, mode: 'basic' }) }), 'remove-basic', translator('encryption.action.removeBasic.description'), localizedOptions)
    appendAction(document, removal, effectiveCapability(model.evidence, 'remove-aes', authenticatedBlocker ?? (protection.currentMode === 'aes' ? null : { reason: 'aes-protection-is-not-configured', state: 'wrong-media-state' })), createSecurityIntent(model, 'remove-aes', { protection: Object.freeze({ filesystem: null, mode: 'aes' }) }), 'remove-aes', translator('encryption.action.removeAes.description'), localizedOptions)
    appendAction(document, removal, effectiveCapability(model.evidence, 'reset-protection', protection.resetPolicy.allowed ? null : { reason: 'passwordless-reset-is-prohibited-by-cartridge-policy', state: 'insufficient-permission' }), createSecurityIntent(model, 'reset-protection', { protection: Object.freeze({ mode: protection.currentMode, resetWithoutPassword: true }) }), 'reset-protection', translator('encryption.action.resetProtection.description'), localizedOptions)
    view.append(removal)

    if (model.workflow !== undefined) renderGuidedWorkflow(document, view, model, localizedOptions)

    return view
}
