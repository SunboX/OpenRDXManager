// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { englishCatalog } from '../../locales/en.mjs'
import { createTranslator } from '../i18n.mjs'
import { MAX_CREDENTIAL_SLOTS } from './password-workflow.mjs'
import { resolveSecurityCapability } from './protection-workflow.mjs'

const MAX_AUTOMATIC_ASSOCIATIONS = 7
const AUTOMATIC_AUTH_OPERATIONS = Object.freeze(['add-automatic-association', 'delete-automatic-association', 'delete-drive-automatic-credential'])
const defaultTranslator = createTranslator(englishCatalog, englishCatalog)

/**
 * Builds strict SATA III automatic-authentication state while keeping drive-
 * and cartridge-level deletion consequences distinct. Unknown reported state
 * always blocks future proven mutations.
 * @param {{access?: string, associated?: boolean, associationCount?: number, associationSlot?: number, connectionType?: object, driveCredentialExists?: boolean, evidence?: object, mediaPresent?: boolean, protectionMode?: string, slotCount?: number, writeAllowed?: boolean}} model - Current strict drive/cartridge association state.
 * @param {(key: string, params?: object) => string} [translator=defaultTranslator] - Active bounded message translator.
 * @returns {object} Immutable translated automatic-authentication presentation.
 */
export function createAutomaticAuthWorkflow(model = {}, translator = defaultTranslator) {
    const connectionBlocker = connectionPrerequisite(model.connectionType)
    const mediaBlocker = model.mediaPresent === true ? null : { reason: model.mediaPresent === false ? 'cartridge-required' : 'cartridge-state-not-reported', state: 'wrong-media-state' }
    const protectedBlocker = ['basic', 'aes'].includes(model.protectionMode) ? null : { reason: model.protectionMode === 'none' ? 'protected-cartridge-required' : 'protection-state-not-reported', state: 'wrong-media-state' }
    const accessBlocker = model.access === 'enabled' ? null : { reason: model.access === 'disabled' ? 'authenticated-access-required' : 'access-state-not-reported', state: 'authentication-required' }
    const associationBlocker = typeof model.associated === 'boolean' ? null : { reason: 'association-state-not-reported', state: 'wrong-media-state' }
    const associationSlotBlocker = Number.isInteger(model.associationSlot) && model.associationSlot > 0 && model.associationSlot < MAX_CREDENTIAL_SLOTS ? null : { reason: 'automatic-association-slot-not-reported-or-out-of-bounds', state: 'wrong-media-state' }
    const driveCredentialBlocker = typeof model.driveCredentialExists === 'boolean' ? null : { reason: 'drive-credential-state-not-reported', state: 'wrong-media-state' }
    const slotBlocker = Number.isInteger(model.slotCount) && model.slotCount >= 0 ? (model.slotCount < MAX_CREDENTIAL_SLOTS ? null : { reason: 'all-eight-credential-slots-are-occupied', state: 'wrong-media-state' }) : { reason: 'credential-slot-state-not-reported', state: 'wrong-media-state' }
    const countBlocker = Number.isInteger(model.associationCount) && model.associationCount >= 0 ? (model.associationCount < MAX_AUTOMATIC_ASSOCIATIONS ? null : { reason: 'seven-drive-association-limit-reached', state: 'wrong-media-state' }) : { reason: 'association-count-not-reported', state: 'wrong-media-state' }
    const addCapability = resolveSecurityCapability(model.evidence, 'add-automatic-association')
    const deleteCapability = resolveSecurityCapability(model.evidence, 'delete-automatic-association')
    const driveDeleteCapability = resolveSecurityCapability(model.evidence, 'delete-drive-automatic-credential')
    const addBlocker = firstBlocker(connectionBlocker, mediaBlocker, protectedBlocker, accessBlocker, associationBlocker, driveCredentialBlocker, slotBlocker, countBlocker, model.associated === true ? { reason: 'drive-already-associated-with-cartridge', state: 'wrong-media-state' } : null)
    const deleteBlocker = firstBlocker(connectionBlocker, mediaBlocker, protectedBlocker, accessBlocker, associationBlocker, model.associated === true ? associationSlotBlocker : null, model.associated === false ? { reason: 'automatic-association-not-present', state: 'wrong-media-state' } : null)
    const protectedDriveDeleteAccessBlocker = ['basic', 'aes'].includes(model.protectionMode) ? accessBlocker : null
    const driveDeleteBlocker = firstBlocker(connectionBlocker, mediaBlocker, driveCredentialBlocker, protectedDriveDeleteAccessBlocker, model.driveCredentialExists === false ? { reason: 'drive-automatic-credential-not-present', state: 'wrong-media-state' } : null)
    return Object.freeze({
        add: createDecision(addCapability, addBlocker),
        associated: model.associated === true,
        associationDeleteConsequence: translator('encryption.automatic.associationDeleteConsequence'),
        delete: createDecision(deleteCapability, deleteBlocker),
        driveDelete: createDecision(driveDeleteCapability, driveDeleteBlocker),
        driveDeleteConsequence: translator('encryption.automatic.driveDeleteConsequence'),
        limit: translator('encryption.automatic.limit'),
        reinsertGuidance: translator('encryption.automatic.reinsertGuidance'),
        writeAllowed: model.writeAllowed !== false,
        writeGuidance: translator(model.writeAllowed === false ? 'encryption.automatic.writeDisabled' : 'encryption.automatic.writeEnabled')
    })
}

/**
 * Creates one non-secret automatic-authentication mutation workflow.
 * @param {{operation: string, device: object, association: object}} context - Strict device/media identity and reported association metadata.
 * @returns {object} Initial guided operation state.
 * @throws {TypeError} For unsupported operations, non-SATA III devices, or malformed association slots.
 */
export function createAutomaticAuthOperation(context) {
    if (!AUTOMATIC_AUTH_OPERATIONS.includes(context?.operation)) throw new TypeError('Unknown automatic-authentication operation')
    const target = projectAutomaticTarget(context.device)
    const association = normalizeAssociation(context.association, context.operation)
    const inputRequired = context.operation === 'add-automatic-association'
    return Object.freeze({
        association,
        confirmation: inputRequired ? null : automaticConfirmation(context.operation, target.media.identity),
        device: target.device,
        draft: Object.freeze({ allowWrite: true }),
        media: target.media,
        operation: context.operation,
        phase: inputRequired ? 'input' : 'confirmation',
        progress: null,
        result: null,
        risk: context.operation === 'delete-drive-automatic-credential' ? 'critical' : 'configuration',
        stages: automaticStages(context.operation)
    })
}

/**
 * Applies one explicit automatic-authentication workflow event.
 * @param {object} state - Current immutable automatic-authentication state.
 * @param {object} event - Submit, confirm, progress, finish, or cancel event.
 * @returns {object} Next immutable workflow state.
 * @throws {Error|TypeError} For malformed or out-of-order events.
 */
export function transitionAutomaticAuthOperation(state, event) {
    if (!AUTOMATIC_AUTH_OPERATIONS.includes(state?.operation) || typeof event?.type !== 'string') throw new TypeError('Invalid automatic-authentication workflow transition')
    if (event.type === 'submit' && state.phase === 'input' && state.operation === 'add-automatic-association') {
        const draft = Object.freeze({ allowWrite: event.draft?.allowWrite === true })
        return Object.freeze({ ...state, confirmation: automaticConfirmation(state.operation, state.media.identity), draft, phase: 'confirmation' })
    }
    if (event.type === 'confirm' && state.phase === 'confirmation') {
        if (event.identity !== state.confirmation.expected) throw new Error('exact-media-confirmation-required')
        return Object.freeze({ ...state, phase: 'running', progress: Object.freeze({ activeStage: state.stages[0].id, value: 0 }) })
    }
    if (event.type === 'progress' && state.phase === 'running') {
        if (!hasAutomaticStage(state.stages, event.activeStage)) throw new Error('unknown-automatic-authentication-progress-stage')
        const value = typeof event.value === 'number' && Number.isFinite(event.value) ? Math.max(0, Math.min(1, event.value)) : 0
        return Object.freeze({ ...state, progress: Object.freeze({ activeStage: event.activeStage, value }) })
    }
    if (event.type === 'finish' && state.phase === 'running') {
        const status = ['succeeded', 'failed', 'cancelled'].includes(event.result?.status) ? event.result.status : 'failed'
        return Object.freeze({ ...state, phase: 'result', result: Object.freeze({ ...event.result, status }) })
    }
    if (event.type === 'cancel' && ['input', 'confirmation'].includes(state.phase)) return Object.freeze({ ...state, phase: 'cancelled' })
    throw new Error(`invalid-automatic-authentication-transition:${state.phase}:${event.type}`)
}

/**
 * Builds a strict non-secret automatic-authentication intent after confirmation.
 * @param {object} state - Confirmed or active workflow state.
 * @returns {object} Structured association intent.
 * @throws {Error} Before the workflow reaches confirmation.
 */
export function buildAutomaticAuthIntent(state) {
    if (!['confirmation', 'running', 'result'].includes(state?.phase)) throw new Error('automatic-authentication-intent-not-confirmed')
    const association = { scope: state.operation === 'delete-drive-automatic-credential' ? 'drive-all-cartridges' : 'cartridge-drive-pair' }
    if (state.operation === 'add-automatic-association') {
        association.allowWrite = state.draft.allowWrite
        association.cartridgeSlot = null
        association.driveCredentialExists = state.association.driveCredentialExists
    }
    if (state.operation === 'delete-automatic-association') association.cartridgeSlot = state.association.slot
    return Object.freeze({ association: Object.freeze(association), device: state.device, media: state.media, operation: state.operation })
}

/** @param {object} device - Strict selected device. @returns {{device: object, media: object}} Safe automatic-authentication target. */
function projectAutomaticTarget(device) {
    if (typeof device?.id !== 'string' || !Number.isInteger(device?.revision) || typeof device?.media?.id !== 'string') throw new TypeError('Automatic authentication requires strict device and media identity')
    if (device.drive?.details?.connectionType?.availability !== 'reported' || device.drive.details.connectionType.value !== 'SATA III') throw new TypeError('Automatic authentication requires reported SATA III')
    const identity = typeof device.media.serial === 'string' && device.media.serial.length > 0 ? device.media.serial : device.media.id
    return Object.freeze({ device: Object.freeze({ id: device.id, revision: device.revision }), media: Object.freeze({ id: device.media.id, identity }) })
}

/** @param {object} association - Reported association metadata. @param {string} operation - Selected operation. @returns {object} Validated metadata. */
function normalizeAssociation(association, operation) {
    if (typeof association?.driveCredentialExists !== 'boolean') throw new TypeError('Drive credential state must be reported')
    if (operation === 'delete-drive-automatic-credential' && association.driveCredentialExists !== true) throw new TypeError('Drive automatic credential is required')
    if (operation === 'delete-automatic-association' && (!Number.isInteger(association.slot) || association.slot <= 0 || association.slot >= MAX_CREDENTIAL_SLOTS)) throw new TypeError('Automatic association slot is out of bounds')
    return Object.freeze({ driveCredentialExists: association.driveCredentialExists, slot: operation === 'delete-automatic-association' ? association.slot : null })
}

/** @param {string} operation - Automatic-authentication operation. @param {string} identity - Exact media identity. @returns {object} Confirmation details. */
function automaticConfirmation(operation, identity) {
    const consequenceKey = operation === 'delete-drive-automatic-credential' ? 'encryption.workflow.consequence.deleteDriveAutomaticCredential' : operation === 'delete-automatic-association' ? 'encryption.workflow.consequence.deleteAutomaticAssociation' : 'encryption.workflow.consequence.addAutomaticAssociation'
    return Object.freeze({ consequenceKey, expected: identity, risk: operation === 'delete-drive-automatic-credential' ? 'critical' : 'configuration' })
}

/** @param {string} operation - Automatic-authentication operation. @returns {ReadonlyArray<object>} Ordered progress stages. */
function automaticStages(operation) {
    const firstKey = operation === 'add-automatic-association' ? 'encryption.stage.createAssociation' : operation === 'delete-drive-automatic-credential' ? 'encryption.stage.deleteDriveCredential' : 'encryption.stage.deleteCartridgeAssociation'
    return Object.freeze([Object.freeze({ id: 'association', labelKey: firstKey }), Object.freeze({ id: 'refresh', labelKey: 'encryption.stage.refreshCartridge' }), Object.freeze({ id: 'reinsert', labelKey: 'encryption.stage.reinsertVerify' })])
}

/** @param {ReadonlyArray<object>} stages - Ordered stages. @param {unknown} candidate - Candidate stage. @returns {boolean} True for a known stage. */
function hasAutomaticStage(stages, candidate) {
    for (const stage of stages) {
        if (stage.id === candidate) return true
    }
    return false
}

/** @param {object} connectionType - Typed strict connection field. @returns {object|null} SATA III prerequisite failure. */
function connectionPrerequisite(connectionType) {
    if (connectionType?.availability !== 'reported') return { reason: 'sata-iii-connection-type-not-reported', state: 'unsupported-product' }
    if (connectionType.value !== 'SATA III') return { reason: 'automatic-authentication-requires-sata-iii', state: 'unsupported-product' }
    return null
}

/** @param {...(object|null)} blockers - Ordered prerequisite failures. @returns {object|null} First failure. */
function firstBlocker(...blockers) {
    for (const blocker of blockers) {
        if (blocker !== null) return blocker
    }
    return null
}

/** @param {object} capability - Evidence decision. @param {object|null} blocker - Strict prerequisite. @returns {object} Effective immutable action decision. */
function createDecision(capability, blocker) {
    const effective = capability.state === 'available' && blocker !== null ? blocker : capability
    return Object.freeze({ capability: Object.freeze(effective), disabled: effective.state !== 'available', reason: effective.reason })
}
