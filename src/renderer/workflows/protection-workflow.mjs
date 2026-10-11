// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { englishCatalog } from '../../locales/en.mjs'
import { createTranslator } from '../i18n.mjs'
import { SECURITY_MUTATOR_EVIDENCE } from '../security-evidence-registry.mjs'

const PROTECTION_OPERATIONS = Object.freeze(['configure-basic', 'configure-aes', 'remove-basic', 'remove-aes', 'reset-protection'])
const AES_FILESYSTEMS = Object.freeze(['ntfs', 'exfat'])
const defaultTranslator = createTranslator(englishCatalog, englishCatalog)

/**
 * Normalizes one renderer-supplied evidence decision without promoting unknown
 * or malformed states to available. Generated evidence owns every fallback.
 * @param {object} evidence - Evidence mapping keyed by high-level operation.
 * @param {string} action - Stable high-level security action.
 * @returns {{state: string, reason: string}} Fail-closed capability decision.
 */
export function resolveSecurityCapability(evidence, action) {
    const fallback = SECURITY_MUTATOR_EVIDENCE[action]
    if (fallback === undefined) return Object.freeze({ reason: 'unknown-security-operation', state: 'evidence-incomplete' })
    const decision = evidence?.[action]
    if (decision?.state === 'available') return Object.freeze({ reason: '', state: 'available' })
    if (decision?.state === 'unsupported-product') {
        return Object.freeze({ reason: typeof decision.reason === 'string' && decision.reason.length > 0 ? decision.reason : fallback.reason, state: 'unsupported-product' })
    }
    return Object.freeze({ reason: fallback.reason, state: 'evidence-incomplete' })
}

/**
 * Builds the documented Basic/AES protection presentation without constructing
 * a native command or retaining credential values.
 * @param {{evidence?: object, mode?: string, resetWithoutPassword?: boolean}} model - Current renderer security state.
 * @param {(key: string, params?: object) => string} [translator=defaultTranslator] - Active bounded message translator.
 * @returns {object} Immutable translated protection workflow presentation.
 */
export function createProtectionWorkflow(model = {}, translator = defaultTranslator) {
    return Object.freeze({
        aes: Object.freeze({
            capability: resolveSecurityCapability(model.evidence, 'configure-aes'),
            description: translator('encryption.protection.aes.description'),
            title: translator('encryption.protection.aes.title')
        }),
        basic: Object.freeze({
            capability: resolveSecurityCapability(model.evidence, 'configure-basic'),
            description: translator('encryption.protection.basic.description'),
            title: translator('encryption.protection.basic.title'),
            warning: translator('encryption.protection.basic.warning')
        }),
        currentMode: ['aes', 'basic', 'none'].includes(model.mode) ? model.mode : 'unknown',
        passwordLossWarning: translator('encryption.protection.passwordLossWarning'),
        removeAes: resolveSecurityCapability(model.evidence, 'remove-aes'),
        removeBasic: resolveSecurityCapability(model.evidence, 'remove-basic'),
        resetPolicy: Object.freeze({
            allowed: model.resetWithoutPassword === true,
            capability: resolveSecurityCapability(model.evidence, 'reset-protection'),
            consequence: translator('encryption.protection.reset.consequence')
        })
    })
}

/**
 * Creates one non-secret setup/removal workflow state. Password bytes remain in
 * the mounted form and are supplied only at the terminal intent callback.
 * @param {{operation: string, device: object, access?: string, currentMode?: string, mediaPresent?: boolean}} context - Selected device and strict setup prerequisites.
 * @returns {object} Initial guided workflow state.
 * @throws {TypeError} When operation or strict device identity is missing.
 */
export function createProtectionOperation(context) {
    if (!PROTECTION_OPERATIONS.includes(context?.operation)) throw new TypeError('Unknown protection workflow operation')
    if (['configure-basic', 'configure-aes'].includes(context.operation)) {
        if (context.mediaPresent !== true) throw new TypeError('Protection setup requires inserted media')
        if (context.access !== 'enabled') throw new TypeError('Protection setup requires enabled cartridge access')
        if (context.currentMode !== 'none') throw new TypeError('Protection setup requires an unprotected cartridge')
    }
    const target = projectSecurityTarget(context.device)
    const needsInput = ['configure-basic', 'configure-aes', 'remove-aes'].includes(context.operation)
    return Object.freeze({
        confirmation: needsInput ? null : createConfirmation(context.operation, target.media.identity, null),
        device: target.device,
        draft: Object.freeze({ filesystem: null, resetWithoutPassword: false }),
        filesystemChoices: ['configure-aes', 'remove-aes'].includes(context.operation) ? AES_FILESYSTEMS : Object.freeze([]),
        media: target.media,
        operation: context.operation,
        phase: needsInput ? 'input' : 'confirmation',
        result: null,
        risk: protectionRisk(context.operation),
        stages: protectionStages(context.operation)
    })
}

/**
 * Applies one explicit guided workflow event without retaining password text.
 * @param {object} state - Current protection operation state.
 * @param {object} event - Submit, confirm, progress, finish, or cancel event.
 * @returns {object} Next immutable workflow state.
 * @throws {Error|TypeError} For an invalid transition or malformed input.
 */
export function transitionProtectionOperation(state, event) {
    if (!PROTECTION_OPERATIONS.includes(state?.operation) || typeof event?.type !== 'string') throw new TypeError('Invalid protection workflow transition')
    if (event.type === 'submit' && state.phase === 'input') {
        const requiresCredential = ['configure-basic', 'configure-aes'].includes(state.operation)
        if (requiresCredential && event.credentialValid !== true) throw new Error('master-credential-invalid')
        const filesystem = state.filesystemChoices.length > 0 ? event.draft?.filesystem : null
        if (state.filesystemChoices.length > 0 && !AES_FILESYSTEMS.includes(filesystem)) throw new Error('filesystem-choice-required')
        const draft = Object.freeze({ filesystem, resetWithoutPassword: event.draft?.resetWithoutPassword === true })
        return Object.freeze({ ...state, confirmation: createConfirmation(state.operation, state.media.identity, filesystem), draft, phase: 'confirmation' })
    }
    if (event.type === 'confirm' && state.phase === 'confirmation') {
        if (event.identity !== state.confirmation.expected) throw new Error('exact-media-confirmation-required')
        return Object.freeze({ ...state, phase: 'running', progress: Object.freeze({ activeStage: state.stages[0].id, value: 0 }) })
    }
    if (event.type === 'progress' && state.phase === 'running') {
        if (!hasStage(state.stages, event.activeStage)) throw new Error('unknown-protection-progress-stage')
        const value = typeof event.value === 'number' && Number.isFinite(event.value) ? Math.max(0, Math.min(1, event.value)) : 0
        return Object.freeze({ ...state, progress: Object.freeze({ activeStage: event.activeStage, value }) })
    }
    if (event.type === 'finish' && state.phase === 'running') {
        const status = ['succeeded', 'failed', 'cancelled'].includes(event.result?.status) ? event.result.status : 'failed'
        return Object.freeze({ ...state, phase: 'result', result: Object.freeze({ ...event.result, status }) })
    }
    if (event.type === 'cancel' && ['input', 'confirmation'].includes(state.phase)) return Object.freeze({ ...state, phase: 'cancelled' })
    throw new Error(`invalid-protection-workflow-transition:${state.phase}:${event.type}`)
}

/**
 * Builds a strict password-free high-level intent for native/main validation.
 * @param {object} state - Confirmed or active protection workflow.
 * @returns {object} Structured operation, device, media, protection, and optional master metadata.
 * @throws {Error} Before the workflow reaches confirmation.
 */
export function buildProtectionIntent(state) {
    if (!['confirmation', 'running', 'result'].includes(state?.phase)) throw new Error('protection-intent-not-confirmed')
    const intent = {
        operation: state.operation,
        device: state.device,
        media: state.media,
        protection: {
            filesystem: state.draft.filesystem,
            mode: state.operation.includes('aes') ? 'aes' : state.operation.includes('basic') ? 'basic' : 'none',
            resetWithoutPassword: state.draft.resetWithoutPassword
        }
    }
    if (state.operation.startsWith('configure-')) {
        intent.credential = {
            name: 'Master Password',
            permissions: { manage: true, read: true, write: true },
            role: 'master',
            slot: 0
        }
    }
    return intent
}

/** @param {object} device - Strict renderer device snapshot. @returns {{device: object, media: object}} Safe identity projection. */
function projectSecurityTarget(device) {
    if (typeof device?.id !== 'string' || !Number.isInteger(device?.revision) || typeof device?.media?.id !== 'string') throw new TypeError('Security workflow requires strict device and media identity')
    const identity = typeof device.media.serial === 'string' && device.media.serial.length > 0 ? device.media.serial : device.media.id
    return Object.freeze({ device: Object.freeze({ id: device.id, revision: device.revision }), media: Object.freeze({ id: device.media.id, identity }) })
}

/** @param {string} operation - Protection operation. @returns {'critical'|'destructive'} Shared risk class. */
function protectionRisk(operation) {
    return ['configure-aes', 'remove-aes', 'reset-protection'].includes(operation) ? 'destructive' : 'critical'
}

/** @param {string} operation - Protection operation. @param {string} identity - Exact media identity. @param {string|null} filesystem - Optional format. @returns {object} Confirmation model. */
function createConfirmation(operation, identity, filesystem) {
    const consequenceKey = operation === 'remove-basic' ? 'encryption.workflow.consequence.removeBasic' : operation === 'configure-basic' ? 'encryption.workflow.consequence.configureBasic' : operation === 'reset-protection' ? 'encryption.workflow.consequence.resetProtection' : 'encryption.workflow.consequence.destroyProtectedContents'
    const consequenceParams = filesystem === null ? Object.freeze({}) : Object.freeze({ filesystem: filesystem.toUpperCase() })
    return Object.freeze({ consequenceKey, consequenceParams, expected: identity, risk: protectionRisk(operation) })
}

/** @param {string} operation - Protection operation. @returns {ReadonlyArray<object>} Ordered progress stages. */
function protectionStages(operation) {
    if (['configure-aes', 'remove-aes'].includes(operation)) {
        return Object.freeze([Object.freeze({ id: 'security', labelKey: 'encryption.stage.updateSecurity' }), Object.freeze({ id: 'partition', labelKey: 'encryption.stage.recreatePartition' }), Object.freeze({ id: 'format', labelKey: 'encryption.stage.formatCartridge' }), Object.freeze({ id: 'verify', labelKey: 'encryption.stage.refreshVerify' })])
    }
    return Object.freeze([Object.freeze({ id: 'security', labelKey: 'encryption.stage.updateSecurity' }), Object.freeze({ id: 'verify', labelKey: 'encryption.stage.refreshVerify' })])
}

/** @param {ReadonlyArray<object>} stages - Ordered stages. @param {unknown} candidate - Candidate stage ID. @returns {boolean} True for a known stage. */
function hasStage(stages, candidate) {
    for (const stage of stages) {
        if (stage.id === candidate) return true
    }
    return false
}
