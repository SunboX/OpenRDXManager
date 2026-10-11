// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

export const MAX_CREDENTIAL_SLOTS = 8
export const MAX_PASSWORD_CHARACTERS = 1024
export const MAX_CREDENTIAL_NAME_CHARACTERS = 197
const PASSWORD_OPERATIONS = Object.freeze(['enable-access', 'disable-access', 'create-credential', 'change-credential', 'delete-credential'])

/**
 * Estimates the documented five-level password strength display. This is a
 * local guidance meter, not a cryptographic acceptance decision.
 * @param {string} password - Current unpersisted password field value.
 * @returns {'poor'|'weak'|'better'|'good'|'very-good'} Locale-neutral strength rating.
 */
export function estimatePasswordStrength(password) {
    if (typeof password !== 'string' || password.length < 8) return 'poor'
    let classes = 0
    if (/[a-z]/u.test(password)) classes += 1
    if (/[A-Z]/u.test(password)) classes += 1
    if (/\d/u.test(password)) classes += 1
    if (/[^\p{L}\p{N}]/u.test(password)) classes += 1
    if (password.length >= 16 && classes >= 3) return 'very-good'
    if (password.length >= 10 && classes >= 4) return 'good'
    if (classes >= 3) return 'better'
    return 'weak'
}

/**
 * Validates a new credential using specified name/password/slot limits. Names
 * compare case-insensitively to avoid visually ambiguous duplicates.
 * @param {{name: string, password: string, confirmation: string, existingNames?: string[], slotCount?: number}} draft - Local form values.
 * @returns {{valid: boolean, errors: string[]}} Stable validation outcome without secret echo.
 */
export function validateCredentialDraft(draft) {
    const errors = []
    const name = typeof draft?.name === 'string' ? draft.name : ''
    const password = typeof draft?.password === 'string' ? draft.password : ''
    const confirmation = typeof draft?.confirmation === 'string' ? draft.confirmation : ''
    const existingNames = Array.isArray(draft?.existingNames) ? draft.existingNames : []
    if (name.length === 0) errors.push('credential-name-required')
    else if (name.length > MAX_CREDENTIAL_NAME_CHARACTERS) errors.push('credential-name-too-long')
    else {
        const normalized = name.normalize('NFKC').toLocaleLowerCase('en-US')
        for (const existing of existingNames) {
            if (typeof existing === 'string' && existing.normalize('NFKC').toLocaleLowerCase('en-US') === normalized) {
                errors.push('credential-name-not-unique')
                break
            }
        }
    }
    if (password.length === 0) errors.push('credential-password-required')
    else if ([...password].length > MAX_PASSWORD_CHARACTERS) errors.push('credential-password-too-long')
    if (password !== confirmation) errors.push('credential-confirmation-mismatch')
    if (Number.isInteger(draft?.slotCount) && draft.slotCount >= MAX_CREDENTIAL_SLOTS) errors.push('credential-slots-full')
    return Object.freeze({ errors: Object.freeze(errors), valid: errors.length === 0 })
}

/**
 * Converts one password to transient UTF-8 bytes for the duration of a bounded
 * service-boundary action and zeroes the same buffer after every terminal.
 * @template T
 * @param {string} password - Renderer-local password value.
 * @param {(bytes: Uint8Array) => Promise<T>|T} action - Bounded consumer that must not retain or log bytes.
 * @returns {Promise<T>} Consumer result after buffer zeroization.
 * @throws {TypeError} If the credential/action is malformed or oversized.
 */
export async function withTransientCredentialBytes(password, action) {
    if (typeof password !== 'string' || [...password].length > MAX_PASSWORD_CHARACTERS) {
        throw new TypeError('Credential must be a string of at most 1024 characters')
    }
    if (typeof action !== 'function') throw new TypeError('Transient credential action must be a function')
    const bytes = new TextEncoder().encode(password)
    try {
        return await action(bytes)
    } finally {
        bytes.fill(0)
    }
}

/**
 * Reports whether changing a credential can reserve the documented temporary
 * slot without altering the table.
 * @param {number} slotCount - Occupied master/additional/automatic slots.
 * @returns {{available: boolean, reason: string}} Temporary-slot preflight.
 */
export function credentialChangePreflight(slotCount) {
    const available = Number.isInteger(slotCount) && slotCount >= 0 && slotCount < MAX_CREDENTIAL_SLOTS
    return Object.freeze({
        available,
        reason: available ? '' : 'temporary-free-slot-required',
        reasonKey: available ? '' : 'encryption.credentials.temporarySlotRequired'
    })
}

/**
 * Creates one non-secret authentication or credential-management state.
 * @param {{operation: string, device: object, target?: object}} context - Strict target and optional credential row.
 * @returns {object} Initial guided workflow state.
 * @throws {TypeError} For an unknown operation or malformed target.
 */
export function createPasswordOperation(context) {
    if (!PASSWORD_OPERATIONS.includes(context?.operation)) throw new TypeError('Unknown password workflow operation')
    const target = projectSecurityTarget(context.device)
    const credentialTarget = normalizeCredentialTarget(context.target, context.operation)
    const phase = context.operation === 'enable-access' ? 'input-password' : ['create-credential', 'change-credential'].includes(context.operation) ? 'input-credential' : 'confirmation'
    return Object.freeze({
        confirmation: phase === 'confirmation' ? passwordConfirmation(context.operation, target.media.identity) : null,
        credentialTarget,
        device: target.device,
        draft: Object.freeze({
            name: credentialTarget?.name ?? '',
            permissions: Object.freeze({ manage: credentialTarget?.permissions?.manage === true, read: true, write: credentialTarget?.permissions?.write !== false })
        }),
        media: target.media,
        operation: context.operation,
        phase,
        progress: null,
        result: null,
        risk: context.operation === 'delete-credential' ? 'critical' : 'configuration',
        stages: passwordStages(context.operation)
    })
}

/**
 * Applies one explicit password workflow event without storing credential bytes.
 * @param {object} state - Current password workflow state.
 * @param {object} event - Submit, confirm, progress, finish, or cancel event.
 * @returns {object} Next immutable state.
 * @throws {Error|TypeError} For malformed or out-of-order events.
 */
export function transitionPasswordOperation(state, event) {
    if (!PASSWORD_OPERATIONS.includes(state?.operation) || typeof event?.type !== 'string') throw new TypeError('Invalid password workflow transition')
    if (event.type === 'submit' && ['input-password', 'input-credential'].includes(state.phase)) {
        if (event.credentialValid !== true) throw new Error('credential-input-invalid')
        let draft = state.draft
        if (state.phase === 'input-credential') {
            const name = typeof event.draft?.name === 'string' ? event.draft.name : ''
            if (name.length === 0 || name.length > MAX_CREDENTIAL_NAME_CHARACTERS) throw new Error('credential-name-invalid')
            draft = Object.freeze({ name, permissions: normalizePermissions(event.draft?.permissions) })
        }
        return Object.freeze({ ...state, confirmation: passwordConfirmation(state.operation, state.media.identity), draft, phase: 'confirmation' })
    }
    if (event.type === 'confirm' && state.phase === 'confirmation') {
        if (event.identity !== state.confirmation.expected) throw new Error('exact-media-confirmation-required')
        return Object.freeze({ ...state, phase: 'running', progress: Object.freeze({ activeStage: state.stages[0].id, value: 0 }) })
    }
    if (event.type === 'progress' && state.phase === 'running') {
        if (!hasStage(state.stages, event.activeStage)) throw new Error('unknown-password-progress-stage')
        const value = typeof event.value === 'number' && Number.isFinite(event.value) ? Math.max(0, Math.min(1, event.value)) : 0
        return Object.freeze({ ...state, progress: Object.freeze({ activeStage: event.activeStage, value }) })
    }
    if (event.type === 'finish' && state.phase === 'running') {
        const status = ['succeeded', 'failed', 'cancelled'].includes(event.result?.status) ? event.result.status : 'failed'
        return Object.freeze({ ...state, phase: 'result', result: Object.freeze({ ...event.result, status }) })
    }
    if (event.type === 'cancel' && ['input-password', 'input-credential', 'confirmation'].includes(state.phase)) return Object.freeze({ ...state, phase: 'cancelled' })
    throw new Error(`invalid-password-workflow-transition:${state.phase}:${event.type}`)
}

/**
 * Builds a strict password-free intent after local input reaches confirmation.
 * @param {object} state - Confirmed or active password workflow.
 * @returns {object} Structured target and credential metadata.
 * @throws {Error} Before confirmation.
 */
export function buildPasswordIntent(state) {
    if (!['confirmation', 'running', 'result'].includes(state?.phase)) throw new Error('password-intent-not-confirmed')
    const intent = { operation: state.operation, device: state.device, media: state.media }
    if (state.operation === 'enable-access') intent.credential = { slot: null }
    if (state.operation === 'create-credential') {
        intent.credential = { name: state.draft.name, permissions: state.draft.permissions, role: 'additional', slot: null }
    }
    if (state.operation === 'change-credential') {
        intent.credential = { name: state.draft.name, permissions: state.draft.permissions, role: state.credentialTarget.role, slot: state.credentialTarget.slot, temporarySlotRequired: true }
    }
    if (state.operation === 'delete-credential') intent.credential = { name: state.credentialTarget.name, role: state.credentialTarget.role, slot: state.credentialTarget.slot }
    return intent
}

/** @param {object} device - Strict renderer device snapshot. @returns {{device: object, media: object}} Safe identity projection. */
function projectSecurityTarget(device) {
    if (typeof device?.id !== 'string' || !Number.isInteger(device?.revision) || typeof device?.media?.id !== 'string') throw new TypeError('Password workflow requires strict device and media identity')
    const identity = typeof device.media.serial === 'string' && device.media.serial.length > 0 ? device.media.serial : device.media.id
    return Object.freeze({ device: Object.freeze({ id: device.id, revision: device.revision }), media: Object.freeze({ id: device.media.id, identity }) })
}

/** @param {object|undefined} target - Optional row metadata. @param {string} operation - Requested operation. @returns {object|null} Validated row target. */
function normalizeCredentialTarget(target, operation) {
    if (!['change-credential', 'delete-credential'].includes(operation)) return null
    if (!Number.isInteger(target?.slot) || target.slot < 0 || target.slot >= MAX_CREDENTIAL_SLOTS || typeof target?.name !== 'string' || !['master', 'additional', 'automatic'].includes(target?.role)) throw new TypeError('Credential row target is invalid')
    return Object.freeze({ name: target.name, permissions: normalizePermissions(target.permissions), role: target.role, slot: target.slot })
}

/** @param {object|undefined} permissions - Candidate permission set. @returns {object} Immutable mandatory-read permissions. */
function normalizePermissions(permissions) {
    return Object.freeze({ manage: permissions?.manage === true, read: true, write: permissions?.write === true })
}

/** @param {string} operation - Password operation. @param {string} identity - Exact media identity. @returns {object} Confirmation model. */
function passwordConfirmation(operation, identity) {
    return Object.freeze({
        consequenceKey: operation === 'disable-access' ? 'encryption.workflow.consequence.disableAccess' : operation === 'delete-credential' ? 'encryption.workflow.consequence.deleteCredential' : 'encryption.workflow.consequence.refreshCredentials',
        expected: identity,
        risk: operation === 'delete-credential' ? 'critical' : 'configuration'
    })
}

/** @param {string} operation - Password operation. @returns {ReadonlyArray<object>} Ordered operation stages. */
function passwordStages(operation) {
    const stages = [{ id: 'security', labelKey: operation === 'enable-access' ? 'encryption.stage.authenticateCredential' : 'encryption.stage.updateSecurity' }]
    if (operation === 'change-credential') stages.push({ id: 'temporary-slot', labelKey: 'encryption.stage.verifyTemporaryReplacement' }, { id: 'remove-old', labelKey: 'encryption.stage.removePreviousCredential' })
    stages.push({ id: 'refresh', labelKey: 'encryption.stage.refreshAccess' })
    return Object.freeze(stages.map(Object.freeze))
}

/** @param {ReadonlyArray<object>} stages - Ordered stages. @param {unknown} candidate - Candidate stage ID. @returns {boolean} True for a known stage. */
function hasStage(stages, candidate) {
    for (const stage of stages) {
        if (stage.id === candidate) return true
    }
    return false
}
