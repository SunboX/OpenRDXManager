// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { operationContinueRequestSchema, operationStartResponseSchema } from '../shared/schemas.mjs'
import { OperationKind } from '../shared/contracts.mjs'

/** Renderer intents that a later preload bridge may bind. */
export const RendererIntentType = Object.freeze({
    SCAN: 'scan',
    OPERATION: 'operation',
    CONTINUE_OPERATION: 'operation-continue',
    RETRY_OPERATION: 'retry-operation',
    RETRY_SERVICE: 'retry-service',
    OPEN_SUPPORT: 'open-support',
    OPEN_EVENT_LOG: 'open-event-log'
})

const intentTypes = Object.freeze(Object.values(RendererIntentType))

/**
 * Checks a bounded opaque identifier without accepting paths or whitespace.
 * @param {unknown} value - Candidate renderer identifier.
 * @returns {boolean} True for a bounded opaque identifier.
 */
function isIdentifier(value) {
    return typeof value === 'string' && /^[a-z][a-z0-9:-]*$/i.test(value) && value.length <= 128
}

/**
 * Compares an object's own enumerable keys to an exact intent allowlist.
 * @param {object} value - Candidate intent object.
 * @param {string[]} allowedKeys - Exact permitted property names.
 * @returns {boolean} True when no key is missing or extra.
 */
function hasExactKeys(value, allowedKeys) {
    const keys = Object.keys(value).sort()
    const expected = [...allowedKeys].sort()
    if (keys.length !== expected.length) {
        return false
    }
    for (let index = 0; index < keys.length; index += 1) {
        if (keys[index] !== expected[index]) {
            return false
        }
    }
    return true
}

/**
 * Validates the renderer's narrow presentation intent before delegation.
 * Paths, raw commands, parameter bags, and unknown keys are never accepted.
 * @param {unknown} intent - Candidate high-level renderer intent.
 * @returns {boolean} True when the intent matches an exact public variant.
 */
function isValidIntent(intent) {
    if (intent === null || typeof intent !== 'object' || Array.isArray(intent) || !intentTypes.includes(intent.type)) {
        return false
    }

    switch (intent.type) {
        case RendererIntentType.SCAN:
        case RendererIntentType.RETRY_SERVICE:
        case RendererIntentType.OPEN_SUPPORT:
        case RendererIntentType.OPEN_EVENT_LOG:
            return hasExactKeys(intent, ['type'])
        case RendererIntentType.CONTINUE_OPERATION:
            return hasExactKeys(intent, ['type', 'operationId', 'stage']) && operationContinueRequestSchema.safeParse({ operationId: intent.operationId, stage: intent.stage }).success
        case RendererIntentType.OPERATION:
            return hasExactKeys(intent, ['type', 'kind', 'deviceId', 'deviceRevision']) && Object.values(OperationKind).includes(intent.kind) && isIdentifier(intent.deviceId) && Number.isInteger(intent.deviceRevision) && intent.deviceRevision >= 0
        case RendererIntentType.RETRY_OPERATION:
            return hasExactKeys(intent, ['type', 'kind', 'deviceId', 'deviceRevision', 'operationId']) && Object.values(OperationKind).includes(intent.kind) && isIdentifier(intent.deviceId) && Number.isInteger(intent.deviceRevision) && intent.deviceRevision >= 0 && isIdentifier(intent.operationId)
        default:
            return false
    }
}

/**
 * Creates the narrow renderer intent boundary used by the UI controller.
 * With no binding it is safely unavailable; Task 6 may inject supported types
 * and a validated preload delegate without changing view code.
 * @param {{supportedIntents?: string[], invoke?: (intent: object) => Promise<object|boolean|void>|object|boolean|void}} [options] - Explicit adapter binding.
 * @returns {{isAvailable: (intentType: string) => boolean, invoke: (intent: object) => Promise<object|boolean>}} Frozen intent adapter.
 */
export function createRendererIntentAdapter(options = {}) {
    const supported = new Set()
    if (Array.isArray(options.supportedIntents)) {
        for (const intentType of options.supportedIntents) {
            if (intentTypes.includes(intentType)) {
                supported.add(intentType)
            }
        }
    }
    const delegate = typeof options.invoke === 'function' ? options.invoke : null

    /**
     * Reports whether a validated delegate explicitly binds an intent type.
     * @param {string} intentType - Candidate high-level intent type.
     * @returns {boolean} True only for an allowlisted and delegated type.
     */
    function isAvailable(intentType) {
        return delegate !== null && supported.has(intentType)
    }

    /**
     * Validates one intent and awaits its delegate without exposing bridge errors.
     * @param {object} intent - Candidate intent built by the controller.
     * @returns {Promise<object|boolean>} Admission response, completion flag, or false when unavailable.
     */
    async function invoke(intent) {
        if (!isValidIntent(intent) || !isAvailable(intent.type)) {
            return false
        }
        try {
            const result = await delegate(intent)
            return result !== null && typeof result === 'object' ? result : result !== false
        } catch {
            return { ok: false, reason: 'service-failure' }
        }
    }

    return Object.freeze({ isAvailable, invoke })
}

/**
 * Creates the production renderer binding from the frozen named preload API.
 * Only reviewed intents with a concrete named preload method become available.
 * @param {unknown} api - Candidate `window.openRdx` preload API.
 * @returns {{isAvailable: (intentType: string) => boolean, invoke: (intent: object) => Promise<object|boolean>}} Frozen renderer intent adapter.
 */
export function createOpenRdxIntentAdapter(api) {
    const delegates = new Map()
    if (typeof api?.devices?.scan === 'function') {
        delegates.set(RendererIntentType.SCAN, api.devices.scan)
    }
    if (typeof api?.operations?.continue === 'function') delegates.set(RendererIntentType.CONTINUE_OPERATION, api.operations.continue)
    if (typeof api?.operations?.start === 'function') {
        delegates.set(RendererIntentType.OPERATION, api.operations.start)
    }
    if (typeof api?.service?.retry === 'function') {
        delegates.set(RendererIntentType.RETRY_SERVICE, api.service.retry)
    }
    if (typeof api?.support?.generateSummary === 'function') {
        delegates.set(RendererIntentType.OPEN_SUPPORT, api.support.generateSummary)
    }
    if (typeof api?.logs?.list === 'function') {
        delegates.set(RendererIntentType.OPEN_EVENT_LOG, api.logs.list)
    }

    /**
     * Invokes the named preload method and returns its bounded admission result.
     * @param {object} intent - Validated renderer intent.
     * @returns {Promise<object|boolean>} Validated operation admission or completion flag.
     * @throws {Error} Bridge failures are sanitized by the outer intent adapter.
     */
    async function invoke(intent) {
        const method = delegates.get(intent.type)
        if (typeof method !== 'function') return false
        if (intent.type === RendererIntentType.CONTINUE_OPERATION) {
            const parsed = operationStartResponseSchema.safeParse(await method({ operationId: intent.operationId, stage: intent.stage }))
            return parsed.success ? parsed.data : { ok: false, reason: 'invalid-service-response' }
        }
        if (intent.type === RendererIntentType.OPERATION) {
            // Admission is distinct from execution: only native lifecycle events
            // may report operation progress or success.
            const response = await method({ kind: intent.kind, deviceId: intent.deviceId, deviceRevision: intent.deviceRevision })
            const parsed = operationStartResponseSchema.safeParse(response)
            return parsed.success ? parsed.data : { ok: false, reason: 'invalid-service-response' }
        }
        await method({})
        return true
    }

    return createRendererIntentAdapter({ supportedIntents: [...delegates.keys()], invoke })
}
