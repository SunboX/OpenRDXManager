// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { escapeHtml, toDomToken } from './view-helpers.mjs'

const INTENT_UNAVAILABLE_CODES = Object.freeze({
    scan: 'INTENT_SCAN_UNAVAILABLE',
    operation: 'INTENT_OPERATION_UNAVAILABLE',
    'retry-operation': 'INTENT_RETRY_OPERATION_UNAVAILABLE',
    'retry-service': 'INTENT_RETRY_SERVICE_UNAVAILABLE',
    'open-support': 'INTENT_OPEN_SUPPORT_UNAVAILABLE',
    'open-event-log': 'INTENT_OPEN_EVENT_LOG_UNAVAILABLE'
})

/**
 * Builds the stable DOM identifier for one physical control's unavailable
 * renderer intent reason.
 * @param {string} intentType - High-level renderer intent type.
 * @param {string} context - Unique physical control context.
 * @returns {string} Stable, DOM-safe reason identifier.
 */
export function getIntentUnavailableReasonId(intentType, context) {
    return `intent-${toDomToken(intentType)}-${toDomToken(context)}-unavailable`
}

/**
 * Builds concise copy for an unsupported high-level renderer intent.
 * @param {string} intentType - High-level renderer intent type.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @returns {string} Intent-specific unavailable guidance.
 */
export function getIntentUnavailableMessage(intentType, t) {
    return composeTrustedCatalogText(t('intent.unavailable'), { intent: t(getIntentMessageKey(intentType)) })
}

/**
 * Composes already-trusted bundled catalog fragments without sending a
 * translated fragment back through the primitive-input escaping boundary.
 * Callers must escape raw values before passing them into this helper.
 * @param {string} template - Trusted local catalog message with named placeholders.
 * @param {Record<string, string>} fragments - Trusted or pre-escaped replacement fragments.
 * @returns {string} One-pass composed renderer message.
 */
function composeTrustedCatalogText(template, fragments) {
    let result = template
    for (const [name, fragment] of Object.entries(fragments)) {
        result = result.replaceAll(`{${name}}`, fragment)
    }
    return result
}

/**
 * Resolves the catalog key for a stable renderer intent without translating the
 * machine-readable intent value used in DOM attributes or reason codes.
 * @param {string} intentType - High-level renderer intent type.
 * @returns {string} Bundled intent display-message key.
 */
function getIntentMessageKey(intentType) {
    const keys = {
        scan: 'intent.scan',
        operation: 'intent.operation',
        'retry-operation': 'intent.retryOperation',
        'retry-service': 'intent.retryService',
        'open-support': 'intent.openSupport',
        'open-event-log': 'intent.openEventLog'
    }
    return keys[intentType] ?? 'intent.operation'
}

/**
 * Resolves the stable visible reason code for one unavailable renderer intent.
 * @param {string} intentType - High-level renderer intent type.
 * @returns {string} Stable intent-specific unavailable code.
 */
export function getIntentUnavailableCode(intentType) {
    return INTENT_UNAVAILABLE_CODES[intentType] ?? 'INTENT_UNKNOWN_UNAVAILABLE'
}

/**
 * Renders one control-owned unavailable reason only when its exact intent is
 * unsupported. The exact code remains visible beside its logical control group
 * so a disabled control never relies on hover or assistive-only content.
 * @param {string} intentType - High-level renderer intent type.
 * @param {string} context - Unique physical control context.
 * @param {boolean} available - Whether this exact intent is bound.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @returns {string} Screen-reader reason markup or empty text.
 */
export function renderIntentUnavailableReason(intentType, context, available, t) {
    if (available) {
        return ''
    }
    const reasonId = getIntentUnavailableReasonId(intentType, context)
    const reasonCode = getIntentUnavailableCode(intentType)
    const accessibleReason = composeTrustedCatalogText(t('intent.reason'), { message: getIntentUnavailableMessage(intentType, t), code: escapeHtml(reasonCode) })
    return `<span class="intent-unavailable-reason" id="${reasonId}" data-intent-unavailable="${escapeHtml(intentType)}" data-intent-unavailable-code="${escapeHtml(reasonCode)}" aria-label="${accessibleReason}">${escapeHtml(reasonCode)}</span>`
}
