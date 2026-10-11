// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Reads a canonical reported field without turning unavailable metadata into a value.
 * @param {object|undefined} field - Renderer-safe reported-or-unavailable field.
 * @returns {unknown} Reported value or undefined.
 */
export function reportedUtilityValue(field) {
    return field?.availability === 'reported' ? field.value : undefined
}

/**
 * Collects only renderer-reported product/interface identity used for family gates.
 * @param {object} device - Selected renderer-safe device.
 * @returns {string} Bounded identity text, or an empty string when unavailable.
 */
export function reportedUtilityProductIdentity(device) {
    const candidates = [reportedUtilityValue(device?.drive?.details?.connectionType), reportedUtilityValue(device?.drive?.details?.productType), reportedUtilityValue(device?.drive?.details?.product), device?.drive?.connectionType, device?.drive?.productType, device?.product]
    const values = []
    for (const candidate of candidates) {
        if (typeof candidate === 'string' && candidate.trim() !== '' && !values.includes(candidate.trim())) values.push(candidate.trim())
    }
    return values.join(' ')
}

/**
 * Returns the most specific reported host-interface identity for interface-only gates.
 * @param {object} device - Selected renderer-safe device.
 * @returns {string} Connection identity, product-name fallback, or an empty string.
 */
export function reportedUtilityConnectionIdentity(device) {
    const candidates = [reportedUtilityValue(device?.drive?.details?.connectionType), device?.drive?.connectionType, reportedUtilityValue(device?.drive?.details?.product), device?.product]
    for (const candidate of candidates) {
        if (typeof candidate === 'string' && candidate.trim() !== '') return candidate.trim()
    }
    return ''
}

/**
 * Creates one immutable visible prerequisite.
 * @param {string} id - Stable prerequisite identifier.
 * @param {string} labelKey - Bundled requirement message key.
 * @param {boolean} met - Whether current evidence proves the requirement.
 * @param {string} detailKey - Bundled current-state message key.
 * @param {object} [detailParams={}] - Bounded translation parameters.
 * @returns {object} Frozen prerequisite.
 */
export function utilityPrerequisite(id, labelKey, met, detailKey, detailParams = {}) {
    return Object.freeze({ detailKey, detailParams: Object.freeze({ ...detailParams }), id, labelKey, met })
}

/**
 * Reports whether every prerequisite is currently proven.
 * @param {object[]} prerequisites - Complete prerequisite list.
 * @returns {boolean} True only when every row is met.
 */
export function utilityPrerequisitesMet(prerequisites) {
    for (const item of prerequisites) {
        if (item.met !== true) return false
    }
    return true
}

/**
 * Resolves the published device capability together with renderer and workflow gates.
 * @param {object} device - Selected renderer-safe RDX device.
 * @param {string} kind - Published operation kind.
 * @param {object[]} prerequisites - Current operation prerequisites.
 * @param {{locked?: boolean, operationIntentAvailable?: boolean, unmetState?: string, unmetReason?: string}} [options={}] - Shell and prerequisite gates.
 * @returns {{state: string, reason: string}} Fail-closed capability decision.
 */
export function resolveUtilityCapability(device, kind, prerequisites, options = {}) {
    const reported = device?.capabilities?.[kind]
    if (reported?.state !== 'available') {
        return Object.freeze({
            reason: typeof reported?.reason === 'string' ? reported.reason : `${kind}-capability-not-reported`,
            state: typeof reported?.state === 'string' ? reported.state : 'evidence-incomplete'
        })
    }
    if (options.locked === true) return Object.freeze({ reason: 'operation-in-progress', state: 'busy' })
    if (options.operationIntentAvailable === false) return Object.freeze({ reason: 'operation-intent-unavailable', state: 'transport-unavailable' })
    if (!utilityPrerequisitesMet(prerequisites)) {
        return Object.freeze({ reason: options.unmetReason ?? `${kind}-prerequisites-not-met`, state: options.unmetState ?? 'wrong-media-state' })
    }
    return Object.freeze({ reason: '', state: 'available' })
}

/**
 * Freezes a stage list with bundled message keys.
 * @param {Array<[string, string]>} values - Stage identifiers and message keys.
 * @returns {object[]} Frozen progress stages.
 */
export function utilityStages(values) {
    return Object.freeze(values.map(([id, labelKey]) => Object.freeze({ id, labelKey })))
}
