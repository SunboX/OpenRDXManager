// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { firmwareTargetBinding } from '../shared/firmware-target-binding.mjs'
import { evaluateOperation } from './safety-policy.mjs'

/**
 * Captures a valid firmware request before waiting for an already running scan.
 * Only the scan lock is temporary; all other admission checks remain required.
 * @param {object} request - Strict parsed operation request.
 * @param {object} context - Main-owned current safety context.
 * @returns {object|null} Binding for a valid current request, or null.
 */
export function captureFirmwareScanBinding(request, context) {
    if (request.kind !== 'firmware-update' || context?.activeOperation?.kind !== 'scan') return null
    const binding = firmwareTargetBinding(context.device)
    if (binding === null || !evaluateOperation(request, { ...context, activeOperation: null }).allowed) return null
    return { binding, generation: context.generation }
}

/**
 * Advances only the telemetry revision of the same dock after the awaited scan.
 * Changed identity, firmware, media, capability or generation retains the stale
 * request, which normal admission rejects. No operation is retried or retargeted.
 * @param {object} request - Original strict firmware request.
 * @param {object|null} captured - Previously eligible main-owned scan binding.
 * @param {object} context - Fresh safety context after the existing scan.
 * @returns {object} Original request or its safely refreshed revision.
 */
export function refreshFirmwareScanRevision(request, captured, context) {
    if (captured === null || context.generation !== captured.generation || firmwareTargetBinding(context.device) !== captured.binding || context.device.id !== request.deviceId || context.device.revision < request.deviceRevision) return request
    return { ...request, deviceRevision: context.device.revision }
}
