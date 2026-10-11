// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { CapabilityState, OperationKind, RiskClass } from '../shared/contracts.mjs'
import { operationRequestSchema } from '../shared/schemas.mjs'

const OPERATION_POLICY = Object.freeze({
    [OperationKind.SCAN]: Object.freeze({ riskClass: RiskClass.READ_ONLY, confirmationRequired: false }),
    [OperationKind.STATUS_REFRESH]: Object.freeze({ riskClass: RiskClass.READ_ONLY, confirmationRequired: false }),
    [OperationKind.ACCESS_ENABLE]: Object.freeze({ riskClass: RiskClass.ROUTINE, confirmationRequired: false }),
    [OperationKind.ACCESS_DISABLE]: Object.freeze({ riskClass: RiskClass.ROUTINE, confirmationRequired: false }),
    [OperationKind.SELF_TEST]: Object.freeze({ riskClass: RiskClass.ROUTINE, confirmationRequired: false }),
    [OperationKind.LED_TEST]: Object.freeze({ riskClass: RiskClass.ROUTINE, confirmationRequired: false }),
    [OperationKind.WRITE_READ_TEST]: Object.freeze({ riskClass: RiskClass.ROUTINE, confirmationRequired: false }),
    [OperationKind.EJECT_SAFE]: Object.freeze({ riskClass: RiskClass.ROUTINE, confirmationRequired: false }),
    [OperationKind.CREDENTIAL_CREATE]: Object.freeze({ riskClass: RiskClass.CONFIGURATION, confirmationRequired: true }),
    [OperationKind.CREDENTIAL_CHANGE]: Object.freeze({ riskClass: RiskClass.CONFIGURATION, confirmationRequired: true }),
    [OperationKind.CREDENTIAL_DELETE]: Object.freeze({ riskClass: RiskClass.CONFIGURATION, confirmationRequired: true }),
    [OperationKind.CREDENTIAL_CONFIGURE]: Object.freeze({ riskClass: RiskClass.CONFIGURATION, confirmationRequired: true }),
    [OperationKind.VOLUME_LABEL_SET]: Object.freeze({ riskClass: RiskClass.CONFIGURATION, confirmationRequired: false }),
    [OperationKind.DRIVE_LETTER_SET]: Object.freeze({ riskClass: RiskClass.CONFIGURATION, confirmationRequired: false }),
    [OperationKind.DRIVE_LETTER_RESET]: Object.freeze({ riskClass: RiskClass.CONFIGURATION, confirmationRequired: false }),
    [OperationKind.DRIVE_MODE_SET]: Object.freeze({ riskClass: RiskClass.CONFIGURATION, confirmationRequired: false }),
    [OperationKind.SATA_MODE_SET]: Object.freeze({ riskClass: RiskClass.CONFIGURATION, confirmationRequired: false }),
    [OperationKind.FIRMWARE_UPDATE]: Object.freeze({ riskClass: RiskClass.CRITICAL, confirmationRequired: false }),
    [OperationKind.EJECT_FORCE]: Object.freeze({ riskClass: RiskClass.CRITICAL, confirmationRequired: true }),
    [OperationKind.CREDENTIAL_RESET]: Object.freeze({ riskClass: RiskClass.DESTRUCTIVE, confirmationRequired: true }),
    [OperationKind.FORMAT]: Object.freeze({ riskClass: RiskClass.DESTRUCTIVE, confirmationRequired: true })
})

const PRIVILEGED_RISK_CLASSES = new Set([RiskClass.ROUTINE, RiskClass.CONFIGURATION, RiskClass.CRITICAL, RiskClass.DESTRUCTIVE])
const CAPABILITY_STATES = new Set(Object.values(CapabilityState))

/**
 * Returns the stable risk class for a published high-level operation.
 * @param {string} kind - Candidate operation kind.
 * @returns {string|null} Published risk class, or null for an unknown kind.
 */
export function getOperationRiskClass(kind) {
    return OPERATION_POLICY[kind]?.riskClass ?? null
}

/**
 * Applies main-owned identity, lock, capability, platform, privilege, and
 * confirmation gates to a strict high-level request. It performs no dispatch.
 * @param {unknown} request - Candidate renderer operation request.
 * @param {object} context - Current trusted service and device context.
 * @returns {{allowed: false, reason: string}|{allowed: true, request: object, riskClass: string}} Frozen-safe policy decision.
 */
export function evaluateOperation(request, context) {
    const parsedRequest = operationRequestSchema.safeParse(request)
    if (!parsedRequest.success) {
        return { allowed: false, reason: 'invalid-operation-request' }
    }

    const operation = parsedRequest.data
    const policy = OPERATION_POLICY[operation.kind]
    if (policy === undefined) {
        return { allowed: false, reason: 'unknown-operation' }
    }
    const riskClass = policy.riskClass
    if (context?.activeOperation !== null && context?.activeOperation !== undefined) {
        return { allowed: false, reason: 'operation-in-progress' }
    }
    if (context?.serviceMode !== 'native') {
        return { allowed: false, reason: 'hardware-unavailable' }
    }
    if (operation.kind === OperationKind.SCAN) {
        return { allowed: true, request: operation, riskClass }
    }
    if (context?.hardwareReady !== true) {
        return { allowed: false, reason: 'hardware-unavailable' }
    }
    if (context?.device === null || typeof context?.device !== 'object' || context.device.id !== operation.deviceId) {
        return { allowed: false, reason: 'device-not-found' }
    }
    if (context.device.revision !== operation.deviceRevision) {
        return { allowed: false, reason: 'stale-device-revision' }
    }

    const capability = context.device.capabilities?.[operation.kind]
    if (capability?.state !== 'available') {
        return { allowed: false, reason: CAPABILITY_STATES.has(capability?.state) ? capability.state : 'capability-unknown' }
    }
    if (context.platformCapability?.state !== 'available') {
        return { allowed: false, reason: CAPABILITY_STATES.has(context.platformCapability?.state) ? context.platformCapability.state : 'platform-capability-unknown' }
    }
    if (PRIVILEGED_RISK_CLASSES.has(riskClass) && context.hasPrivilege !== true) {
        return { allowed: false, reason: 'insufficient-permission' }
    }
    if (policy.confirmationRequired === true && context.confirmationTokenValid !== true) {
        return { allowed: false, reason: 'confirmation-required' }
    }

    return { allowed: true, request: operation, riskClass }
}
