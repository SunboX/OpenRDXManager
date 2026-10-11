// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { OperationKind } from '../shared/contracts.mjs'

/**
 * Freezes one complete per-operation lifecycle policy.
 * @param {{stages: string[], cancellableStages?: string[], cancellationCloseBoundaries?: string[], recoveryObligationStart?: string|null, recoveryStages?: string[], safeFailureStages?: string[], cancelTerminalStages?: string[]}} definition - Explicit lifecycle definition.
 * @returns {Readonly<object>} Immutable coordinator policy.
 */
function freezePolicy(definition) {
    const stages = Object.freeze([...definition.stages])
    return Object.freeze({
        stages,
        cancellableStages: Object.freeze([...(definition.cancellableStages ?? [])]),
        cancellationCloseBoundaries: Object.freeze([...(definition.cancellationCloseBoundaries ?? [])]),
        recoveryObligationStart: definition.recoveryObligationStart ?? null,
        recoveryStages: Object.freeze([...(definition.recoveryStages ?? [])]),
        safeFailureStages: Object.freeze([...(definition.safeFailureStages ?? [stages.at(-1)])]),
        cancelTerminalStages: Object.freeze([...(definition.cancelTerminalStages ?? [])]),
        safeTerminalStage: stages.at(-1)
    })
}

const POLICIES = Object.freeze({
    [OperationKind.STATUS_REFRESH]: freezePolicy({ stages: ['status-reading'], cancellableStages: ['queued', 'outcome-unknown'], safeFailureStages: ['queued', 'status-reading'], cancelTerminalStages: ['queued'] }),
    [OperationKind.ACCESS_ENABLE]: freezePolicy({ stages: ['access-changing', 'access-readback'], recoveryObligationStart: 'access-changing', recoveryStages: ['access-readback'] }),
    [OperationKind.ACCESS_DISABLE]: freezePolicy({ stages: ['access-changing', 'access-readback'], recoveryObligationStart: 'access-changing', recoveryStages: ['access-readback'] }),
    [OperationKind.CREDENTIAL_CREATE]: freezePolicy({ stages: ['credential-validating', 'credential-writing', 'credential-readback'], cancellableStages: ['queued', 'outcome-unknown', 'credential-validating'], recoveryObligationStart: 'credential-writing', recoveryStages: ['credential-readback'], cancelTerminalStages: ['queued', 'credential-validating'] }),
    [OperationKind.CREDENTIAL_CHANGE]: freezePolicy({ stages: ['credential-validating', 'credential-writing', 'credential-readback'], cancellableStages: ['queued', 'outcome-unknown', 'credential-validating'], recoveryObligationStart: 'credential-writing', recoveryStages: ['credential-readback'], cancelTerminalStages: ['queued', 'credential-validating'] }),
    [OperationKind.CREDENTIAL_DELETE]: freezePolicy({ stages: ['credential-validating', 'credential-writing', 'credential-readback'], cancellableStages: ['queued', 'outcome-unknown', 'credential-validating'], recoveryObligationStart: 'credential-writing', recoveryStages: ['credential-readback'], cancelTerminalStages: ['queued', 'credential-validating'] }),
    [OperationKind.CREDENTIAL_RESET]: freezePolicy({ stages: ['credential-validating', 'credential-writing', 'credential-readback'], cancellableStages: ['queued', 'outcome-unknown', 'credential-validating'], recoveryObligationStart: 'credential-writing', recoveryStages: ['credential-readback'], cancelTerminalStages: ['queued', 'credential-validating'] }),
    [OperationKind.CREDENTIAL_CONFIGURE]: freezePolicy({ stages: ['credential-validating', 'credential-writing', 'credential-readback'], cancellableStages: ['queued', 'outcome-unknown', 'credential-validating'], recoveryObligationStart: 'credential-writing', recoveryStages: ['credential-readback'], cancelTerminalStages: ['queued', 'credential-validating'] }),
    [OperationKind.SELF_TEST]: freezePolicy({ stages: ['diagnostic-running', 'diagnostic-cleanup'], cancellableStages: ['queued', 'outcome-unknown', 'diagnostic-running'], recoveryObligationStart: 'diagnostic-running', recoveryStages: ['diagnostic-cleanup'], cancelTerminalStages: ['diagnostic-cleanup'] }),
    [OperationKind.LED_TEST]: freezePolicy({ stages: ['led-testing', 'led-restoring', 'led-readback'], cancellableStages: ['queued', 'outcome-unknown', 'led-testing'], recoveryObligationStart: 'led-testing', recoveryStages: ['led-restoring', 'led-readback'], cancelTerminalStages: ['led-readback'] }),
    [OperationKind.WRITE_READ_TEST]: freezePolicy({ stages: ['host-writing', 'host-reading', 'host-cleanup'], cancellableStages: ['queued', 'outcome-unknown', 'host-writing', 'host-reading'], cancellationCloseBoundaries: ['host-writing'], recoveryObligationStart: 'host-writing', recoveryStages: ['host-cleanup'], cancelTerminalStages: ['host-cleanup'] }),
    [OperationKind.FIRMWARE_UPDATE]: freezePolicy({ stages: ['firmware-validating', 'firmware-capturing', 'firmware-compatibility-setup', 'firmware-staging', 'firmware-awaiting-bootloader', 'firmware-programming-bootstrap', 'firmware-awaiting-bootstrap', 'firmware-restoring-identity', 'firmware-writing', 'firmware-finalizing', 'device-reconnecting', 'firmware-readback'], cancellableStages: ['queued', 'outcome-unknown', 'firmware-validating', 'firmware-capturing'], recoveryObligationStart: 'firmware-compatibility-setup', recoveryStages: ['firmware-finalizing', 'device-reconnecting', 'firmware-readback'], cancelTerminalStages: ['queued', 'firmware-validating', 'firmware-capturing', 'firmware-readback'] }),
    [OperationKind.VOLUME_LABEL_SET]: freezePolicy({ stages: ['host-volume-changing', 'host-volume-readback'] }),
    [OperationKind.DRIVE_LETTER_SET]: freezePolicy({ stages: ['host-volume-changing', 'host-volume-readback'], recoveryObligationStart: 'host-volume-changing', recoveryStages: ['host-volume-readback'] }),
    [OperationKind.DRIVE_LETTER_RESET]: freezePolicy({ stages: ['host-volume-changing', 'host-volume-readback'], recoveryObligationStart: 'host-volume-changing', recoveryStages: ['host-volume-readback'] }),
    [OperationKind.FORMAT]: freezePolicy({ stages: ['format-validating', 'format-writing', 'format-finalizing', 'format-readback'], cancellableStages: ['queued', 'outcome-unknown', 'format-validating'], recoveryStages: ['format-finalizing', 'format-readback'], cancelTerminalStages: ['queued', 'format-validating'] }),
    [OperationKind.DRIVE_MODE_SET]: freezePolicy({ stages: ['device-configuring', 'device-reconnecting', 'device-readback'], recoveryObligationStart: 'device-configuring', recoveryStages: ['device-reconnecting', 'device-readback'] }),
    [OperationKind.SATA_MODE_SET]: freezePolicy({ stages: ['device-configuring', 'device-reconnecting', 'device-readback'], recoveryObligationStart: 'device-configuring', recoveryStages: ['device-reconnecting', 'device-readback'] }),
    [OperationKind.EJECT_SAFE]: freezePolicy({ stages: ['host-unmounting', 'host-ejecting', 'eject-readback'], cancellableStages: ['queued', 'outcome-unknown', 'host-unmounting'], cancellationCloseBoundaries: ['host-unmounting'], recoveryObligationStart: 'host-ejecting', recoveryStages: ['eject-readback'], cancelTerminalStages: ['queued', 'host-unmounting'] }),
    [OperationKind.EJECT_FORCE]: freezePolicy({ stages: ['host-ejecting', 'eject-readback'], recoveryObligationStart: 'host-ejecting', recoveryStages: ['eject-readback'] })
})

/**
 * Returns the complete immutable lifecycle policy for one operation kind.
 * @param {string} kind - Published operation kind.
 * @returns {Readonly<object>|null} Exact policy or null for Scan/unknown.
 */
export function getOperationLifecyclePolicy(kind) {
    return POLICIES[kind] ?? null
}

/**
 * Returns the frozen ordered stages for one operation kind.
 * @param {string} kind - Published high-level operation kind.
 * @returns {readonly string[]|null} Ordered stages or null for Scan/unknown.
 */
export function getOperationStageGraph(kind) {
    return getOperationLifecyclePolicy(kind)?.stages ?? null
}

/**
 * Checks whether cancellation is explicitly allowed at the current stage.
 * @param {string} kind - Published operation kind.
 * @param {string} stage - Current coordinator-owned stage.
 * @returns {boolean} True only for a per-kind cancellable stage.
 */
export function isCancellationAllowed(kind, stage) {
    return getOperationLifecyclePolicy(kind)?.cancellableStages.includes(stage) === true
}

/**
 * Checks whether native may close cancellation without advancing the public stage.
 * @param {string} kind - Published operation kind.
 * @param {string} stage - Current coordinator-owned stage.
 * @returns {boolean} True only at an explicit pre-mutation close boundary.
 */
export function isCancellationCloseBoundary(kind, stage) {
    return getOperationLifecyclePolicy(kind)?.cancellationCloseBoundaries.includes(stage) === true
}

/**
 * Checks whether a stage creates an operation-specific recovery obligation.
 * @param {string} kind - Published operation kind.
 * @param {string} stage - Current validated stage.
 * @returns {boolean} True once that kind's mutation or cleanup barrier is crossed.
 */
export function hasRecoveryObligation(kind, stage) {
    const policy = getOperationLifecyclePolicy(kind)
    if (policy === null || policy.recoveryObligationStart === null) return false
    const startIndex = policy.stages.indexOf(policy.recoveryObligationStart)
    return policy.stages.indexOf(stage) >= startIndex
}

/**
 * Checks whether a post-cancel stage is a policy-owned cleanup/recovery step.
 * @param {string} kind - Published operation kind.
 * @param {string} stage - Candidate progress stage.
 * @returns {boolean} True only for an explicit recovery stage.
 */
export function isCancellationRecoveryStage(kind, stage) {
    return getOperationLifecyclePolicy(kind)?.recoveryStages.includes(stage) === true
}

/**
 * Returns the earliest still-outstanding recovery stage after one current stage.
 * @param {string} kind - Published operation kind.
 * @param {string} currentStage - Current coordinator-owned stage or outcome marker.
 * @returns {string|null} Next mandatory recovery stage, or null after all recovery.
 */
export function getNextCancellationRecoveryStage(kind, currentStage) {
    const policy = getOperationLifecyclePolicy(kind)
    if (policy === null) return null
    const currentIndex = policy.stages.indexOf(currentStage)
    for (const recoveryStage of policy.recoveryStages) {
        if (policy.stages.indexOf(recoveryStage) > currentIndex) {
            return recoveryStage
        }
    }
    return null
}

/**
 * Checks whether a cancelled terminal identifies a safe per-kind boundary.
 * @param {string} kind - Published operation kind.
 * @param {string} stage - Candidate terminal stage.
 * @returns {boolean} True only for an explicit cancellation terminal.
 */
export function isCancellationTerminalStage(kind, stage) {
    return getOperationLifecyclePolicy(kind)?.cancelTerminalStages.includes(stage) === true
}

/**
 * Checks whether a failure may release an owner with its current obligation.
 * @param {string} kind - Published operation kind.
 * @param {string} stage - Correlated failure stage.
 * @param {boolean} recoveryRequired - Whether mutation/test activity began.
 * @returns {boolean} True only when any required cleanup/readback is complete.
 */
export function isSafeFailureStage(kind, stage, recoveryRequired) {
    const policy = getOperationLifecyclePolicy(kind)
    return policy !== null && (!recoveryRequired || policy.safeFailureStages.includes(stage))
}

/**
 * Allows a safe failure or an explicit unresolved first-install recovery terminal.
 * Callers must also verify the actual owner/stage and primary/cleanup evidence order.
 * Unfinished migration cannot truthfully advance to final readback just to report failure.
 * @param {string} kind - Owned operation kind.
 * @param {object} event - Strict failure event at the actual current stage.
 * @param {boolean} recoveryRequired - Whether mutation/test activity began.
 * @returns {boolean} True for a failure terminal, without asserting cleanup or firmware success.
 */
export function isFailureTerminalAllowed(kind, event, recoveryRequired) {
    if (isSafeFailureStage(kind, event.stage, recoveryRequired)) return true
    // A definitive eject rejection proves no media removal occurred. Native
    // reports it at the dispatch stage; it must not fabricate departure readback.
    if ([OperationKind.EJECT_SAFE, OperationKind.EJECT_FORCE].includes(kind) && event.state === 'failed' && event.stage === 'host-ejecting' && event.error.stage === event.stage && event.error.dispatchCertainty === 'definitely-rejected' && event.error.retryable === false && event.error.cleanupEvidence.length === 0) return true
    return kind === OperationKind.FIRMWARE_UPDATE && event.state === 'failed' && ['firmware-compatibility-setup', 'firmware-staging', 'firmware-awaiting-bootloader', 'firmware-programming-bootstrap', 'firmware-awaiting-bootstrap', 'firmware-restoring-identity'].includes(event.stage) && event.error.stage === event.stage && event.error.dispatchCertainty === 'completion-unknown' && event.error.retryable === false && event.error.cleanupEvidence.some((evidence) => evidence.stage === event.stage && evidence.code === 'cleanup-incomplete' && evidence.dispatchCertainty === 'completion-unknown')
}

/**
 * Resolves a candidate stage index in one exact operation graph.
 * @param {string} kind - Published operation kind.
 * @param {string} stage - Candidate service stage.
 * @returns {number} Zero-based index, or -1 when invalid.
 */
export function getOperationStageIndex(kind, stage) {
    const graph = getOperationStageGraph(kind)
    return graph === null ? -1 : graph.indexOf(stage)
}

/**
 * Accepts repeated/adjacent phases and the explicit direct-update branches.
 * Entering capture commits the operation to every first-install boundary.
 * @param {string} kind - Exact operation kind.
 * @param {string} currentStage - Last accepted stage.
 * @param {string} nextStage - Candidate service stage.
 * @returns {boolean} True only for a declared forward transition.
 */
export function isOperationStageTransitionAllowed(kind, currentStage, nextStage) {
    const current = getOperationStageIndex(kind, currentStage)
    const next = getOperationStageIndex(kind, nextStage)
    if (current < 0 || next < 0) return false
    const firmwareDirectUpdate = kind === OperationKind.FIRMWARE_UPDATE && currentStage === 'firmware-validating' && nextStage === 'firmware-writing'
    const firmwareFailedTransferRecovery = kind === OperationKind.FIRMWARE_UPDATE && currentStage === 'firmware-writing' && nextStage === 'device-reconnecting'
    return (next >= current && next <= current + 1) || firmwareDirectUpdate || firmwareFailedTransferRecovery
}
