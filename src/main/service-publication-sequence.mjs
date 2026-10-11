// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { OperationKind } from '../shared/contracts.mjs'
import { getNextCancellationRecoveryStage, getOperationStageGraph, getOperationStageIndex, hasRecoveryObligation, isCancellationAllowed, isCancellationCloseBoundary, isCancellationRecoveryStage, isCancellationTerminalStage, isFailureTerminalAllowed, isOperationStageTransitionAllowed } from './operation-lifecycle-policy.mjs'

const TERMINAL_STATES = new Set(['succeeded', 'failed', 'cancelled'])
/** Matches Rust's start plus 128 progress records plus terminal budget. */
const MAX_OPERATION_PUBLICATIONS = 130

/** @param {object} event - Strict failure event. @param {object} active - Shadow lifecycle state. @returns {boolean} True when failure evidence cannot name a future stage. */
function isFailureConsistent(event, active) {
    if (event.stage !== active.stage || (event.error.stage !== 'queued' && getOperationStageIndex(active.kind, event.error.stage) < 0)) return false
    if (active.phase === 'accepted') {
        return event.stage === 'queued' && event.error.stage === 'queued' && event.error.cleanupEvidence.every((evidence) => evidence.stage === 'queued') && event.error.attemptHistory.length === 0
    }
    const terminalIndex = getOperationStageIndex(active.kind, active.stage)
    const primaryIndex = getOperationStageIndex(active.kind, event.error.stage)
    if (primaryIndex < 0 || primaryIndex > terminalIndex) return false
    let previousIndex = primaryIndex
    for (const evidence of event.error.cleanupEvidence) {
        const index = getOperationStageIndex(active.kind, evidence.stage)
        if (index < previousIndex || index > terminalIndex) return false
        previousIndex = index
    }
    if (active.kind !== OperationKind.FIRMWARE_UPDATE && event.error.attemptHistory.length > 0) return false
    if ((active.attempt === 2) !== (event.error.attemptHistory.length === 1)) return false
    for (const attempt of event.error.attemptHistory) {
        const index = getOperationStageIndex(active.kind, attempt.stage)
        if (attempt.attempt !== 1 || index < 0 || index > primaryIndex) return false
    }
    return isFailureTerminalAllowed(active.kind, event, active.recoveryRequired || hasRecoveryObligation(active.kind, event.error.stage))
}

/** @param {object} event - Strict progress event. @param {object} active - Shadow lifecycle. @param {number} publicationSequence - Exact native FIFO position. @returns {boolean} True when cancellation availability matches request linearization. */
function isProgressCancellationStateConsistent(event, active, publicationSequence) {
    const isPreRequestPrefix = active.cancellationAccepted && Number.isSafeInteger(active.cancellationCutover) && publicationSequence <= active.cancellationCutover
    if (active.cancellationAccepted && !isPreRequestPrefix) return event.cancellationState === 'requested'
    if (event.cancellationState === 'requested') return active.cancellationRequested
    if (event.cancellationState === 'cancellable') return (!active.cancellationRequested || isPreRequestPrefix) && !active.cancellationClosed && isCancellationAllowed(active.kind, event.stage)
    const closesAtCurrentBoundary = active.phase === 'running' && active.stage === event.stage && isCancellationCloseBoundary(active.kind, event.stage)
    return event.cancellationState === 'closed' && (active.cancellationClosed || !isCancellationAllowed(active.kind, event.stage) || closesAtCurrentBoundary)
}

/**
 * Verifies the native service's generation-wide FIFO publication sequence and
 * the lifecycle invariants that are independent of main's acknowledgement races.
 */
export class ServicePublicationSequence {
    #active = null
    #lastPublicationSequence = 0
    #terminal = null

    /** @returns {void} Resets all proof state for one newly launched generation. */
    reset() {
        this.#active = null
        this.#lastPublicationSequence = 0
        this.#terminal = null
    }

    /**
     * Binds future publications to one complete immutable main-owned reservation.
     * @param {{operationId: string, kind: string, deviceId: string, deviceRevision: number, generation: number}} owner - Validated reservation tuple.
     * @returns {boolean} True only when no other operation remains bound.
     */
    reserve(owner) {
        if (this.#active !== null) return false
        this.#active = {
            operationId: owner.operationId,
            kind: owner.kind,
            deviceId: owner.deviceId,
            deviceRevision: owner.deviceRevision,
            generation: owner.generation,
            baseSequence: this.#lastPublicationSequence,
            eventCount: 0,
            phase: 'accepted',
            stage: 'queued',
            stageIndex: -1,
            progress: 0,
            attempt: 0,
            cancellationRequested: false,
            cancellationAccepted: false,
            cancellationCutover: null,
            cancellationClosed: false,
            recoveryRequired: false,
            terminalPending: false
        }
        this.#terminal = null
        return true
    }

    /**
     * Releases only a reservation whose start was rejected before lifecycle proof.
     * @param {string} operationId - Exact rejected operation identity.
     * @returns {void} Completes after an exact-owner release.
     */
    release(operationId) {
        if (this.#active?.operationId === operationId && this.#active.eventCount === 0) {
            this.#active = null
        }
    }

    /** @param {string} operationId - Exact cancellation owner. @returns {boolean} True when the active lifecycle was marked requested. */
    beginCancellation(operationId) {
        if (this.#active?.operationId !== operationId || this.#active.terminalPending || this.#active.cancellationClosed) return false
        this.#active.cancellationRequested = true
        return true
    }

    /** @param {string} operationId - Exact cancellation owner. @returns {boolean} True when a definitive rejection restored pre-request proof. */
    rejectCancellation(operationId) {
        if (this.#active?.operationId !== operationId || !this.#active.cancellationRequested || this.#active.cancellationAccepted) return false
        this.#active.cancellationRequested = false
        this.#active.cancellationCutover = null
        return true
    }

    /**
     * Consumes one exact next publication for the bound tuple and lifecycle.
     * Terminal ownership remains reserved until the downstream coordinator commits.
     * @param {{publicationSequence: number, event: object}} envelope - Strict wire operation event.
     * @returns {boolean} True only for the exact next valid publication.
     */
    consume(envelope) {
        const active = this.#active
        const nextSequence = this.#lastPublicationSequence + 1
        if (active === null || active.terminalPending || active.generation < 1 || active.eventCount >= MAX_OPERATION_PUBLICATIONS || !Number.isSafeInteger(nextSequence) || envelope.publicationSequence !== nextSequence || !this.#matches(active, envelope.event) || !this.#acceptLifecycle(active, envelope.event, envelope.publicationSequence)) {
            return false
        }
        active.eventCount += 1
        this.#lastPublicationSequence = nextSequence
        if (TERMINAL_STATES.has(envelope.event.state)) active.terminalPending = true
        return true
    }

    /**
     * Releases a terminal only after the exact downstream lifecycle consumer accepts it.
     * @param {{publicationSequence: number, event: object}} envelope - Previously consumed terminal.
     * @returns {boolean} True only when the pending terminal was committed.
     */
    commit(envelope) {
        const active = this.#active
        if (active === null || !active.terminalPending || envelope.publicationSequence !== this.#lastPublicationSequence || !TERMINAL_STATES.has(envelope.event.state) || !this.#matches(active, envelope.event)) return false
        this.#terminal = { operationId: active.operationId, baseSequence: active.baseSequence, cancellationRequested: active.cancellationRequested }
        this.#active = null
        return true
    }

    /**
     * Validates a cancellation cutover against the reservation's absolute budget.
     * @param {string} operationId - Exact cancellation request owner.
     * @param {number} cutover - Native linearized publication prefix.
     * @returns {boolean} True only for the consumed prefix through base plus 130.
     */
    acceptsCancellationCutover(operationId, cutover) {
        const proof = this.#active?.operationId === operationId ? this.#active : this.#terminal?.operationId === operationId ? this.#terminal : null
        if (proof === null || proof.cancellationRequested !== true || !Number.isSafeInteger(cutover) || cutover < this.#lastPublicationSequence) return false
        const upperBound = proof.baseSequence + MAX_OPERATION_PUBLICATIONS
        if (!Number.isSafeInteger(upperBound) || cutover > upperBound) return false
        if (proof === this.#active) {
            proof.cancellationAccepted = true
            proof.cancellationCutover = cutover
        }
        return true
    }

    /** @param {object} active - Reservation. @param {object} event - Strict event. @returns {boolean} Exact immutable owner match. */
    #matches(active, event) {
        return event.operationId === active.operationId && event.kind === active.kind && event.deviceId === active.deviceId && event.deviceRevision === active.deviceRevision
    }

    /** @param {object} active - Mutable shadow state. @param {object} event - Strict event. @param {number} publicationSequence - Exact native FIFO position. @returns {boolean} True after a valid lifecycle transition. */
    #acceptLifecycle(active, event, publicationSequence) {
        if (event.state === 'queued') return false
        if (event.state === 'started') {
            const firstStage = getOperationStageGraph(active.kind)?.[0]
            if (active.phase !== 'accepted' || event.stage !== firstStage) return false
            active.phase = 'running'
            active.stage = event.stage
            active.stageIndex = 0
            active.recoveryRequired = hasRecoveryObligation(active.kind, event.stage)
            if (active.cancellationRequested && !isCancellationAllowed(active.kind, event.stage) && !isCancellationRecoveryStage(active.kind, event.stage)) active.cancellationClosed = true
            return true
        }
        if (event.state === 'progress') {
            const nextIndex = getOperationStageIndex(active.kind, event.stage)
            const recoveryStage = active.cancellationRequested && getNextCancellationRecoveryStage(active.kind, active.stage) === event.stage
            const sequential = active.phase === 'running' && isOperationStageTransitionAllowed(active.kind, active.stage, event.stage)
            const attempt = event.attempt
            const attemptAllowed = attempt === undefined || (active.kind === OperationKind.FIRMWARE_UPDATE && event.stage === 'firmware-writing' && attempt >= active.attempt && attempt <= active.attempt + 1 && (active.attempt !== 0 || attempt === 1))
            const cancellationStateAllowed = isProgressCancellationStateConsistent(event, active, publicationSequence)
            if ((!sequential && !recoveryStage) || event.progress < active.progress || !attemptAllowed || !cancellationStateAllowed) return false
            active.phase = 'running'
            active.stage = event.stage
            active.stageIndex = nextIndex
            active.progress = event.progress
            if (attempt !== undefined) active.attempt = attempt
            active.recoveryRequired ||= hasRecoveryObligation(active.kind, event.stage)
            if (event.cancellationState === 'closed' || (active.cancellationRequested && !isCancellationAllowed(active.kind, event.stage) && !isCancellationRecoveryStage(active.kind, event.stage))) active.cancellationClosed = true
            return true
        }
        if (event.state === 'succeeded') {
            const graph = getOperationStageGraph(active.kind)
            return active.phase === 'running' && event.stage === 'complete' && active.stageIndex === graph?.length - 1
        }
        if (event.state === 'cancelled') {
            return active.cancellationRequested && !active.cancellationClosed && event.stage === active.stage && isCancellationTerminalStage(active.kind, event.stage)
        }
        return event.state === 'failed' && isFailureConsistent(event, active)
    }
}
