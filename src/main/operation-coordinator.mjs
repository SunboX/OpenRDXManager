// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomUUID } from 'node:crypto'

import { OperationKind } from '../shared/contracts.mjs'
import { operationCancelRequestSchema, operationEventSchema, operationRequestSchema, scanRequestSchema } from '../shared/schemas.mjs'
import { getNextCancellationRecoveryStage, getOperationStageGraph, getOperationStageIndex, hasRecoveryObligation, isCancellationAllowed, isCancellationCloseBoundary, isCancellationRecoveryStage, isCancellationTerminalStage, isFailureTerminalAllowed, isOperationStageTransitionAllowed } from './operation-lifecycle-policy.mjs'
import { evaluateOperation } from './safety-policy.mjs'

/** @returns {string} Main-owned opaque operation identifier. */
function createDefaultOperationId() {
    return `op:${randomUUID()}`
}

/** @returns {string} Main-owned support correlation identifier. */
function createDefaultCorrelationId() {
    return `support:${randomUUID()}`
}

/** @returns {null} Fail-closed missing device. */
function getNoDevice() {
    return null
}

/** @returns {object} Fail-closed platform capability. */
function getUnavailablePlatformCapability() {
    return { state: 'transport-unavailable', reason: 'service-unavailable' }
}

/** @returns {boolean} Fail-closed boolean dependency. */
function returnFalse() {
    return false
}

/** @returns {null} Fail-closed missing service mode. */
function getNoServiceMode() {
    return null
}

/** @returns {number} Initial non-running service generation. */
function getNoGeneration() {
    return 0
}

/** @returns {null} No fatal service-health failure. */
function getNoServiceFailure() {
    return null
}

/** @returns {Promise<object>} Stable unavailable cancellation response. */
async function rejectCancellation() {
    return { ok: false, reason: 'service-unavailable' }
}

/** @returns {Promise<object>} Stable unavailable Scan response. */
async function rejectScan() {
    return { ok: false, reason: 'service-unavailable' }
}

/** @returns {boolean} Fail-closed unavailable generation fault boundary. */
function rejectGenerationFault() {
    return false
}

/**
 * Converts an untrusted failure reason into a bounded stable code.
 * @param {unknown} reason - Candidate service failure reason.
 * @returns {string} Safe failure code.
 */
function normalizeFailureReason(reason) {
    return typeof reason === 'string' && /^[a-z][a-z0-9-]{0,127}$/.test(reason) ? reason : 'service-failure'
}

/**
 * Maps a stable internal failure code to renderer-translated copy.
 * @param {string} code - Safe failure code.
 * @returns {string} Published message key.
 */
function failureMessageKey(code) {
    return ['service-unavailable', 'transport-unavailable', 'service-exited'].includes(code) ? 'errors.service.unavailable' : 'errors.service.failure'
}

/**
 * Creates one complete renderer-safe terminal failure event.
 * @param {object} active - Current main-owned operation lock.
 * @param {unknown} reason - Candidate failure code.
 * @param {() => string} correlationIdFactory - Main-owned ID factory.
 * @returns {object} Strict operation failure event.
 */
function createFailureEvent(active, reason, correlationIdFactory) {
    const code = normalizeFailureReason(reason)
    return operationEventSchema.parse({
        state: 'failed',
        operationId: active.operationId,
        kind: active.kind,
        deviceId: active.deviceId,
        deviceRevision: active.deviceRevision,
        stage: active.stage,
        error: {
            code,
            messageKey: failureMessageKey(code),
            stage: active.stage,
            category: 'transport',
            retryable: code !== 'operation-not-cancellable',
            supportCorrelationId: correlationIdFactory(),
            cleanupEvidence: [],
            attemptHistory: []
        }
    })
}

/**
 * Validates primary, cleanup, and attempt evidence against one terminal stage.
 * @param {object} event - Strict failure event.
 * @param {string} kind - Owned high-level operation kind.
 * @param {string} terminalStage - Current or projected safe terminal stage.
 * @param {number} observedAttempt - Highest accepted firmware attempt substate.
 * @returns {boolean} True when all cause evidence is graph-valid and non-future.
 */
function isFailureEvidenceConsistent(event, kind, terminalStage, observedAttempt) {
    if (event.stage !== terminalStage) return false
    if (kind !== OperationKind.FIRMWARE_UPDATE && event.error.attemptHistory.length > 0) return false
    if (terminalStage === 'queued') {
        return event.error.stage === 'queued' && event.error.cleanupEvidence.every((evidence) => evidence.stage === 'queued') && event.error.attemptHistory.length === 0
    }
    const terminalIndex = getOperationStageIndex(kind, terminalStage)
    if (terminalIndex < 0) return false
    const primaryIndex = getOperationStageIndex(kind, event.error.stage)
    if (primaryIndex < 0 || primaryIndex > terminalIndex) return false
    let previousCleanupIndex = primaryIndex
    for (const cleanup of event.error.cleanupEvidence) {
        const index = getOperationStageIndex(kind, cleanup.stage)
        if (index < previousCleanupIndex || index > terminalIndex) return false
        previousCleanupIndex = index
    }
    if ((observedAttempt === 2) !== (event.error.attemptHistory.length === 1)) return false
    for (const attempt of event.error.attemptHistory) {
        const index = getOperationStageIndex(kind, attempt.stage)
        if (attempt.attempt !== 1 || index < 0 || index > primaryIndex) return false
    }
    return true
}

/**
 * Validates native cancellation availability against main-owned request state.
 * @param {object} event - Strict progress event.
 * @param {object} active - Current exact operation owner.
 * @param {number|undefined} publicationSequence - Private native FIFO sequence.
 * @returns {boolean} True when the cancellation state is lifecycle-consistent.
 */
function isProgressCancellationStateConsistent(event, active, publicationSequence) {
    const hasExactCutover = Number.isSafeInteger(active.cancellationCutover) && Number.isSafeInteger(publicationSequence)
    const isPreRequestPrefix = active.cancellationAccepted && hasExactCutover && publicationSequence <= active.cancellationCutover
    if (active.cancellationAccepted && !isPreRequestPrefix) return event.cancellationState === 'requested'
    if (event.cancellationState === 'requested') return active.cancellationRequested
    if (event.cancellationState === 'cancellable') {
        return (!active.cancellationRequested || isPreRequestPrefix) && !active.cancellationClosed && isCancellationAllowed(active.kind, event.stage)
    }
    const closesAtCurrentBoundary = active.phase === 'running' && active.stage === event.stage && isCancellationCloseBoundary(active.kind, event.stage)
    return event.cancellationState === 'closed' && (active.cancellationClosed || !isCancellationAllowed(active.kind, event.stage) || closesAtCurrentBoundary)
}

/** Owns atomic safety admission and the one global Scan/operation reservation. */
export class OperationCoordinator {
    #active = null
    #shuttingDown = false
    #cancelDispatch
    #correlationIdFactory
    #dispatch
    #faultGeneration
    #getDevice
    #getGeneration
    #getPlatformCapability
    #getServiceFailure
    #getServiceMode
    #hasPrivilege
    #idFactory
    #isHardwareReady
    #getRecoveryOwner
    #listeners = new Set()
    #peekConfirmation
    #scanDispatch
    #terminalBarrier
    #validateConfirmation

    /**
     * Creates a fail-closed coordinator around narrow service dependencies.
     * @param {{dispatch: (operation: object) => Promise<object>, scanDispatch?: (request: object) => Promise<object>, cancelDispatch?: (request: object) => Promise<object>, faultGeneration?: (generation: number) => boolean, getDevice?: (deviceId: string) => object|null, getGeneration?: () => number, getPlatformCapability?: () => object, getServiceFailure?: () => string|null, getServiceMode?: () => string|null, hasPrivilege?: () => boolean, isHardwareReady?: () => boolean, terminalBarrier?: (event: object) => boolean|Promise<boolean>, peekConfirmation?: (request: object) => boolean, validateConfirmation?: (request: object) => boolean, idFactory?: () => string, correlationIdFactory?: () => string}} options - Main-owned dependencies.
     * @param {() => object|null} [options.getRecoveryOwner] - Recovery reservation sharing hardware and shutdown admission.
     * @throws {TypeError} When operation dispatch is unavailable.
     */
    constructor(options) {
        if (typeof options?.dispatch !== 'function') {
            throw new TypeError('OperationCoordinator requires a dispatcher')
        }
        this.#dispatch = options.dispatch
        this.#scanDispatch = typeof options.scanDispatch === 'function' ? options.scanDispatch : rejectScan
        this.#cancelDispatch = typeof options.cancelDispatch === 'function' ? options.cancelDispatch : rejectCancellation
        this.#faultGeneration = typeof options.faultGeneration === 'function' ? options.faultGeneration : rejectGenerationFault
        this.#getDevice = typeof options.getDevice === 'function' ? options.getDevice : getNoDevice
        this.#getGeneration = typeof options.getGeneration === 'function' ? options.getGeneration : getNoGeneration
        this.#getPlatformCapability = typeof options.getPlatformCapability === 'function' ? options.getPlatformCapability : getUnavailablePlatformCapability
        this.#getServiceFailure = typeof options.getServiceFailure === 'function' ? options.getServiceFailure : getNoServiceFailure
        this.#getServiceMode = typeof options.getServiceMode === 'function' ? options.getServiceMode : getNoServiceMode
        this.#hasPrivilege = typeof options.hasPrivilege === 'function' ? options.hasPrivilege : returnFalse
        this.#isHardwareReady = typeof options.isHardwareReady === 'function' ? options.isHardwareReady : returnFalse
        this.#getRecoveryOwner = typeof options.getRecoveryOwner === 'function' ? options.getRecoveryOwner : getNoDevice
        this.#terminalBarrier = typeof options.terminalBarrier === 'function' ? options.terminalBarrier : null
        this.#validateConfirmation = typeof options.validateConfirmation === 'function' ? options.validateConfirmation : returnFalse
        this.#peekConfirmation = typeof options.peekConfirmation === 'function' ? options.peekConfirmation : this.#validateConfirmation
        this.#idFactory = typeof options.idFactory === 'function' ? options.idFactory : createDefaultOperationId
        this.#correlationIdFactory = typeof options.correlationIdFactory === 'function' ? options.correlationIdFactory : createDefaultCorrelationId
    }

    /**
     * Atomically revalidates safety, reserves the lock, and starts dispatch.
     * @param {unknown} request - Candidate operation request.
     * @returns {Promise<object>} Immediate accepted identity or stable rejection.
     */
    async start(request) {
        if (this.#shuttingDown) return { ok: false, reason: 'application-shutting-down' }
        const parsedRequest = operationRequestSchema.safeParse(request)
        if (!parsedRequest.success || parsedRequest.data.kind === OperationKind.SCAN) {
            return { ok: false, reason: 'invalid-operation-request' }
        }
        // Discovery is read-only but owns the same native lease. A user action
        // waits for that existing pass, then repeats every admission check.
        if (this.#active?.kind === OperationKind.SCAN) await this.waitForScan()
        if (this.#shuttingDown) return { ok: false, reason: 'application-shutting-down' }
        if (this.#recoveryOwner() !== null) return { ok: false, reason: 'operation-in-progress' }
        const serviceFailure = this.#safeServiceFailure()
        if (serviceFailure !== null) return { ok: false, reason: serviceFailure }
        const decision = evaluateOperation(parsedRequest.data, this.#createContext(parsedRequest.data))
        if (!decision.allowed) {
            return { ok: false, reason: decision.reason }
        }

        const operationId = this.#idFactory()
        const queuedEvent = operationEventSchema.parse({ state: 'queued', operationId, kind: decision.request.kind, deviceId: decision.request.deviceId, deviceRevision: decision.request.deviceRevision, stage: 'queued' })
        const active = {
            operationId,
            kind: decision.request.kind,
            deviceId: decision.request.deviceId,
            deviceRevision: decision.request.deviceRevision,
            generation: this.#safeGeneration(),
            generationFaulted: false,
            terminalCommitPending: false,
            startAcknowledgementPending: true,
            bufferedStartTerminal: null,
            bufferedStartTerminalSettle: null,
            phase: 'dispatching',
            stage: 'queued',
            stageIndex: -1,
            progress: 0,
            attempt: 0,
            cancellationRequested: false,
            cancellationAccepted: false,
            cancellationCutover: null,
            cancellationClosed: false,
            cancellationStage: null,
            bufferedCancellationEvents: [],
            recoveryRequired: false
        }
        this.#active = active
        this.#publish(queuedEvent)
        void this.#runDispatch(active, { operationId, request: decision.request })
        return { ok: true, operationId }
    }

    /**
     * Atomically reserves the same global lock for one strict discovery Scan.
     * @param {unknown} request - Candidate literal Scan request.
     * @returns {Promise<object>} Safe Scan acknowledgement or rejection.
     */
    async scan(request) {
        if (this.#shuttingDown) return { ok: false, reason: 'application-shutting-down' }
        if (this.#recoveryOwner() !== null) return { ok: false, reason: 'operation-in-progress' }
        const parsedRequest = scanRequestSchema.safeParse(request)
        if (!parsedRequest.success) {
            return { ok: false, reason: 'invalid-request' }
        }
        const serviceFailure = this.#safeServiceFailure()
        if (serviceFailure !== null) return { ok: false, reason: serviceFailure }
        const decision = evaluateOperation(parsedRequest.data, this.#createContext(parsedRequest.data))
        if (!decision.allowed) {
            return { ok: false, reason: decision.reason }
        }
        const operationId = this.#idFactory()
        const scanCompletion = Promise.withResolvers()
        const active = { completion: scanCompletion.promise, operationId, kind: OperationKind.SCAN, generation: this.#safeGeneration(), generationFaulted: false, phase: 'dispatching', stage: 'scan-running', cancellationRequested: false, cancellationAccepted: false, cancellationClosed: true, cancellationStage: null, recoveryRequired: false }
        this.#active = active

        let response
        try {
            response = await this.#scanDispatch(parsedRequest.data)
        } catch {
            response = { ok: false, reason: 'service-failure' }
        }
        if (this.#active === active && !active.generationFaulted && active.phase === 'dispatching') {
            if (response?.ambiguous === true) {
                active.phase = 'outcome-unknown'
                active.stage = 'outcome-unknown'
            } else {
                this.#active = null
            }
        }
        scanCompletion.resolve()
        return response?.ok === true ? { ok: true } : { ok: false, reason: normalizeFailureReason(response?.reason) }
    }

    /**
     * Waits only for the current discovery response, without starting another scan.
     * Ambiguous scan outcomes keep their lock; callers must re-evaluate safety.
     * Other active operations are never queued or treated as discovery.
     * @returns {Promise<void>} Resolves once the captured scan has acknowledged.
     */
    async waitForScan() {
        const active = this.#active
        if (active?.kind === OperationKind.SCAN) await active.completion
    }

    /**
     * Cancels only the exact owner at a policy-approved current stage.
     * @param {unknown} request - Candidate cancellation identity.
     * @returns {Promise<object>} Safe cancellation acknowledgement.
     */
    async cancel(request) {
        const parsedRequest = operationCancelRequestSchema.safeParse(request)
        if (!parsedRequest.success) {
            return { ok: false, reason: 'invalid-request' }
        }
        const serviceFailure = this.#safeServiceFailure()
        if (serviceFailure !== null) return { ok: false, reason: serviceFailure }
        const active = this.#active
        if (active === null || active.kind === OperationKind.SCAN || parsedRequest.data.operationId !== active.operationId) {
            return { ok: false, reason: 'operation-not-found' }
        }
        if (active.generationFaulted || active.terminalCommitPending || active.bufferedStartTerminal !== null || active.cancellationRequested || active.cancellationClosed || !isCancellationAllowed(active.kind, active.stage)) {
            return { ok: false, reason: 'operation-not-cancellable' }
        }

        active.cancellationRequested = true
        active.cancellationStage = active.stage
        const cancellationStage = active.cancellationStage
        let response
        try {
            response = await this.#cancelDispatch({ operationId: active.operationId })
        } catch {
            response = { ok: false, reason: 'service-failure' }
        }
        if (this.#active !== active || active.generationFaulted || !active.cancellationRequested || active.cancellationStage !== cancellationStage) {
            return response?.ok === true ? { ok: true } : { ok: false, reason: normalizeFailureReason(response?.reason) }
        }
        if (response?.ok === true) {
            active.cancellationAccepted = true
            active.cancellationCutover = Number.isSafeInteger(response.cancellationCutover) && response.cancellationCutover >= 0 ? response.cancellationCutover : null
            const bufferedEvents = active.bufferedCancellationEvents
            active.bufferedCancellationEvents = []
            for (let index = 0; index < bufferedEvents.length; index += 1) {
                const bufferedEvent = bufferedEvents[index]
                if (this.#active !== active || active.generationFaulted) {
                    this.#settleCancellationSuffix(bufferedEvents, index, false)
                    break
                }
                const accepted = (await this.handleServiceEvent(bufferedEvent.event, bufferedEvent.publicationSequence)) === true
                bufferedEvent.settle?.(accepted)
                if (!accepted) {
                    this.#settleCancellationSuffix(bufferedEvents, index + 1, false)
                    this.#faultActiveGeneration(active)
                    break
                }
            }
            return { ok: true }
        }
        const bufferedEvents = active.bufferedCancellationEvents
        active.bufferedCancellationEvents = []
        const heldTerminal = bufferedEvents.some((bufferedEvent) => bufferedEvent.settle !== undefined)
        if (heldTerminal) {
            this.#settleCancellationSuffix(bufferedEvents, 0, false)
            this.#faultActiveGeneration(active)
            return { ok: false, reason: normalizeFailureReason(response?.reason) }
        }
        if (response?.ambiguous !== true) {
            active.cancellationRequested = false
            active.cancellationAccepted = false
            active.cancellationCutover = null
            active.cancellationStage = null
            for (const bufferedEvent of bufferedEvents) {
                if (bufferedEvent.event.state === 'cancelled') continue
                if (this.#active !== active || active.generationFaulted) break
                if (!(await this.handleServiceEvent(bufferedEvent.event, bufferedEvent.publicationSequence))) {
                    this.#faultActiveGeneration(active)
                    break
                }
            }
        }
        return { ok: false, reason: normalizeFailureReason(response?.reason) }
    }

    /**
     * Builds current safety context for Task 6 preflight without awaiting.
     * @param {object} request - Strict high-level request.
     * @returns {object} Fail-closed identity, lock, service, and privilege context.
     */
    getContext(request) {
        return this.#createContext(request, false)
    }

    /**
     * Returns a detached frozen view of the current reservation.
     * @returns {object|null} Current Scan/operation owner or null.
     */
    getActiveOperation() {
        if (this.#active === null) {
            return null
        }
        return Object.freeze({ operationId: this.#active.operationId, kind: this.#active.kind, deviceId: this.#active.deviceId, deviceRevision: this.#active.deviceRevision, generation: this.#active.generation, stage: this.#active.stage, cancellationRequested: this.#active.cancellationRequested, ...(this.#active.cancellationState === undefined ? {} : { cancellationState: this.#active.cancellationState }), irreversible: this.#active.recoveryRequired })
    }

    /**
     * Reports whether application shutdown may begin without abandoning work.
     * @returns {{allowed: true}|{allowed: false, reason: string}} Shutdown policy.
     */
    getShutdownPolicy() {
        return this.#active === null && this.#recoveryOwner() === null ? { allowed: true } : { allowed: false, reason: 'operation-in-progress' }
    }

    /** @returns {boolean} True once approved shutdown has synchronously closed all admission. */
    isShuttingDown() {
        return this.#shuttingDown
    }

    /** @returns {boolean} Atomically reserves idle shutdown before any asynchronous teardown. */
    beginShutdown() {
        if (this.#shuttingDown || !this.getShutdownPolicy().allowed) return false
        this.#shuttingDown = true
        return true
    }

    /** @returns {object|null} Recovery owner, conservatively occupied on dependency failure. */
    #recoveryOwner() {
        try {
            return this.#getRecoveryOwner()
        } catch {
            return { kind: 'firmware-recovery' }
        }
    }

    /**
     * Accepts only graph-valid service events for the exact reservation owner.
     * @param {unknown} event - Candidate operation event.
     * @param {number} [publicationSequence] - Private native FIFO sequence.
     * @returns {boolean|Promise<boolean>} True when the exact state machine and terminal barrier accepted the event.
     */
    handleServiceEvent(event, publicationSequence) {
        const parsedEvent = operationEventSchema.safeParse(event)
        if (!parsedEvent.success || !this.#owns(parsedEvent.data)) {
            return false
        }
        const safeEvent = parsedEvent.data
        const active = this.#active
        if (active.generationFaulted || active.terminalCommitPending) {
            return false
        }
        if (safeEvent.state === 'queued') {
            return false
        }
        if (active.bufferedStartTerminal !== null) {
            this.#faultActiveGeneration(active)
            return false
        }
        const bufferedCancellation = this.#bufferPendingCancellationEvent(safeEvent, active, publicationSequence)
        if (bufferedCancellation !== null) {
            return bufferedCancellation
        }
        if (safeEvent.state === 'progress' && !isProgressCancellationStateConsistent(safeEvent, active, publicationSequence)) {
            return false
        }
        if (safeEvent.state === 'started') {
            const firstStage = getOperationStageGraph(active.kind)?.[0]
            if (!['dispatching', 'awaiting-start', 'outcome-unknown'].includes(active.phase) || safeEvent.stage !== firstStage) {
                return false
            }
            active.phase = 'running'
            active.stage = safeEvent.stage
            active.stageIndex = 0
            active.progress = 0
            active.attempt = 0
            active.recoveryRequired = hasRecoveryObligation(active.kind, active.stage)
            if (active.cancellationRequested && !isCancellationAllowed(active.kind, active.stage) && !isCancellationRecoveryStage(active.kind, active.stage)) {
                active.cancellationClosed = true
            }
            if (active.cancellationRequested && !active.cancellationAccepted) {
                active.bufferedCancellationEvents = []
            }
            this.#publish(safeEvent)
            return true
        }
        if (safeEvent.state === 'progress') {
            const expectedRecoveryStage = active.cancellationAccepted ? getNextCancellationRecoveryStage(active.kind, active.stage) : null
            const cancellationRecoveryFromAwait = ['dispatching', 'awaiting-start', 'outcome-unknown'].includes(active.phase) && safeEvent.stage === expectedRecoveryStage
            if (active.phase !== 'running' && !cancellationRecoveryFromAwait) {
                return false
            }
            const nextIndex = getOperationStageIndex(active.kind, safeEvent.stage)
            const sequential = isOperationStageTransitionAllowed(active.kind, active.stage, safeEvent.stage)
            const cancellationRecoveryJump = safeEvent.stage === expectedRecoveryStage
            const hasAttempt = safeEvent.attempt !== undefined
            const attemptAllowed = !hasAttempt || (active.kind === OperationKind.FIRMWARE_UPDATE && safeEvent.stage === 'firmware-writing' && safeEvent.attempt >= active.attempt && safeEvent.attempt <= active.attempt + 1 && (active.attempt !== 0 || safeEvent.attempt === 1))
            if ((!sequential && !cancellationRecoveryJump) || safeEvent.progress < active.progress || !attemptAllowed) {
                return false
            }
            active.phase = 'running'
            active.stage = safeEvent.stage
            active.stageIndex = nextIndex
            active.progress = safeEvent.progress
            active.cancellationState = safeEvent.cancellationState
            if (hasAttempt) active.attempt = safeEvent.attempt
            active.recoveryRequired ||= hasRecoveryObligation(active.kind, active.stage)
            if (safeEvent.cancellationState === 'closed' || (active.cancellationRequested && !isCancellationAllowed(active.kind, active.stage) && !isCancellationRecoveryStage(active.kind, active.stage))) {
                active.cancellationClosed = true
            }
            if (active.cancellationRequested && !active.cancellationAccepted) {
                active.bufferedCancellationEvents = []
            }
            this.#publish(safeEvent)
            return true
        }
        if (safeEvent.state === 'succeeded') {
            const graph = getOperationStageGraph(active.kind)
            if (active.phase !== 'running' || safeEvent.stage !== 'complete' || active.stageIndex !== graph.length - 1) {
                return false
            }
            return this.#acceptTerminalEvent(safeEvent, active)
        }
        if (safeEvent.state === 'cancelled') {
            const awaitingTerminalWithoutProgress = ['dispatching', 'awaiting-start', 'outcome-unknown'].includes(active.phase) && safeEvent.stage === active.cancellationStage
            if (!active.cancellationAccepted || active.cancellationClosed || !isCancellationTerminalStage(active.kind, safeEvent.stage) || (!awaitingTerminalWithoutProgress && safeEvent.stage !== active.stage)) {
                return false
            }
            return this.#acceptTerminalEvent(safeEvent, active)
        }
        const graph = getOperationStageGraph(active.kind)
        const awaitingFirstStage = ['dispatching', 'awaiting-start', 'outcome-unknown'].includes(active.phase)
        const terminalStage = awaitingFirstStage ? 'queued' : active.stage
        const failureStageAllowed = isFailureEvidenceConsistent(safeEvent, active.kind, terminalStage, active.attempt)
        const recoveryRequired = active.recoveryRequired || hasRecoveryObligation(active.kind, safeEvent.error.stage)
        if (graph === null || !failureStageAllowed || !isFailureTerminalAllowed(active.kind, safeEvent, recoveryRequired)) {
            return false
        }
        return this.#acceptTerminalEvent(safeEvent, active)
    }

    /**
     * Reconciles only the owner admitted under a confirmed terminated generation.
     * @param {number} generation - Exact terminated transport generation.
     * @param {unknown} reason - Stable lifecycle failure reason.
     * @param {boolean} [publishTerminal=true] - Whether durable public failure evidence remains possible.
     * @returns {boolean|Promise<boolean>} True when one exact owner was failed or released.
     */
    handleGenerationLoss(generation, reason, publishTerminal = true) {
        if (this.#active === null || this.#active.generation !== generation) {
            return false
        }
        const active = this.#active
        this.#rejectBufferedStartTerminal(active)
        this.#rejectBufferedCancellationEvents(active)
        if (active.kind === OperationKind.SCAN || !publishTerminal || active.terminalCommitPending) {
            this.#active = null
            return true
        }
        return this.#commitTerminalEvent(createFailureEvent(active, reason, this.#correlationIdFactory), active, true, true)
    }

    /**
     * Converts a confirmed generic service loss into one terminal owner event.
     * @param {unknown} reason - Candidate lifecycle reason.
     * @returns {boolean|Promise<boolean>} True when one reservation was released.
     */
    failActiveOperation(reason) {
        const active = this.#active
        return active === null ? false : this.#failReservation(active, reason)
    }

    /**
     * Subscribes to validated coordinator-owned operation events.
     * @param {(event: object) => void} listener - Main-process callback.
     * @returns {() => void} Idempotent unsubscribe callback.
     */
    subscribe(listener) {
        if (typeof listener !== 'function') {
            throw new TypeError('Operation listener must be a function')
        }
        this.#listeners.add(listener)
        const listeners = this.#listeners
        let subscribed = true

        /** @returns {void} Removes this exact listener once. */
        function unsubscribe() {
            if (subscribed) {
                subscribed = false
                listeners.delete(listener)
            }
        }
        return unsubscribe
    }

    /**
     * Dispatches after reservation and preserves ambiguous ownership.
     * @param {object} active - Exact reservation that initiated dispatch.
     * @param {{operationId: string, request: object}} operation - Owned dispatch.
     * @returns {Promise<void>} Resolves after acknowledgement mapping.
     */
    async #runDispatch(active, operation) {
        let response
        try {
            response = await this.#dispatch(operation)
        } catch {
            response = { ok: false, reason: 'service-failure' }
        }
        if (this.#active !== active || active.generationFaulted) {
            return
        }
        const lifecycleAdvanced = active.phase !== 'dispatching' || active.bufferedCancellationEvents.length > 0 || active.bufferedStartTerminal !== null
        active.startAcknowledgementPending = false
        if (response?.ok === true) {
            if (active.phase === 'dispatching') {
                active.phase = 'awaiting-start'
            }
            await this.#replayStartTerminal(active)
            return
        }
        if (lifecycleAdvanced) {
            this.#faultActiveGeneration(active)
            return
        }
        if (response?.ambiguous === true) {
            active.phase = 'outcome-unknown'
            active.stage = 'outcome-unknown'
            return
        }
        await this.#failReservation(active, response?.reason)
    }

    /**
     * Retains a graph-valid terminal until the operation-start acknowledgement
     * establishes whether service lifecycle evidence may be committed.
     * @param {object} event - Strict already-validated terminal event.
     * @param {object} active - Exact coordinator reservation.
     * @returns {boolean|Promise<boolean>} True when the terminal was buffered or committed.
     */
    #acceptTerminalEvent(event, active) {
        if (this.#active !== active || active.generationFaulted) {
            return false
        }
        if (active.startAcknowledgementPending) {
            if (active.bufferedStartTerminal !== null) {
                this.#faultActiveGeneration(active)
                return false
            }
            active.bufferedStartTerminal = event
            const completion = Promise.withResolvers()
            active.bufferedStartTerminalSettle = completion.resolve
            return completion.promise
        }
        return this.#commitTerminalEvent(event, active)
    }

    /**
     * Replays the one deferred terminal after a positive exact start response.
     * @param {object} active - Exact non-faulted acknowledged reservation.
     * @returns {Promise<void>} Completes after terminal commit or protocol fault latching.
     */
    async #replayStartTerminal(active) {
        if (this.#active !== active || active.generationFaulted || active.bufferedStartTerminal === null) {
            return
        }
        const terminal = active.bufferedStartTerminal
        const settle = active.bufferedStartTerminalSettle
        active.bufferedStartTerminal = null
        active.bufferedStartTerminalSettle = null
        const accepted = await this.handleServiceEvent(terminal)
        settle?.(accepted)
        if (!accepted) {
            this.#faultActiveGeneration(active)
        }
    }

    /**
     * Builds a fail-closed context while containing dependency failure.
     * @param {object} request - Candidate strict operation.
     * @param {boolean} [consumeConfirmation=true] - Whether a matching one-shot token is atomically consumed.
     * @returns {object} Current safety context.
     */
    #createContext(request, consumeConfirmation = true) {
        let device = null
        let platformCapability = getUnavailablePlatformCapability()
        let serviceMode = null
        let hasPrivilege = false
        let hardwareReady = false
        let confirmationTokenValid = false
        try {
            device = request?.deviceId === undefined ? null : this.#getDevice(request.deviceId)
        } catch {
            device = null
        }
        try {
            platformCapability = this.#getPlatformCapability()
        } catch {
            platformCapability = getUnavailablePlatformCapability()
        }
        try {
            serviceMode = this.#getServiceMode()
        } catch {
            serviceMode = null
        }
        try {
            hasPrivilege = this.#hasPrivilege() === true
            hardwareReady = this.#isHardwareReady() === true
            confirmationTokenValid = (consumeConfirmation ? this.#validateConfirmation : this.#peekConfirmation)(request) === true
        } catch {
            hasPrivilege = false
            hardwareReady = false
            confirmationTokenValid = false
        }
        const activeOperation = this.#active === null ? this.#recoveryOwner() : { id: this.#active.operationId, kind: this.#active.kind, deviceId: this.#active.deviceId, deviceRevision: this.#active.deviceRevision }
        return { activeOperation, confirmationTokenValid, device, generation: this.#safeGeneration(), hardwareReady, hasPrivilege, platformCapability, serviceMode }
    }

    /** @returns {number} Current nonnegative service generation or zero. */
    #safeGeneration() {
        try {
            const generation = this.#getGeneration()
            return Number.isSafeInteger(generation) && generation >= 0 ? generation : 0
        } catch {
            return 0
        }
    }

    /** @returns {string|null} One allowlisted fatal service-health reason or null. */
    #safeServiceFailure() {
        try {
            return this.#getServiceFailure() === 'event-log-unavailable' ? 'event-log-unavailable' : null
        } catch {
            return 'event-log-unavailable'
        }
    }

    /** @param {object} event - Strict event. @returns {boolean} Exact ownership match. */
    #owns(event) {
        return this.#active !== null && this.#active.kind !== OperationKind.SCAN && event.operationId === this.#active.operationId && event.kind === this.#active.kind && event.deviceId === this.#active.deviceId && event.deviceRevision === this.#active.deviceRevision
    }

    /**
     * Buffers exact cancellation cleanup while its acknowledgement promise is
     * pending, validating against a projected state without publishing or release.
     * @param {object} event - Strict exact-owner service event.
     * @param {object} active - Current coordinator reservation.
     * @param {number|undefined} publicationSequence - Private native FIFO sequence.
     * @returns {boolean|Promise<boolean>|null} Held terminal outcome, progress result, or null.
     */
    #bufferPendingCancellationEvent(event, active, publicationSequence) {
        if (!active.cancellationRequested || active.cancellationAccepted || active.cancellationClosed) {
            return null
        }
        const isProgress = event.state === 'progress'
        const isTerminal = ['succeeded', 'failed', 'cancelled'].includes(event.state)
        if (!isProgress && !isTerminal) {
            return null
        }
        let terminalAlreadyBuffered = false
        for (const bufferedEvent of active.bufferedCancellationEvents) {
            terminalAlreadyBuffered ||= bufferedEvent.event.state !== 'progress'
        }
        if (terminalAlreadyBuffered) {
            this.#faultActiveGeneration(active)
            return false
        }
        const projection = this.#projectPendingCancellation(active)
        if (event.state === 'progress') {
            const candidateIndex = getOperationStageIndex(active.kind, event.stage)
            const sameStage = event.stage === projection.stage && candidateIndex === projection.stageIndex
            const nextRecoveryStage = getNextCancellationRecoveryStage(active.kind, projection.stage)
            if ((!sameStage && event.stage !== nextRecoveryStage) || event.progress < projection.progress) {
                return false
            }
            const bufferedEvents = active.bufferedCancellationEvents
            const lastBufferedEvent = bufferedEvents.at(-1)
            if (sameStage && lastBufferedEvent?.event.state === 'progress' && lastBufferedEvent.event.stage === event.stage) {
                bufferedEvents[bufferedEvents.length - 1] = { event, publicationSequence }
                return true
            }
            const graphLength = getOperationStageGraph(active.kind)?.length ?? 0
            if (bufferedEvents.length >= graphLength) {
                this.#faultActiveGeneration(active)
                return false
            }
            bufferedEvents.push({ event, publicationSequence })
            return true
        }
        const recoveryIncomplete = projection.recoveryRequired && getNextCancellationRecoveryStage(active.kind, projection.stage) !== null
        if (recoveryIncomplete || !this.#isProjectedCancellationTerminal(event, active, projection)) {
            return false
        }
        const terminalCapacity = (getOperationStageGraph(active.kind)?.length ?? 0) + 1
        if (active.bufferedCancellationEvents.length >= terminalCapacity) {
            this.#faultActiveGeneration(active)
            return false
        }
        const { promise: outcome, resolve: settle } = Promise.withResolvers()
        active.bufferedCancellationEvents.push({ event, publicationSequence, settle })
        return outcome
    }

    /**
     * Requests bounded teardown for the exact active service generation while
     * leaving operation ownership intact until lifecycle reconciliation.
     * @param {object} active - Exact coordinator reservation detecting the fault.
     * @returns {void} Completes after contained fault notification.
     */
    #faultActiveGeneration(active) {
        if (this.#active !== active || active.generationFaulted) return
        this.#rejectBufferedStartTerminal(active)
        this.#rejectBufferedCancellationEvents(active)
        // Latch before crossing into client teardown because lifecycle callbacks and
        // transport doubles may reenter the coordinator synchronously.
        active.generationFaulted = true
        try {
            this.#faultGeneration(active.generation)
        } catch {
            // A failed fault boundary cannot authorize releasing ambiguous work.
        }
    }

    /**
     * Rejects a terminal whose start acknowledgement can no longer authorize it.
     * @param {object} active - Exact reservation with optional buffered terminal.
     * @returns {void} Completes after settling the held client FIFO once.
     */
    #rejectBufferedStartTerminal(active) {
        const settle = active.bufferedStartTerminalSettle
        active.bufferedStartTerminal = null
        active.bufferedStartTerminalSettle = null
        settle?.(false)
    }

    /** @param {object} active - Reservation with optional held cancellation terminal. @returns {void} Settles and clears every held outcome false. */
    #rejectBufferedCancellationEvents(active) {
        if (!Array.isArray(active.bufferedCancellationEvents)) return
        this.#settleCancellationSuffix(active.bufferedCancellationEvents, 0, false)
        active.bufferedCancellationEvents = []
    }

    /** @param {object[]} events - Buffered cancellation events. @param {number} start - First unsettled index. @param {boolean} accepted - Shared outcome. @returns {void} Settles terminal outcomes in the suffix. */
    #settleCancellationSuffix(events, start, accepted) {
        for (let index = start; index < events.length; index += 1) events[index].settle?.(accepted)
    }

    /**
     * Publishes a safe terminal failure for one exact non-faulted reservation.
     * @param {object} active - Exact coordinator reservation to reconcile.
     * @param {unknown} reason - Stable candidate failure reason.
     * @returns {boolean|Promise<boolean>} True only when that reservation was terminally reconciled.
     */
    #failReservation(active, reason) {
        if (this.#active !== active || active.generationFaulted) {
            return false
        }
        return this.#commitTerminalEvent(createFailureEvent(active, reason, this.#correlationIdFactory), active)
    }

    /**
     * Holds ownership while one terminal crosses the durable audit barrier.
     * @param {object} event - Strict terminal event.
     * @param {object} active - Exact reservation owner.
     * @param {boolean} [releaseOnFailure=false] - Whether generation loss already proves reconciliation.
     * @param {boolean} [allowFaulted=false] - Whether exact generation loss permits a latched owner.
     * @returns {boolean|Promise<boolean>} True only after durable admission and publication.
     */
    #commitTerminalEvent(event, active, releaseOnFailure = false, allowFaulted = false) {
        if (this.#active !== active || (!allowFaulted && active.generationFaulted) || active.terminalCommitPending) {
            return false
        }
        active.terminalCommitPending = true
        let barrierResult = true
        try {
            barrierResult = this.#terminalBarrier?.(event) ?? true
        } catch {
            barrierResult = false
        }

        /** @param {unknown} accepted - Barrier outcome. @returns {boolean} Exact commit result. */
        const complete = (accepted) => {
            if (this.#active !== active || (!allowFaulted && active.generationFaulted) || !active.terminalCommitPending) {
                return false
            }
            active.terminalCommitPending = false
            if (accepted !== true) {
                if (releaseOnFailure) {
                    this.#active = null
                } else {
                    this.#faultActiveGeneration(active)
                }
                return false
            }
            this.#publish(event)
            if (this.#active === active) {
                this.#active = null
            }
            return true
        }

        /** @returns {Promise<boolean>} Commits only after the asynchronous audit barrier settles. */
        async function completeAfterBarrier() {
            let accepted
            try {
                accepted = await barrierResult
            } catch {
                accepted = false
            }
            return complete(accepted)
        }

        return typeof barrierResult?.then === 'function' ? completeAfterBarrier() : complete(barrierResult)
    }

    /**
     * Validates one terminal against projected cleanup without releasing state.
     * @param {object} event - Strict success, failure, or cancelled terminal.
     * @param {object} active - Current coordinator reservation.
     * @param {object} projection - Projected buffered cleanup state.
     * @returns {boolean} True only when replay can accept the exact terminal.
     */
    #isProjectedCancellationTerminal(event, active, projection) {
        if (event.state === 'succeeded') {
            const graph = getOperationStageGraph(active.kind)
            return !projection.awaiting && event.stage === 'complete' && projection.stageIndex === graph?.length - 1
        }
        if (event.state === 'failed') {
            const terminalStage = projection.awaiting ? 'queued' : projection.stage
            const failureStageAllowed = isFailureEvidenceConsistent(event, active.kind, terminalStage, projection.attempt)
            const recoveryRequired = projection.recoveryRequired || hasRecoveryObligation(active.kind, event.error.stage)
            return failureStageAllowed && isFailureTerminalAllowed(active.kind, event, recoveryRequired)
        }
        const terminalMatchesProjection = event.stage === projection.stage || (projection.awaiting && event.stage === active.cancellationStage)
        return terminalMatchesProjection && isCancellationTerminalStage(active.kind, event.stage)
    }

    /**
     * Projects buffered cleanup progress without mutating visible operation state.
     * @param {object} active - Current coordinator reservation.
     * @returns {{stage: string, stageIndex: number, progress: number, attempt: number, recoveryRequired: boolean, awaiting: boolean}} Projected cancellation state.
     */
    #projectPendingCancellation(active) {
        let stage = active.stage
        let stageIndex = active.stageIndex
        let progress = active.progress
        let attempt = active.attempt
        let recoveryRequired = active.recoveryRequired
        let awaiting = ['dispatching', 'awaiting-start', 'outcome-unknown'].includes(active.phase)
        for (const bufferedEvent of active.bufferedCancellationEvents) {
            const event = bufferedEvent.event
            if (event.state !== 'progress') continue
            stage = event.stage
            stageIndex = getOperationStageIndex(active.kind, event.stage)
            progress = event.progress
            if (event.attempt !== undefined) attempt = event.attempt
            recoveryRequired ||= hasRecoveryObligation(active.kind, event.stage)
            awaiting = false
        }
        return { stage, stageIndex, progress, attempt, recoveryRequired, awaiting }
    }

    /** @param {object} event - Strict safe event. @returns {void} Publishes safely. */
    #publish(event) {
        for (const listener of this.#listeners) {
            try {
                listener(event)
            } catch {
                // One observer cannot block later exact lifecycle observers.
            }
        }
    }
}
