// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { isAbsolute } from 'node:path'
import { isDeepStrictEqual } from 'node:util'
import { RecoveryWireClient } from './recovery-wire-client.mjs'
import { ManufacturingWireClient } from './manufacturing-wire-client.mjs'
import { actionResponseSchema, operationCancelRequestSchema, operationContinueRequestSchema, operationConfirmationRequestSchema, operationConfirmationResponseSchema, operationIdSchema, operationRequestSchema, operationStartResponseSchema, scanRequestSchema } from '../shared/schemas.mjs'
import { deepFreeze, publishContained, subscribeContained } from './contained-observers.mjs'
import { DiscoveryState } from './discovery-state.mjs'
import { registerFirmwareImageFrames } from './firmware-registration-client.mjs'
import { AMBIGUOUS_METHODS, SCAN_REQUEST_TIMEOUT_MS, SHUTDOWN_REQUEST_TIMEOUT_MS, TERMINAL_STATES, isBoundedRestartDelay, isBoundedTimeout } from './device-service-client-config.mjs'
import { ExpiredDiscoveryRequests } from './expired-discovery-requests.mjs'
import { ServiceInboundQueue } from './service-inbound-queue.mjs'
import { ServicePublicationSequence } from './service-publication-sequence.mjs'
import { StartupWaiter } from './startup-waiter.mjs'
import { DEFAULT_MAX_FRAME_BYTES, DEFAULT_RESTART_BACKOFF_MS, DEVICE_SERVICE_ARGUMENTS, SERVICE_PROTOCOL_VERSION, createChildProcessTransportFactory, createDeviceServiceTransportFactory, createNoDeviceTransportFactory, encodeServiceFrame, isNativeDiagnosticCode, resolveDeviceServiceExecutable } from './device-service-transport.mjs'
import { handshakeSchema, wireCancellationResponseSchema, wireDeviceListResponseSchema, wireEventSchema, wireResponseSchema } from './device-service-wire.mjs'
export { DEVICE_SERVICE_ARGUMENTS, createChildProcessTransportFactory, createDeviceServiceTransportFactory, createNoDeviceTransportFactory, resolveDeviceServiceExecutable }
const defaultTimers = Object.freeze({ setTimeout, clearTimeout })

/**
 * Records the fixed handshake boundary without letting a diagnostic sink throw into transport admission.
 * @param {{write: Function}|null} logger - Existing main-owned event logger.
 * @returns {Promise<void>} Settles after the diagnostic write, independently of protocol progress.
 */
async function recordHandshakeStart(logger) {
    try {
        await logger?.write({ event: 'service-handshake-start', messageKey: 'activity.service', severity: 'info' })
    } catch {
        // The logger retains its existing failure latch; diagnostics cannot change protocol sequencing.
    }
}

/**
 * Supervises the local native-service transport, bounded handshake, request
 * correlation, strict event mapping, restart backoff, and clean shutdown.
 */
export class DeviceServiceClient {
    #desired = false
    #discovery = new DiscoveryState()
    #eventListeners = new Set()
    #executable
    #emitHandshakeDiagnostics
    #expiredDiscoveryRequests = new ExpiredDiscoveryRequests()
    #fatalReason = null
    #generation = 0
    #faultingGeneration = null
    #handshake = null
    #handshakeTimer = null
    #handshakeTimeoutMs
    #inbound
    #lifecycleListeners = new Set()
    #logger
    #maxFrameBytes
    #maxPendingBytes
    #maxPendingCount
    #maxRestarts
    #nativeDiagnostic = null
    #pending = new Map()
    #pendingBytes = 0
    #platform
    #privileged = false
    #publicationSequence = new ServicePublicationSequence()
    #requestId = 0
    #requestTimeoutMs
    #restartBackoffMs
    #restartTimer = null
    #startup = new StartupWaiter()
    #state = deepFreeze({ status: 'stopped', restartCount: 0 })
    #stopPromise = null
    #shutdownGeneration = null
    #teardownPromise = null
    #timers
    #transport = null
    #transportFactory
    /**
     * Creates a supervised service client with fixed arguments and injected transport.
     * @param {{executable: string, transportFactory: Function, platform?: 'darwin'|'win32'|'linux', maxFrameBytes?: number, maxPendingCount?: number, maxPendingBytes?: number, handshakeTimeoutMs?: number, requestTimeoutMs?: number, maxRestarts?: number, restartBackoffMs?: number[], timers?: {setTimeout: Function, clearTimeout: Function}, logger?: {write: Function}, emitHandshakeDiagnostics?: boolean}} options - Main-owned service configuration.
     * @throws {TypeError} When configuration would weaken bounds or launch ownership.
     */
    constructor(options) {
        Object.defineProperty(this, 'recovery', { value: Object.freeze(new RecoveryWireClient(this.#request.bind(this))) })
        // Full-sector capture, durable storage, and exact readback can exceed the
        // ordinary control request deadline. A timeout still retains uncertainty.
        Object.defineProperty(this, 'manufacturing', { value: Object.freeze(new ManufacturingWireClient((method, payload, schema) => this.#request(method, payload, schema, false, method === 'manufacturing-restore' ? 180_000 : 60_000))) })
        const maxFrameBytes = options?.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES
        if (typeof options?.executable !== 'string' || !isAbsolute(options.executable) || typeof options?.transportFactory !== 'function') {
            throw new TypeError('DeviceServiceClient launch configuration is invalid')
        }
        if (!Number.isInteger(maxFrameBytes) || maxFrameBytes < 64 || maxFrameBytes > 1_048_576) {
            throw new TypeError('DeviceServiceClient frame bound is invalid')
        }
        this.#executable = options.executable
        this.#emitHandshakeDiagnostics = options.emitHandshakeDiagnostics === true
        this.#transportFactory = options.transportFactory
        this.#platform = options.platform ?? process.platform
        this.#maxFrameBytes = maxFrameBytes
        this.#maxPendingCount = options.maxPendingCount ?? 64
        this.#maxPendingBytes = options.maxPendingBytes ?? 1_048_576
        this.#handshakeTimeoutMs = options.handshakeTimeoutMs ?? 2_000
        this.#requestTimeoutMs = options.requestTimeoutMs ?? 5_000
        this.#maxRestarts = options.maxRestarts ?? 2
        this.#restartBackoffMs = Object.freeze([...(options.restartBackoffMs ?? DEFAULT_RESTART_BACKOFF_MS)])
        this.#timers = options.timers ?? defaultTimers
        this.#logger = typeof options.logger?.write === 'function' ? options.logger : null
        const timeoutsAreBounded = [this.#handshakeTimeoutMs, this.#requestTimeoutMs].every(isBoundedTimeout)
        const backoffIsBounded = this.#restartBackoffMs.length >= 1 && this.#restartBackoffMs.length <= 11 && this.#restartBackoffMs.every(isBoundedRestartDelay)
        if (!['darwin', 'win32', 'linux'].includes(this.#platform) || !Number.isInteger(this.#maxRestarts) || this.#maxRestarts < 0 || this.#maxRestarts > 10 || !Number.isInteger(this.#maxPendingCount) || this.#maxPendingCount < 1 || this.#maxPendingCount > 1024 || !Number.isInteger(this.#maxPendingBytes) || this.#maxPendingBytes < this.#maxFrameBytes || this.#maxPendingBytes > 16_777_216 || !timeoutsAreBounded || !backoffIsBounded || typeof this.#timers.setTimeout !== 'function' || typeof this.#timers.clearTimeout !== 'function') {
            throw new TypeError('DeviceServiceClient lifecycle configuration is invalid')
        }
        this.#inbound = new ServiceInboundQueue({
            maxFrameBytes: this.#maxFrameBytes,
            pending: this.#pending,
            /** @param {number} generation - Candidate generation. @returns {boolean} True while inbound data belongs to the live transport. */
            isCurrent: (generation) => generation === this.#generation && generation !== this.#faultingGeneration && this.#desired,
            /** @returns {number} Current transport generation. */
            getGeneration: () => this.#generation,
            /** @param {object} message - Decoded wire message. @param {number} generation - Exact owner. @returns {boolean|Promise<boolean>} Ordered observer acceptance. */
            handleMessage: (message, generation) => this.#handleMessage(message, generation),
            /** @param {object} response - Strict response envelope. @returns {boolean} True after exact correlation accepts it. */
            handleResponse: (response) => this.#handleResponse(response),
            /** @param {object} response - Strict expired discovery response. @returns {boolean} True only when the late reply is owned and valid. */
            consumeExpiredDiscoveryResponse: (response) => this.#expiredDiscoveryRequests.consume(response),
            /** @param {number} generation - Faulted owner. @param {number} restartCount - Completed restarts. @returns {void} Faults malformed input. */
            fault: (generation, restartCount) => this.#handleTransportFault('service-malformed-data', generation, restartCount)
        })
    }

    /**
     * Starts the service and resolves at the first ready or terminal unavailable state.
     * @returns {Promise<object>} Frozen terminal startup state.
     */
    async start() {
        if (this.#stopPromise !== null) {
            await this.#stopPromise
            this.#stopPromise = null
        }
        if (this.#fatalReason !== null) {
            await Promise.resolve()
            if (this.#teardownPromise !== null) await this.#teardownPromise
            return this.getState()
        }
        if (this.#state.status === 'teardown-unconfirmed') {
            return this.#state
        }
        if (this.#state.status === 'ready') {
            return this.#state
        }
        if (this.#startup.getPending() !== null) {
            return this.#startup.getPending()
        }
        if (this.#desired && ['starting', 'handshaking', 'reconciling', 'recovering', 'restarting'].includes(this.#state.status)) {
            return this.#startup.create()
        }
        this.#desired = true
        const startupPromise = this.#startup.create()
        this.#launch(0)
        return startupPromise
    }

    /**
     * Stops restart timers, closes transport, and rejects pending calls safely.
     * @returns {Promise<void>} Resolves after local lifecycle cleanup.
     */
    async stop() {
        if (this.#stopPromise !== null) return this.#stopPromise
        this.#stopPromise = this.#performStop()
        return this.#stopPromise
    }

    /** @returns {Promise<void>} Performs the one current-generation teardown. */
    async #performStop() {
        const teardownWasUnconfirmed = this.#state.status === 'teardown-unconfirmed'
        const shutdownGeneration = this.#generation
        if (this.#state.status === 'ready' && this.#transport?.supportsGracefulShutdown === true) {
            this.#shutdownGeneration = shutdownGeneration
            await this.#request('service-shutdown', {}, actionResponseSchema, false, SHUTDOWN_REQUEST_TIMEOUT_MS)
        }
        this.#desired = false
        this.#shutdownGeneration = null
        this.#clearTimers()
        this.#inbound.reset()
        const transport = this.#detachTransport()
        const faultTeardown = this.#teardownPromise
        this.#resolvePending('service-unavailable')
        this.#expiredDiscoveryRequests.clear()
        this.#handshake = null
        this.#privileged = false
        this.#publicationSequence.reset()
        this.#discovery.reset(this.#generation + 1)
        const transportConfirmed = await this.#closeTransport(transport)
        const faultConfirmed = faultTeardown === null ? true : await faultTeardown
        const teardownConfirmed = !teardownWasUnconfirmed && transportConfirmed && faultConfirmed !== false
        const stoppedState = this.#fatalReason === null ? { status: 'stopped', restartCount: this.#state.restartCount ?? 0 } : { status: 'unavailable', reason: this.#fatalReason, restartCount: this.#state.restartCount ?? 0, terminatedGeneration: this.#generation }
        this.#transition(teardownConfirmed ? stoppedState : { status: 'teardown-unconfirmed', reason: 'service-teardown-unconfirmed', restartCount: this.#state.restartCount ?? 0, generation: this.#generation })
        this.#startup.settle(this.#state)
    }

    /**
     * Returns the current frozen lifecycle snapshot.
     * @returns {object} Current service state.
     */
    getState() {
        if (this.#fatalReason !== null && !['unavailable', 'teardown-unconfirmed'].includes(this.#state.status)) {
            return deepFreeze({ status: 'unavailable', reason: this.#fatalReason, restartCount: this.#state.restartCount ?? 0, ...(this.#generation > 0 ? { terminatedGeneration: this.#generation } : {}) })
        }
        return this.#state
    }

    /**
     * Returns one strict cached device owned by service discovery.
     * @param {string} deviceId - Opaque device identifier.
     * @returns {object|null} Current device snapshot or null.
     */
    getDevice(deviceId) {
        return this.#discovery.getDevice(deviceId)
    }

    /** @returns {object} Handshaken capability or a frozen fail-closed default. */
    getPlatformCapability() {
        return this.#state.status === 'ready' && this.#fatalReason === null ? this.#state.platformCapability : deepFreeze({ state: 'transport-unavailable', reason: this.#fatalReason ?? 'service-unavailable' })
    }

    /** @returns {number} Current launched service generation. */
    getGeneration() {
        return this.#generation
    }

    /**
     * Contains a coordinator-detected protocol contradiction in one exact service
     * generation without accepting stale ownership or caller-selected reasons.
     * @param {number} generation - Exact coordinator-owned service generation.
     * @returns {boolean} True only when bounded teardown started for that generation.
     */
    faultGeneration(generation) {
        if (this.#fatalReason !== null || !Number.isSafeInteger(generation) || generation < 1 || generation !== this.#generation || generation === this.#faultingGeneration || !this.#desired) {
            return false
        }
        this.#handleFault('service-malformed-data', generation, this.#state.restartCount ?? 0)
        return this.#faultingGeneration === generation
    }

    /**
     * Contains a main-owned event-log health failure without restarting into a
     * generation that still cannot preserve terminal and audit records.
     * @param {number} generation - Exact current service generation.
     * @returns {boolean} True only when the permanent fatal latch was accepted.
     */
    faultEventLog(generation) {
        if (!Number.isSafeInteger(generation) || generation < 0 || generation !== this.#generation) {
            return false
        }
        this.#fatalReason = 'event-log-unavailable'
        this.#clearTimers()
        const needsContainment = (this.#desired && generation !== this.#faultingGeneration) || (['restarting', 'stopped', 'unavailable'].includes(this.#state.status) && this.#state.reason !== this.#fatalReason)
        if (needsContainment) {
            /** @returns {void} Contains the fatal latch outside a logger callback stack. */
            const containFailure = () => {
                if (this.#fatalReason === null || generation !== this.#generation) return
                if (this.#desired && generation !== this.#faultingGeneration) {
                    this.#handleFault(this.#fatalReason, generation, this.#state.restartCount ?? 0, false)
                } else if (['restarting', 'stopped', 'unavailable'].includes(this.#state.status) && this.#state.reason !== this.#fatalReason) {
                    this.#transition({ status: 'unavailable', reason: this.#fatalReason, restartCount: this.#state.restartCount ?? 0, terminatedGeneration: generation })
                    this.#startup.settle(this.#state)
                }
            }
            queueMicrotask(containFailure)
        }
        return true
    }

    /** @returns {string|null} Current reconciled service mode. */
    getServiceMode() {
        return this.#state.status === 'ready' && this.#fatalReason === null ? this.#state.mode : null
    }

    /** @returns {boolean} True only for reconciled native hardware readiness. */
    isHardwareReady() {
        return this.#fatalReason === null && this.#state.status === 'ready' && this.#state.hardwareReady === true
    }

    /** @returns {boolean} True only for a ready privileged service. */
    hasPrivilege() {
        return this.#fatalReason === null && this.#state.status === 'ready' && this.#privileged
    }

    /** @returns {Promise<object>} Strict current device-list response. */
    async list() {
        return this.#request('devices-list', {}, wireDeviceListResponseSchema)
    }

    /**
     * Requests one non-overlapping service discovery scan.
     * @param {object} request - Strict literal scan request.
     * @returns {Promise<object>} Safe action response.
     */
    async scan(request) {
        const parsedRequest = scanRequestSchema.safeParse(request)
        if (!parsedRequest.success) {
            return { ok: false, reason: 'invalid-request' }
        }
        return this.#request('devices-scan', parsedRequest.data, actionResponseSchema, false, SCAN_REQUEST_TIMEOUT_MS)
    }

    /**
     * Starts one coordinator-owned high-level operation through the service protocol.
     * @param {{operationId: string, request: object}} operation - Exact owned operation.
     * @returns {Promise<object>} Safe action response.
     */
    async startOperation(operation) {
        const parsedRequest = operationRequestSchema.safeParse(operation?.request)
        const parsedOperationId = operationIdSchema.safeParse(operation?.operationId)
        if (!parsedOperationId.success || !parsedRequest.success || parsedRequest.data.kind === 'scan') {
            return { ok: false, reason: 'invalid-request' }
        }
        if (!this.#publicationSequence.reserve({ operationId: parsedOperationId.data, kind: parsedRequest.data.kind, deviceId: parsedRequest.data.deviceId, deviceRevision: parsedRequest.data.deviceRevision, generation: this.#generation })) {
            return { ok: false, reason: 'service-saturated' }
        }
        const result = await this.#request('operation-start', { operationId: parsedOperationId.data, request: parsedRequest.data }, actionResponseSchema)
        if (result.ok !== true && result.ambiguous !== true) {
            this.#publicationSequence.release(parsedOperationId.data)
        }
        return result
    }

    /**
     * Registers one validated main-owned modern image through bounded ordered frames.
     * No path or unrestricted native file-read authority crosses this boundary.
     * @param {{fileToken: string, extension: string, bytes: Buffer}} registration - One-shot path-free firmware snapshot.
     * @returns {Promise<object>} Safe action response.
     */
    async registerFirmwareImage(registration) {
        return registerFirmwareImageFrames({ registration, request: this.#request.bind(this) })
    }

    /**
     * Requests one service-owned short-lived destructive confirmation.
     * @param {unknown} request - Exact destructive action and options without a token.
     * @returns {Promise<object>} Strict token response or bounded failure.
     */
    async issueConfirmation(request) {
        const parsedRequest = operationConfirmationRequestSchema.safeParse(request)
        if (!parsedRequest.success) {
            return { ok: false, reason: 'invalid-request' }
        }
        return this.#request('operation-confirmation-issue', parsedRequest.data, operationConfirmationResponseSchema)
    }

    /**
     * Requests cancellation only for an already coordinator-validated operation ID.
     * @param {unknown} request - Exact cancellation request.
     * @returns {Promise<object>} Safe action response.
     */
    async cancelOperation(request) {
        const parsedRequest = operationCancelRequestSchema.safeParse(request)
        if (!parsedRequest.success) {
            return { ok: false, reason: 'invalid-request' }
        }
        this.#publicationSequence.beginCancellation(parsedRequest.data.operationId)
        const result = await this.#request('operation-cancel', parsedRequest.data, wireCancellationResponseSchema)
        if (result.ok !== true && result.ambiguous !== true) {
            this.#publicationSequence.rejectCancellation(parsedRequest.data.operationId)
        }
        return result
    }

    /**
     * Acknowledges only the coordinator-owned first-install operator gate.
     * @param {unknown} request - Exact operation ID and awaiting stage.
     * @returns {Promise<object>} Correlated native acceptance or bounded failure.
     */
    async continueOperation(request) {
        const parsed = operationContinueRequestSchema.safeParse(request)
        return parsed.success ? this.#request('operation-continue', parsed.data, operationStartResponseSchema) : { ok: false, reason: 'invalid-request' }
    }

    /**
     * Subscribes to frozen service lifecycle snapshots.
     * @param {(state: object) => void} listener - Lifecycle callback.
     * @returns {() => void} Idempotent unsubscribe callback.
     */
    subscribeLifecycle(listener) {
        return subscribeContained(this.#lifecycleListeners, listener, 'Lifecycle')
    }

    /**
     * Subscribes to strict frozen device/operation event envelopes.
     * @param {(event: object) => void} listener - Service event callback.
     * @returns {() => void} Idempotent unsubscribe callback.
     */
    subscribeEvents(listener) {
        return subscribeContained(this.#eventListeners, listener, 'Service event')
    }

    /**
     * Launches one transport generation and begins the bounded handshake.
     * @param {number} restartCount - Completed restart attempts.
     * @returns {void} Completes after launch or contained fault scheduling.
     */
    #launch(restartCount) {
        if (!this.#desired) {
            return
        }
        if (this.#fatalReason !== null) {
            this.#transition({ status: 'unavailable', reason: this.#fatalReason, restartCount, terminatedGeneration: this.#generation })
            this.#startup.settle(this.#state)
            return
        }
        this.#generation += 1
        const generation = this.#generation
        this.#faultingGeneration = null
        this.#teardownPromise = null
        this.#expiredDiscoveryRequests.clear()
        this.#inbound.reset()
        this.#handshake = null
        this.#privileged = false
        this.#publicationSequence.reset()
        this.#discovery.reset(generation)
        this.#nativeDiagnostic = null
        this.#transition({ status: 'starting', restartCount })
        if (this.#fatalReason !== null) return
        let transport
        try {
            transport = this.#transportFactory({ command: this.#executable, args: DEVICE_SERVICE_ARGUMENTS })
            if (transport === null || typeof transport?.on !== 'function' || typeof transport?.write !== 'function' || typeof transport?.close !== 'function' || (transport?.isReady === false && typeof transport?.once !== 'function')) {
                throw new TypeError('invalid-service-transport')
            }
        } catch {
            this.#handleFault('service-start-failed', generation, restartCount)
            return
        }
        this.#transport = transport

        /**
         * Sends transport bytes only to the current generation decoder.
         * @param {Buffer} chunk - Candidate native stdout data.
         * @returns {void} Completes after bounded processing.
         */
        const handleData = (chunk) => this.#inbound.receive(chunk, generation, restartCount)
        /**
         * Maps an endpoint's narrow installation/permission diagnostics or a
         * generic native transport error without forwarding native details.
         * @param {object} [failure] - Optional sanitized endpoint failure.
         * @returns {void} Completes after contained fault handling.
         */
        const handleError = (failure) => {
            this.#rememberNativeDiagnostic(failure, generation)
            this.#handleTransportFault(['service-not-installed', 'insufficient-permission', 'service-identity-unverified'].includes(failure?.reason) ? failure.reason : 'service-exited', generation, restartCount)
        }
        /**
         * Maps native exit to generic service loss.
         * @param {object} [evidence] - Optional fixed child diagnostic evidence.
         * @returns {void} Completes after contained fault handling.
         */
        const handleExit = (evidence) => {
            this.#rememberNativeDiagnostic(evidence, generation)
            this.#handleTransportFault('service-exited', generation, restartCount)
        }
        /**
         * Remembers only one closed native breadcrumb for this generation.
         * @param {object} diagnostic - Candidate fixed diagnostic envelope.
         * @returns {void} Completes after bounded validation.
         */
        const handleDiagnostic = (diagnostic) => {
            if (!this.#rememberNativeDiagnostic({ diagnosticCode: diagnostic?.code }, generation) || this.#logger === null) return
            void this.#logger.write({ event: 'service-diagnostic', messageKey: 'activity.service', severity: 'info', nativeDiagnostic: diagnostic.code })
        }
        transport.on('data', handleData)
        transport.on('error', handleError)
        transport.on('exit', handleExit)
        transport.on('diagnostic', handleDiagnostic)
        this.#transition({ status: 'handshaking', restartCount })

        let handshakeSent = false
        /** @returns {void} Sends the initial frame exactly once after any transport readiness gate. */
        const sendHandshake = () => {
            if (handshakeSent || generation !== this.#generation || generation === this.#faultingGeneration || !this.#desired || transport !== this.#transport) return
            handshakeSent = true
            /** @returns {void} Fails only this ready generation when its first complete frame misses the absolute bound. */
            const handleHandshakeTimeout = () => this.#handleFault('service-handshake-timeout', generation, restartCount)
            this.#handshakeTimer = this.#timers.setTimeout(handleHandshakeTimeout, this.#handshakeTimeoutMs)
            // This timestamp brackets the real handshake timer, after transport identity is ready.
            if (this.#emitHandshakeDiagnostics) void recordHandshakeStart(this.#logger)
            try {
                const writeResult = transport.write(encodeServiceFrame({ type: 'handshake-request', protocolVersion: SERVICE_PROTOCOL_VERSION }, this.#maxFrameBytes))
                if (writeResult === false || writeResult?.ok === false) {
                    throw new Error('service-write-failed')
                }
            } catch {
                this.#handleFault('service-start-failed', generation, restartCount)
            }
        }
        if (transport.isReady === false) transport.once('ready', sendHandshake)
        else sendHandshake()
    }

    /**
     * Maps one decoded message without exposing arbitrary payloads.
     * @param {object} message - Decoded candidate service message.
     * @param {number} generation - Owning transport generation.
     * @returns {boolean|Promise<boolean>} True when the message and ordered observers accept it.
     */
    #handleMessage(message, generation) {
        if (this.#state.status === 'handshaking') {
            const parsedHandshake = handshakeSchema.safeParse(message)
            if (!parsedHandshake.success || parsedHandshake.data.platform !== this.#platform) {
                return false
            }
            this.#timers.clearTimeout(this.#handshakeTimer)
            this.#handshakeTimer = null
            this.#privileged = parsedHandshake.data.privileged
            this.#handshake = parsedHandshake.data
            this.#transition({ status: 'reconciling', generation, restartCount: this.#state.restartCount })
            void this.#reconcile(generation)
            return true
        }
        if (!['ready', 'reconciling'].includes(this.#state.status) || generation !== this.#generation) {
            return false
        }

        const parsedResponse = wireResponseSchema.safeParse(message)
        if (parsedResponse.success) {
            return this.#handleResponse(parsedResponse.data)
        }
        const parsedEvent = wireEventSchema.safeParse(message)
        if (parsedEvent.success && this.#state.status === 'ready') {
            if (parsedEvent.data.channel === 'operation') {
                if (!this.#publicationSequence.consume(parsedEvent.data)) {
                    return false
                }
                const inboundEpoch = this.#inbound.getEpoch()
                const transport = this.#transport
                /** @returns {boolean} True only while this exact observer delivery still owns the inbound generation. */
                const isCurrent = () => this.#isInboundCurrent(generation, inboundEpoch, transport)
                const published = publishContained(this.#eventListeners, deepFreeze(parsedEvent.data), isCurrent)
                /** @param {unknown} accepted - Observer result. @returns {boolean} Commits only a current accepted terminal. */
                const commit = (accepted) => accepted !== false && isCurrent() && (!TERMINAL_STATES.has(parsedEvent.data.event.state) || this.#publicationSequence.commit(parsedEvent.data))
                /** @returns {Promise<boolean>} Commits after the ordered asynchronous publication. */
                async function commitAfterPublication() {
                    return commit(await published)
                }
                return typeof published?.then === 'function' ? commitAfterPublication() : commit(published)
            }
            if (this.#handshake?.mode === 'no-device' && (parsedEvent.data.event.type !== 'list' || parsedEvent.data.event.devices.length !== 0)) {
                return false
            }
            const publicEvent = this.#applyDeviceEvent(parsedEvent.data.event)
            if (publicEvent !== null) {
                const inboundEpoch = this.#inbound.getEpoch()
                const transport = this.#transport
                /** @returns {boolean} True only while this exact device delivery remains current. */
                const isCurrent = () => this.#isInboundCurrent(generation, inboundEpoch, transport)
                const published = publishContained(this.#eventListeners, deepFreeze({ channel: 'device', event: publicEvent }), isCurrent)
                /** @param {unknown} accepted - Observer result. @returns {boolean} Accepts only the current device delivery. */
                const accept = (accepted) => accepted !== false && isCurrent()
                /** @returns {Promise<boolean>} Checks currency after asynchronous device publication. */
                async function acceptAfterPublication() {
                    return accept(await published)
                }
                return typeof published?.then === 'function' ? acceptAfterPublication() : accept(published)
            }
            return true
        }
        return false
    }
    /** @param {number} generation - Captured generation. @param {number} inboundEpoch - Captured inbound epoch. @param {object|null} transport - Captured transport. @returns {boolean} True only for the exact live inbound delivery. */
    #isInboundCurrent(generation, inboundEpoch, transport) {
        return this.#desired && this.#stopPromise === null && this.#fatalReason === null && generation === this.#generation && generation !== this.#faultingGeneration && inboundEpoch === this.#inbound.getEpoch() && transport !== null && transport === this.#transport
    }

    /**
     * Resolves one exact pending request after method-specific result validation.
     * @param {object} response - Strict wire response.
     * @returns {boolean} True when a matching pending request was resolved.
     */
    #handleResponse(response) {
        const pending = this.#pending.get(response.requestId)
        if (pending === undefined) {
            return this.#expiredDiscoveryRequests.consume(response)
        }
        if (!response.ok) {
            if (pending.method === 'operation-cancel') this.#publicationSequence.rejectCancellation(pending.operationId)
            this.#settleResponse(response.requestId, pending, { ok: false, reason: response.reason })
            return true
        }
        const parsedResult = pending.responseSchema.safeParse(response.result)
        if (!parsedResult.success) {
            if (!AMBIGUOUS_METHODS.has(pending.method)) {
                this.#settleResponse(response.requestId, pending, { ok: false, reason: 'invalid-service-response' })
            }
            return false
        }
        if (pending.method === 'operation-cancel') {
            if (parsedResult.data.ok === true) {
                if (!this.#publicationSequence.acceptsCancellationCutover(pending.operationId, parsedResult.data.cancellationCutover)) return false
            } else {
                this.#publicationSequence.rejectCancellation(pending.operationId)
            }
        }
        if (pending.method === 'devices-list' && parsedResult.data.ok === true) {
            const isCurrentRead = parsedResult.data.listRevision === this.#discovery.getListRevision() && JSON.stringify(parsedResult.data.devices) === JSON.stringify(this.#discovery.getDevices())
            const applied = isCurrentRead ? { epoch: this.#discovery.getEpoch(), listRevision: this.#discovery.getListRevision(), devices: this.#discovery.getDevices(), ...(parsedResult.data.diagnostics === undefined ? {} : { diagnostics: parsedResult.data.diagnostics }) } : this.#discovery.applyList(parsedResult.data.listRevision, parsedResult.data.devices, parsedResult.data.diagnostics)
            if (applied === null || (this.#handshake?.mode === 'no-device' && parsedResult.data.devices.length !== 0)) {
                this.#settleResponse(response.requestId, pending, { ok: false, reason: 'invalid-service-response' })
                return false
            }
            const mode = this.#handshake?.mode ?? 'no-device'
            this.#settleResponse(
                response.requestId,
                pending,
                deepFreeze({
                    ok: true,
                    status: 'ready',
                    mode,
                    privileged: this.#privileged,
                    hardwareReady: mode === 'native' && this.#handshake?.platformCapability.state === 'available',
                    hardwareVerified: this.#handshake?.hardwareVerified === true,
                    platformCapability: this.#handshake?.platformCapability ?? { state: 'transport-unavailable', reason: 'service-unavailable' },
                    epoch: applied.epoch,
                    listRevision: applied.listRevision,
                    devices: applied.devices,
                    ...(applied.diagnostics === undefined ? {} : { diagnostics: applied.diagnostics })
                })
            )
            return true
        }
        this.#settleResponse(response.requestId, pending, deepFreeze(parsedResult.data))
        return true
    }

    /**
     * Removes and resolves one exact correlated request after full validation.
     * @param {string} requestId - Exact current pending request identity.
     * @param {object} pending - Matching pending request record.
     * @param {object} result - Strict public response.
     * @returns {void} Completes after accounting, timer cleanup, and resolution.
     */
    #settleResponse(requestId, pending, result) {
        if (!this.#pending.delete(requestId)) return
        this.#pendingBytes -= pending.bytes
        this.#timers.clearTimeout(pending.timer)
        pending.resolve(result)
    }

    /**
     * Establishes the initial current-generation discovery baseline before ready.
     * @param {number} generation - Current launched generation.
     * @returns {Promise<void>} Resolves after readiness or contained failure.
     */
    async #reconcile(generation) {
        const context = { generation, inboundEpoch: this.#inbound.getEpoch(), transport: this.#transport, handshake: this.#handshake, discoveryEpoch: this.#discovery.getEpoch() }
        const result = await this.#request('devices-list', {}, wireDeviceListResponseSchema, true)
        if (!this.#isReconciliationCurrent(context)) return
        if (result.ok !== true) {
            this.#handleFault(result.reason === 'invalid-service-response' ? 'service-malformed-data' : result.reason, generation, this.#state.restartCount)
            return
        }
        const handshake = this.#handshake
        if (handshake === null) {
            this.#handleFault('service-malformed-data', generation, this.#state.restartCount)
            return
        }
        const state = {
            status: 'ready',
            mode: handshake.mode,
            privileged: this.#privileged,
            hardwareReady: handshake.mode === 'native' && handshake.platformCapability.state === 'available',
            hardwareVerified: handshake.hardwareVerified === true,
            platformCapability: handshake.platformCapability,
            generation,
            epoch: result.epoch,
            listRevision: result.listRevision,
            restartCount: this.#state.restartCount
        }
        if (!(await this.#persistCriticalLifecycle(state, context)) || !this.#isReconciliationCurrent(context)) return
        this.#transition(state, true)
        const readyState = this.#state
        if (!this.#isReadyCurrent(context, readyState)) return
        /** @returns {boolean} True only while this exact ready generation still owns initial-list publication. */
        const isCurrent = () => this.#isReadyCurrent(context, readyState)
        const published = publishContained(this.#eventListeners, deepFreeze({ channel: 'device', event: { type: 'list', epoch: result.epoch, listRevision: result.listRevision, devices: result.devices, ...(result.diagnostics === undefined ? {} : { diagnostics: result.diagnostics }) } }), isCurrent)
        if ((await published) === false || !this.#isReadyCurrent(context, readyState)) {
            if (this.#isReadyCurrent(context, readyState)) this.#handleFault('service-malformed-data', generation, this.#state.restartCount)
            return
        }
        if (!this.#isReadyCurrent(context, readyState)) return
        this.#startup.settle(this.#state)
    }

    /** @param {object} context - Captured reconciliation identity. @returns {boolean} True only for the exact live reconciling generation. */
    #isReconciliationCurrent(context) {
        return this.#desired && this.#stopPromise === null && this.#fatalReason === null && this.#state.status === 'reconciling' && this.#state.generation === context.generation && context.generation === this.#generation && context.generation !== this.#faultingGeneration && context.inboundEpoch === this.#inbound.getEpoch() && context.transport !== null && context.transport === this.#transport && context.handshake !== null && context.handshake === this.#handshake && context.discoveryEpoch === this.#discovery.getEpoch()
    }

    /** @param {object} context - Captured reconciliation identity. @param {object} state - Exact published ready state. @returns {boolean} True only while initial ready publication remains current. */
    #isReadyCurrent(context, state) {
        return this.#desired && this.#stopPromise === null && this.#fatalReason === null && this.#state === state && state.status === 'ready' && state.generation === context.generation && context.generation === this.#generation && context.generation !== this.#faultingGeneration && context.inboundEpoch === this.#inbound.getEpoch() && context.transport !== null && context.transport === this.#transport && context.handshake === this.#handshake && context.discoveryEpoch === this.#discovery.getEpoch()
    }

    /**
     * Applies one wire discovery event through epoch and tombstone ordering.
     * @param {object} event - Strict current-generation service event.
     * @returns {object|null} Renderer-safe versioned event or null when stale.
     */
    #applyDeviceEvent(event) {
        if (this.#handshake?.mode === 'no-device') {
            return event.type === 'list' && event.devices.length === 0 ? this.#discovery.applyList(event.listRevision, event.devices, event.diagnostics) : null
        }
        if (event.type === 'list') {
            return this.#discovery.applyList(event.listRevision, event.devices, event.diagnostics)
        }
        if (event.type === 'snapshot') {
            return this.#discovery.applySnapshot(event.listRevision, event.device)
        }
        return this.#discovery.applyRemoval(event.listRevision, event.deviceId, event.deviceRevision)
    }

    /**
     * Sends one narrow request and validates its correlated public result.
     * @param {string} method - Fixed internal service method.
     * @param {object} payload - Already validated main-owned payload.
     * @param {import('zod').ZodType} responseSchema - Exact public result schema.
     * @param {boolean} allowReconciling - Allows only the initial list baseline.
     * @param {number} timeoutMs - Exact bounded correlation timeout.
     * @returns {Promise<object>} Safe response or stable unavailable result.
     */
    async #request(method, payload, responseSchema, allowReconciling = false, timeoutMs = this.#requestTimeoutMs) {
        if (this.#fatalReason !== null) return { ok: false, reason: this.#fatalReason }
        if ((this.#state.status !== 'ready' && !(allowReconciling && this.#state.status === 'reconciling')) || this.#transport === null) {
            return { ok: false, reason: 'service-unavailable' }
        }
        this.#requestId += 1
        const requestId = `request:${this.#requestId}`
        const generation = this.#generation
        const restartCount = this.#state.restartCount
        let frame
        try {
            frame = encodeServiceFrame({ type: 'request', protocolVersion: SERVICE_PROTOCOL_VERSION, requestId, method, payload }, this.#maxFrameBytes)
        } catch {
            return { ok: false, reason: 'invalid-request' }
        }
        if (this.#pending.size >= this.#maxPendingCount || this.#pendingBytes + frame.length > this.#maxPendingBytes) {
            return { ok: false, reason: 'service-saturated' }
        }

        // Correlation must be installed before write, including synchronous transports.
        const completion = Promise.withResolvers()
        const resolveRequest = completion.resolve
        /**
         * Resolves a request timeout without exposing payload or method details.
         * @returns {void} Completes after safe timeout response.
         */
        const handleTimeout = () => {
            const pending = this.#pending.get(requestId)
            if (pending !== undefined && this.#pending.delete(requestId)) {
                this.#pendingBytes -= pending.bytes
                const isScanRefresh = method === 'devices-scan'
                const ambiguous = !isScanRefresh && AMBIGUOUS_METHODS.has(method)
                this.#expiredDiscoveryRequests.remember(requestId, method)
                resolveRequest({ ok: false, reason: ambiguous ? 'operation-outcome-unknown' : 'service-request-timeout', ...(ambiguous ? { ambiguous: true } : {}) })
                if (ambiguous) {
                    this.#handleFault('service-request-timeout', generation, restartCount)
                }
            }
        }
        const timer = this.#timers.setTimeout(handleTimeout, timeoutMs)
        this.#pending.set(requestId, { bytes: frame.length, method, operationId: payload.operationId, resolve: resolveRequest, responseSchema, timer })
        this.#pendingBytes += frame.length
        try {
            const result = this.#transport.write(frame)
            if (result === false || result?.ok === false) {
                if (result?.reason === 'service-saturated') {
                    const pending = this.#pending.get(requestId)
                    this.#pending.delete(requestId)
                    this.#pendingBytes -= pending?.bytes ?? 0
                    this.#timers.clearTimeout(timer)
                    resolveRequest({ ok: false, reason: 'service-saturated' })
                    return completion.promise
                }
                throw new Error('service-write-failed')
            }
        } catch {
            this.#handleTransportFault('service-write-failed', generation, restartCount)
        }
        return completion.promise
    }

    /**
     * Suppresses restart during an intentional acknowledged shutdown while
     * still settling a response lost to an earlier-than-acknowledgement exit.
     * @param {string} reason - Stable generic transport failure.
     * @param {number} generation - Exact transport generation.
     * @param {number} restartCount - Completed restart attempts.
     * @returns {void} Completes after shutdown containment or ordinary faulting.
     */
    #handleTransportFault(reason, generation, restartCount) {
        if (generation === this.#shutdownGeneration) {
            this.#resolvePending('service-unavailable')
            return
        }
        this.#handleFault(reason, generation, restartCount)
    }

    /**
     * Retains one allowlisted breadcrumb only for the active service generation.
     * @param {object} evidence - Candidate transport diagnostic evidence.
     * @param {number} generation - Exact transport generation.
     * @returns {boolean} True only when the breadcrumb belongs to the active generation.
     */
    #rememberNativeDiagnostic(evidence, generation) {
        if (generation === this.#generation && generation !== this.#faultingGeneration && isNativeDiagnosticCode(evidence?.diagnosticCode)) {
            this.#nativeDiagnostic = evidence.diagnosticCode
            return true
        }
        return false
    }

    /**
     * Contains one current-generation failure and applies bounded restart policy.
     * @param {string} reason - Stable generic failure code.
     * @param {number} generation - Failing transport generation.
     * @param {number} restartCount - Completed restart attempts.
     * @param {boolean} [allowRestart=true] - Whether confirmed teardown may restart.
     * @returns {void} Completes after restart scheduling or terminal transition.
     */
    #handleFault(reason, generation, restartCount, allowRestart = true) {
        if (!this.#desired || generation !== this.#generation || generation === this.#faultingGeneration) {
            return
        }
        this.#faultingGeneration = generation
        this.#clearTimers()
        this.#inbound.reset()
        const transport = this.#detachTransport()
        this.#resolveFaultPending()
        this.#expiredDiscoveryRequests.clear()
        this.#handshake = null
        this.#discovery.reset(generation + 1)
        this.#privileged = false
        const nativeDiagnostic = this.#nativeDiagnostic
        this.#transition({ status: 'recovering', reason, restartCount, generation, ...(nativeDiagnostic === null ? {} : { nativeDiagnostic }) })
        this.#teardownPromise = this.#completeFault(reason, generation, restartCount, transport, allowRestart, nativeDiagnostic)
    }

    /**
     * Waits for generation teardown before publishing restart or terminal loss.
     * @param {string} reason - Stable generic failure code.
     * @param {number} generation - Exact failed launched generation.
     * @param {number} restartCount - Completed restart attempts.
     * @param {object|null} transport - Detached failed generation transport.
     * @param {boolean} allowRestart - Whether a confirmed teardown may restart.
     * @param {string|null} nativeDiagnostic - Last closed breadcrumb for the failed generation.
     * @returns {Promise<boolean>} True only after confirmed teardown and scheduling.
     */
    async #completeFault(reason, generation, restartCount, transport, allowRestart, nativeDiagnostic) {
        const teardownConfirmed = await this.#closeTransport(transport)
        if (!this.#desired || generation !== this.#generation || generation !== this.#faultingGeneration) {
            return teardownConfirmed
        }
        if (!teardownConfirmed) {
            this.#transition({ status: 'teardown-unconfirmed', reason: 'service-teardown-unconfirmed', restartCount, generation })
            this.#startup.settle(this.#state)
            return false
        }
        if (this.#fatalReason === null && allowRestart && restartCount < this.#maxRestarts) {
            const nextRestartCount = restartCount + 1
            this.#transition({ status: 'restarting', reason, restartCount: nextRestartCount, terminatedGeneration: generation, ...(nativeDiagnostic === null ? {} : { nativeDiagnostic }) })
            const delay = this.#restartBackoffMs[Math.min(restartCount, this.#restartBackoffMs.length - 1)] ?? 0

            /**
             * Launches the next bounded restart attempt.
             * @returns {void} Completes after invoking launch.
             */
            const restart = () => {
                this.#restartTimer = null
                this.#launch(nextRestartCount)
            }
            this.#restartTimer = this.#timers.setTimeout(restart, delay)
            return true
        }
        this.#transition({ status: 'unavailable', reason: this.#fatalReason ?? reason, restartCount, terminatedGeneration: generation, ...(nativeDiagnostic === null ? {} : { nativeDiagnostic }) })
        this.#startup.settle(this.#state)
        return true
    }

    /**
     * Clears owned handshake and restart timers.
     * @returns {void} Completes after idempotent timer cleanup.
     */
    #clearTimers() {
        if (this.#handshakeTimer !== null) {
            this.#timers.clearTimeout(this.#handshakeTimer)
            this.#handshakeTimer = null
        }
        if (this.#restartTimer !== null) {
            this.#timers.clearTimeout(this.#restartTimer)
            this.#restartTimer = null
        }
    }

    /**
     * Closes the current transport while containing teardown failures.
     * @returns {void} Completes after detaching the current transport reference.
     */
    #detachTransport() {
        const transport = this.#transport
        this.#transport = null
        return transport
    }

    /**
     * Awaits one detached transport close while containing teardown failures.
     * @param {object|null} transport - Detached current-generation transport.
     * @returns {Promise<boolean>} True only when closure confirms no live child.
     */
    async #closeTransport(transport) {
        if (transport === null) return true
        try {
            const result = await transport.close()
            return result?.confirmed === true
        } catch {
            return false
        }
    }

    /**
     * Resolves requests at a generation fault without collapsing mutating work
     * into an ordinary unavailable response before teardown reconciliation.
     * @returns {void} Completes after clearing all exact pending correlations.
     */
    #resolveFaultPending() {
        for (const pending of this.#pending.values()) {
            this.#timers.clearTimeout(pending.timer)
            pending.resolve(AMBIGUOUS_METHODS.has(pending.method) ? { ok: false, reason: 'operation-outcome-unknown', ambiguous: true } : { ok: false, reason: 'service-unavailable' })
        }
        this.#pending.clear()
        this.#pendingBytes = 0
    }

    /**
     * Resolves all correlated requests with one stable safe failure.
     * @param {string} reason - Bounded failure reason.
     * @returns {void} Completes after clearing all pending calls.
     */
    #resolvePending(reason) {
        for (const pending of this.#pending.values()) {
            this.#timers.clearTimeout(pending.timer)
            pending.resolve({ ok: false, reason })
        }
        this.#pending.clear()
        this.#pendingBytes = 0
    }

    /**
     * Publishes and optionally logs one frozen lifecycle transition.
     * @param {object} state - Safe lifecycle state.
     * @param {boolean} [alreadyLogged=false] - Whether a critical barrier persisted this state.
     * @returns {void} Completes after contained observer notification.
     */
    #transition(state, alreadyLogged = false) {
        const nextState = deepFreeze(state)
        if (isDeepStrictEqual(this.#state, nextState)) return
        this.#state = nextState
        const generation = this.#generation
        const inboundEpoch = this.#inbound.getEpoch()
        publishContained(this.#lifecycleListeners, this.#state, () => this.#state === nextState && this.#generation === generation && this.#inbound.getEpoch() === inboundEpoch)
        if (this.#logger !== null && !alreadyLogged) {
            void this.#logger.write({ event: 'service-lifecycle', messageKey: 'activity.service', severity: ['teardown-unconfirmed', 'unavailable'].includes(state.status) ? 'error' : 'info', status: state.status, reason: state.reason, ...(isNativeDiagnosticCode(state.nativeDiagnostic) ? { nativeDiagnostic: state.nativeDiagnostic } : {}) })
        }
    }

    /**
     * Persists ready before any state getter, lifecycle listener, or startup waiter can observe it.
     * @param {object} state - Candidate ready state.
     * @param {object} context - Exact captured reconciliation identity.
     * @returns {Promise<boolean>} True only after bounded durable persistence.
     */
    async #persistCriticalLifecycle(state, context) {
        if (!this.#isReconciliationCurrent(context)) return false
        if (this.#logger === null) return true
        let persisted = false
        try {
            const write = typeof this.#logger.writeCritical === 'function' ? this.#logger.writeCritical.bind(this.#logger) : this.#logger.write.bind(this.#logger)
            persisted = (await write({ event: 'service-lifecycle', messageKey: 'activity.service', severity: 'info', status: state.status })) === true
        } catch {
            persisted = false
        }
        if (!this.#isReconciliationCurrent(context)) return false
        if (!persisted) this.faultEventLog(context.generation)
        return persisted && this.#isReconciliationCurrent(context)
    }
}
