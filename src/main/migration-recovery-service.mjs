// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { recoveryContinueRequestSchema, recoveryListResponseSchema, recoveryStartRequestSchema, recoveryStatusResponseSchema } from '../shared/recovery-schemas.mjs'
import { isDeepStrictEqual } from 'node:util'

/** Keeps recovery admission, ambiguous outcomes and renderer reloads under one owner. */
export class MigrationRecoveryService {
    #wire
    #getActiveOperation
    #getGeneration
    #isReady
    #getAdmissionFailure
    #generation = -1
    #status = { state: 'idle', revision: 0 }
    #pending = false
    #uncertain = false
    #fence = 0
    #acknowledged = new Set()

    /** @param {{wire: object, getActiveOperation: Function, getGeneration: Function, isReady: Function, getAdmissionFailure?: Function}} options - Main-owned authority, shutdown and wire boundaries. */
    constructor(options) {
        this.#wire = options.wire
        this.#getActiveOperation = options.getActiveOperation
        this.#getGeneration = options.getGeneration
        this.#isReady = options.isReady
        this.#getAdmissionFailure = options.getAdmissionFailure ?? (() => null)
    }

    /** @returns {boolean} True while accepted or uncertain work can own hardware. */
    isBusy() {
        return this.#pending || this.#uncertain || this.#status.state === 'running'
    }

    /** @returns {object|null} Safe global-owner summary for shutdown and contention. */
    getActiveOperation() {
        return this.isBusy() ? Object.freeze({ operationId: this.#status.attemptId ?? 'recovery:pending', kind: 'firmware-recovery', stage: this.#status.stage ?? 'recovery-preparing', irreversible: true }) : null
    }

    /** @returns {Promise<object>} Validated read-only inventory with current progress. */
    async list() {
        return this.#read('list', recoveryListResponseSchema)
    }

    /** @returns {Promise<object>} Current progress; this never starts or retries recovery. */
    async status() {
        return this.#read('status', recoveryStatusResponseSchema)
    }

    /** @param {unknown} request - Explicit user selection. @returns {Promise<object>} Accepted progress or a fixed failure. */
    async start(request) {
        const parsed = recoveryStartRequestSchema.safeParse(request)
        if (!parsed.success) return { ok: false, reason: 'invalid-request' }
        if (this.#getAdmissionFailure() !== null) return { ok: false, reason: 'application-shutting-down' }
        if (!this.#isReady()) return { ok: false, reason: 'privileged-service-unavailable' }
        if (this.isBusy() || this.#getActiveOperation() !== null) return { ok: false, reason: 'operation-in-progress' }
        // Reserve synchronously before any promise can admit a competing operation.
        this.#pending = true
        this.#fence += 1
        const generation = this.#getGeneration()
        try {
            return this.#acceptMutation(await this.#wire.start(parsed.data), generation)
        } catch {
            return this.#unknown()
        } finally {
            this.#pending = false
        }
    }

    /** @param {unknown} request - Current attempt's exact gate. @returns {Promise<object>} Single-use acknowledgment result. */
    async continue(request) {
        const parsed = recoveryContinueRequestSchema.safeParse(request)
        if (!parsed.success) return { ok: false, reason: 'invalid-request' }
        const status = this.#status
        const generation = this.#getGeneration()
        const key = `${generation}:${parsed.data.attemptId}:${parsed.data.stage}`
        if (this.#generation !== generation || status.state !== 'running' || status.attemptId !== parsed.data.attemptId || status.stage !== parsed.data.stage || !status.awaitingAcknowledgment || this.#acknowledged.has(key)) return { ok: false, reason: 'recovery-not-continuable' }
        this.#acknowledged.add(key)
        this.#fence += 1
        try {
            const result = this.#acceptMutation(await this.#wire.continue(parsed.data), generation)
            if (!result.ok && result.reason !== 'recovery-outcome-unknown') this.#acknowledged.delete(key)
            return result
        } catch {
            return this.#unknown()
        }
    }

    /** @returns {object} Preserves the hardware reservation after a lost mutation reply. */
    #unknown() {
        this.#uncertain = true
        return { ok: false, reason: 'recovery-outcome-unknown' }
    }

    /** @param {object} result - Candidate native result. @param {number} generation - Dispatch generation. @returns {object} Safe mutation result. */
    #acceptMutation(result, generation) {
        if (generation !== this.#getGeneration() || result?.ambiguous === true) return this.#unknown()
        const parsed = recoveryStatusResponseSchema.safeParse(result)
        if (!parsed.success) return this.#unknown()
        if (parsed.data.ok) {
            if (parsed.data.status.state === 'idle') return this.#unknown()
            this.#acceptStatus(parsed.data.status, generation)
            return { ok: true, status: this.#status }
        }
        return parsed.data
    }

    /** @param {'list'|'status'} method - Read-only method. @param {object} schema - Closed response validator. @returns {Promise<object>} Fresh result or fixed failure. */
    async #read(method, schema) {
        const generation = this.#getGeneration()
        const fence = this.#fence
        try {
            const parsed = schema.safeParse(await this.#wire[method]())
            if (!parsed.success) return { ok: false, reason: 'invalid-service-response' }
            if (generation !== this.#getGeneration() || fence !== this.#fence) return { ok: false, reason: 'recovery-state-changed' }
            if (!parsed.data.ok) return parsed.data
            this.#acceptStatus(parsed.data.status, generation)
            return { ...parsed.data, status: this.#status }
        } catch {
            return { ok: false, reason: 'service-unavailable' }
        }
    }

    /** @param {object} status - Validated native snapshot. @param {number} generation - Current supervised owner. @returns {void} Accepts only monotonic current-owner progress. */
    #acceptStatus(status, generation) {
        if (this.#generation === generation && status.revision < this.#status.revision) return
        if (this.#generation === generation && status.revision === this.#status.revision && !isDeepStrictEqual(status, this.#status)) {
            this.#uncertain = true
            throw new Error('recovery-state-conflict')
        }
        if (this.#generation !== generation || status.attemptId !== this.#status.attemptId) this.#acknowledged.clear()
        this.#generation = generation
        this.#status = Object.freeze({ ...status })
        this.#uncertain = false
    }
}
