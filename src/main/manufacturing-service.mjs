// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { manufacturingRequestSchema, manufacturingRestoreRequestSchema, manufacturingResponseSchema } from '../shared/manufacturing-schemas.mjs'

/** Serializes manufacturing actions with ordinary operations and retains uncertain ownership. */
export class ManufacturingService {
    #options
    #pending = false
    #uncertain = false
    #kind = 'manufacturing-backup'

    /** @param {{wire: object, isReady: Function, getGeneration: Function, getActiveOperation: Function, getAdmissionFailure: Function}} options - Main-owned transport and admission boundaries. */
    constructor(options) {
        this.#options = options
    }

    /** @returns {boolean} True until native hardware ownership is known to have ended. */
    isBusy() {
        return this.#pending || this.#uncertain
    }

    /** @returns {object|null} Global coordinator and shutdown reservation. */
    getActiveOperation() {
        return this.isBusy() ? { operationId: 'manufacturing:pending', kind: this.#kind, stage: this.#kind, irreversible: this.#kind === 'manufacturing-restore' } : null
    }

    /** @param {unknown} request - Exact current device. @returns {Promise<object>} Validated inventory or safe failure. */
    async list(request) {
        return this.#run('list', request, manufacturingRequestSchema)
    }

    /** @param {unknown} request - Exact current device. @returns {Promise<object>} Inventory after durable capture. */
    async backup(request) {
        return this.#run('backup', request, manufacturingRequestSchema)
    }

    /** @param {unknown} request - Explicit saved record and original serial. @returns {Promise<object>} Verified completion or safe failure. */
    async restore(request) {
        return this.#run('restore', request, manufacturingRestoreRequestSchema)
    }

    /**
     * Reserves before awaiting; only a later ordered list reply can reconcile a lost mutation.
     * @param {'list'|'backup'|'restore'} method - Closed operation name.
     * @param {unknown} request - Candidate renderer selection.
     * @param {object} schema - Strict request validator.
     * @returns {Promise<object>} Path-free native result.
     */
    async #run(method, request, schema) {
        const parsed = schema.safeParse(request)
        if (!parsed.success) return { ok: false, reason: 'invalid-request' }
        const options = this.#options
        if (options.getAdmissionFailure() !== null) return { ok: false, reason: 'application-shutting-down' }
        if (!options.isReady()) return { ok: false, reason: 'privileged-service-unavailable' }
        const other = options.getActiveOperation()
        if (this.#pending || (this.#uncertain && method !== 'list') || (other !== null && other.operationId !== 'manufacturing:pending')) return { ok: false, reason: 'operation-in-progress' }
        this.#pending = true
        if (method !== 'list') this.#kind = `manufacturing-${method}`
        const generation = options.getGeneration()
        try {
            const result = await options.wire[method](method === 'list' && this.#uncertain ? { ...parsed.data, reconcile: true } : parsed.data)
            const response = manufacturingResponseSchema.safeParse(result)
            if (generation !== options.getGeneration() || !response.success || result?.ambiguous === true || (!result.ok && ['manufacturing-outcome-unknown', 'service-unavailable', 'service-request-timeout', 'operation-outcome-unknown', 'backend-worker-unavailable'].includes(result.reason))) {
                return this.#unknown(method)
            }
            if (response.data.ok) this.#uncertain = false
            return response.data
        } catch {
            return this.#unknown(method)
        } finally {
            this.#pending = false
        }
    }

    /** @param {string} method - Attempted action. @returns {object} Fixed failure retaining any possible mutation owner. */
    #unknown(method) {
        if (method !== 'list') this.#uncertain = true
        return { ok: false, reason: this.#uncertain ? 'manufacturing-outcome-unknown' : 'service-unavailable' }
    }
}
