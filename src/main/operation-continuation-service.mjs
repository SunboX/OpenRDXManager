// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { operationContinueRequestSchema, operationStartResponseSchema } from '../shared/schemas.mjs'

/** Keeps operator continuation bound to the coordinator's current firmware owner. */
export class OperationContinuationService {
    #getActiveOperation
    #dispatch
    #gate = null

    /**
     * @param {{getActiveOperation: () => object|null, dispatch: (request: object) => Promise<object>}} options - Main-owned state and native transport.
     */
    constructor(options) {
        this.#getActiveOperation = options.getActiveOperation
        this.#dispatch = options.dispatch
    }

    /**
     * Consumes one explicit operator acknowledgement without releasing the operation lock.
     * A missing acknowledgement remains consumed because native may already have resumed.
     * @param {unknown} request - Exact operation identifier and one of two awaiting stages.
     * @returns {Promise<object>} Correlated acceptance or a bounded failure.
     */
    async continue(request) {
        const parsed = operationContinueRequestSchema.safeParse(request)
        if (!parsed.success) return { ok: false, reason: 'invalid-request' }
        const active = this.#getActiveOperation()
        const { operationId, stage } = parsed.data
        if (active?.operationId !== operationId) return { ok: false, reason: 'operation-not-found' }
        if (active.kind !== 'firmware-update' || active.stage !== stage) return { ok: false, reason: 'operation-not-continuable' }
        const key = `${active.generation}:${operationId}:${stage}`
        if (this.#gate?.key === key) return { ok: false, reason: 'operation-not-continuable' }
        const gate = { key }
        this.#gate = gate
        let result
        try {
            result = await this.#dispatch(parsed.data)
        } catch {
            return { ok: false, reason: 'operation-outcome-unknown' }
        }
        if (result?.ambiguous === true) return { ok: false, reason: 'operation-outcome-unknown' }
        const response = operationStartResponseSchema.safeParse(result)
        if (!response.success || (response.data.ok && response.data.operationId !== operationId)) return { ok: false, reason: 'operation-outcome-unknown' }
        if (!response.data.ok && this.#gate === gate) this.#gate = null
        return response.data
    }
}
