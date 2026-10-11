// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { recoveryContinueRequestSchema, recoveryListResponseSchema, recoveryStartRequestSchema, recoveryStatusResponseSchema } from '../shared/recovery-schemas.mjs'

/** Exposes only four closed recovery messages on the already supervised transport. */
export class RecoveryWireClient {
    #request

    /** @param {Function} request - Existing correlated service request boundary. */
    constructor(request) {
        this.#request = request
    }

    /** @returns {Promise<object>} Current saved profiles, observed loaders, and progress. */
    async list() {
        return this.#request('recovery-list', {}, recoveryListResponseSchema)
    }

    /** @returns {Promise<object>} Current session-owned recovery progress. */
    async status() {
        return this.#request('recovery-status', {}, recoveryStatusResponseSchema)
    }

    /** @param {unknown} request - Explicit profile/physical-target association. @returns {Promise<object>} Accepted progress or a bounded failure. */
    async start(request) {
        const parsed = recoveryStartRequestSchema.safeParse(request)
        return parsed.success ? this.#request('recovery-start', parsed.data, recoveryStatusResponseSchema) : { ok: false, reason: 'invalid-request' }
    }

    /** @param {unknown} request - Exact attempt's newly armed prompt. @returns {Promise<object>} Current progress or a bounded failure. */
    async continue(request) {
        const parsed = recoveryContinueRequestSchema.safeParse(request)
        return parsed.success ? this.#request('recovery-continue', parsed.data, recoveryStatusResponseSchema) : { ok: false, reason: 'invalid-request' }
    }
}
