// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { manufacturingRequestSchema, manufacturingRestoreRequestSchema, manufacturingResponseSchema } from '../shared/manufacturing-schemas.mjs'
import { actionResponseSchema } from '../shared/schemas.mjs'

/** Closed manufacturing methods on the existing authenticated and supervised native transport. */
export class ManufacturingWireClient {
    #request
    /** @param {Function} request - Correlated native request boundary. */
    constructor(request) {
        this.#request = request
    }
    /** @returns {Promise<object>} Prepares the single local backup store without device access or renderer-selected paths. */
    async prepareFolder() {
        return this.#request('manufacturing-prepare-folder', {}, actionResponseSchema)
    }
    /** @param {object} request - Current device selection. @returns {Promise<object>} Verified metadata only. */
    async list(request) {
        return this.#invoke('list', request, manufacturingRequestSchema)
    }
    /** @param {object} request - Current device selection. @returns {Promise<object>} Inventory after verified persistence. */
    async backup(request) {
        return this.#invoke('backup', request, manufacturingRequestSchema)
    }
    /** @param {object} request - Explicit original-record association. @returns {Promise<object>} Readback-verified completion. */
    async restore(request) {
        return this.#invoke('restore', request, manufacturingRestoreRequestSchema)
    }
    /** @param {string} method - Closed method suffix. @param {unknown} request - Candidate request. @param {object} schema - Exact validator. @returns {Promise<object>} Bounded safe response. */
    async #invoke(method, request, schema) {
        const parsed = schema.safeParse(request)
        return parsed.success ? this.#request(`manufacturing-${method}`, parsed.data, manufacturingResponseSchema) : { ok: false, reason: 'invalid-request' }
    }
}
