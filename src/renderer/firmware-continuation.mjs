// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { operationContinueRequestSchema } from '../shared/schemas.mjs'

/** Retains one operator click while its exact power-cycle gate awaits native acknowledgement. */
export class FirmwareContinuation {
    #store
    #adapter
    #render
    #gate = null

    /** @param {object} store - Renderer state. @param {object} adapter - Narrow intent delegate. @param {() => void} render - Local presentation refresh. */
    constructor(store, adapter, render) {
        this.#store = store
        this.#adapter = adapter
        this.#render = render
    }

    /**
     * Resets local acknowledgement state only when the native operation or phase changes.
     * @param {object|null} operation - Current renderer-safe owner.
     * @returns {{state: string, available: boolean}} Button presentation without hardware authority.
     */
    getState(operation) {
        const request = { operationId: operation?.operationId ?? operation?.id, stage: operation?.stage }
        const parsed = operationContinueRequestSchema.safeParse(request)
        if (operation?.kind !== 'firmware-update' || !parsed.success) {
            this.#gate = null
            return { state: 'unavailable', available: false }
        }
        const key = `${request.operationId}:${request.stage}`
        if (this.#gate?.key !== key) this.#gate = { key, request: parsed.data, state: 'idle' }
        return { state: this.#gate.state, available: this.#adapter.isAvailable('operation-continue') }
    }

    /** @returns {Promise<void>} Submits the exact current gate once and preserves uncertainty until native advances. */
    async submit() {
        const view = this.getState(this.#store.getState().activeOperation)
        if (!view.available || !['idle', 'failed'].includes(view.state)) return
        const gate = this.#gate
        gate.state = 'pending'
        this.#render()
        const result = await this.#adapter.invoke({ type: 'operation-continue', ...gate.request })
        if (this.#gate !== gate) return
        gate.state = result?.ok === true ? 'accepted' : ['operation-outcome-unknown', 'operation-not-continuable'].includes(result?.reason) ? 'uncertain' : 'failed'
        this.#render()
    }
}
