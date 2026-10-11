// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { OperationKind } from '../shared/contracts.mjs'

const DIAGNOSTICS = new Set([OperationKind.SELF_TEST, OperationKind.LED_TEST, OperationKind.WRITE_READ_TEST])

/** Tracks diagnostic admission separately from native execution and results. */
export class DiagnosticSubmission {
    #store
    #adapter
    #onChange
    #pending = null
    #request = null
    #destroyed = false

    /**
     * @param {object} store - Read-only renderer snapshot access.
     * @param {object} adapter - Validated intent boundary returning awaitable admission results.
     * @param {Function} onChange - Reconciles presentation without moving focus or scroll.
     */
    constructor(store, adapter, onChange) {
        this.#store = store
        this.#adapter = adapter
        this.#onChange = onChange
    }

    /** @returns {object|null} Current admission feedback, never a fabricated operation. */
    get request() {
        return this.#request
    }

    /** @param {object} intent - Candidate operation intent. @returns {boolean} Whether this controller owns its admission feedback. */
    handles(intent) {
        return DIAGNOSTICS.has(intent.kind)
    }

    /**
     * Submits one diagnostic and awaits admission while native events may advance it.
     * @param {object} intent - Exact selected-device operation intent.
     * @returns {Promise<void>} Resolves after admission feedback or a native event takes over.
     */
    async start(intent) {
        if (!this.handles(intent) || this.#destroyed || this.#pending !== null || this.#store.getState().activeOperation !== null) return
        const request = { ...intent, status: 'submitting' }
        const pending = { request, previousOperationId: this.#store.getState().lastOperation?.id }
        // Reserve synchronously so rapid clicks cannot submit a second request.
        this.#pending = pending
        this.#request = request
        this.#onChange()
        let result
        try {
            result = await this.#adapter.invoke(intent)
            if (result === false) result = { ok: false, reason: 'operation-intent-unavailable' }
        } catch {
            result = { ok: false, reason: 'service-failure' }
        }
        if (this.#destroyed || this.#pending !== pending) return
        if (result?.ok === true) {
            this.#request = { ...request, status: 'accepted', operationId: result.operationId }
        } else {
            this.#pending = null
            this.#request = { ...request, status: 'failed', reason: result?.reason ?? 'service-failure' }
        }
        this.#onChange()
    }

    /**
     * Lets correlated native events take over, including events before acknowledgement.
     * Snapshot revision changes do not invalidate historical diagnostic evidence.
     * @param {object} state - Current immutable renderer state.
     * @returns {void} Retires admission feedback when native execution is observed.
     */
    observe(state) {
        const pending = this.#pending
        if (pending === null) return
        for (const operation of [state.activeOperation, state.lastOperation]) {
            if (operation === null || operation === undefined) continue
            if (operation.id === pending.previousOperationId || operation.deviceId !== pending.request.deviceId || operation.deviceRevision !== pending.request.deviceRevision || operation.kind !== pending.request.kind) continue
            if (this.#request.operationId !== undefined && operation.id !== this.#request.operationId) continue
            this.#pending = null
            this.#request = null
            return
        }
    }

    /** @returns {void} Prevents late bridge completions from rendering after teardown. */
    destroy() {
        this.#destroyed = true
        this.#pending = null
        this.#request = null
    }
}
