// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { operationEventSchema } from '../../shared/schemas.mjs'

/** Retains bounded public operation state independently of client connections. */
export class McpOperationStore {
    #operations = new Map()
    #listeners = new Set()

    /** @param {unknown} event - Coordinator-accepted candidate event. @returns {boolean} Whether the strict public event was retained. */
    publish(event) {
        const parsed = operationEventSchema.safeParse(event)
        if (!parsed.success) return false
        const value = parsed.data
        this.#operations.delete(value.operationId)
        this.#operations.set(value.operationId, value)
        while (this.#operations.size > 128) this.#operations.delete(this.#operations.keys().next().value)
        for (const listener of this.#listeners) {
            try {
                listener(structuredClone(value))
            } catch {
                // An observer cannot interrupt the coordinator's accepted publication.
            }
        }
        return true
    }

    /** @returns {{ok: true, operations: object[]}} Detached recent state, oldest first. */
    list() {
        return { ok: true, operations: structuredClone([...this.#operations.values()]) }
    }

    /** @param {string} operationId - Opaque operation identity. @returns {object} Detached public state or explicit missing history. */
    get(operationId) {
        const value = this.#operations.get(operationId)
        return value === undefined ? { ok: false, reason: 'operation-not-found' } : { ok: true, operation: structuredClone(value) }
    }

    /** @param {Function} listener - Main-owned observer. @returns {Function} Idempotent unsubscribe. @throws {TypeError} For invalid observers. */
    subscribe(listener) {
        if (typeof listener !== 'function') throw new TypeError('Operation observer must be callable')
        this.#listeners.add(listener)
        return () => this.#listeners.delete(listener)
    }
}
