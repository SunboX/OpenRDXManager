// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { actionResponseSchema } from '../shared/schemas.mjs'
import { wireDeviceListResponseSchema } from './device-service-wire.mjs'

const MAX_EXPIRED_DISCOVERY_REQUESTS = 64
const responseSchemas = new Map([
    ['devices-scan', actionResponseSchema],
    ['devices-list', wireDeviceListResponseSchema]
])

/** Owns bounded, single-use correlations for harmless late discovery replies. */
export class ExpiredDiscoveryRequests {
    #requests = new Map()

    /** @returns {void} Invalidates every correlation when its service generation ends. */
    clear() {
        this.#requests.clear()
    }

    /**
     * Remembers only an exact timed-out discovery request in the current generation.
     * @param {string} requestId - Main-owned correlation.
     * @param {string} method - Discovery method; operations cannot use this history.
     * @returns {void} Completes after bounded insertion.
     */
    remember(requestId, method) {
        const schema = responseSchemas.get(method)
        if (schema === undefined) return
        this.#requests.set(requestId, schema)
        while (this.#requests.size > MAX_EXPIRED_DISCOVERY_REQUESTS) this.#requests.delete(this.#requests.keys().next().value)
    }

    /**
     * Consumes one strict late reply without publishing its stale result.
     * The outer response was already validated by the inbound protocol boundary.
     * @param {object} response - Strict correlated wire response.
     * @returns {boolean} True only for one remembered, valid discovery reply.
     */
    consume(response) {
        const schema = this.#requests.get(response.requestId)
        if (schema === undefined) return false
        this.#requests.delete(response.requestId)
        return !response.ok || schema.safeParse(response.result).success
    }
}
