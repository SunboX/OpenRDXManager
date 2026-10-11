// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { FramedJsonDecoder } from './device-service-transport.mjs'
import { wireEventSchema, wireResponseSchema } from './device-service-wire.mjs'

const MAX_QUEUED_INBOUND_MESSAGES = 1024
const TERMINAL_STATES = new Set(['succeeded', 'failed', 'cancelled'])

/** Owns framed inbound FIFO delivery and the exact observer barrier that may suspend it. */
export class ServiceInboundQueue {
    #active = false
    #decoder
    #epoch = 0
    #maxFrameBytes
    #options
    #queue = []
    #suspension = null

    /**
     * Creates an inbound decoder around the client's exact-generation policies.
     * @param {{maxFrameBytes: number, pending: Map<string, object>, isCurrent: (generation: number) => boolean, getGeneration: () => number, handleMessage: (message: object, generation: number) => boolean|Promise<boolean>, handleResponse: (response: object) => boolean, consumeExpiredDiscoveryResponse: (response: object) => boolean, fault: (generation: number, restartCount: number) => void}} options - Main-owned protocol dependencies.
     */
    constructor(options) {
        this.#options = options
        this.#maxFrameBytes = options.maxFrameBytes
        this.#decoder = new FramedJsonDecoder(this.#maxFrameBytes)
    }

    /** @returns {number} Monotonic identity invalidated on every transport reset. */
    getEpoch() {
        return this.#epoch
    }

    /** @returns {void} Invalidates a suspended delivery, queued suffix, and partial frame. */
    reset() {
        this.#epoch += 1
        this.#active = false
        this.#queue = []
        this.#suspension = null
        this.#decoder = new FramedJsonDecoder(this.#maxFrameBytes)
    }

    /**
     * Decodes complete frames and delivers them synchronously until a barrier suspends.
     * @param {unknown} chunk - Candidate binary chunk.
     * @param {number} generation - Owning transport generation.
     * @param {number} restartCount - Completed restart attempts.
     * @returns {void} Completes after immediate delivery or bounded fault containment.
     */
    receive(chunk, generation, restartCount) {
        if (!this.#options.isCurrent(generation)) return
        let messages
        try {
            messages = this.#decoder.push(chunk)
        } catch {
            this.#options.fault(generation, restartCount)
            return
        }
        if (this.#queue.length + messages.length > MAX_QUEUED_INBOUND_MESSAGES) {
            this.#options.fault(generation, restartCount)
            return
        }
        this.#queue.push(...messages.map((message) => ({ generation, message, restartCount })))
        this.#drain()
    }

    /** @returns {void} Processes messages synchronously until one observer barrier suspends the FIFO. */
    #drain() {
        if (this.#active) {
            this.#drainControl()
            return
        }
        this.#active = true
        while (this.#queue.length > 0) {
            const entry = this.#queue.shift()
            if (!this.#options.isCurrent(entry.generation)) continue
            const result = this.#options.handleMessage(entry.message, entry.generation)
            if (typeof result?.then === 'function') {
                const inboundEpoch = this.#epoch
                this.#suspension = { entry, inboundEpoch }
                void this.#resumeAfterPublication(result, entry, inboundEpoch)
                this.#drainControl()
                return
            }
            if (!result) {
                this.#queue = []
                this.#options.fault(entry.generation, entry.restartCount)
                return
            }
        }
        this.#active = false
    }

    /** @param {PromiseLike<boolean>} result - Suspended observer publication. @param {object} entry - Exact message owner. @param {number} inboundEpoch - Captured drain epoch. @returns {Promise<void>} Resumes only that delivery after contained settlement. */
    async #resumeAfterPublication(result, entry, inboundEpoch) {
        let accepted
        try {
            accepted = await result
        } catch {
            accepted = false
        }
        this.#resume(accepted, entry, inboundEpoch)
    }

    /** @param {boolean} accepted - Suspended observer result. @param {object} entry - Exact message owner. @param {number} inboundEpoch - Exact drain epoch. @returns {void} Resumes or faults. */
    #resume(accepted, entry, inboundEpoch) {
        if (inboundEpoch !== this.#epoch) return
        this.#suspension = null
        this.#active = false
        if (!accepted) {
            this.#queue = []
            this.#options.fault(entry.generation, entry.restartCount)
            return
        }
        this.#drain()
    }

    /** @returns {void} Drains FIFO responses to the exact awaited owner acknowledgement; reversed owning acknowledgements fail closed. */
    #drainControl() {
        const suspension = this.#suspension
        if (suspension === null) return
        const suspendedEvent = wireEventSchema.safeParse(suspension.entry.message)
        if (!suspendedEvent.success || suspendedEvent.data.channel !== 'operation' || !TERMINAL_STATES.has(suspendedEvent.data.event.state)) return
        const operationId = suspendedEvent.data.event.operationId
        for (let index = 0; index < this.#queue.length; index += 1) {
            const entry = this.#queue[index]
            if (entry.generation !== suspension.entry.generation || entry.generation !== this.#options.getGeneration()) return this.#resume(false, suspension.entry, suspension.inboundEpoch)
            const parsed = wireResponseSchema.safeParse(entry.message)
            if (!parsed.success) {
                const event = wireEventSchema.safeParse(entry.message)
                if (event.success && event.data.channel === 'device') continue
                return this.#resume(false, suspension.entry, suspension.inboundEpoch)
            }
            const pending = this.#options.pending.get(parsed.data.requestId)
            if (pending === undefined) {
                if (this.#options.consumeExpiredDiscoveryResponse(parsed.data)) {
                    this.#queue.splice(index, 1)
                    index -= 1
                    continue
                }
                return this.#resume(false, suspension.entry, suspension.inboundEpoch)
            }
            if (pending.operationId === operationId && pending.method === 'operation-cancel' && [...this.#options.pending.values()].some((candidate) => candidate.method === 'operation-start' && candidate.operationId === operationId)) return this.#resume(false, suspension.entry, suspension.inboundEpoch)
            const releasesTerminal = pending.operationId === operationId && pending.method === ([...this.#options.pending.values()].some((candidate) => candidate.method === 'operation-cancel' && candidate.operationId === operationId) ? 'operation-cancel' : 'operation-start')
            this.#queue.splice(index, 1)
            index -= 1
            if (!this.#options.handleResponse(parsed.data)) return this.#resume(false, suspension.entry, suspension.inboundEpoch)
            if (releasesTerminal) return
        }
    }
}
