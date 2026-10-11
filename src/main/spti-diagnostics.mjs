// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { EventLogger } from './event-logger.mjs'
import { randomUUID } from 'node:crypto'

export const SPTI_DIAGNOSTIC_PREFIX = 'openrdx-hardware: spti-v1 '

/** @param {unknown} value - Candidate integer. @param {number} max - Inclusive bound. @returns {boolean} Whether the unsigned integer fits. */
function integer(value, max) {
    return Number.isInteger(value) && value >= 0 && value <= max
}

/** @param {unknown} value - Candidate object. @param {string[]} keys - Exact keys. @returns {boolean} Whether only those own fields exist. */
function exactKeys(value, keys) {
    return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === [...keys].sort().join(',')
}

/**
 * Independently admits only non-secret inquiry/sense and firmware-buffer-zero headers.
 * Padded command length and firmware-field mismatches remain observable, not repaired.
 * @param {object} record - Shape-checked numeric envelope.
 * @returns {boolean} Whether its header family can safely be retained.
 */
function allowedHeader(record) {
    if (typeof record.frame !== 'string' || !/^(?:[0-9A-F]{2}){6,16}$/.test(record.frame)) return false
    const bytes = Buffer.from(record.frame, 'hex')
    const base = bytes[0] === 0x12 ? 6 : 10
    if (bytes.length < base || bytes.subarray(base).some((byte) => byte !== 0)) return false
    const frame = bytes.subarray(0, base).toString('hex').toUpperCase()
    if (['12000000FE00', '12018300FE00'].includes(frame)) return record.dir === 1 && record.requested === 254
    if (/^(?:4D|5A)00[0-9A-F]{2}0000000000FE00$/.test(frame)) return record.dir === 1 && record.requested === 254
    if (bytes[0] !== 0x3b || bytes[2] !== 0) return false
    const mode = bytes[1] & 0x1f
    return (mode === 4 && record.dir === 0 && record.requested > 0) || (mode === 5 && record.dir === 2 && record.requested === 0)
}

/** @param {unknown} sense - Decoded standard sense fields, never raw bytes. @returns {boolean} Whether every field is bounded and known. */
function validSense(sense) {
    if (sense === null) return true
    if (!exactKeys(sense, ['format', 'code', 'asc', 'ascq', 'field']) || ![112, 113, 114, 115].includes(sense.format) || !integer(sense.code, 15) || !integer(sense.asc, 255) || !integer(sense.ascq, 255)) return false
    const field = sense.field
    return field === null || ([112, 113].includes(sense.format) && sense.code === 5 && exactKeys(field, ['inHeader', 'offset', 'bit']) && typeof field.inHeader === 'boolean' && integer(field.offset, 65535) && (field.bit === null || integer(field.bit, 7)))
}

/**
 * Parses one bounded diagnostic line without forwarding arbitrary native stderr.
 * @param {unknown} line - Complete line without a newline.
 * @returns {object|null} Exact admitted envelope or null; never throws.
 */
export function parseSptiDiagnostic(line) {
    if (typeof line !== 'string' || line.length > 512 || !line.startsWith(SPTI_DIAGNOSTIC_PREFIX)) return null
    try {
        const record = JSON.parse(line.slice(SPTI_DIAGNOSTIC_PREFIX.length))
        if (!exactKeys(record, ['v', 'seq', 'phase', 'frame', 'dir', 'requested', 'completed', 'status', 'sense', 'reported', 'copied', 'returned', 'host'])) return null
        if (record.v !== 1 || !integer(record.seq, 256) || record.seq === 0 || !integer(record.dir, 2) || !integer(record.requested, 4096) || !integer(record.reported, 252) || !integer(record.copied, 252) || record.copied > record.reported || !allowedHeader(record) || !validSense(record.sense)) return null
        if (record.phase === 'submit') {
            if (record.host !== 'pending' || record.completed !== null || record.status !== null || record.sense !== null || record.returned !== null || record.reported !== 0 || record.copied !== 0) return null
        } else if (record.phase === 'complete') {
            if (!integer(record.returned, 0xffffffff)) return null
            if (record.host === 'device') {
                if (!integer(record.completed, 0xffffffff) || !integer(record.status, 255) || (record.sense !== null && (record.status !== 2 || record.copied < ([112, 113].includes(record.sense.format) ? 14 : 8))) || (record.sense?.field !== null && record.sense?.field !== undefined && record.copied < 18)) return null
            } else if (!['io-error', 'invalid-response'].includes(record.host) || record.completed !== null || record.status !== null || record.sense !== null || record.reported !== 0 || record.copied !== 0) return null
        } else return null
        return record
    } catch {
        return null
    }
}

/** Separate ACL-verified local log; failure disables diagnostics, not hardware safety. */
export class SptiDiagnosticLog {
    #logger
    #captureId = randomUUID()
    #disabled = false
    #count = 0
    #generations = new Map()

    /** @param {object} options - Main-owned EventLogger options, or injected test logger. */
    constructor(options) {
        this.#logger =
            options.logger ??
            new EventLogger({
                ...options,
                enabled: true,
                maxBytes: 1_048_576,
                maxPendingEntries: 1024,
                onFailure: () => {
                    this.#disabled = true
                }
            })
    }

    /**
     * Correlates each completion with one submitted header and persists safe metadata.
     * @param {string} line - Native diagnostic line.
     * @param {number} generation - Main-owned child generation, not a device identifier.
     * @returns {Promise<boolean>} False on rejection, exhausted budget or contained I/O failure.
     */
    async record(line, generation) {
        if (this.#disabled || this.#count >= 2048 || !integer(generation, 4) || generation === 0) return false
        const record = parseSptiDiagnostic(line)
        if (record === null) return false
        let state = this.#generations.get(generation)
        if (!state) {
            state = { seen: new Set(), pending: new Map() }
            this.#generations.set(generation, state)
        }
        const binding = `${record.frame}:${record.dir}:${record.requested}`
        if (record.phase === 'submit') {
            if (state.seen.has(record.seq)) return false
            state.seen.add(record.seq)
            state.pending.set(record.seq, binding)
        } else {
            if (state.pending.get(record.seq) !== binding) return false
            state.pending.delete(record.seq)
        }
        this.#count += 1
        try {
            const result = await this.#logger.write({ event: 'spti-observation', messageKey: 'activity.service', severity: 'info', captureId: this.#captureId, generation, ...record })
            if (result === false || result?.ok === false) this.#disabled = true
            return !this.#disabled
        } catch {
            this.#disabled = true
            return false
        }
    }

    /** @returns {Promise<void>} Flushes only this diagnostic log and contains close errors. */
    async close() {
        this.#disabled = true
        try {
            await this.#logger.close()
        } catch {
            /* Optional diagnostics cannot block normal shutdown. */
        }
    }
}
