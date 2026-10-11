// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createPublicKey, verify } from 'node:crypto'

import { z } from '../../node_modules/zod/index.js'

/** @param {string} value - Parsed URL. @returns {boolean} True only for HTTPS. */
function isHttpsUrl(value) {
    return new URL(value).protocol === 'https:'
}

const httpsUrlSchema = z.string().url().refine(isHttpsUrl, 'HTTPS URL required')
const firmwareEntrySchema = z.object({ product: z.string().trim().min(1).max(128), revision: z.string().trim().min(1).max(64), url: httpsUrlSchema }).strict()
const updatePayloadSchema = z
    .object({
        expiresAt: z.string().datetime({ offset: true }),
        firmware: z.array(firmwareEntrySchema).max(128),
        issuedAt: z.string().datetime({ offset: true }),
        manager: z.object({ url: httpsUrlSchema, version: z.string().trim().min(1).max(64) }).strict(),
        schemaVersion: z.literal(1)
    })
    .strict()
const signedManifestSchema = updatePayloadSchema
    .extend({
        signature: z
            .string()
            .min(40)
            .max(256)
            .regex(/^[A-Za-z0-9+/]+={0,2}$/)
    })
    .strict()

/** @param {unknown} value - JSON-compatible value. @returns {string} Canonical JSON used for signature verification. */
function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
    if (value !== null && typeof value === 'object') {
        const entries = []
        for (const key of Object.keys(value).sort()) entries.push(`${JSON.stringify(key)}:${canonicalJson(value[key])}`)
        return `{${entries.join(',')}}`
    }
    return JSON.stringify(value)
}

/**
 * Serializes the exact signed payload independent of source key order.
 * @param {object} payload - Valid unsigned manifest payload.
 * @returns {string} Canonical UTF-8 JSON.
 */
export function serializeUpdatePayload(payload) {
    return canonicalJson(payload)
}

/** @param {string} left - Installed version. @param {string} right - Candidate version. @returns {number} Negative, zero, or positive comparison. */
function compareVersions(left, right) {
    const leftParts = String(left).split(/[.-]/)
    const rightParts = String(right).split(/[.-]/)
    const length = Math.max(leftParts.length, rightParts.length)
    for (let index = 0; index < length; index += 1) {
        const leftPart = leftParts[index] ?? '0'
        const rightPart = rightParts[index] ?? '0'
        const leftNumber = /^\d+$/.test(leftPart) ? Number(leftPart) : Number.NaN
        const rightNumber = /^\d+$/.test(rightPart) ? Number(rightPart) : Number.NaN
        const comparison = Number.isNaN(leftNumber) || Number.isNaN(rightNumber) ? leftPart.localeCompare(rightPart) : leftNumber - rightNumber
        if (comparison !== 0) return comparison
    }
    return 0
}

/** @param {object} device - Renderer-safe device. @returns {string|null} Current firmware revision. */
function currentFirmware(device) {
    const direct = device?.drive?.firmwareRevision
    if (typeof direct === 'string') return direct
    const typed = device?.drive?.details?.firmwareRevision
    return typed?.availability === 'reported' && typeof typed.value === 'string' ? typed.value : null
}

/** @returns {Promise<object[]>} Default empty discovery snapshot. */
async function noDevices() {
    return []
}

/** @returns {Date} Current wall-clock time. */
function currentTime() {
    return new Date()
}

/** Read-only, signature-verifying application and dock update metadata service. */
export class UpdateService {
    #currentVersion
    #devices
    #endpoint
    #fetch
    #now
    #publicKey

    /**
     * @param {{currentVersion: string, endpoint?: string, publicKey?: string|Buffer|import('node:crypto').KeyObject, fetch?: Function, devices?: () => Promise<object[]>, now?: () => Date}} options - Trusted metadata dependencies.
     */
    constructor(options) {
        this.#currentVersion = typeof options?.currentVersion === 'string' ? options.currentVersion : '0.0.0'
        this.#endpoint = typeof options?.endpoint === 'string' && httpsUrlSchema.safeParse(options.endpoint).success ? options.endpoint : null
        this.#fetch = typeof options?.fetch === 'function' ? options.fetch : globalThis.fetch
        this.#devices = typeof options?.devices === 'function' ? options.devices : noDevices
        this.#now = typeof options?.now === 'function' ? options.now : currentTime
        try {
            this.#publicKey = options?.publicKey?.type === 'public' ? options.publicKey : options?.publicKey === undefined ? null : createPublicKey(options.publicKey)
        } catch {
            this.#publicKey = null
        }
    }

    /**
     * Parses exact metadata and verifies its detached Ed25519 signature and lifetime.
     * @param {string} text - Bounded response body.
     * @returns {Promise<object>} Verified unsigned payload.
     * @throws {Error} For malformed, unsigned, untrusted, or expired metadata.
     */
    async parse(text) {
        if (this.#publicKey === null || typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > 1_048_576) throw new Error('unsigned-or-invalid-manifest')
        let candidate
        try {
            candidate = JSON.parse(text)
        } catch {
            throw new Error('unsigned-or-invalid-manifest')
        }
        const parsed = signedManifestSchema.safeParse(candidate)
        if (!parsed.success) throw new Error('unsigned-or-invalid-manifest')
        const { signature, ...payload } = parsed.data
        const signatureBytes = Buffer.from(signature, 'base64')
        if (!verify(null, Buffer.from(serializeUpdatePayload(payload), 'utf8'), this.#publicKey, signatureBytes)) throw new Error('unsigned-or-invalid-manifest')
        const now = this.#now().getTime()
        if (!Number.isFinite(now) || Date.parse(payload.issuedAt) > now || Date.parse(payload.expiresAt) <= now) throw new Error('expired-or-not-yet-valid-manifest')
        return Object.freeze(payload)
    }

    /**
     * Performs one read-only authoritative GET and computes local applicability.
     * @param {{silent?: boolean}} [request={}] - Whether current-state UI may stay silent.
     * @returns {Promise<object>} Bounded update availability with no apply/install action.
     */
    async check(request = {}) {
        if (this.#endpoint === null) return { ok: false, reason: 'update-endpoint-unconfigured' }
        if (this.#publicKey === null) return { ok: false, reason: 'update-signing-key-unconfigured' }
        if (typeof this.#fetch !== 'function') return { ok: false, reason: 'update-network-unavailable' }
        try {
            const response = await this.#fetch(this.#endpoint, { headers: { accept: 'application/json' }, method: 'GET', redirect: 'error' })
            if (response?.ok !== true || response.status !== 200 || response.url !== this.#endpoint || typeof response.text !== 'function') return { ok: false, reason: 'update-network-failure' }
            const manifest = await this.parse(await response.text())
            const devices = await this.#devices()
            const updates = []
            let applicableCount = 0
            for (const device of Array.isArray(devices) ? devices.slice(0, 128) : []) {
                const revision = currentFirmware(device)
                if (revision === null) continue
                let available
                for (const entry of manifest.firmware) {
                    if (entry.product === device.product) {
                        available = entry
                        break
                    }
                }
                if (available !== undefined) applicableCount += 1
                if (available !== undefined && compareVersions(revision, available.revision) < 0) updates.push({ product: device.product, currentRevision: revision, availableRevision: available.revision })
            }
            const managerAvailable = compareVersions(this.#currentVersion, manifest.manager.version) < 0
            return {
                ok: true,
                silent: request?.silent === true,
                manager: managerAvailable ? { status: 'available', currentVersion: this.#currentVersion, availableVersion: manifest.manager.version } : { status: 'current', currentVersion: this.#currentVersion },
                firmware: updates.length > 0 ? { status: 'available', updates } : { status: applicableCount > 0 ? 'current' : 'not-applicable', updates: [] }
            }
        } catch (error) {
            const reason = error?.message === 'expired-or-not-yet-valid-manifest' ? error.message : error?.message === 'unsigned-or-invalid-manifest' ? error.message : 'update-network-failure'
            return { ok: false, reason }
        }
    }
}
