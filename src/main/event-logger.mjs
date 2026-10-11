// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomUUID } from 'node:crypto'
import { join } from 'node:path'

import { logListResponseSchema } from '../shared/schemas.mjs'
import { closeLogHandle, createLogFileSecurity } from './log-file-security.mjs'

const CURRENT_LOG_NAME = 'RDXManager.jsonl'
const BACKUP_LOG_NAME = '_RDXManager.bak'
const REDACTED = '[REDACTED]'
const SENSITIVE_KEY_PATTERN = /(password|passphrase|secret|token|credential|authorization|firmware|payload|command|cdb|path|environment|buffer|bytes|key)/i
const PATH_VALUE_PATTERN = /(?:[a-zA-Z]:[\\/]|\/[a-zA-Z0-9._-]+(?:[\\/][^\s]*)?|file:|\\\\)/
const SAFE_MESSAGE_KEY_PATTERN = /^[a-z][a-z0-9]*(?:\.[a-z][a-z0-9]*)*$/i
const SAFE_IDENTIFIER_PATTERN = /^[a-z][a-z0-9:-]*$/i
const DEFAULT_MAX_PENDING_ENTRIES = 256
const DEFAULT_MAX_PENDING_BYTES = 1_048_576
const DEFAULT_PERSISTENCE_TIMEOUT_MS = 5_000
const MAX_PERSISTENCE_TIMEOUT_MS = 30_000
const PRIORITY_RESERVED_ENTRIES = 1
const DEFAULT_TIMERS = Object.freeze({
    setTimeout(callback, delay) {
        return globalThis.setTimeout(callback, delay)
    },
    clearTimeout(timer) {
        globalThis.clearTimeout(timer)
    }
})

/**
 * Creates a local event identifier without device or host information.
 * @returns {string} Opaque bounded log ID.
 */
function createDefaultId() {
    return `activity:${randomUUID()}`
}

/**
 * Returns the current wall-clock timestamp.
 * @returns {Date} Current time.
 */
function createCurrentTime() {
    return new Date()
}

/**
 * Tests whether a string resembles an absolute host path or file URL.
 * @param {string} value - Candidate log value.
 * @returns {boolean} True when the value must not enter a log.
 */
function looksLikePath(value) {
    return PATH_VALUE_PATTERN.test(value.trim())
}

/**
 * Detects byte-shaped arrays that may contain commands, firmware, or secrets.
 * @param {unknown} value - Candidate array value.
 * @returns {boolean} True when every element is one byte.
 */
function isByteArray(value) {
    if (!Array.isArray(value) || value.length === 0) {
        return false
    }
    for (const byte of value) {
        if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
            return false
        }
    }
    return true
}

/**
 * Bounds and sanitizes a scalar log value.
 * @param {unknown} value - Candidate scalar.
 * @returns {string|number|boolean|null} Safe bounded scalar.
 */
function sanitizeScalar(value) {
    if (value === null || typeof value === 'boolean') {
        return value
    }
    if (typeof value === 'number') {
        return Number.isFinite(value) ? value : null
    }
    if (typeof value === 'string') {
        if (looksLikePath(value)) {
            return REDACTED
        }
        return value.slice(0, 512)
    }
    return REDACTED
}

/**
 * Recursively copies only enumerable data properties while redacting sensitive
 * keys before any filesystem operation can observe the record.
 * @param {unknown} value - Candidate structured detail.
 * @param {number} depth - Current bounded recursion depth.
 * @param {Set<object>} ancestors - Current cycle-detection set.
 * @returns {unknown} Sanitized JSON-safe detail.
 */
function sanitizeValue(value, depth, ancestors) {
    if (value === null || typeof value !== 'object') {
        return sanitizeScalar(value)
    }
    if (ArrayBuffer.isView(value) || isByteArray(value)) {
        return REDACTED
    }
    if (depth >= 5 || ancestors.has(value)) {
        return REDACTED
    }

    let descriptors
    try {
        descriptors = Object.getOwnPropertyDescriptors(value)
    } catch {
        return REDACTED
    }
    ancestors.add(value)
    try {
        if (Array.isArray(value)) {
            const sanitized = []
            const length = Math.min(value.length, 32)
            for (let index = 0; index < length; index += 1) {
                const descriptor = descriptors[String(index)]
                sanitized.push(descriptor !== undefined && 'value' in descriptor ? sanitizeValue(descriptor.value, depth + 1, ancestors) : REDACTED)
            }
            return sanitized
        }

        const sanitized = {}
        let count = 0
        let redacted = false
        for (const [key, descriptor] of Object.entries(descriptors)) {
            if (count >= 64) {
                break
            }
            if (!descriptor.enumerable || !('value' in descriptor) || ['__proto__', 'constructor', 'prototype'].includes(key)) {
                redacted = true
                continue
            }
            if (SENSITIVE_KEY_PATTERN.test(key)) {
                redacted = true
                continue
            }
            sanitized[key.slice(0, 64)] = sanitizeValue(descriptor.value, depth + 1, ancestors)
            count += 1
        }
        if (redacted) {
            sanitized.redacted = REDACTED
        }
        return sanitized
    } finally {
        ancestors.delete(value)
    }
}

/**
 * Normalizes renderer-visible activity severity.
 * @param {unknown} severity - Candidate severity.
 * @returns {'info'|'warning'|'error'} Safe severity.
 */
function normalizeSeverity(severity) {
    return ['info', 'warning', 'error'].includes(severity) ? severity : 'info'
}

/**
 * Normalizes a translated activity message key.
 * @param {unknown} messageKey - Candidate message key.
 * @returns {string} Safe message key.
 */
function normalizeMessageKey(messageKey) {
    return typeof messageKey === 'string' && messageKey.length <= 128 && SAFE_MESSAGE_KEY_PATTERN.test(messageKey) ? messageKey : 'activity.event'
}

/**
 * Keeps an optional support correlation ID only when it is bounded and opaque.
 * @param {unknown} value - Candidate correlation ID.
 * @returns {string|undefined} Safe correlation ID or undefined.
 */
function normalizeCorrelationId(value) {
    return typeof value === 'string' && value.length <= 128 && SAFE_IDENTIFIER_PATTERN.test(value) ? value : undefined
}

/**
 * Reads only an own data property without invoking accessors or proxy getters.
 * @param {object} value - Candidate event record.
 * @param {string} key - Exact metadata field.
 * @returns {unknown} Own data value or undefined.
 */
function readOwnDataProperty(value, key) {
    try {
        const descriptor = Object.getOwnPropertyDescriptor(value, key)
        return descriptor !== undefined && 'value' in descriptor ? descriptor.value : undefined
    } catch {
        return undefined
    }
}

/**
 * Creates a completely sanitized JSONL record in memory.
 * @param {unknown} event - Candidate event input.
 * @param {() => string} idFactory - Main-owned activity ID factory.
 * @param {() => Date} now - Timestamp provider.
 * @returns {object} JSON-safe sanitized record.
 */
function createSanitizedRecord(event, idFactory, now) {
    const source = event !== null && typeof event === 'object' ? event : {}
    const safeSource = sanitizeValue(source, 0, new Set())
    const severity = readOwnDataProperty(source, 'severity')
    const messageKey = readOwnDataProperty(source, 'messageKey')
    const eventName = readOwnDataProperty(source, 'event')
    const correlationId = readOwnDataProperty(source, 'supportCorrelationId')
    const occurredAt = now().toISOString()
    const candidateId = idFactory()
    const id = typeof candidateId === 'string' && candidateId.length <= 64 && SAFE_IDENTIFIER_PATTERN.test(candidateId) ? candidateId : 'activity:redacted'
    const record = {
        id,
        occurredAt,
        severity: normalizeSeverity(severity),
        messageKey: normalizeMessageKey(messageKey),
        event: typeof eventName === 'string' ? sanitizeScalar(eventName) : 'event',
        details: safeSource
    }
    const supportCorrelationId = normalizeCorrelationId(correlationId)
    if (supportCorrelationId !== undefined) {
        record.supportCorrelationId = supportCorrelationId
    }
    return record
}

/**
 * Returns a bounded key for replaceable progress and informational diagnostics.
 * Service lifecycle, non-info diagnostics, and mandatory audits retain ordered priority.
 * @param {unknown} event - Candidate event before sanitization.
 * @returns {string|null} Safe coalescing key or null for ordered priority data.
 */
function activityCoalescingKey(event) {
    if (event === null || typeof event !== 'object') {
        return null
    }
    const eventName = readOwnDataProperty(event, 'event')
    // Complete manufacturing reads emit hundreds of alternating native breadcrumbs.
    // Keep the latest queued diagnostic without exhausting mandatory audit capacity.
    if (eventName === 'service-diagnostic' && readOwnDataProperty(event, 'severity') === 'info') {
        return 'service-diagnostic'
    }
    const state = readOwnDataProperty(event, 'state')
    const operationId = readOwnDataProperty(event, 'operationId')
    if (eventName !== 'operation-lifecycle' || state !== 'progress' || typeof operationId !== 'string' || operationId.length > 128 || !SAFE_IDENTIFIER_PATTERN.test(operationId)) {
        return null
    }
    return `operation-progress:${operationId}`
}

/**
 * Serializes one sanitized record within the configured single-entry bound.
 * Oversized details are replaced before any append or rotation occurs.
 * @param {object} record - Already-sanitized activity record.
 * @param {number} maxBytes - Configured log size bound.
 * @returns {string} Bounded JSONL line.
 */
function serializeBoundedRecord(record, maxBytes) {
    let line = `${JSON.stringify(record)}\n`
    if (Buffer.byteLength(line, 'utf8') <= maxBytes) {
        return line
    }
    line = `${JSON.stringify({ ...record, details: { redacted: REDACTED } })}\n`
    if (Buffer.byteLength(line, 'utf8') <= maxBytes) {
        return line
    }
    line = `${JSON.stringify({ id: record.id, occurredAt: record.occurredAt, severity: record.severity, messageKey: 'activity.event', event: 'event', details: { redacted: REDACTED } })}\n`
    return line
}

/**
 * Reads a log file only when it remains within the logger's owned size bound.
 * @param {{openRead: (path: string) => Promise<object>}} fileSecurity - Platform descriptor boundary.
 * @param {string} path - Exact logger-owned file path.
 * @param {number} maxBytes - Maximum accepted file size.
 * @returns {Promise<string>} File text or an empty string for absent/oversized data.
 */
async function readBoundedLog(fileSecurity, path, maxBytes) {
    let handle
    try {
        handle = await fileSecurity.openRead(path)
        const metadata = await handle.stat()
        if (!metadata.isFile() || metadata.size > maxBytes) {
            return ''
        }
        const buffer = Buffer.allocUnsafe(maxBytes + 1)
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0)
        return bytesRead <= maxBytes ? buffer.subarray(0, bytesRead).toString('utf8') : ''
    } catch {
        return ''
    } finally {
        await closeLogHandle(handle)
    }
}

/**
 * Parses one bounded activity line without surfacing filesystem corruption.
 * @param {string} line - Candidate JSONL line.
 * @returns {object|null} Renderer-safe activity entry or null.
 */
function parseActivityLine(line) {
    if (line.length === 0 || Buffer.byteLength(line, 'utf8') > 16_384) {
        return null
    }
    try {
        const record = JSON.parse(line)
        const entry = {
            id: record.id,
            occurredAt: record.occurredAt,
            severity: record.severity,
            messageKey: record.messageKey
        }
        if (record.supportCorrelationId !== undefined) {
            entry.supportCorrelationId = record.supportCorrelationId
        }
        const parsed = logListResponseSchema.safeParse({ ok: true, entries: [entry] })
        return parsed.success ? parsed.data.entries[0] : null
    } catch {
        return null
    }
}

/**
 * Writes redacted rotating local JSONL and exposes only bounded renderer-safe
 * activity entries.
 */
export class EventLogger {
    #backupPath
    #closed = false
    #closePromise = null
    #currentPath
    #directory
    #enabled
    #fileSecurity
    #failureReason = null
    #failureReported = false
    #idFactory
    #maxBytes
    #maxPendingBytes
    #maxPendingEntries
    #now
    #onFailure
    #pendingBytes = 0
    #pendingEntries = 0
    #persistenceTimeoutMs
    #pumpPromise = null
    #queue = []
    #timers

    /**
     * Creates one logger rooted at a main-owned local directory.
     * @param {{directory: string, enabled?: boolean, maxBytes?: number, maxPendingBytes?: number, maxPendingEntries?: number, persistenceTimeoutMs?: number, timers?: {setTimeout: Function, clearTimeout: Function}, idFactory?: () => string, now?: () => Date, onFailure?: (reason: string) => void, platform?: string, windowsSecurityAdapter?: unknown, fileSecurity?: object}} options - Logger configuration.
     * @throws {TypeError} When the directory or bounds are invalid.
     */
    constructor(options) {
        if (typeof options?.directory !== 'string' || options.directory.length === 0) {
            throw new TypeError('EventLogger requires a directory')
        }
        const maxBytes = options.maxBytes ?? 1_048_576
        if (!Number.isInteger(maxBytes) || maxBytes < 256 || maxBytes > 16_777_216) {
            throw new TypeError('EventLogger maxBytes is invalid')
        }
        const maxPendingEntries = options.maxPendingEntries ?? DEFAULT_MAX_PENDING_ENTRIES
        const maxPendingBytes = options.maxPendingBytes ?? Math.max(maxBytes * 2, DEFAULT_MAX_PENDING_BYTES)
        if (!Number.isInteger(maxPendingEntries) || maxPendingEntries < PRIORITY_RESERVED_ENTRIES + 1 || maxPendingEntries > 4096) {
            throw new TypeError('EventLogger maxPendingEntries is invalid')
        }
        if (!Number.isInteger(maxPendingBytes) || maxPendingBytes < maxBytes * 2 || maxPendingBytes > 67_108_864) {
            throw new TypeError('EventLogger maxPendingBytes is invalid')
        }
        if (options.onFailure !== undefined && typeof options.onFailure !== 'function') {
            throw new TypeError('EventLogger onFailure is invalid')
        }
        const persistenceTimeoutMs = options.persistenceTimeoutMs ?? DEFAULT_PERSISTENCE_TIMEOUT_MS
        if (!Number.isInteger(persistenceTimeoutMs) || persistenceTimeoutMs < 1 || persistenceTimeoutMs > MAX_PERSISTENCE_TIMEOUT_MS) {
            throw new TypeError('EventLogger persistenceTimeoutMs is invalid')
        }
        if (options.timers !== undefined && (typeof options.timers?.setTimeout !== 'function' || typeof options.timers?.clearTimeout !== 'function')) {
            throw new TypeError('EventLogger timers are invalid')
        }
        this.#directory = options.directory
        this.#currentPath = join(options.directory, CURRENT_LOG_NAME)
        this.#backupPath = join(options.directory, BACKUP_LOG_NAME)
        this.#enabled = options.enabled !== false
        this.#fileSecurity = options.fileSecurity ?? createLogFileSecurity({ platform: options.platform, windowsSecurityAdapter: options.windowsSecurityAdapter })
        this.#maxBytes = maxBytes
        this.#maxPendingBytes = maxPendingBytes
        this.#maxPendingEntries = maxPendingEntries
        this.#persistenceTimeoutMs = persistenceTimeoutMs
        this.#timers = options.timers ?? DEFAULT_TIMERS
        this.#idFactory = typeof options.idFactory === 'function' ? options.idFactory : createDefaultId
        this.#now = typeof options.now === 'function' ? options.now : createCurrentTime
        this.#onFailure = options.onFailure ?? null
    }

    /**
     * Sanitizes and serializes one event before any rotation or append occurs.
     * @param {unknown} event - Candidate local activity event.
     * @returns {Promise<boolean>} True when the accepted line or its coalesced successor persisted.
     */
    write(event) {
        if (!this.#enabled || this.#closed) {
            return Promise.resolve(false)
        }
        return this.#writeSanitized(event, activityCoalescingKey(event))
    }

    /**
     * Persists one mandatory lifecycle or configuration audit record even when
     * optional activity logging is disabled.
     * @param {unknown} event - Candidate mandatory audit event.
     * @returns {Promise<boolean>} True only after the bounded line persisted.
     */
    writeCritical(event) {
        if (this.#closed) {
            return Promise.resolve(false)
        }
        return this.#writeSanitized(event, null)
    }

    /**
     * Sanitizes one event and admits it to the bounded persistence queue.
     * @param {unknown} event - Candidate local event.
     * @param {string|null} coalescingKey - Replaceable progress key or mandatory priority.
     * @returns {Promise<boolean>} True only after persistence completes.
     */
    #writeSanitized(event, coalescingKey) {
        const record = createSanitizedRecord(event, this.#idFactory, this.#now)
        const line = serializeBoundedRecord(record, this.#maxBytes)
        return this.#enqueue(line, coalescingKey)
    }

    /**
     * Enqueues one already-sanitized line without exceeding count or byte bounds.
     * @param {string} line - Bounded sanitized JSONL.
     * @param {string|null} coalescingKey - Replaceable progress identity.
     * @returns {Promise<boolean>} Shared persistence result or immediate backpressure rejection.
     */
    #enqueue(line, coalescingKey) {
        const bytes = Buffer.byteLength(line, 'utf8')
        const priority = coalescingKey === null
        if (coalescingKey !== null) {
            const existing = this.#queue.at(-1)
            if (existing?.coalescingKey === coalescingKey) {
                const nextBytes = this.#pendingBytes - existing.bytes + bytes
                if (nextBytes > this.#maxPendingBytes - this.#maxBytes) {
                    return Promise.resolve(false)
                }
                this.#pendingBytes = nextBytes
                existing.line = line
                existing.bytes = bytes
                return existing.promise
            }
        }

        this.#evictProgressUntilCapacity(bytes, priority)
        if (!this.#hasCapacity(bytes, priority)) {
            if (priority) {
                this.#failureReason ??= 'event-log-priority-overflow'
                this.#closed = true
                this.#reportFailure(this.#failureReason)
            }
            return Promise.resolve(false)
        }

        const { promise, resolve: settle } = Promise.withResolvers()
        this.#queue.push({ line, bytes, coalescingKey, priority, promise, settle })
        this.#pendingBytes += bytes
        this.#pendingEntries += 1
        this.#startPump()
        return promise
    }

    /**
     * Reports whether one more entry fits both hard queue bounds.
     * @param {number} bytes - UTF-8 bytes of the candidate line.
     * @param {boolean} priority - Whether reserved capacity is available.
     * @returns {boolean} True when the candidate fits.
     */
    #hasCapacity(bytes, priority) {
        const entryLimit = priority ? this.#maxPendingEntries : this.#maxPendingEntries - PRIORITY_RESERVED_ENTRIES
        const byteLimit = priority ? this.#maxPendingBytes : this.#maxPendingBytes - this.#maxBytes
        return this.#pendingEntries < entryLimit && this.#pendingBytes + bytes <= byteLimit
    }

    /**
     * Evicts only queued replaceable progress so ordered priority records can proceed.
     * @param {number} bytes - UTF-8 bytes required by the priority or new progress line.
     * @param {boolean} priority - Whether reserved capacity is available.
     * @returns {void} Completes after capacity is available or no progress remains.
     */
    #evictProgressUntilCapacity(bytes, priority) {
        while (!this.#hasCapacity(bytes, priority)) {
            const index = this.#queue.findIndex((entry) => entry.coalescingKey !== null)
            if (index < 0) {
                return
            }
            const [entry] = this.#queue.splice(index, 1)
            this.#pendingBytes -= entry.bytes
            this.#pendingEntries -= 1
            entry.settle(false)
        }
    }

    /**
     * Escalates one sanitized logger health failure without trusting the callback.
     * @param {string} reason - Stable non-sensitive health reason.
     * @returns {void} Completes after the one callback attempt.
     */
    #reportFailure(reason) {
        if (this.#failureReported) {
            return
        }
        this.#failureReported = true
        try {
            this.#onFailure?.(reason)
        } catch {
            // Health escalation must not make bounded logger admission throw.
        }
    }

    /** Starts the single persistence pump when queued work exists. @returns {void} */
    #startPump() {
        if (this.#pumpPromise !== null || this.#queue.length === 0) {
            return
        }
        const pump = this.#drainQueue()
        this.#pumpPromise = pump
        void this.#finishPump(pump)
    }

    /** @param {Promise<void>} pump - Exact active persistence pump. @returns {Promise<void>} Resolves after contained completion and resuming boundary work. */
    async #finishPump(pump) {
        try {
            await pump
        } catch {
            // Pump ownership still needs releasing after an unexpected dependency failure.
        } finally {
            if (this.#pumpPromise === pump) {
                this.#pumpPromise = null
            }
            this.#startPump()
        }
    }

    /**
     * Persists accepted entries serially and contains each filesystem failure.
     * @returns {Promise<void>} Resolves after the queue observed by this pump drains.
     */
    async #drainQueue() {
        while (this.#queue.length > 0) {
            const entry = this.#queue.shift()
            const outcome = await this.#persistWithDeadline(entry.line)
            this.#pendingBytes -= entry.bytes
            this.#pendingEntries -= 1
            entry.settle(outcome.ok)
            if (!outcome.ok) {
                if (outcome.reason === 'event-log-persistence-timeout') {
                    this.#failPersistence(outcome.reason)
                    return
                }
                this.#failureReason ??= outcome.reason
                this.#reportFailure(this.#failureReason)
            }
        }
    }

    /**
     * Observes one persistence attempt through a deterministic absolute bound.
     * The observed branch owns a rejection handler so late filesystem settlement
     * cannot become an unhandled rejection after the timeout wins the race.
     * @param {string} line - Already-sanitized JSONL line.
     * @returns {Promise<{ok: true}|{ok: false, reason: string}>} Typed bounded outcome.
     */
    async #persistWithDeadline(line) {
        let timer = null
        const observed = this.#observePersistence(line)
        const timeout = new Promise((resolve) => {
            timer = this.#timers.setTimeout(() => resolve({ ok: false, reason: 'event-log-persistence-timeout' }), this.#persistenceTimeoutMs)
        })
        const outcome = await Promise.race([observed, timeout])
        if (outcome.reason !== 'event-log-persistence-timeout') {
            this.#timers.clearTimeout(timer)
        }
        return outcome
    }

    /** @param {string} line - Sanitized line admitted to the persistence queue. @returns {Promise<{ok: true}|{ok: false, reason: string}>} Contained persistence result, including late rejection. */
    async #observePersistence(line) {
        // Arm the absolute deadline and publish pump ownership before invoking storage.
        await Promise.resolve()
        try {
            await this.#persistLine(line)
            return { ok: true }
        } catch {
            return { ok: false, reason: 'event-log-persistence-failed' }
        }
    }

    /**
     * Latches one persistence-health failure and rejects all queued work without
     * starting another potentially hanging filesystem operation.
     * @param {string} reason - Stable non-sensitive persistence failure reason.
     * @returns {void} Completes after queued promises are rejected.
     */
    #failPersistence(reason) {
        this.#failureReason ??= reason
        this.#closed = true
        this.#reportFailure(this.#failureReason)
        for (const entry of this.#queue.splice(0)) {
            this.#pendingBytes -= entry.bytes
            this.#pendingEntries -= 1
            entry.settle(false)
        }
    }

    /**
     * Waits until every previously queued write has settled.
     * @returns {Promise<{ok: true}|{ok: false, reason: string}>} Typed persistence-health result.
     */
    async flush() {
        while (this.#pumpPromise !== null) {
            await this.#pumpPromise
        }
        return this.#failureReason === null ? { ok: true } : { ok: false, reason: this.#failureReason }
    }

    /**
     * Stops admission and drains every previously accepted entry exactly once.
     * @returns {Promise<{ok: true}|{ok: false, reason: string}>} Shared idempotent close result.
     */
    close() {
        if (this.#closePromise === null) {
            this.#closed = true
            this.#closePromise = this.flush()
        }
        return this.#closePromise
    }

    /**
     * Lists at most 500 renderer-safe activity entries from backup then current log.
     * @returns {Promise<object>} Strict log-list response.
     */
    async list() {
        await this.flush()
        const readLimit = this.#maxBytes + 16_384
        try {
            await this.#fileSecurity.prepareDirectory(this.#directory)
        } catch {
            return logListResponseSchema.parse({ ok: true, entries: [] })
        }
        const [backup, current] = await Promise.all([readBoundedLog(this.#fileSecurity, this.#backupPath, readLimit), readBoundedLog(this.#fileSecurity, this.#currentPath, readLimit)])
        const entries = []
        for (const line of `${backup}${current}`.split('\n')) {
            const entry = parseActivityLine(line)
            if (entry !== null) {
                entries.push(entry)
            }
        }
        return logListResponseSchema.parse({ ok: true, entries: entries.slice(-500) })
    }

    /**
     * Durably audits and then changes the optional activity-logging setting.
     * @param {unknown} request - Candidate exact enabled setting.
     * @returns {Promise<object>} Stable action response.
     */
    async setEnabled(request) {
        if (request === null || typeof request !== 'object' || Object.keys(request).length !== 1 || typeof request.enabled !== 'boolean') {
            return { ok: false, reason: 'invalid-request' }
        }
        const persisted = await this.writeCritical({ event: 'logging-setting', messageKey: 'activity.loggingSetting', severity: 'info', enabled: request.enabled })
        if (!persisted) {
            return { ok: false, reason: 'event-log-unavailable' }
        }
        this.#enabled = request.enabled
        return { ok: true }
    }

    /**
     * Rotates the current file when the next sanitized line would cross the bound.
     * @param {string} line - Already-sanitized JSONL line.
     * @returns {Promise<void>} Resolves after rotation and append.
     */
    async #persistLine(line) {
        await this.#fileSecurity.prepareDirectory(this.#directory)
        let currentSize = 0
        let currentHandle
        try {
            currentHandle = await this.#fileSecurity.openAppend(this.#currentPath)
            const metadata = await currentHandle.stat()
            currentSize = metadata.size
            if (currentSize > 0 && currentSize + Buffer.byteLength(line, 'utf8') > this.#maxBytes) {
                await currentHandle.close()
                currentHandle = null
                await this.#fileSecurity.removeFile(this.#backupPath)
                await this.#fileSecurity.renameFile(this.#currentPath, this.#backupPath)
                currentHandle = await this.#fileSecurity.openAppend(this.#currentPath)
            }
            await currentHandle.writeFile(line, { encoding: 'utf8' })
        } finally {
            await closeLogHandle(currentHandle)
        }
    }
}
