// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { mkdtemp, open, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const MAX_FILE_BYTES = 65_536
const MAX_RECORDS = 32
const MAX_OUTPUT_BYTES = 8192
const STATUSES = new Set(['starting', 'handshaking', 'reconciling', 'ready', 'recovering', 'restarting', 'unavailable', 'teardown-unconfirmed', 'stopped'])
const REASONS = new Set(['event-log-unavailable', 'insufficient-permission', 'service-exited', 'service-handshake-timeout', 'service-identity-unverified', 'service-malformed-data', 'service-not-installed', 'service-request-timeout', 'service-saturated', 'service-shutdown', 'service-start-failed', 'service-teardown-unconfirmed', 'service-unavailable', 'service-write-failed'])
const PREFIX = 'OpenRDXManager installed service lifecycle: '

/**
 * Copies only closed lifecycle fields from the actual EventLogger envelope.
 * @param {string} line - One bounded JSONL line, never an arbitrary error message.
 * @returns {object|null} Timestamp and closed event/status/reason fields, or no evidence.
 */
function lifecycleRecord(line) {
    if (line.length > 4096) return null
    try {
        const record = JSON.parse(line)
        if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(record?.occurredAt) || new Date(record.occurredAt).toISOString() !== record.occurredAt) return null
        if (record.event === 'service-handshake-start') return { occurredAt: record.occurredAt, event: record.event }
        if (record.event !== 'service-lifecycle' || !STATUSES.has(record.details?.status) || (record.details.reason !== undefined && !REASONS.has(record.details.reason))) return null
        return { occurredAt: record.occurredAt, event: record.event, status: record.details.status, ...(record.details.reason === undefined ? {} : { reason: record.details.reason }) }
    } catch {
        return null
    }
}

/**
 * Reads a bounded tail of one known logger file; missing/unreadable evidence is empty.
 * @param {string} file - Verifier-owned fixed log filename inside its ephemeral profile.
 * @returns {Promise<object[]>} At most 32 safe records; no raw lines or filesystem errors escape.
 */
async function readLifecycleTail(file) {
    let handle
    try {
        handle = await open(file, 'r')
        const stat = await handle.stat()
        if (!stat.isFile()) return []
        const buffer = Buffer.alloc(Math.min(stat.size, MAX_FILE_BYTES))
        const offset = Math.max(0, stat.size - buffer.length)
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, offset)
        const lines = buffer.subarray(0, bytesRead).toString('utf8').split('\n')
        if (offset > 0) lines.shift() // The bounded tail may begin inside a JSON record.
        return lines
            .map(lifecycleRecord)
            .filter((record) => record !== null)
            .slice(-MAX_RECORDS)
    } catch {
        return []
    } finally {
        if (handle) await handle.close()
    }
}

/**
 * Owns and always removes an ephemeral smoke profile. Only an installed auth
 * failure exports bounded allowlisted timestamps before cleanup; diagnostics
 * never replace the original launch/authentication failure.
 * @param {(profile: string) => Promise<*>} operation - Existing smoke verification, awaited once.
 * @param {{installed: boolean, requireService: boolean, writeDiagnostic?: (line: string) => void}} options - Trusted verification mode and diagnostic sink.
 * @returns {Promise<*>} Original operation result.
 * @throws {*} Original verification failure, or ordinary profile creation/cleanup failure.
 */
export async function withPackagedSmokeProfile(operation, { installed, requireService, writeDiagnostic = console.error }) {
    const profile = await mkdtemp(join(tmpdir(), 'openrdx-packaged-smoke-'))
    try {
        return await operation(profile)
    } catch (error) {
        if (installed === true && requireService === true) {
            try {
                const previous = await readLifecycleTail(join(profile, 'logs', '_RDXManager.bak'))
                const current = await readLifecycleTail(join(profile, 'logs', 'RDXManager.jsonl'))
                const records = [...previous, ...current].slice(-MAX_RECORDS)
                while (Buffer.byteLength(`${PREFIX}${JSON.stringify(records)}`) > MAX_OUTPUT_BYTES) records.shift()
                writeDiagnostic(`${PREFIX}${JSON.stringify(records)}`)
            } catch {
                // Diagnostic storage and output are never authentication evidence.
            }
        }
        throw error
    } finally {
        await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 })
    }
}
