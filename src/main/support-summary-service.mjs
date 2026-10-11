// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomUUID } from 'node:crypto'
import { mkdir } from 'node:fs/promises'
import { isAbsolute, join } from 'node:path'

const SUMMARY_FILENAME = 'RdxSystemSummary.txt'
const ACTIVITY_FILENAME = 'RDXManagerActivity.txt'
const SUMMARY_EXPORT_PREFIX = 'RdxSystemSummary'
const ACTIVITY_EXPORT_PREFIX = 'RDXManagerActivity'
const MAX_DEVICES = 128
const MAX_FIELD_LENGTH = 512

/** @param {unknown} value - Candidate report scalar. @returns {string} Bounded single-line text. */
function safeText(value) {
    if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') return 'Unavailable'
    return (
        String(value)
            .replace(/[\u0000-\u001f\u007f]/g, ' ')
            .trim()
            .slice(0, MAX_FIELD_LENGTH) || 'Unavailable'
    )
}

/** @param {unknown} value - Candidate reported/unavailable status field. @returns {string} Safe field text. */
function readStatusField(value) {
    if (value?.availability === 'reported') return safeText(value.value)
    if (value?.availability === 'unavailable') return `Unavailable (${safeText(value.reason)})`
    return safeText(value)
}

/** @param {object|undefined} direct - Direct compatibility field. @param {object|undefined} details - Typed details. @param {string} key - Exact allowlisted key. @returns {string} Safe selected value. */
function readDeviceField(direct, details, key) {
    return readStatusField(direct?.[key] ?? details?.[key])
}

/** @param {unknown} value - Candidate boolean. @returns {string} Human-readable safe value. */
function yesNo(value) {
    if (value?.availability === 'reported') return value.value === true ? 'Yes' : 'No'
    if (typeof value === 'boolean') return value ? 'Yes' : 'No'
    return readStatusField(value)
}

/** @param {unknown} value - Candidate byte count. @returns {string} Bounded report value. */
function byteCount(value) {
    const candidate = value?.availability === 'reported' ? value.value : value
    return Number.isSafeInteger(candidate) && candidate >= 0 ? `${candidate} bytes` : readStatusField(value)
}

/** @param {object} device - Renderer-safe discovered device. @param {number} index - One-based report index. @returns {string[]} Sanitized device lines. */
function renderDevice(device, index) {
    const drive = device?.drive ?? {}
    const driveDetails = drive.details ?? {}
    const media = device?.media ?? null
    const mediaDetails = media?.details ?? {}
    const lines = ['', `Device ${index}`, '--------', `Vendor: ${safeText(device?.vendor)}`, `Product: ${safeText(device?.product)}`, `Serial number: ${safeText(device?.serial)}`, `Discovery revision: ${safeText(device?.revision)}`, `Firmware revision: ${readDeviceField(drive, driveDetails, 'firmwareRevision')}`, `Connection type: ${readDeviceField(drive, driveDetails, 'connectionType')}`, `Operation mode: ${readDeviceField(drive, driveDetails, 'operationMode')}`, `Drive status: ${readDeviceField(drive, driveDetails, 'status')}`, `Drive errors: ${readDeviceField(drive, driveDetails, 'errors')}`, `Drive sense: ${readDeviceField(drive, driveDetails, 'senseSummary')}`, `Media present: ${media === null ? 'No' : 'Yes'}`]
    if (media !== null) {
        const encrypted = media.encrypted ?? mediaDetails.encrypted
        lines.push(`Cartridge label: ${safeText(media.label)}`, `Cartridge serial: ${safeText(media.serial ?? mediaDetails.serialNumber)}`, `Cartridge status: ${readDeviceField(media, mediaDetails, 'status')}`, `Filesystem: ${safeText(media.filesystem)}`, `Capacity: ${byteCount(media.capacityBytes ?? mediaDetails.capacityBytes)}`, `Write permitted: ${typeof media.writable === 'boolean' ? (media.writable ? 'Yes' : 'No') : 'Unavailable'}`, `Protection state: ${encrypted?.availability === 'reported' ? (encrypted.value ? 'Encrypted' : 'NOT Encrypted') : encrypted === true ? 'Encrypted' : encrypted === false ? 'NOT Encrypted' : 'Unavailable'}`, `Physical write protection: ${yesNo(mediaDetails.writeProtected)}`, `Cartridge sense: ${readDeviceField(media, mediaDetails, 'senseSummary')}`)
    }
    return lines
}

/** @param {object[]} entries - Renderer-safe activity entries. @returns {string} Sanitized text export. */
function renderActivity(entries) {
    const lines = ['OpenRDXManager Activity Export', 'Generated from redacted local event records.', '']
    for (const entry of entries.slice(-500)) {
        const correlation = entry.supportCorrelationId === undefined ? '' : ` | Support ID: ${safeText(entry.supportCorrelationId)}`
        lines.push(`${safeText(entry.occurredAt)} | ${safeText(entry.severity).toUpperCase()} | ${safeText(entry.messageKey)}${correlation}`)
    }
    return `${lines.join('\n')}\n`
}

/** Main-owned sanitized support summary and activity export service. */
export class SupportSummaryService {
    #chooseDestination
    #collect
    #exportDirectory
    #randomUUID
    #writeText

    /**
     * @param {{collect?: () => Promise<object>, chooseDestination?: (defaultName: string) => Promise<object>, exportDirectory?: string, randomUUID?: () => string, writeText?: (path: string, text: string, options?: {exclusive?: boolean}) => Promise<void>}} [options={}] - Main-only collection and file dependencies.
     */
    constructor(options = {}) {
        this.#collect = typeof options.collect === 'function' ? options.collect : null
        this.#chooseDestination = typeof options.chooseDestination === 'function' ? options.chooseDestination : null
        this.#exportDirectory = typeof options.exportDirectory === 'string' && isAbsolute(options.exportDirectory) ? options.exportDirectory : null
        this.#randomUUID = typeof options.randomUUID === 'function' ? options.randomUUID : randomUUID
        this.#writeText = typeof options.writeText === 'function' ? options.writeText : null
    }

    /**
     * Generates a deterministic allowlist-only text summary in memory.
     * @param {object} input - Main-owned host, application, service, and device snapshot.
     * @returns {Promise<string>} Sanitized text report.
     */
    async generate(input) {
        const application = input?.application ?? {}
        const host = input?.host ?? {}
        const service = input?.service ?? {}
        const devices = Array.isArray(input?.devices) ? input.devices.slice(0, MAX_DEVICES) : []
        const lines = ['OpenRDXManager System Summary', '=============================', `Generated at: ${safeText(input?.generatedAt)}`, '', 'Application and host', '--------------------', `Application: ${safeText(application.name)}`, `Manager version: ${safeText(application.version)}`, `Platform: ${safeText(host.platform)}`, `OS release: ${safeText(host.release)}`, `Architecture: ${safeText(host.architecture)}`, '', 'Hardware service', '----------------', `Service status: ${safeText(service.status)}`, `Service mode: ${safeText(service.mode)}`, `Hardware ready: ${yesNo(service.hardwareReady)}`, `Hardware verified: ${yesNo(service.hardwareVerified)}`, `Devices discovered: ${devices.length}`]
        for (let index = 0; index < devices.length; index += 1) lines.push(...renderDevice(devices[index], index + 1))
        lines.push('', 'Privacy: This local report contains only allowlisted diagnostic fields and is never uploaded by OpenRDXManager.')
        return `${lines.join('\n')}\n`
    }

    /** @returns {Promise<object>} Returns one freshly collected sanitized summary without filesystem access. */
    async readSummary() {
        const report = await this.#readSummaryReport()
        return report.ok === true ? { ok: true, text: report.text } : report
    }

    /**
     * Returns only the logger's already redacted renderer-safe activity fields.
     * @param {{list: () => Promise<object>}} logger - EventLogger public read boundary.
     * @returns {Promise<object>} Sanitized in-memory report or stable failure.
     */
    async readActivity(logger) {
        if (typeof logger?.list !== 'function') return { ok: false, reason: 'log-export-unavailable' }
        try {
            const listed = await logger.list()
            if (listed?.ok !== true || !Array.isArray(listed.entries)) return { ok: false, reason: 'log-export-unavailable' }
            return { ok: true, text: renderActivity(listed.entries) }
        } catch {
            return { ok: false, reason: 'log-export-failed' }
        }
    }

    /** @returns {Promise<object>} Saves the sanitized summary through one main-owned chooser. */
    async generateSummary() {
        if (this.#collect === null || this.#chooseDestination === null || this.#writeText === null) return { ok: false, reason: 'support-service-unavailable' }
        try {
            const report = await this.#readSummaryReport()
            if (report.ok !== true) return { ok: false, reason: 'support-summary-save-failed' }
            const destination = await this.#chooseDestination(SUMMARY_FILENAME)
            if (destination?.canceled === true || typeof destination?.filePath !== 'string') return { ok: false, reason: 'export-cancelled' }
            await this.#writeText(destination.filePath, report.text)
            return { ok: true, savedPath: destination.filePath, deviceCount: report.deviceCount }
        } catch {
            return { ok: false, reason: 'support-summary-save-failed' }
        }
    }

    /**
     * Saves only the logger's already redacted renderer-safe activity fields.
     * @param {{list: () => Promise<object>}} logger - EventLogger public read boundary.
     * @returns {Promise<object>} Saved path result or stable failure.
     */
    async exportActivity(logger) {
        if (typeof logger?.list !== 'function' || this.#chooseDestination === null || this.#writeText === null) return { ok: false, reason: 'log-export-unavailable' }
        try {
            const report = await this.readActivity(logger)
            if (report.ok !== true) return report
            const destination = await this.#chooseDestination(ACTIVITY_FILENAME)
            if (destination?.canceled === true || typeof destination?.filePath !== 'string') return { ok: false, reason: 'export-cancelled' }
            await this.#writeText(destination.filePath, report.text)
            return { ok: true, savedPath: destination.filePath }
        } catch {
            return { ok: false, reason: 'log-export-failed' }
        }
    }

    /** @returns {Promise<object>} Exclusively saves one generated sanitized summary in the configured automatic export directory. */
    async exportSummaryAutomatically() {
        if (this.#exportDirectory === null || this.#writeText === null) return { ok: false, reason: 'support-export-unavailable' }
        const report = await this.#readSummaryReport()
        if (report.ok !== true) return report
        try {
            await this.#prepareExportDirectory()
            const savedPath = this.#generatedExportPath(SUMMARY_EXPORT_PREFIX)
            await this.#writeText(savedPath, report.text, { exclusive: true })
            return { ok: true, savedPath }
        } catch {
            return { ok: false, reason: 'support-summary-save-failed' }
        }
    }

    /**
     * Exclusively saves one generated redacted activity report in the configured automatic export directory.
     * @param {{list: () => Promise<object>}} logger - EventLogger public read boundary.
     * @returns {Promise<object>} Saved path result or stable failure.
     */
    async exportActivityAutomatically(logger) {
        if (this.#exportDirectory === null || this.#writeText === null) return { ok: false, reason: 'log-export-unavailable' }
        const report = await this.readActivity(logger)
        if (report.ok !== true) return report
        try {
            await this.#prepareExportDirectory()
            const savedPath = this.#generatedExportPath(ACTIVITY_EXPORT_PREFIX)
            await this.#writeText(savedPath, report.text, { exclusive: true })
            return { ok: true, savedPath }
        } catch {
            return { ok: false, reason: 'log-export-failed' }
        }
    }

    /** @returns {Promise<object>} Collects and renders one sanitized summary with its bounded device count. */
    async #readSummaryReport() {
        if (this.#collect === null) return { ok: false, reason: 'support-service-unavailable' }
        try {
            const input = await this.#collect()
            const devices = Array.isArray(input?.devices) ? input.devices.slice(0, MAX_DEVICES) : []
            return { deviceCount: devices.length, ok: true, text: await this.generate({ ...input, devices }) }
        } catch {
            return { ok: false, reason: 'support-service-unavailable' }
        }
    }

    /** @returns {Promise<void>} Creates the configured application-owned export directory with owner-only defaults. */
    async #prepareExportDirectory() {
        await mkdir(this.#exportDirectory, { mode: 0o700, recursive: true })
    }

    /** @param {string} prefix - Fixed allowlisted report prefix. @returns {string} Generated child path under the configured export directory. */
    #generatedExportPath(prefix) {
        return join(this.#exportDirectory, `${prefix}-${this.#randomUUID()}.txt`)
    }
}
