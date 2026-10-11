// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { CapabilityState, OperationKind, RiskClass, deviceSnapshotSchema, fixtureDeviceSnapshotInputSchema } from './schemas.mjs'

export { CapabilityState, OperationKind, RiskClass }

/**
 * Recursively freezes a parsed data-only value so renderer state cannot be
 * changed outside its explicit store transition path.
 * @template T
 * @param {T} value - Parsed snapshot value to freeze.
 * @returns {T} The same deeply frozen value.
 */
function deepFreeze(value) {
    if (value === null || typeof value !== 'object' || Object.isFrozen(value)) {
        return value
    }

    for (const nestedValue of Object.values(value)) {
        deepFreeze(nestedValue)
    }
    return Object.freeze(value)
}

/** @param {unknown} value - Optional fixture value. @returns {object} Canonical typed field. */
function fixtureStatusField(value) {
    return value === undefined || value === null ? { availability: 'unavailable', reason: 'fixture-not-reported' } : { availability: 'reported', value }
}

/** @param {object} field - Canonical typed field. @returns {unknown} Reported value or undefined. */
function reportedFixtureValue(field) {
    return field.availability === 'reported' ? field.value : undefined
}

/**
 * Produces complete canonical drive details and derives every legacy duplicate.
 * @param {object|undefined} drive - Optional legacy fixture drive.
 * @param {{vendor: string, product: string, serial: string}} identity - Required fixture identity.
 * @returns {object} Complete production-shaped drive projection.
 */
function normalizeFixtureDrive(drive, identity) {
    const details = drive?.details ?? {
        oemName: fixtureStatusField(),
        serialNumber: fixtureStatusField(identity.serial),
        product: fixtureStatusField(identity.product),
        vendor: fixtureStatusField(identity.vendor),
        firmwareRevision: fixtureStatusField(drive?.firmwareRevision),
        bornOnDate: fixtureStatusField(),
        productType: fixtureStatusField(drive?.productType),
        connectionType: fixtureStatusField(drive?.connectionType),
        operationMode: fixtureStatusField(drive?.operationMode),
        sataMode: fixtureStatusField(drive?.sataMode),
        status: fixtureStatusField(),
        loadCount: fixtureStatusField(),
        errors: fixtureStatusField(),
        camState: fixtureStatusField(),
        policy: fixtureStatusField(),
        powerSource: fixtureStatusField(drive?.powerSource),
        supportStatus: fixtureStatusField(),
        senseSummary: { availability: 'unavailable', reason: 'no-safe-sense-available' }
    }
    const normalized = {
        ...(drive?.availableDriveLetters === undefined ? {} : { availableDriveLetters: drive.availableDriveLetters }),
        details
    }
    for (const key of ['firmwareRevision', 'productType', 'connectionType', 'operationMode', 'sataMode', 'powerSource']) {
        const value = reportedFixtureValue(details[key])
        if (value !== undefined) normalized[key] = value
    }
    return normalized
}

/**
 * Produces complete canonical media details and derives every legacy duplicate.
 * @param {object|null} media - Optional legacy fixture media.
 * @returns {object|null} Complete production-shaped media projection.
 */
function normalizeFixtureMedia(media) {
    if (media === null) return null
    const freeBytes = typeof media.capacityBytes === 'number' && typeof media.usedBytes === 'number' && media.capacityBytes >= media.usedBytes ? media.capacityBytes - media.usedBytes : undefined
    const details = media.details ?? {
        vendor: fixtureStatusField(),
        model: fixtureStatusField(),
        serialNumber: fixtureStatusField(media.serial),
        status: fixtureStatusField(media.status),
        loadCount: fixtureStatusField(),
        hddFirmware: fixtureStatusField(),
        cartridgeType: fixtureStatusField(),
        writeProtected: fixtureStatusField(typeof media.writable === 'boolean' ? !media.writable : undefined),
        temperatureCelsius: fixtureStatusField(),
        capacityBytes: fixtureStatusField(media.capacityBytes),
        usedBytes: fixtureStatusField(media.usedBytes),
        freeBytes: fixtureStatusField(freeBytes),
        mounted: fixtureStatusField(media.mounted),
        bytesRead: fixtureStatusField(),
        bytesWritten: fixtureStatusField(),
        encrypted: fixtureStatusField(media.encrypted),
        supportStatus: fixtureStatusField(),
        senseSummary: { availability: 'unavailable', reason: 'no-safe-sense-available' }
    }
    const normalized = { id: media.id, ...(media.label === undefined ? {} : { label: media.label }), ...(media.filesystem === undefined ? {} : { filesystem: media.filesystem }), details }
    const directFields = [
        ['serial', details.serialNumber],
        ['status', details.status],
        ['capacityBytes', details.capacityBytes],
        ['usedBytes', details.usedBytes],
        ['encrypted', details.encrypted]
    ]
    for (const [key, field] of directFields) {
        const value = reportedFixtureValue(field)
        if (value !== undefined) normalized[key] = value
    }
    const writeProtected = reportedFixtureValue(details.writeProtected)
    if (typeof writeProtected === 'boolean') normalized.writable = !writeProtected
    return normalized
}

/**
 * Validates and normalizes a concise trusted fixture into renderer-safe state.
 * Production service messages use `deviceSnapshotSchema` directly and cannot
 * omit typed details. OS paths and transport details remain excluded here.
 * @param {object} input - Unnormalized local fixture data.
 * @returns {object} A deeply frozen device snapshot with derived media state.
 * @throws {z.ZodError} When input is malformed or includes an unsafe field.
 */
export function createDeviceSnapshot(input) {
    const parsed = fixtureDeviceSnapshotInputSchema.parse(input)
    const snapshot = {
        ...parsed,
        drive: normalizeFixtureDrive(parsed.drive, parsed),
        media: normalizeFixtureMedia(parsed.media),
        mediaState: parsed.media === null ? 'no-media' : 'present'
    }

    return deepFreeze(deviceSnapshotSchema.parse(snapshot))
}
