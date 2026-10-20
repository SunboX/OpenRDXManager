// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { assertAuthenticatedServiceReadiness, SmokeReadinessError } from './smoke-readiness.mjs'

/**
 * Requires actual validated discovery through an authenticated installed service.
 * Capability flags alone never establish access to a connected dock.
 * @param {object} readiness - Native service handshake evidence.
 * @param {object} result - Main-owned, schema-validated devices-list response.
 * @param {string|undefined} expectedId - Optional exact opaque selected dock ID.
 * @param {string|undefined} expectedFirmware - Optional exact reported revision on that dock.
 * @returns {number} Number of validated docks in the authoritative inventory.
 * @throws {Error} When service proof, discovery, or exact selected identity is absent.
 */
export function assertInstalledDeviceDiscovery(readiness, result, expectedId, expectedFirmware) {
    assertAuthenticatedServiceReadiness(readiness)
    if (expectedId !== undefined && !/^rdx:[a-z0-9:-]+$/iu.test(expectedId)) throw new SmokeReadinessError('installed-device-target-invalid')
    if (result?.ok !== true || !Array.isArray(result.devices) || result.devices.length === 0) throw new SmokeReadinessError('installed-device-discovery-empty')
    if (expectedId !== undefined && !result.devices.some((device) => device.id === expectedId)) throw new SmokeReadinessError('installed-device-target-not-found')
    if (expectedFirmware !== undefined) {
        if (expectedId === undefined || !/^[a-z0-9._-]{1,32}$/iu.test(expectedFirmware)) throw new SmokeReadinessError('installed-firmware-target-invalid')
        const revision = result.devices.find((device) => device.id === expectedId)?.drive?.details?.firmwareRevision
        if (revision?.availability !== 'reported' || revision.value !== expectedFirmware) throw new SmokeReadinessError('installed-firmware-revision-mismatch')
    }
    return result.devices.length
}
