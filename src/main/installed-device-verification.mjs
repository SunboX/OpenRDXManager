// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { assertAuthenticatedServiceReadiness, SmokeReadinessError } from './smoke-readiness.mjs'

/**
 * Requires actual validated discovery through an authenticated installed service.
 * Capability flags alone never establish access to a connected dock.
 * @param {object} readiness - Native service handshake evidence.
 * @param {object} result - Main-owned, schema-validated devices-list response.
 * @param {string|undefined} expectedId - Optional exact opaque selected dock ID.
 * @returns {number} Number of validated docks in the authoritative inventory.
 * @throws {Error} When service proof, discovery, or exact selected identity is absent.
 */
export function assertInstalledDeviceDiscovery(readiness, result, expectedId) {
    assertAuthenticatedServiceReadiness(readiness)
    if (expectedId !== undefined && !/^rdx:[a-z0-9:-]+$/iu.test(expectedId)) throw new SmokeReadinessError('installed-device-target-invalid')
    if (result?.ok !== true || !Array.isArray(result.devices) || result.devices.length === 0) throw new SmokeReadinessError('installed-device-discovery-empty')
    if (expectedId !== undefined && !result.devices.some((device) => device.id === expectedId)) throw new SmokeReadinessError('installed-device-target-not-found')
    return result.devices.length
}
