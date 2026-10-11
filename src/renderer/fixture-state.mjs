// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createDeviceSnapshot } from '../shared/contracts.mjs'

/**
 * Freezes a renderer-safe data tree so fixture callers cannot accidentally
 * mutate the state that views and stores consume.
 * @template T
 * @param {T} value - Serializable value to freeze recursively.
 * @returns {T} The deeply frozen value.
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

/**
 * Creates the deterministic RDX snapshot used solely by renderer fixtures.
 * The identity strings mirror the supplied manual screenshot and are not
 * discovery evidence or a real connected device.
 * @returns {object} A frozen, renderer-safe RDX device snapshot.
 */
function createScreenshotDeviceFixture() {
    return createDeviceSnapshot({
        id: 'rdx:7810544062',
        revision: 4,
        vendor: 'TANDBERG',
        product: 'RDX QuikStor USB3+ External',
        serial: '7810544062',
        media: {
            id: 'media:858601695580',
            serial: '858601695580',
            label: 'RDX Cartridge',
            capacityBytes: 1000000000000,
            usedBytes: 428000000000,
            writable: true,
            encrypted: false,
            mounted: true,
            filesystem: 'exfat',
            status: 'ready'
        },
        capabilities: {
            'status-refresh': { state: 'available' },
            'self-test': { state: 'available' },
            'led-test': { state: 'available' },
            'write-read-test': { state: 'available' },
            'firmware-update': { state: 'available' },
            format: { state: 'available' },
            'eject-safe': { state: 'available' }
        }
    })
}

/**
 * Creates a complete immutable renderer fixture state for a named primary UI
 * condition. It never models a live hardware connection.
 * @param {{mode: 'one-device'|'no-device'|'service-unavailable'|'busy'|'operation-failed'}} options - Fixture selection.
 * @returns {object} A serializable, deeply frozen renderer state.
 * @throws {RangeError} When the requested fixture mode is unknown.
 */
export function createFixtureState({ mode }) {
    const device = createScreenshotDeviceFixture()
    const readyState = {
        provenance: 'fixture',
        service: { status: 'ready' },
        discovery: { epoch: 0, listRevision: -1, tombstones: {}, diagnostics: { candidateCount: 1, acceptedCount: 1, rejections: [] }, scanStatus: 'idle' },
        devices: [device],
        selectedDeviceId: device.id,
        activeArea: 'status',
        settings: { autoScan: true, eventLogging: true, language: 'en', lastSafeView: 'status', updateChecks: true },
        activeOperation: null,
        authenticationSessions: {},
        lastOperation: null,
        activity: []
    }

    switch (mode) {
        case 'one-device':
            return deepFreeze(readyState)
        case 'no-device':
            return deepFreeze({ ...readyState, devices: [], selectedDeviceId: null })
        case 'service-unavailable':
            return deepFreeze({
                ...readyState,
                service: { status: 'unavailable', reason: 'service-unavailable' },
                devices: [],
                selectedDeviceId: null
            })
        case 'busy':
            return deepFreeze({
                ...readyState,
                activeOperation: {
                    id: 'op-fixture-firmware-update',
                    kind: 'firmware-update',
                    deviceId: device.id,
                    status: 'started',
                    stage: 'firmware-writing',
                    progress: 0.42
                }
            })
        case 'operation-failed':
            return deepFreeze({
                ...readyState,
                lastOperation: {
                    id: 'op-fixture-self-test',
                    kind: 'self-test',
                    deviceId: device.id,
                    status: 'failed',
                    error: {
                        code: 'transport-timeout',
                        messageKey: 'errors.transport.timeout',
                        stage: 'diagnostic-running',
                        category: 'transport',
                        retryable: true,
                        supportCorrelationId: 'support-fixture-01'
                    }
                }
            })
        default:
            throw new RangeError(`Unknown fixture mode: ${mode}`)
    }
}
