// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { CapabilityState, OperationKind, RiskClass, createDeviceSnapshot } from '../src/shared/contracts.mjs'
import { getOperationRiskClass } from '../src/main/safety-policy.mjs'
import { deviceSnapshotSchema, operationEventSchema, operationRequestSchema } from '../src/shared/schemas.mjs'

const nativeModelContractFixture = JSON.parse(readFileSync(fileURLToPath(new URL('./fixtures/native-model-contract.json', import.meta.url)), 'utf8'))

/**
 * Verifies that the shared enum values cover the complete public operation
 * surface and use stable renderer-safe strings.
 * @returns {void} Throws when a required contract value is absent.
 */
function testPublishedContractEnums() {
    assert.deepEqual(Object.values(CapabilityState), ['available', 'busy', 'unsupported-product', 'unsupported-platform', 'wrong-media-state', 'authentication-required', 'insufficient-permission', 'host-dependency-missing', 'evidence-incomplete', 'transport-unavailable', 'hardware-unverified'])
    assert.deepEqual(Object.values(RiskClass), ['read-only', 'routine', 'configuration', 'critical', 'destructive'])
    assert.deepEqual(Object.values(OperationKind), ['scan', 'status-refresh', 'access-enable', 'access-disable', 'credential-create', 'credential-change', 'credential-delete', 'credential-reset', 'credential-configure', 'self-test', 'led-test', 'write-read-test', 'firmware-update', 'volume-label-set', 'drive-letter-set', 'drive-letter-reset', 'format', 'drive-mode-set', 'sata-mode-set', 'eject-safe', 'eject-force'])
    assert.equal(Object.isFrozen(CapabilityState), true)
    assert.equal(Object.isFrozen(OperationKind), true)
    assert.equal(Object.isFrozen(RiskClass), true)
}

/**
 * Verifies that the JSON fixture accepted by Rust uses the same strings and
 * serialized request/event shapes accepted at the JavaScript boundary.
 * @returns {void} Throws when the shared native fixture drifts.
 */
function testNativeModelContractFixtureMatchesJavaScriptSchemas() {
    assert.deepEqual(nativeModelContractFixture.capabilityStates, Object.values(CapabilityState))
    assert.deepEqual(nativeModelContractFixture.operationKinds, Object.values(OperationKind))
    assert.deepEqual(nativeModelContractFixture.riskClasses, Object.values(OperationKind).map(getOperationRiskClass))
    assert.equal(operationRequestSchema.safeParse(nativeModelContractFixture.operationRequest).success, true)
    assert.equal(
        nativeModelContractFixture.operationRequests.every((request) => operationRequestSchema.safeParse(request).success),
        true
    )
    assert.equal(operationEventSchema.safeParse(nativeModelContractFixture.operationEvent).success, true)
    assert.equal(operationEventSchema.safeParse(nativeModelContractFixture.firmwareRetryEvent).success, true)
    assert.equal(operationEventSchema.safeParse(nativeModelContractFixture.operationFailureEvent).success, true)
}

/**
 * Verifies that request validation rejects renderer-controlled operating-system
 * paths, raw commands, and unknown object keys.
 * @returns {void} Throws when an unsafe request is accepted.
 */
function testRejectsRendererSuppliedDevicePathsAndUnknownOperationKeys() {
    const request = {
        kind: 'self-test',
        deviceId: 'rdx:7810544062',
        deviceRevision: 4,
        osPath: '/dev/sg4'
    }

    assert.equal(operationRequestSchema.safeParse(request).success, false)
    assert.equal(
        operationRequestSchema.safeParse({
            kind: 'self-test',
            deviceId: 'rdx:7810544062',
            deviceRevision: 4,
            command: '1d0400000000'
        }).success,
        false
    )
}

/**
 * Verifies that the snapshot factory derives no-media state and protects the
 * complete normalized snapshot from mutation.
 * @returns {void} Throws when normalization or immutability is incomplete.
 */
function testNormalizesANoMediaRdxSnapshot() {
    const snapshot = createDeviceSnapshot({
        id: 'rdx:7810544062',
        revision: 4,
        vendor: 'TANDBERG',
        product: 'RDX',
        serial: '7810544062',
        media: null,
        capabilities: { 'self-test': { state: 'available' } }
    })

    assert.equal(snapshot.mediaState, 'no-media')
    assert.equal(Object.isFrozen(snapshot), true)
    assert.equal(Object.isFrozen(snapshot.capabilities), true)
    assert.equal(Object.isFrozen(snapshot.capabilities['self-test']), true)
    assert.deepEqual(snapshot.drive.details.vendor, { availability: 'reported', value: 'TANDBERG' })
    assert.deepEqual(snapshot.drive.details.firmwareRevision, { availability: 'unavailable', reason: 'fixture-not-reported' })
    assert.equal(deviceSnapshotSchema.safeParse(snapshot).success, true)
}

/**
 * Verifies that operation request variants accept only bounded, high-level
 * values and never filesystem locations.
 * @returns {void} Throws when a request variant is not strictly validated.
 */
function testValidatesHighLevelOperationVariants() {
    assert.equal(
        operationRequestSchema.safeParse({
            kind: 'firmware-update',
            deviceId: 'rdx:7810544062',
            deviceRevision: 4,
            firmwareFileToken: 'firmware-selection-1'
        }).success,
        true
    )
    assert.equal(
        operationRequestSchema.safeParse({
            kind: 'firmware-update',
            deviceId: 'rdx:7810544062',
            deviceRevision: 4,
            firmwareFileToken: '/Users/example/update.bin'
        }).success,
        false
    )
    assert.equal(
        operationRequestSchema.safeParse({
            kind: 'drive-mode-set',
            deviceId: 'rdx:7810544062',
            deviceRevision: 4,
            mode: 'fixed'
        }).success,
        true
    )
}

/**
 * Creates a valid renderer-visible device snapshot for direct schema tests.
 * @param {object|null} media - Media value to include in the snapshot.
 * @param {'no-media'|'present'} mediaState - Declared media state.
 * @returns {object} A complete device snapshot fixture.
 */
function createSnapshotFixture(media, mediaState) {
    const snapshot = createDeviceSnapshot({
        id: 'rdx:7810544062',
        revision: 4,
        vendor: 'TANDBERG',
        product: 'RDX',
        serial: '7810544062',
        media,
        capabilities: { 'self-test': { state: 'available' } }
    })
    return { ...structuredClone(snapshot), mediaState }
}

/**
 * Verifies proven native drive facts cross the strict wire contract intact.
 * @returns {void} Throws when status fields are dropped or unsafe extras pass.
 */
function testPreservesStrictDriveStatus() {
    const fixture = createSnapshotFixture(null, 'no-media')
    fixture.drive = {
        firmwareRevision: '0283',
        productType: 'USB 3 / SATA III',
        connectionType: 'USB 3',
        operationMode: 'Fixed disk',
        powerSource: 'Power adapter'
    }
    const { mediaState: _mediaState, ...input } = fixture
    const snapshot = createDeviceSnapshot(input)
    assert.equal(snapshot.drive.firmwareRevision, '0283')
    assert.deepEqual(snapshot.drive.details.firmwareRevision, { availability: 'reported', value: '0283' })
    assert.deepEqual(snapshot.drive.details.status, { availability: 'unavailable', reason: 'fixture-not-reported' })
    assert.throws(() => createDeviceSnapshot({ ...input, drive: { ...fixture.drive, osPath: '/dev/sg2' } }))
}

/**
 * Verifies production snapshots require every typed reason and reject any
 * duplicate legacy value that disagrees with its canonical detail field.
 * @returns {void} Throws when incomplete or contradictory wire state passes.
 */
function testRejectsIncompleteOrContradictoryServiceSnapshots() {
    const complete = createDeviceSnapshot({
        id: 'rdx:strict-service',
        revision: 3,
        vendor: 'TANDBERG',
        product: 'RDX',
        serial: 'STRICT1',
        drive: { firmwareRevision: '0283' },
        media: { id: 'media:strict', capacityBytes: 1000, usedBytes: 400, writable: true },
        capabilities: { 'status-refresh': { state: 'available' } }
    })
    const missingDriveDetails = structuredClone(complete)
    delete missingDriveDetails.drive.details
    const contradictoryFirmware = structuredClone(complete)
    contradictoryFirmware.drive.firmwareRevision = '9999'
    const contradictoryWritable = structuredClone(complete)
    contradictoryWritable.media.writable = false
    const missingMediaReason = structuredClone(complete)
    delete missingMediaReason.media.details.senseSummary

    assert.equal(deviceSnapshotSchema.safeParse(missingDriveDetails).success, false)
    assert.equal(deviceSnapshotSchema.safeParse(contradictoryFirmware).success, false)
    assert.equal(deviceSnapshotSchema.safeParse(contradictoryWritable).success, false)
    assert.equal(deviceSnapshotSchema.safeParse(missingMediaReason).success, false)
}

/**
 * Verifies the native service's machine-readable cartridge reason and its
 * equivalent human-readable status survive the strict service boundary.
 * @returns {void} Throws when equivalent status forms are rejected or a real
 * mismatch is accepted.
 */
function testAcceptsEquivalentNativeMediaStatusForms() {
    const snapshot = structuredClone(
        createDeviceSnapshot({
            id: 'rdx:native-media-status',
            revision: 3,
            vendor: 'TANDBERG',
            product: 'RDX',
            serial: 'STATUS1',
            media: { id: 'media:status', status: 'good' },
            capabilities: { 'status-refresh': { state: 'available' } }
        })
    )
    snapshot.media.details.status = { availability: 'reported', value: 'Good' }
    const contradictory = structuredClone(snapshot)
    contradictory.media.details.status = { availability: 'reported', value: 'Cartridge error' }

    assert.equal(deviceSnapshotSchema.safeParse(snapshot).success, true)
    assert.equal(deviceSnapshotSchema.safeParse(contradictory).success, false)
}

/**
 * Verifies the production snapshot accepts only a bounded sorted unique D-Z
 * letter list and never accepts system letters or path-shaped host values.
 * @returns {void} Throws when unsafe host letter evidence crosses the bridge.
 */
function testValidatesAvailableDriveLetterSnapshotFacts() {
    const complete = createDeviceSnapshot({
        id: 'rdx:drive-letters',
        revision: 3,
        vendor: 'TANDBERG',
        product: 'RDX',
        serial: 'LETTERS1',
        drive: { availableDriveLetters: ['D', 'R', 'Z'], connectionType: 'USB 3' },
        media: null,
        capabilities: { 'drive-letter-set': { state: 'available' }, 'drive-letter-reset': { state: 'available' } }
    })
    assert.equal(deviceSnapshotSchema.safeParse(complete).success, true)
    assert.deepEqual(complete.drive.availableDriveLetters, ['D', 'R', 'Z'])

    for (const invalid of [['C'], ['R', 'D'], ['R', 'R'], ['R:\\\\']]) {
        const candidate = structuredClone(complete)
        candidate.drive.availableDriveLetters = invalid
        assert.equal(deviceSnapshotSchema.safeParse(candidate).success, false)
    }
}

/**
 * Verifies complete field availability is typed, bounded, and path-free across
 * the native-to-renderer snapshot contract.
 * @returns {void} Throws when unavailable reasons are dropped or malformed.
 */
function testPreservesTypedStatusAvailability() {
    const fixture = createSnapshotFixture(
        {
            id: 'media:fixture',
            details: {
                vendor: { availability: 'unavailable', reason: 'status-probe-unavailable' },
                model: { availability: 'unavailable', reason: 'status-probe-unavailable' },
                serialNumber: { availability: 'unavailable', reason: 'status-probe-unavailable' },
                status: { availability: 'unavailable', reason: 'status-probe-unavailable' },
                loadCount: { availability: 'unavailable', reason: 'field-decoder-unavailable' },
                hddFirmware: { availability: 'unavailable', reason: 'field-decoder-unavailable' },
                cartridgeType: { availability: 'unavailable', reason: 'field-decoder-unavailable' },
                writeProtected: { availability: 'reported', value: false },
                temperatureCelsius: { availability: 'unavailable', reason: 'status-probe-unavailable' },
                capacityBytes: { availability: 'reported', value: 1000 },
                usedBytes: { availability: 'reported', value: 400 },
                freeBytes: { availability: 'reported', value: 600 },
                mounted: { availability: 'reported', value: true },
                bytesRead: { availability: 'unavailable', reason: 'field-decoder-unavailable' },
                bytesWritten: { availability: 'unavailable', reason: 'field-decoder-unavailable' },
                encrypted: { availability: 'unavailable', reason: 'not-reported' },
                supportStatus: { availability: 'unavailable', reason: 'status-probe-unavailable' },
                senseSummary: { availability: 'unavailable', reason: 'no-safe-sense-available' }
            }
        },
        'present'
    )
    fixture.drive = {
        details: {
            oemName: { availability: 'unavailable', reason: 'not-reported' },
            serialNumber: { availability: 'reported', value: '7810544062' },
            product: { availability: 'reported', value: 'RDX' },
            vendor: { availability: 'reported', value: 'TANDBERG' },
            firmwareRevision: { availability: 'reported', value: '0283' },
            bornOnDate: { availability: 'unavailable', reason: 'not-reported' },
            productType: { availability: 'reported', value: 'USB 3 / SATA III' },
            connectionType: { availability: 'reported', value: 'USB 3' },
            operationMode: { availability: 'unavailable', reason: 'status-probe-unavailable' },
            sataMode: { availability: 'reported', value: '3g-6g' },
            status: { availability: 'unavailable', reason: 'field-decoder-unavailable' },
            loadCount: { availability: 'unavailable', reason: 'field-decoder-unavailable' },
            errors: { availability: 'unavailable', reason: 'field-decoder-unavailable' },
            camState: { availability: 'unavailable', reason: 'field-decoder-unavailable' },
            policy: { availability: 'unavailable', reason: 'field-decoder-unavailable' },
            powerSource: { availability: 'reported', value: 'Power adapter' },
            supportStatus: { availability: 'unavailable', reason: 'status-probe-unavailable' },
            senseSummary: { availability: 'unavailable', reason: 'no-safe-sense-available' }
        }
    }
    const { mediaState: _mediaState, ...input } = fixture
    const snapshot = createDeviceSnapshot(input)
    assert.deepEqual(snapshot.drive.details, fixture.drive.details)
    assert.equal(snapshot.drive.sataMode, '3g-6g')
    assert.deepEqual(snapshot.media.details, fixture.media.details)
    assert.throws(() =>
        createDeviceSnapshot({
            ...input,
            drive: { details: { ...fixture.drive.details, status: { availability: 'unavailable', reason: '/dev/sg2' } } }
        })
    )
    assert.throws(() =>
        createDeviceSnapshot({
            ...input,
            drive: { details: { ...fixture.drive.details, loadCount: { availability: 'reported', value: Number.MAX_SAFE_INTEGER + 1 } } }
        })
    )
}

/**
 * Verifies that scan is global but status refresh is locked to an opaque,
 * revisioned device target.
 * @returns {void} Throws when target scope is not enforced.
 */
function testScopesStatusRefreshToADeviceTarget() {
    assert.equal(operationRequestSchema.safeParse({ kind: 'scan' }).success, true)
    assert.equal(
        operationRequestSchema.safeParse({
            kind: 'scan',
            deviceId: 'rdx:7810544062',
            deviceRevision: 4
        }).success,
        false
    )
    assert.equal(
        operationRequestSchema.safeParse({
            kind: 'status-refresh',
            deviceId: 'rdx:7810544062',
            deviceRevision: 4
        }).success,
        true
    )
    assert.equal(operationRequestSchema.safeParse({ kind: 'status-refresh' }).success, false)
}

/**
 * Verifies that direct snapshot validation accepts only internally consistent
 * media and media-state pairs.
 * @returns {void} Throws when contradictory snapshots are accepted.
 */
function testRejectsContradictoryDeviceMediaStates() {
    const media = { id: 'media:7810544062', writable: true }

    assert.equal(deviceSnapshotSchema.safeParse(createSnapshotFixture(null, 'no-media')).success, true)
    assert.equal(deviceSnapshotSchema.safeParse(createSnapshotFixture(media, 'present')).success, true)
    assert.equal(deviceSnapshotSchema.safeParse(createSnapshotFixture(null, 'present')).success, false)
    assert.equal(deviceSnapshotSchema.safeParse(createSnapshotFixture(media, 'no-media')).success, false)
}

/**
 * Verifies that sparse capability maps do not permit renderer-visible features
 * outside the published operation contract.
 * @returns {void} Throws when an unknown capability key is accepted.
 */
function testRejectsUnknownCapabilityMapKeys() {
    const snapshot = createSnapshotFixture(null, 'no-media')
    snapshot.capabilities['raw-command'] = { state: 'available' }

    assert.equal(deviceSnapshotSchema.safeParse(snapshot).success, false)
}

/**
 * Verifies that renderer-visible events remain structured, bounded, and strict.
 * @returns {void} Throws when an event contains an unsafe or malformed field.
 */
function testValidatesStructuredOperationEvents() {
    const event = {
        operationId: 'op:19',
        kind: 'self-test',
        deviceId: 'rdx:7810544062',
        deviceRevision: 4,
        state: 'progress',
        stage: 'diagnostic-running',
        progress: 0.5,
        cancellationState: 'cancellable',
        messageKey: 'tests.selfTest.running'
    }

    const failure = {
        operationId: 'op:20',
        kind: 'self-test',
        deviceId: 'rdx:7810544062',
        deviceRevision: 4,
        state: 'failed',
        stage: 'diagnostic-cleanup',
        error: {
            code: 'transport-timeout',
            messageKey: 'errors.transport.timeout',
            stage: 'diagnostic-running',
            category: 'transport',
            retryable: true,
            senseSummary: {
                key: 'not-ready',
                asc: 4,
                ascq: 1,
                messageKey: 'errors.sense.notReady'
            },
            supportCorrelationId: 'support-20260825-01',
            cleanupEvidence: [],
            attemptHistory: []
        }
    }

    assert.equal(operationEventSchema.safeParse(event).success, true)
    const { cancellationState: _omittedCancellationState, ...missingCancellationState } = event
    assert.equal(operationEventSchema.safeParse(missingCancellationState).success, false)
    assert.equal(operationEventSchema.safeParse({ ...event, cancellationState: 'maybe' }).success, false)
    assert.equal(operationEventSchema.safeParse(failure).success, true)
    assert.equal(operationEventSchema.safeParse({ ...failure, error: { ...failure.error, rawSense: '700002' } }).success, false)
    assert.equal(operationEventSchema.safeParse({ ...failure, rawCdb: '1d0400000000' }).success, false)
    assert.equal(operationEventSchema.safeParse({ ...failure, error: undefined }).success, false)
}

test('publishes stable device operation enum contracts', testPublishedContractEnums)
test('shares enum and serialized model fixtures with the native service', testNativeModelContractFixtureMatchesJavaScriptSchemas)
test('rejects renderer supplied device paths and unknown operation keys', testRejectsRendererSuppliedDevicePathsAndUnknownOperationKeys)
test('normalizes a no-media RDX snapshot', testNormalizesANoMediaRdxSnapshot)
test('preserves strict path-free native drive status', testPreservesStrictDriveStatus)
test('rejects incomplete or contradictory production service snapshots', testRejectsIncompleteOrContradictoryServiceSnapshots)
test('accepts equivalent native machine and display media status forms', testAcceptsEquivalentNativeMediaStatusForms)
test('validates bounded available Windows drive-letter snapshot facts', testValidatesAvailableDriveLetterSnapshotFacts)
test('preserves typed per-field status availability', testPreservesTypedStatusAvailability)
test('validates high-level operation variants', testValidatesHighLevelOperationVariants)
test('scopes status refresh to a device target', testScopesStatusRefreshToADeviceTarget)
test('rejects contradictory device media states', testRejectsContradictoryDeviceMediaStates)
test('rejects unknown capability map keys', testRejectsUnknownCapabilityMapKeys)
test('validates structured operation events', testValidatesStructuredOperationEvents)
