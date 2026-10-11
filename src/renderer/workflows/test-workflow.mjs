// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { OperationKind } from '../../shared/contracts.mjs'

const MINIMUM_WRITE_READ_BYTES = 64 * 1024
const DIAGNOSTIC_KINDS = new Set([OperationKind.SELF_TEST, OperationKind.LED_TEST, OperationKind.WRITE_READ_TEST])
const STAGES = Object.freeze({
    [OperationKind.SELF_TEST]: Object.freeze([Object.freeze({ id: 'diagnostic-running', labelKey: 'tests.stage.diagnosticRunning' }), Object.freeze({ id: 'diagnostic-cleanup', labelKey: 'tests.stage.revalidateSelectedDevice' })]),
    [OperationKind.LED_TEST]: Object.freeze([Object.freeze({ id: 'led-testing', labelKey: 'tests.stage.ledTesting' }), Object.freeze({ id: 'led-restoring', labelKey: 'tests.stage.ledRestoring' }), Object.freeze({ id: 'led-readback', labelKey: 'tests.stage.revalidateSelectedDevice' })]),
    [OperationKind.WRITE_READ_TEST]: Object.freeze([Object.freeze({ id: 'host-writing', labelKey: 'tests.stage.hostWriting' }), Object.freeze({ id: 'host-reading', labelKey: 'tests.stage.hostReading' }), Object.freeze({ id: 'host-cleanup', labelKey: 'tests.stage.hostCleanup' })])
})

const PRESENTATION = Object.freeze({
    [OperationKind.SELF_TEST]: Object.freeze({
        actionLabelKey: 'tests.selfTest.action',
        descriptionKey: 'tests.selfTest.description',
        icon: 'ph-stethoscope',
        protocol: '1D 04 00 00 00 00',
        titleKey: 'tests.selfTest.title'
    }),
    [OperationKind.LED_TEST]: Object.freeze({
        actionLabelKey: 'tests.ledTest.action',
        descriptionKey: 'tests.ledTest.description',
        icon: 'ph-lightbulb-filament',
        protocolKey: 'tests.ledTest.protocol',
        titleKey: 'tests.ledTest.title'
    }),
    [OperationKind.WRITE_READ_TEST]: Object.freeze({
        actionLabelKey: 'tests.writeReadTest.action',
        descriptionKey: 'tests.writeReadTest.description',
        icon: 'ph-file-arrow-up',
        protocolKey: 'tests.writeReadTest.protocol',
        titleKey: 'tests.writeReadTest.title'
    })
})

/**
 * Reads one canonical renderer-safe reported field without using unavailable
 * metadata as a false value.
 * @param {object|undefined} field - Typed reported-or-unavailable field.
 * @returns {unknown} Reported value or undefined.
 */
function reportedValue(field) {
    return field?.availability === 'reported' ? field.value : undefined
}

/**
 * Creates one immutable prerequisite row.
 * @param {string} id - Stable prerequisite identifier.
 * @param {string} labelKey - Bundled requirement message key.
 * @param {boolean} met - Whether the current snapshot proves the requirement.
 * @param {string} detailKey - Bundled current-state message key.
 * @returns {object} Frozen prerequisite presentation.
 */
function prerequisite(id, labelKey, met, detailKey) {
    return Object.freeze({ detailKey, id, labelKey, met })
}

/**
 * Derives every documented Write/Read prerequisite independently so the UI can
 * explain multiple simultaneous blockers instead of showing only the first.
 * @param {object} device - Selected renderer-safe RDX snapshot.
 * @returns {object[]} Frozen prerequisite rows.
 */
function writeReadPrerequisites(device) {
    const media = device?.media ?? null
    const freeBytes = reportedValue(media?.details?.freeBytes)
    const inserted = media !== null
    const mounted = inserted && reportedValue(media.details?.mounted) === true
    const writable = inserted && media.writable === true
    const spaceAvailable = inserted && typeof freeBytes === 'number' && freeBytes >= MINIMUM_WRITE_READ_BYTES
    return Object.freeze([prerequisite('media-inserted', 'tests.prerequisite.mediaInserted.label', inserted, inserted ? 'tests.prerequisite.mediaInserted.present' : 'tests.prerequisite.mediaInserted.absent'), prerequisite('media-formatted', 'tests.prerequisite.mediaFormatted.label', mounted, mounted ? 'tests.prerequisite.mediaFormatted.met' : 'tests.prerequisite.mediaFormatted.unmet'), prerequisite('write-access', 'tests.prerequisite.writeAccess.label', writable, writable ? 'tests.prerequisite.writeAccess.met' : 'tests.prerequisite.writeAccess.unmet'), prerequisite('free-space', 'tests.prerequisite.freeSpace.label', spaceAvailable, spaceAvailable ? 'tests.prerequisite.freeSpace.met' : 'tests.prerequisite.freeSpace.unmet')])
}

/**
 * Derives informative prerequisites for diagnostic commands that deliberately
 * allow both media states.
 * @param {object} device - Selected renderer-safe RDX snapshot.
 * @param {string} kind - Published diagnostic operation kind.
 * @returns {object[]} Frozen prerequisite rows.
 */
function diagnosticPrerequisites(device, kind) {
    if (kind === OperationKind.WRITE_READ_TEST) return writeReadPrerequisites(device)
    if (kind === OperationKind.SELF_TEST) {
        return Object.freeze([prerequisite('device-selected', 'tests.prerequisite.validatedDock.label', typeof device?.id === 'string', 'tests.prerequisite.validatedDock.selfTestDetail'), prerequisite('media-optional', 'tests.prerequisite.cartridgeState.label', true, device?.media === null ? 'tests.prerequisite.cartridgeState.noMedia' : 'tests.prerequisite.cartridgeState.withMedia')])
    }
    return Object.freeze([prerequisite('device-selected', 'tests.prerequisite.validatedDock.label', typeof device?.id === 'string', 'tests.prerequisite.validatedDock.ledTestDetail'), prerequisite('media-optional', 'tests.prerequisite.cartridgeObservation.label', true, device?.media === null ? 'tests.prerequisite.cartridgeObservation.noMedia' : 'tests.prerequisite.cartridgeObservation.withMedia')])
}

/**
 * Returns whether every mandatory prerequisite is currently proven.
 * Informative optional rows are represented as met and therefore do not block.
 * @param {object[]} prerequisites - Complete current workflow prerequisites.
 * @returns {boolean} True when every row is met.
 */
function allPrerequisitesMet(prerequisites) {
    for (const item of prerequisites) {
        if (item.met !== true) return false
    }
    return true
}

/**
 * Resolves device capability, host prerequisites, renderer intent availability,
 * and the global operation lock without ever promoting malformed input.
 * @param {object} device - Selected renderer-safe RDX snapshot.
 * @param {string} kind - Published diagnostic operation kind.
 * @param {object[]} prerequisites - Derived requirements.
 * @param {{locked?: boolean, operationIntentAvailable?: boolean}} options - Current shell boundaries.
 * @returns {{state: string, reason: string}} Fail-closed capability decision.
 */
function resolveCapability(device, kind, prerequisites, options) {
    const reported = device?.capabilities?.[kind]
    if (reported?.state !== 'available') {
        return Object.freeze({ reason: typeof reported?.reason === 'string' ? reported.reason : 'diagnostic-capability-not-reported', state: typeof reported?.state === 'string' ? reported.state : 'evidence-incomplete' })
    }
    if (options.locked === true) return Object.freeze({ reason: 'operation-in-progress', state: 'busy' })
    if (options.operationIntentAvailable === false) return Object.freeze({ reason: 'operation-intent-unavailable', state: 'transport-unavailable' })
    if (!allPrerequisitesMet(prerequisites)) return Object.freeze({ reason: 'diagnostic-prerequisites-not-met', state: 'wrong-media-state' })
    return Object.freeze({ reason: '', state: 'available' })
}

/**
 * Builds a complete immutable diagnostic workflow from current device state.
 * The workflow contains presentation and prerequisite data only; it cannot
 * construct a CDB, native path, filename, payload, or selector.
 * @param {object} device - Selected renderer-safe RDX snapshot.
 * @param {'self-test'|'led-test'|'write-read-test'} kind - Diagnostic operation kind.
 * @param {{locked?: boolean, operationIntentAvailable?: boolean}} [options={}] - Current shell boundaries.
 * @returns {object} Frozen workflow presentation.
 * @throws {RangeError} When kind is not one of the three published diagnostics.
 */
export function createDiagnosticWorkflow(device, kind, options = {}) {
    if (!DIAGNOSTIC_KINDS.has(kind)) throw new RangeError('Unknown diagnostic operation kind')
    const prerequisites = diagnosticPrerequisites(device, kind)
    const presentation = PRESENTATION[kind]
    const workflow = {
        ...presentation,
        capability: resolveCapability(device, kind, prerequisites, options),
        kind,
        prerequisites,
        stages: STAGES[kind]
    }
    if (kind === OperationKind.SELF_TEST) {
        workflow.twoPass = Object.freeze({
            currentPass: device?.media === null ? 'drive-only' : 'drive-and-cartridge',
            firstKey: 'tests.twoPass.first',
            secondKey: 'tests.twoPass.second'
        })
    } else if (kind === OperationKind.LED_TEST) {
        workflow.cleanupGuidanceKey = 'tests.ledTest.cleanupGuidance'
    } else {
        workflow.cleanupGuidanceKey = 'tests.writeReadTest.cleanupGuidance'
    }
    return Object.freeze(workflow)
}

/**
 * Accepts only renderer-safe reason tokens for diagnostic evidence copy.
 * @param {unknown} value - Candidate wire reason.
 * @param {string} fallback - Safe fallback text.
 * @returns {string} Bounded reason token.
 */
function safeReason(value, fallback) {
    return typeof value === 'string' && /^[a-z][a-z0-9-]{0,127}$/.test(value) ? value : fallback
}

/**
 * Creates one safe localizable terminal failure without stack traces or payloads.
 * @param {object} error - Strict renderer operation error.
 * @returns {object} Message key and bounded raw result-token parameters.
 */
function primaryFailure(error) {
    const code = safeReason(error?.code, 'diagnostic-failed')
    const stage = safeReason(error?.stage, 'unknown-stage')
    if (error?.senseSummary !== undefined) {
        const sense = safeReason(error.senseSummary.key, 'sense-reported')
        const bytes = [error.senseSummary.asc, error.senseSummary.ascq].filter((value) => Number.isInteger(value)).map((value) => `0x${value.toString(16).padStart(2, '0')}`)
        return Object.freeze({
            key: 'tests.result.failureWithSense',
            params: Object.freeze({ bytes: bytes.length > 0 ? ` (${bytes.join('/')})` : '', code, sense, stage })
        })
    }
    return Object.freeze({ key: 'tests.result.failureAt', params: Object.freeze({ code, stage }) })
}

/**
 * Formats bounded cleanup evidence separately from the primary result.
 * @param {object[]} evidence - Strict cleanup evidence entries.
 * @returns {object[]|undefined} Localizable cleanup failures, when present.
 */
function cleanupFailures(evidence) {
    if (!Array.isArray(evidence) || evidence.length === 0) return undefined
    const summaries = []
    for (const item of evidence) {
        summaries.push(
            Object.freeze({
                key: 'tests.result.failureAt',
                params: Object.freeze({ code: safeReason(item?.code, 'cleanup-failed'), stage: safeReason(item?.stage, 'cleanup') })
            })
        )
    }
    return Object.freeze(summaries)
}

/**
 * Builds operation-specific success evidence that is guaranteed by reaching the
 * existing native terminal success state.
 * @param {string} kind - Published diagnostic kind.
 * @returns {object[]} Frozen evidence rows.
 */
function successEvidence(kind) {
    if (kind === OperationKind.LED_TEST) {
        return Object.freeze([Object.freeze({ labelKey: 'tests.result.deviceResult', value: 'SCSI GOOD' }), Object.freeze({ labelKey: 'tests.result.ledCleanup', valueKey: 'tests.result.normalLedOwnershipRestored' })])
    }
    if (kind === OperationKind.WRITE_READ_TEST) {
        return Object.freeze([Object.freeze({ labelKey: 'tests.result.dataPath', valueKey: 'tests.result.dataPathPassed' }), Object.freeze({ labelKey: 'tests.result.testFileCleanup', valueKey: 'tests.result.testFileRemoved' })])
    }
    return Object.freeze([Object.freeze({ labelKey: 'tests.result.deviceResult', value: 'SCSI GOOD' }), Object.freeze({ labelKey: 'tests.result.finalValidation', valueKey: 'tests.result.deviceRevalidated' })])
}

/**
 * Converts one strict terminal diagnostic event into the shared result-panel
 * model while preserving primary and cleanup outcomes independently.
 * @param {object|null} operation - Renderer terminal operation record.
 * @returns {object|null} Frozen result presentation, or null for unrelated/nonterminal input.
 */
export function createDiagnosticResult(operation) {
    if (!DIAGNOSTIC_KINDS.has(operation?.kind) || !['succeeded', 'failed', 'cancelled'].includes(operation?.status)) return null
    const presentation = PRESENTATION[operation.kind]
    if (operation.status === 'succeeded') {
        return Object.freeze({ evidence: successEvidence(operation.kind), status: 'succeeded', summaryKey: 'tests.result.succeededSummary', testTitleKey: presentation.titleKey, titleKey: 'tests.result.passedTitle' })
    }
    if (operation.status === 'cancelled') {
        return Object.freeze({ evidence: Object.freeze([{ labelKey: 'tests.result.terminalStage', value: safeReason(operation.stage, 'cancelled') }]), status: 'cancelled', summaryKey: 'tests.result.cancelledSummary', testTitleKey: presentation.titleKey, titleKey: 'tests.result.cancelledTitle' })
    }
    return Object.freeze({
        cleanupFailures: cleanupFailures(operation.error?.cleanupEvidence),
        evidence: Object.freeze([Object.freeze(typeof operation.error?.supportCorrelationId === 'string' ? { labelKey: 'tests.result.supportId', value: operation.error.supportCorrelationId } : { labelKey: 'tests.result.supportId', valueKey: 'state.notReported' }), Object.freeze({ labelKey: 'tests.result.retryable', valueKey: operation.error?.retryable === true ? 'tests.value.yes' : 'tests.value.no' })]),
        primaryFailure: primaryFailure(operation.error),
        status: 'failed',
        summaryKey: 'tests.result.failedSummary',
        testTitleKey: presentation.titleKey,
        titleKey: 'tests.result.failedTitle'
    })
}
