// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { OperationCoordinator } from '../src/main/operation-coordinator.mjs'
import { operationEventSchema } from '../src/shared/schemas.mjs'

/** @returns {object} One complete lossless firmware failure terminal. */
function firmwareFailure() {
    return {
        state: 'failed',
        operationId: 'op:failure-contract',
        kind: 'firmware-update',
        deviceId: 'rdx:1',
        deviceRevision: 7,
        stage: 'firmware-readback',
        error: {
            code: 'firmware-revision-mismatch',
            messageKey: 'errors.firmware.revisionMismatch',
            stage: 'firmware-writing',
            category: 'transport',
            retryable: false,
            dispatchCertainty: 'definitely-rejected',
            senseSummary: { key: 'scsi-check-condition', asc: 36, ascq: 0, messageKey: 'errors.transport.scsi' },
            supportCorrelationId: 'support:failure-contract',
            cleanupEvidence: [
                {
                    stage: 'firmware-finalizing',
                    code: 'transport-timeout',
                    dispatchCertainty: 'completion-unknown'
                }
            ],
            attemptHistory: [
                {
                    attempt: 1,
                    stage: 'firmware-writing',
                    code: 'transport-unavailable',
                    dispatchCertainty: 'not-sent'
                }
            ]
        }
    }
}

/** @returns {OperationCoordinator} Ready firmware-capable coordinator fixture. */
function createFirmwareCoordinator() {
    /** @returns {Promise<object>} Accepts the controlled operation. */
    async function dispatch() {
        return { ok: true }
    }

    /** @returns {object} Current no-media firmware-capable device. */
    function getDevice() {
        return {
            id: 'rdx:1',
            revision: 7,
            mediaState: 'no-media',
            capabilities: { 'firmware-update': { state: 'available' } }
        }
    }

    /** @returns {object} Available native platform capability. */
    function getPlatformCapability() {
        return { state: 'available' }
    }

    /** @returns {'native'} Native service mode. */
    function getServiceMode() {
        return 'native'
    }

    /** @returns {boolean} Controlled positive admission gate. */
    function returnTrue() {
        return true
    }

    /** @returns {string} Stable operation ID for this isolated fixture. */
    function createOperationId() {
        return 'op:failure-contract'
    }

    return new OperationCoordinator({
        dispatch,
        getDevice,
        getPlatformCapability,
        getServiceMode,
        hasPrivilege: returnTrue,
        isHardwareReady: returnTrue,
        idFactory: createOperationId
    })
}

/** @returns {Promise<void>} Resolves after dispatch acknowledgement mapping. */
async function nextTurn() {
    await new Promise(setImmediate)
}

test('strict failure schema preserves terminal, primary, cleanup, and retry evidence', () => {
    const failure = firmwareFailure()

    assert.equal(operationEventSchema.safeParse(failure).success, true)
    assert.equal(operationEventSchema.safeParse({ ...failure, stage: undefined }).success, false)
    assert.equal(operationEventSchema.safeParse({ ...failure, error: { ...failure.error, cleanupEvidence: undefined } }).success, false)
    assert.equal(operationEventSchema.safeParse({ ...failure, error: { ...failure.error, attemptHistory: undefined } }).success, false)
    assert.equal(operationEventSchema.safeParse({ ...failure, error: { ...failure.error, cleanupEvidence: [...failure.error.cleanupEvidence, ...Array(16).fill(failure.error.cleanupEvidence[0])] } }).success, false)
    assert.equal(operationEventSchema.safeParse({ ...failure, error: { ...failure.error, attemptHistory: Array(5).fill(failure.error.attemptHistory[0]) } }).success, false)
    assert.equal(operationEventSchema.safeParse({ ...failure, error: { ...failure.error, attemptHistory: [{ ...failure.error.attemptHistory[0], secretPath: '/dev/sg4' }] } }).success, false)
    assert.equal(operationEventSchema.safeParse({ ...failure, error: { ...failure.error, cleanupEvidence: [{ ...failure.error.cleanupEvidence[0], dispatchCertainty: 'succeeded' }] } }).success, false)
    assert.equal(operationEventSchema.safeParse({ ...failure, error: { ...failure.error, dispatchCertainty: 'succeeded' } }).success, false)
    assert.equal(operationEventSchema.safeParse({ ...failure, error: { ...failure.error, attemptHistory: [{ ...failure.error.attemptHistory[0], attempt: 2 }] } }).success, false)
    assert.equal(operationEventSchema.safeParse({ ...failure, error: { ...failure.error, attemptHistory: [{ ...failure.error.attemptHistory[0], stage: 'device-reconnecting' }] } }).success, false)
    assert.equal(operationEventSchema.safeParse({ ...failure, error: { ...failure.error, attemptHistory: [...failure.error.attemptHistory, failure.error.attemptHistory[0]] } }).success, false)
})

test('coordinator accepts an earlier primary cause at the safe current terminal stage', async () => {
    const coordinator = createFirmwareCoordinator()
    await coordinator.start({
        kind: 'firmware-update',
        deviceId: 'rdx:1',
        deviceRevision: 7,
        firmwareFileToken: 'firmware:fixture'
    })
    await nextTurn()

    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'firmware-validating' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'firmware-writing', progress: 0.2, attempt: 1, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'firmware-writing', progress: 0.4, attempt: 2, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'firmware-writing', progress: 0.5, attempt: 1, cancellationState: 'closed' }), false)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'firmware-finalizing', progress: 0.8, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'device-reconnecting', progress: 0.9, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'firmware-readback', progress: 1, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent(firmwareFailure()), true)
    assert.equal(coordinator.getActiveOperation(), null)
})

test('coordinator rejects attempt-two history even when attempt two was observed', async () => {
    const coordinator = createFirmwareCoordinator()
    await coordinator.start({
        kind: 'firmware-update',
        deviceId: 'rdx:1',
        deviceRevision: 7,
        firmwareFileToken: 'firmware:fixture'
    })
    await nextTurn()

    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'firmware-validating' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'firmware-writing', progress: 0.2, attempt: 1, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'firmware-writing', progress: 0.4, attempt: 2, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'firmware-finalizing', progress: 0.8, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'device-reconnecting', progress: 0.9, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'firmware-readback', progress: 1, cancellationState: 'closed' }), true)

    const impossible = firmwareFailure()
    impossible.error.attemptHistory[0].attempt = 2
    assert.equal(coordinator.handleServiceEvent(impossible), false)
    assert.notEqual(coordinator.getActiveOperation(), null)

    const outOfOrder = firmwareFailure()
    outOfOrder.error.cleanupEvidence = [
        { stage: 'device-reconnecting', code: 'transport-timeout', dispatchCertainty: 'completion-unknown' },
        { stage: 'firmware-finalizing', code: 'transport-unavailable', dispatchCertainty: 'not-sent' }
    ]
    assert.equal(coordinator.handleServiceEvent(outOfOrder), false)

    const futureRecoveredStage = firmwareFailure()
    futureRecoveredStage.error.attemptHistory[0].stage = 'firmware-finalizing'
    assert.equal(coordinator.handleServiceEvent(futureRecoveredStage), false)

    const missingRecoveredAttempt = firmwareFailure()
    missingRecoveredAttempt.error.attemptHistory = []
    assert.equal(coordinator.handleServiceEvent(missingRecoveredAttempt), false)

    assert.equal(coordinator.handleServiceEvent(firmwareFailure()), true)
    assert.equal(coordinator.getActiveOperation(), null)
})

test('coordinator rejects recovered history unless attempt two was observed and evidence order is monotonic', async () => {
    const coordinator = createFirmwareCoordinator()
    await coordinator.start({
        kind: 'firmware-update',
        deviceId: 'rdx:1',
        deviceRevision: 7,
        firmwareFileToken: 'firmware:fixture'
    })
    await nextTurn()

    assert.equal(coordinator.handleServiceEvent({ state: 'started', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'firmware-validating' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'firmware-writing', progress: 0.2, attempt: 1, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'firmware-finalizing', progress: 0.8, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'device-reconnecting', progress: 0.9, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent({ state: 'progress', operationId: 'op:failure-contract', kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 7, stage: 'firmware-readback', progress: 1, cancellationState: 'closed' }), true)

    assert.equal(coordinator.handleServiceEvent(firmwareFailure()), false)
    assert.notEqual(coordinator.getActiveOperation(), null)
})
