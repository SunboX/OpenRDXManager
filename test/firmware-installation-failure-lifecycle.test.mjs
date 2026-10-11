// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { OperationCoordinator } from '../src/main/operation-coordinator.mjs'
import { ServicePublicationSequence } from '../src/main/service-publication-sequence.mjs'

const STAGES = ['firmware-validating', 'firmware-capturing', 'firmware-compatibility-setup', 'firmware-staging', 'firmware-awaiting-bootloader', 'firmware-programming-bootstrap', 'firmware-awaiting-bootstrap', 'firmware-restoring-identity', 'firmware-writing', 'firmware-finalizing', 'device-reconnecting', 'firmware-readback']
const OWNER = { operationId: 'op:migration-failure', kind: 'firmware-update', deviceId: 'rdx:migration-fixture', deviceRevision: 1 }

/** @param {string} stage - Last actually reached stage. @returns {object} Explicit incomplete recovery failure with no invented readback. */
function recoveryFailure(stage) {
    return { ...OWNER, state: 'failed', stage, error: { code: 'firmware-migration-readback-mismatch', messageKey: 'errors.operation.failed', stage, category: 'transport', retryable: false, dispatchCertainty: 'completion-unknown', supportCorrelationId: 'support:migration-fixture', cleanupEvidence: [{ stage, code: 'cleanup-incomplete', dispatchCertainty: 'completion-unknown' }], attemptHistory: [] } }
}

/** @param {string} stage - Stage to reach using the complete first-install graph. @returns {Promise<object>} Independent shadow and coordinator fixtures without any device calls. */
async function reachStage(stage) {
    const shadow = new ServicePublicationSequence()
    assert.equal(shadow.reserve({ ...OWNER, generation: 1 }), true)
    const coordinator = new OperationCoordinator({ getDevice: () => ({ id: OWNER.deviceId, revision: 1, mediaState: 'no-media', capabilities: { 'firmware-update': { state: 'available' } } }), getPlatformCapability: () => ({ state: 'available' }), getServiceMode: () => 'native', hasPrivilege: () => true, isHardwareReady: () => true, dispatch: async () => ({ ok: true }), idFactory: () => OWNER.operationId })
    assert.equal((await coordinator.start({ kind: OWNER.kind, deviceId: OWNER.deviceId, deviceRevision: 1, firmwareFileToken: 'firmware:migration-fixture' })).ok, true)
    await new Promise(setImmediate)
    let sequence = 1
    const started = { ...OWNER, state: 'started', stage: STAGES[0] }
    assert.equal(shadow.consume({ publicationSequence: sequence, event: started }), true)
    assert.equal(coordinator.handleServiceEvent(started), true)
    for (const [index, current] of STAGES.entries()) {
        if (index === 0 || index > STAGES.indexOf(stage)) continue
        sequence += 1
        const event = { ...OWNER, state: 'progress', stage: current, progress: index / STAGES.length, cancellationState: index === 1 ? 'cancellable' : 'closed' }
        assert.equal(shadow.consume({ publicationSequence: sequence, event }), true, current)
        assert.equal(coordinator.handleServiceEvent(event), true, current)
    }
    return { shadow, coordinator, sequence: sequence + 1 }
}

test('both lifecycle validators accept explicit incomplete recovery at each actual migration stage', async () => {
    for (const stage of STAGES.slice(2, 8)) {
        const { shadow, coordinator, sequence } = await reachStage(stage)
        const prematureSuccess = { ...OWNER, state: 'succeeded', stage: 'complete' }
        assert.equal(shadow.consume({ publicationSequence: sequence, event: prematureSuccess }), false)
        assert.equal(coordinator.handleServiceEvent(prematureSuccess), false)
        assert.equal(coordinator.getActiveOperation().irreversible, true)
        assert.equal(coordinator.getShutdownPolicy().allowed, false)
        const event = recoveryFailure(stage)
        const envelope = { publicationSequence: sequence, event }
        assert.equal(shadow.consume(envelope), true, stage)
        assert.equal(coordinator.handleServiceEvent(event), true, stage)
        assert.equal(shadow.reserve({ ...OWNER, generation: 1 }), false, 'terminal remains reserved until its downstream commit')
        assert.equal(shadow.commit(envelope), true)
        assert.equal(coordinator.getActiveOperation(), null)
    }
})

test('incomplete migration recovery needs exact nonretryable primary and cleanup evidence', async () => {
    const stage = 'firmware-restoring-identity'
    const { shadow, coordinator, sequence } = await reachStage(stage)
    const base = recoveryFailure(stage)
    const invalid = [
        { ...base, stage: 'firmware-readback' },
        { ...base, error: { ...base.error, stage: 'firmware-awaiting-bootstrap' } },
        { ...base, error: { ...base.error, retryable: true } },
        { ...base, error: { ...base.error, dispatchCertainty: 'definitely-rejected' } },
        { ...base, error: { ...base.error, cleanupEvidence: [] } },
        { ...base, error: { ...base.error, cleanupEvidence: [{ stage, code: 'transport-unavailable', dispatchCertainty: 'completion-unknown' }] } },
        { ...base, error: { ...base.error, cleanupEvidence: [{ stage, code: 'cleanup-incomplete', dispatchCertainty: 'not-sent' }] } },
        { ...base, error: { ...base.error, cleanupEvidence: [{ stage: 'firmware-readback', code: 'cleanup-incomplete', dispatchCertainty: 'completion-unknown' }] } },
        { ...base, error: { ...base.error, cleanupEvidence: [base.error.cleanupEvidence[0], { stage: 'firmware-staging', code: 'cleanup-incomplete', dispatchCertainty: 'completion-unknown' }] } },
        { ...base, error: { ...base.error, attemptHistory: [{ attempt: 1, stage: 'firmware-writing', code: 'transport-timeout', dispatchCertainty: 'completion-unknown' }] } }
    ]
    for (const event of invalid) {
        assert.equal(shadow.consume({ publicationSequence: sequence, event }), false)
        assert.equal(coordinator.handleServiceEvent(event), false)
        assert.equal(coordinator.getActiveOperation().irreversible, true)
    }
    assert.equal(shadow.consume({ publicationSequence: sequence, event: base }), true)
    assert.equal(coordinator.handleServiceEvent(base), true)
})

test('the incomplete migration exception cannot bypass ordinary final transfer recovery', async () => {
    for (const stage of ['firmware-writing', 'firmware-finalizing', 'device-reconnecting']) {
        const { shadow, coordinator, sequence } = await reachStage(stage)
        const event = recoveryFailure(stage)
        assert.equal(shadow.consume({ publicationSequence: sequence, event }), false, stage)
        assert.equal(coordinator.handleServiceEvent(event), false, stage)
        assert.equal(coordinator.getActiveOperation().irreversible, true)
    }
})
