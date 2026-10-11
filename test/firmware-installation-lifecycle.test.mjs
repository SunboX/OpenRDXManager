// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { OperationCoordinator } from '../src/main/operation-coordinator.mjs'
import { getOperationLifecyclePolicy, hasRecoveryObligation, isCancellationAllowed, isCancellationTerminalStage } from '../src/main/operation-lifecycle-policy.mjs'

const KIND = 'firmware-update'
const INSTALL_STAGES = Object.freeze(['firmware-validating', 'firmware-capturing', 'firmware-compatibility-setup', 'firmware-staging', 'firmware-awaiting-bootloader', 'firmware-programming-bootstrap', 'firmware-awaiting-bootstrap', 'firmware-restoring-identity', 'firmware-writing', 'firmware-finalizing', 'device-reconnecting', 'firmware-readback'])

/** @returns {Promise<{coordinator: OperationCoordinator, event: object}>} Starts a deterministic, hardware-free firmware owner. */
async function startFirmware() {
    const coordinator = new OperationCoordinator({
        getDevice: () => ({ id: 'rdx:installation', revision: 7, mediaState: 'no-media', capabilities: { [KIND]: { state: 'available' } } }),
        getPlatformCapability: () => ({ state: 'available' }),
        getServiceMode: () => 'native',
        hasPrivilege: () => true,
        isHardwareReady: () => true,
        dispatch: async () => ({ ok: true }),
        cancelDispatch: async () => ({ ok: true }),
        idFactory: () => 'op:installation'
    })
    const event = { operationId: 'op:installation', kind: KIND, deviceId: 'rdx:installation', deviceRevision: 7 }
    assert.equal((await coordinator.start({ kind: KIND, deviceId: event.deviceId, deviceRevision: 7, firmwareFileToken: 'firmware:installation' })).ok, true)
    await new Promise(setImmediate)
    assert.equal(coordinator.handleServiceEvent({ ...event, state: 'started', stage: INSTALL_STAGES[0] }), true)
    return { coordinator, event }
}

test('first installation closes cancellation before setup and requires final readback', async () => {
    assert.deepEqual(getOperationLifecyclePolicy(KIND).stages, INSTALL_STAGES)
    const { coordinator, event } = await startFirmware()
    for (let index = 1; index < INSTALL_STAGES.length; index += 1) {
        const stage = INSTALL_STAGES[index]
        assert.equal(coordinator.handleServiceEvent({ ...event, state: 'succeeded', stage: 'complete' }), false, `premature success before ${stage}`)
        assert.equal(coordinator.handleServiceEvent({ ...event, state: 'progress', stage, progress: index / INSTALL_STAGES.length, cancellationState: index === 1 ? 'cancellable' : 'closed' }), true, stage)
        assert.equal(isCancellationAllowed(KIND, stage), index === 1, stage)
        assert.equal(hasRecoveryObligation(KIND, stage), index >= 2, stage)
        assert.notEqual(coordinator.getActiveOperation(), null)
        if (index >= 2) {
            assert.equal(coordinator.getShutdownPolicy().allowed, false, stage)
            assert.equal((await coordinator.cancel({ operationId: event.operationId })).ok, false, stage)
        }
    }
    assert.equal(isCancellationTerminalStage(KIND, 'firmware-capturing'), true)
    assert.equal(coordinator.handleServiceEvent({ ...event, state: 'succeeded', stage: 'complete' }), true)
    assert.equal(coordinator.getActiveOperation(), null)
})

test('first installation rejects skipped power-cycle boundaries and ordinary updates retain their direct route', async () => {
    const { coordinator, event } = await startFirmware()
    for (const stage of INSTALL_STAGES.slice(2, -1)) {
        if (stage === 'firmware-writing') continue
        assert.equal(coordinator.handleServiceEvent({ ...event, state: 'progress', stage, progress: 0.1, cancellationState: 'closed' }), false, `skip to ${stage}`)
    }
    for (const [index, stage] of ['firmware-writing', 'firmware-finalizing', 'device-reconnecting', 'firmware-readback'].entries()) {
        assert.equal(coordinator.handleServiceEvent({ ...event, state: 'progress', stage, progress: (index + 1) / 4, cancellationState: 'closed' }), true, stage)
    }
    assert.equal(coordinator.handleServiceEvent({ ...event, state: 'succeeded', stage: 'complete' }), true)
})

test('source capture can cancel safely and cannot jump into transfer or either power-cycle prompt', async () => {
    const { coordinator, event } = await startFirmware()
    assert.equal(coordinator.handleServiceEvent({ ...event, state: 'progress', stage: 'firmware-capturing', progress: 0.05, cancellationState: 'cancellable' }), true)
    for (const stage of INSTALL_STAGES.slice(3)) {
        assert.equal(coordinator.handleServiceEvent({ ...event, state: 'progress', stage, progress: 0.1, cancellationState: 'closed' }), false, stage)
    }
    assert.equal(coordinator.handleServiceEvent({ ...event, state: 'progress', stage: 'firmware-capturing', progress: 0.06, cancellationState: 'closed' }), false, 'capture cannot claim the cutover before setup')
    assert.equal((await coordinator.cancel({ operationId: event.operationId })).ok, true)
    assert.equal(coordinator.handleServiceEvent({ ...event, state: 'cancelled', stage: 'firmware-capturing', reason: 'cancelled-by-user' }), true)
    assert.equal(coordinator.getActiveOperation(), null)
})
