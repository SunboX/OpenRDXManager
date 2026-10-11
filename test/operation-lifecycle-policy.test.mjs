// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { OperationKind } from '../src/shared/contracts.mjs'
import { getNextCancellationRecoveryStage, getOperationLifecyclePolicy, hasRecoveryObligation, isFailureTerminalAllowed, isCancellationAllowed, isCancellationTerminalStage, isOperationStageTransitionAllowed, isSafeFailureStage } from '../src/main/operation-lifecycle-policy.mjs'

const MUTATING_KINDS = Object.freeze(Object.values(OperationKind).filter((kind) => !['scan', 'status-refresh'].includes(kind)))

test('defines a per-kind safe terminal and recovery obligation for every mutation', () => {
    for (const kind of MUTATING_KINDS) {
        const policy = getOperationLifecyclePolicy(kind)
        assert.notEqual(policy, null, `${kind} policy`)
        assert.equal(policy.stages.includes(policy.safeTerminalStage), true, `${kind} safe terminal`)
        assert.equal(policy.safeFailureStages.includes(policy.safeTerminalStage), true, `${kind} failure terminal`)
        assert.equal(policy.recoveryObligationStart === null || policy.stages.includes(policy.recoveryObligationStart), true, `${kind} recovery start`)
    }
})

test('names the required cleanup and readback barriers for high-risk operation families', () => {
    assert.deepEqual(getOperationLifecyclePolicy(OperationKind.LED_TEST).stages, ['led-testing', 'led-restoring', 'led-readback'])
    assert.deepEqual(getOperationLifecyclePolicy(OperationKind.WRITE_READ_TEST).stages, ['host-writing', 'host-reading', 'host-cleanup'])
    assert.deepEqual(getOperationLifecyclePolicy(OperationKind.DRIVE_MODE_SET).stages, ['device-configuring', 'device-reconnecting', 'device-readback'])
    assert.deepEqual(getOperationLifecyclePolicy(OperationKind.SATA_MODE_SET).stages, ['device-configuring', 'device-reconnecting', 'device-readback'])
    assert.deepEqual(getOperationLifecyclePolicy(OperationKind.FIRMWARE_UPDATE).stages, ['firmware-validating', 'firmware-capturing', 'firmware-compatibility-setup', 'firmware-staging', 'firmware-awaiting-bootloader', 'firmware-programming-bootstrap', 'firmware-awaiting-bootstrap', 'firmware-restoring-identity', 'firmware-writing', 'firmware-finalizing', 'device-reconnecting', 'firmware-readback'])
})

test('failed firmware transfer enters read-only recovery without claiming finalization', () => {
    assert.equal(isOperationStageTransitionAllowed(OperationKind.FIRMWARE_UPDATE, 'firmware-writing', 'device-reconnecting'), true)
    assert.equal(isOperationStageTransitionAllowed(OperationKind.FIRMWARE_UPDATE, 'firmware-writing', 'firmware-readback'), false)
})

test('enforces every per-kind failure and cancellation edge from the declared graph', () => {
    for (const kind of Object.values(OperationKind).filter((value) => value !== OperationKind.SCAN)) {
        const policy = getOperationLifecyclePolicy(kind)
        let recoveryRequired = false
        for (const stage of policy.stages) {
            recoveryRequired ||= hasRecoveryObligation(kind, stage)
            assert.equal(isSafeFailureStage(kind, stage, recoveryRequired), !recoveryRequired || policy.safeFailureStages.includes(stage), `${kind}:${stage}:failure`)
            assert.equal(isCancellationAllowed(kind, stage), policy.cancellableStages.includes(stage), `${kind}:${stage}:cancel`)
            assert.equal(isCancellationTerminalStage(kind, stage), policy.cancelTerminalStages.includes(stage), `${kind}:${stage}:cancel-terminal`)
        }
        for (const preflightStage of ['queued', 'outcome-unknown']) {
            assert.equal(isCancellationAllowed(kind, preflightStage), policy.cancellableStages.includes(preflightStage), `${kind}:${preflightStage}:cancel`)
            assert.equal(isCancellationTerminalStage(kind, preflightStage), policy.cancelTerminalStages.includes(preflightStage), `${kind}:${preflightStage}:cancel-terminal`)
        }
    }
})

test('status refresh cancellation closes at the Started boundary', () => {
    assert.equal(isCancellationAllowed(OperationKind.STATUS_REFRESH, 'queued'), true)
    assert.equal(isCancellationAllowed(OperationKind.STATUS_REFRESH, 'outcome-unknown'), true)
    assert.equal(isCancellationAllowed(OperationKind.STATUS_REFRESH, 'status-reading'), false)
    assert.equal(isCancellationTerminalStage(OperationKind.STATUS_REFRESH, 'queued'), true)
    assert.equal(isCancellationTerminalStage(OperationKind.STATUS_REFRESH, 'status-reading'), false)
})

test('returns the literal next recovery stage for every operation kind', () => {
    const cases = [
        [OperationKind.SCAN, 'queued', null],
        [OperationKind.STATUS_REFRESH, 'status-reading', null],
        [OperationKind.ACCESS_ENABLE, 'access-changing', 'access-readback'],
        [OperationKind.ACCESS_DISABLE, 'access-changing', 'access-readback'],
        [OperationKind.CREDENTIAL_CREATE, 'credential-writing', 'credential-readback'],
        [OperationKind.CREDENTIAL_CHANGE, 'credential-writing', 'credential-readback'],
        [OperationKind.CREDENTIAL_DELETE, 'credential-writing', 'credential-readback'],
        [OperationKind.CREDENTIAL_RESET, 'credential-writing', 'credential-readback'],
        [OperationKind.CREDENTIAL_CONFIGURE, 'credential-writing', 'credential-readback'],
        [OperationKind.SELF_TEST, 'diagnostic-running', 'diagnostic-cleanup'],
        [OperationKind.LED_TEST, 'led-testing', 'led-restoring'],
        [OperationKind.WRITE_READ_TEST, 'host-writing', 'host-cleanup'],
        [OperationKind.FIRMWARE_UPDATE, 'firmware-writing', 'firmware-finalizing'],
        [OperationKind.VOLUME_LABEL_SET, 'host-volume-changing', null],
        [OperationKind.DRIVE_LETTER_SET, 'host-volume-changing', 'host-volume-readback'],
        [OperationKind.DRIVE_LETTER_RESET, 'host-volume-changing', 'host-volume-readback'],
        [OperationKind.FORMAT, 'format-writing', 'format-finalizing'],
        [OperationKind.DRIVE_MODE_SET, 'device-configuring', 'device-reconnecting'],
        [OperationKind.SATA_MODE_SET, 'device-configuring', 'device-reconnecting'],
        [OperationKind.EJECT_SAFE, 'host-ejecting', 'eject-readback'],
        [OperationKind.EJECT_FORCE, 'host-ejecting', 'eject-readback']
    ]

    const coveredKinds = new Set()
    for (const [kind] of cases) {
        coveredKinds.add(kind)
    }
    assert.deepEqual([...coveredKinds].sort(), [...Object.values(OperationKind)].sort())
    for (const [kind, currentStage, expectedStage] of cases) {
        assert.equal(getNextCancellationRecoveryStage(kind, currentStage), expectedStage, `${kind}:${currentStage}`)
    }
})

test('only definitive eject rejection can terminate before departure readback', () => {
    const event = { state: 'failed', stage: 'host-ejecting', error: { stage: 'host-ejecting', dispatchCertainty: 'definitely-rejected', retryable: false, cleanupEvidence: [] } }
    for (const kind of [OperationKind.EJECT_SAFE, OperationKind.EJECT_FORCE]) {
        assert.equal(isFailureTerminalAllowed(kind, event, true), true)
        for (const dispatchCertainty of ['not-sent', 'completion-unknown', undefined]) {
            assert.equal(isFailureTerminalAllowed(kind, { ...event, error: { ...event.error, dispatchCertainty } }, true), false)
        }
        assert.equal(isFailureTerminalAllowed(kind, { ...event, error: { ...event.error, retryable: true } }, true), false)
        assert.equal(isFailureTerminalAllowed(kind, { ...event, error: { ...event.error, stage: 'host-unmounting' } }, true), false)
        assert.equal(isFailureTerminalAllowed(kind, { ...event, error: { ...event.error, cleanupEvidence: [{ stage: 'host-ejecting', code: 'cleanup-incomplete' }] } }, true), false)
    }
    assert.equal(isFailureTerminalAllowed(OperationKind.DRIVE_MODE_SET, { ...event, stage: 'device-configuring', error: { ...event.error, stage: 'device-configuring' } }, true), false)
})
