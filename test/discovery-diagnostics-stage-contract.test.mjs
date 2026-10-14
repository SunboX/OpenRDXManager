// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { discoveryDiagnosticsSchema } from '../src/shared/schemas.mjs'

test('fixed native discovery stages use the existing aggregate wire contract', () => {
    const rejections = ['candidate-registry-open-failed', 'candidate-media-map-failed', 'candidate-unmount-failed', 'candidate-worker-acquisition-failed', 'candidate-standard-inquiry-failed', 'candidate-vpd83-inquiry-failed', 'candidate-mode31-probe-failed', 'candidate-inquiry-identity-invalid', 'candidate-mode31-invalid', 'candidate-host-facts-failed'].map((reason) => ({ reason, count: 1 }))
    const evidence = { candidateCount: rejections.length + 1, acceptedCount: 1, rejections }
    assert.deepEqual(discoveryDiagnosticsSchema.parse(evidence), evidence)
})

test('stage diagnostics retain strict count, privacy and reason bounds', () => {
    const evidence = { candidateCount: 1, acceptedCount: 0, rejections: [{ reason: 'candidate-media-map-failed', count: 1 }] }
    for (const reason of ['/private/device', 'native message\nsecret', 'NativeBoundaryFailure', 'x'.repeat(129)]) {
        assert.equal(discoveryDiagnosticsSchema.safeParse({ ...evidence, rejections: [{ reason, count: 1 }] }).success, false)
    }
    for (const extra of [{ path: '/private/device' }, { token: 'private-id' }, { serial: 'private-serial' }]) {
        assert.equal(discoveryDiagnosticsSchema.safeParse({ ...evidence, rejections: [{ ...evidence.rejections[0], ...extra }] }).success, false)
    }
    assert.equal(discoveryDiagnosticsSchema.safeParse({ ...evidence, candidateCount: 2 }).success, false)
    assert.equal(discoveryDiagnosticsSchema.safeParse({ ...evidence, candidateCount: 2, rejections: [...evidence.rejections, ...evidence.rejections] }).success, false)
    const excessive = Array.from({ length: 33 }, (_value, index) => ({ reason: `candidate-stage-${index}`, count: 1 }))
    assert.equal(discoveryDiagnosticsSchema.safeParse({ candidateCount: 33, acceptedCount: 0, rejections: excessive }).success, false)
})

test('closed worker phase and error buckets retain the existing privacy contract', () => {
    const rejections = ['candidate-worker-process-spawn-bad-fd', 'candidate-worker-init-write-transport-unavailable', 'candidate-worker-rematch-select-device-removed', 'candidate-worker-usb-capture-device-access-denied', 'candidate-worker-usb-open-bulk-out-evidence-incomplete'].map((reason) => ({ reason, count: 1 }))
    const evidence = { candidateCount: 5, acceptedCount: 0, rejections }
    assert.deepEqual(discoveryDiagnosticsSchema.parse(evidence), evidence)
    for (const extra of [{ nativeCode: 42 }, { nativeCodeKind: 'nserror' }, { nativeStatus: 3 }, { phaseText: 'native secret' }]) {
        assert.equal(discoveryDiagnosticsSchema.safeParse({ candidateCount: 1, acceptedCount: 0, rejections: [{ reason: rejections[0].reason, count: 1, ...extra }] }).success, false)
    }
})

test('31 fixed worker reasons plus merged overflow remain a complete bounded report', () => {
    const rejections = [{ reason: 'candidate-validation-failed', count: 12 }, ...Array.from({ length: 31 }, (_value, index) => ({ reason: `candidate-worker-phase-${index}-other`, count: 2 }))]
    const evidence = { candidateCount: 76, acceptedCount: 2, rejections }
    assert.deepEqual(discoveryDiagnosticsSchema.parse(evidence), evidence)
    assert.equal(rejections.reduce((total, rejection) => total + rejection.count, 0) + evidence.acceptedCount, evidence.candidateCount)
})

test('interface-open IOReturn classes remain fixed path-free aggregate reasons', () => {
    const classes = ['io-not-ready', 'io-not-attached', 'io-not-found', 'io-offline', 'io-bad-argument', 'io-no-resources', 'io-ipc-error', 'io-internal-error', 'io-error', 'io-general-error', 'error-missing', 'other']
    const rejections = classes.map((code) => ({ reason: `candidate-worker-usb-open-interface-${code}`, count: 1 }))
    const evidence = { candidateCount: classes.length, acceptedCount: 0, rejections }
    assert.deepEqual(discoveryDiagnosticsSchema.parse(evidence), evidence)
    for (const extra of [{ nativeCode: 3758097112 }, { nativeCodeKind: 'nserror' }, { errorDomain: 'IOUSBHostErrorDomain' }, { localizedDescription: 'kernel text' }]) {
        assert.equal(discoveryDiagnosticsSchema.safeParse({ candidateCount: 1, acceptedCount: 0, rejections: [{ ...rejections[0], ...extra }] }).success, false)
    }
})

test('fresh current-call error classes fit existing path-free counts without private metadata', () => {
    const codes = ['error-missing', 'error-malformed', 'evidence-invalid', 'super-init-under-posix-permission', 'reason-missing-under-host-not-ready', 'service-open-under-mach-unknown', 'reason-malformed-current-host-internal-error', 'reason-unknown-under-malformed', 'reason-missing-current-posix-unknown', 'reason-missing-current-cocoa-unknown', 'reason-unknown-current-other-unknown']
    const rejections = codes.map((code) => ({ reason: `candidate-worker-usb-interface-fresh-${code}`, count: 1 }))
    const evidence = { candidateCount: codes.length, acceptedCount: 0, rejections }
    assert.deepEqual(discoveryDiagnosticsSchema.parse(evidence), evidence)
    for (const extra of [{ domain: 1 }, { code: 9 }, { reasonClass: 1 }, { underDomain: 2 }, { underCode: 21 }, { userInfo: 'private' }, { underlyingError: 'private' }]) {
        assert.equal(discoveryDiagnosticsSchema.safeParse({ candidateCount: 1, acceptedCount: 0, rejections: [{ ...rejections[0], ...extra }] }).success, false)
    }
})
