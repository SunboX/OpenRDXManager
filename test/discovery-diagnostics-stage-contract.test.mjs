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
