// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { evaluateOperation, getOperationRiskClass } from '../src/main/safety-policy.mjs'

const device = Object.freeze({
    id: 'rdx:1',
    revision: 3,
    mediaState: 'present',
    capabilities: Object.freeze({
        'status-refresh': Object.freeze({ state: 'available' }),
        'self-test': Object.freeze({ state: 'available' }),
        'firmware-update': Object.freeze({ state: 'available' }),
        'eject-force': Object.freeze({ state: 'available' })
    })
})

/**
 * Builds a main-owned safety context with no active operation.
 * @param {object} [overrides] - Context properties to replace.
 * @returns {object} Safety context for one selected device.
 */
function createContext(overrides = {}) {
    return {
        device,
        activeOperation: null,
        hardwareReady: true,
        hasPrivilege: true,
        confirmationTokenValid: true,
        platformCapability: { state: 'available' },
        serviceMode: 'native',
        ...overrides
    }
}

test('rejects stale device revisions before dispatch', () => {
    const result = evaluateOperation({ kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 2 }, createContext())

    assert.deepEqual(result, { allowed: false, reason: 'stale-device-revision' })
})

test('rejects paths and unknown request keys through the shared operation schema', () => {
    const result = evaluateOperation({ kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 3, osPath: '/dev/sg4' }, createContext())

    assert.deepEqual(result, { allowed: false, reason: 'invalid-operation-request' })
})

test('rejects a second operation before capability dispatch', () => {
    const result = evaluateOperation({ kind: 'status-refresh', deviceId: 'rdx:1', deviceRevision: 3 }, createContext({ activeOperation: { id: 'op:active' } }))

    assert.deepEqual(result, { allowed: false, reason: 'operation-in-progress' })
})

test('allows a native cold-start scan while keeping device operations gated', () => {
    const cold = createContext({ device: null, hardwareReady: false, platformCapability: { state: 'transport-unavailable', reason: 'no-current-candidate' } })

    assert.deepEqual(evaluateOperation({ kind: 'scan' }, cold), {
        allowed: true,
        request: { kind: 'scan' },
        riskClass: 'read-only'
    })
    assert.deepEqual(evaluateOperation({ kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 3 }, cold), {
        allowed: false,
        reason: 'hardware-unavailable'
    })
})

test('preserves the exact unavailable capability reason', () => {
    const unavailableDevice = {
        ...device,
        capabilities: { ...device.capabilities, 'self-test': { state: 'evidence-incomplete' } }
    }
    const result = evaluateOperation({ kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 3 }, createContext({ device: unavailableDevice }))

    assert.deepEqual(result, { allowed: false, reason: 'evidence-incomplete' })
})

test('does not forward an unrecognized service capability state', () => {
    const unsafeDevice = {
        ...device,
        capabilities: { ...device.capabilities, 'self-test': { state: '../../../secret' } }
    }
    const result = evaluateOperation({ kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 3 }, createContext({ device: unsafeDevice }))

    assert.deepEqual(result, { allowed: false, reason: 'capability-unknown' })
})

test('requires main-owned confirmation for force eject independent of its risk class', () => {
    const request = {
        kind: 'eject-force',
        deviceId: 'rdx:1',
        deviceRevision: 3,
        confirmationToken: 'confirm:force-eject'
    }

    assert.deepEqual(evaluateOperation(request, createContext({ confirmationTokenValid: false })), {
        allowed: false,
        reason: 'confirmation-required'
    })
    assert.deepEqual(evaluateOperation(request, createContext()), {
        allowed: true,
        request,
        riskClass: 'critical'
    })
})

test('allows a strict request only after identity and main-owned gates pass', () => {
    const request = { kind: 'status-refresh', deviceId: 'rdx:1', deviceRevision: 3 }

    assert.deepEqual(evaluateOperation(request, createContext()), {
        allowed: true,
        request,
        riskClass: 'read-only'
    })
    assert.equal(getOperationRiskClass('firmware-update'), 'critical')
})
