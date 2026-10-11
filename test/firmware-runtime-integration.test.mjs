// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { dispatchRegisteredFirmwareOperation } from '../src/main/service-runtime.mjs'

/** @returns {Promise<void>} Verifies registration precedes dispatch and main bytes are cleared. */
async function testRegisteredDispatch() {
    const calls = []
    const bytes = Buffer.from([1, 2, 3, 4])
    const operation = { operationId: 'op:firmware-runtime', request: { kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 2, firmwareFileToken: 'firmware:runtime' } }
    const result = await dispatchRegisteredFirmwareOperation({
        client: {
            /** @param {object} registration - Path-free image registration. @returns {Promise<object>} Accepted registration. */
            async registerFirmwareImage(registration) {
                calls.push({ method: 'register', extension: registration.extension, fileToken: registration.fileToken, bytes: Buffer.from(registration.bytes) })
                return { ok: true }
            },
            /** @param {object} request - Exact operation request. @returns {Promise<object>} Accepted operation. */
            async startOperation(request) {
                calls.push({ method: 'start', request })
                return { ok: true }
            }
        },
        firmwareFileService: {
            /** @returns {Promise<object>} One main-owned byte snapshot. */
            async claimFirmwareFile() {
                return { bytes, extension: '.BIN', size: bytes.length }
            }
        },
        operation
    })
    assert.deepEqual(result, { ok: true })
    assert.deepEqual(
        calls.map((call) => call.method),
        ['register', 'start']
    )
    assert.equal(JSON.stringify(calls).includes('/'), false)
    assert.deepEqual(bytes, Buffer.alloc(4))
}

/** @returns {Promise<void>} Verifies legacy and failed registrations never dispatch hardware. */
async function testFailedRegistration() {
    const calls = []
    const bytes = Buffer.from([1, 2])
    const operation = { operationId: 'op:firmware-runtime-fail', request: { kind: 'firmware-update', deviceId: 'rdx:1', deviceRevision: 2, firmwareFileToken: 'firmware:runtime-fail' } }
    const client = {
        /** @returns {Promise<object>} Records an unexpected registration. */
        async registerFirmwareImage() {
            calls.push('register')
            return { ok: false, reason: 'firmware-image-invalid' }
        },
        /** @returns {Promise<object>} Records an unsafe dispatch. */
        async startOperation() {
            calls.push('start')
            return { ok: true }
        }
    }
    assert.deepEqual(
        await dispatchRegisteredFirmwareOperation({
            client,
            firmwareFileService: {
                /** @returns {Promise<object>} One controlled legacy byte snapshot. */
                async claimFirmwareFile() {
                    return { bytes, extension: '.BIP', size: bytes.length }
                }
            },
            operation
        }),
        { ok: false, reason: 'legacy-bip-format-unproven' }
    )
    assert.deepEqual(calls, [])
    assert.deepEqual(bytes, Buffer.alloc(2))

    const invalidBytes = Buffer.from([3, 4])
    assert.deepEqual(
        await dispatchRegisteredFirmwareOperation({
            client,
            firmwareFileService: {
                /** @returns {Promise<object>} One controlled modern byte snapshot. */
                async claimFirmwareFile() {
                    return { bytes: invalidBytes, extension: '.BIN', size: invalidBytes.length }
                }
            },
            operation
        }),
        { ok: false, reason: 'firmware-image-invalid' }
    )
    assert.deepEqual(calls, ['register'])
    assert.deepEqual(invalidBytes, Buffer.alloc(2))
}

test('firmware runtime registers path-free bytes before exact operation dispatch', testRegisteredDispatch)
test('firmware runtime fails closed for legacy images and registration failures', testFailedRegistration)
