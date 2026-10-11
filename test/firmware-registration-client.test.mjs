// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { registerFirmwareImageFrames } from '../src/main/firmware-registration-client.mjs'

/** @returns {Promise<void>} Verifies bounded ordered path-free registration frames. */
async function testFirmwareRegistrationFrames() {
    const requests = []
    /** @param {string} method - Strict method. @param {object} payload - Strict payload. @returns {Promise<object>} Accepted response. */
    async function request(method, payload) {
        requests.push({ method, payload })
        return { ok: true }
    }
    const fileToken = 'firmware:12345678-1234-1234-1234-123456789abc'
    assert.deepEqual(await registerFirmwareImageFrames({ registration: { fileToken, extension: '.BIN', bytes: Buffer.alloc(5000, 0xa5) }, request }), { ok: true })
    assert.deepEqual(
        requests.map((entry) => entry.method),
        ['firmware-registration-begin', 'firmware-registration-chunk', 'firmware-registration-chunk', 'firmware-registration-commit']
    )
    assert.deepEqual(
        requests.slice(1, 3).map((entry) => entry.payload.offset),
        [0, 4096]
    )
    assert.equal(Buffer.from(requests[1].payload.bytesBase64, 'base64').length, 4096)
    assert.equal(JSON.stringify(requests).includes('/'), false)
    assert.deepEqual(await registerFirmwareImageFrames({ registration: { fileToken, extension: '.BIN', bytes: Buffer.alloc(0x1000000) }, request }), { ok: false, reason: 'invalid-request' })
}

/** @returns {Promise<void>} Verifies a failed chunk always triggers one token-only abort. */
async function testRegistrationAbort() {
    const methods = []
    /** @param {string} method - Strict method. @returns {Promise<object>} Controlled result. */
    async function request(method) {
        methods.push(method)
        return method === 'firmware-registration-chunk' ? { ok: false, reason: 'firmware-registration-invalid' } : { ok: true }
    }
    const result = await registerFirmwareImageFrames({ registration: { fileToken: 'firmware:abort', extension: '.BIN', bytes: Buffer.alloc(4) }, request })
    assert.deepEqual(result, { ok: false, reason: 'firmware-registration-invalid' })
    assert.deepEqual(methods, ['firmware-registration-begin', 'firmware-registration-chunk', 'firmware-registration-abort'])
}

test('firmware client sends ordered bounded path-free frames', testFirmwareRegistrationFrames)
test('firmware client aborts partial registration after failure', testRegistrationAbort)
