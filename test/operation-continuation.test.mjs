// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { createPreloadApi } from '../src/preload-api.mjs'
import { createOpenRdxIntentAdapter } from '../src/renderer/intent-adapter.mjs'
import { IpcChannel } from '../src/shared/ipc-contract.mjs'
import { OperationContinuationService } from '../src/main/operation-continuation-service.mjs'
import { EventEmitter } from 'node:events'
import { DeviceServiceClient } from '../src/main/device-service-client.mjs'
import { encodeServiceFrame } from '../src/main/device-service-transport.mjs'

test('continuation preload and renderer intent accept only the exact two operator gates', async () => {
    const calls = []
    const api = createPreloadApi({
        invoke: async (channel, request) => {
            calls.push({ channel, request })
            return { ok: true, operationId: request.operationId }
        },
        on: () => {},
        removeListener: () => {}
    })
    assert.equal(typeof api.operations.continue, 'function')
    const adapter = createOpenRdxIntentAdapter(api)
    assert.equal(adapter.isAvailable('operation-continue'), true)
    for (const stage of ['firmware-awaiting-bootloader', 'firmware-awaiting-bootstrap']) {
        const request = { operationId: 'op:continue', stage }
        assert.deepEqual(await adapter.invoke({ type: 'operation-continue', ...request }), { ok: true, operationId: request.operationId })
        assert.deepEqual(calls.at(-1), { channel: IpcChannel.OPERATIONS_CONTINUE, request })
    }
    for (const invalid of [{ operationId: 'op:continue', stage: 'firmware-staging' }, { operationId: 'op:continue', stage: 'firmware-awaiting-bootstrap', cdb: [0] }, { operationId: 'op:continue', stage: 'firmware-awaiting-bootstrap', deviceId: 'rdx:other' }, { operationId: 'op:continue' }]) {
        assert.equal(await adapter.invoke({ type: 'operation-continue', ...invalid }), false)
        await assert.rejects(api.operations.continue(invalid), TypeError)
    }
    assert.equal(calls.length, 2)
})

test('main continuation rejects stale owners and duplicates while retaining both separate gates', async () => {
    let active = { operationId: 'op:continue', kind: 'firmware-update', stage: 'firmware-awaiting-bootloader', generation: 3 }
    const calls = []
    const response = Promise.withResolvers()
    const service = new OperationContinuationService({
        getActiveOperation: () => active,
        dispatch: async (request) => {
            calls.push(request)
            return response.promise
        }
    })
    const request = { operationId: active.operationId, stage: active.stage }
    assert.equal((await service.continue({ ...request, operationId: 'op:stale' })).ok, false)
    assert.equal((await service.continue({ ...request, stage: 'firmware-awaiting-bootstrap' })).ok, false)
    const pending = service.continue(request)
    assert.equal((await service.continue(request)).ok, false)
    response.resolve({ ok: true, operationId: active.operationId })
    assert.deepEqual(await pending, { ok: true, operationId: active.operationId })
    assert.equal((await service.continue(request)).ok, false)
    active = { ...active, stage: 'firmware-awaiting-bootstrap' }
    assert.equal((await service.continue({ ...request, stage: active.stage })).ok, true)
    assert.equal(calls.length, 2)
    assert.equal(active.kind, 'firmware-update', 'acknowledgement never removes the operation owner')
})

test('uncertain continuation acknowledgements cannot authorize a duplicate request', async () => {
    const active = { operationId: 'op:continue', kind: 'firmware-update', stage: 'firmware-awaiting-bootloader', generation: 3 }
    for (const result of [
        { ok: true, operationId: 'op:other' },
        { ok: false, reason: 'operation-outcome-unknown', ambiguous: true }
    ]) {
        let calls = 0
        const service = new OperationContinuationService({
            getActiveOperation: () => active,
            dispatch: async () => {
                calls += 1
                return result
            }
        })
        const request = { operationId: active.operationId, stage: active.stage }
        assert.deepEqual(await service.continue(request), { ok: false, reason: 'operation-outcome-unknown' })
        assert.equal((await service.continue(request)).ok, false)
        assert.equal(calls, 1)
    }
})

test('service client sends the strict continuation method and preserves its owner acknowledgement', async () => {
    const transport = new EventEmitter()
    const calls = []
    /** @param {object} message - Controlled wire response. @returns {void} Emits one bounded production frame. */
    function emit(message) {
        transport.emit('data', encodeServiceFrame(message, 65536))
    }
    /** @param {Buffer} frame - Outgoing production frame. @returns {boolean} Accepts a mocked native request. */
    transport.write = (frame) => {
        const message = JSON.parse(frame.subarray(4).toString('utf8'))
        if (message.method === 'devices-list') queueMicrotask(() => emit({ type: 'response', requestId: message.requestId, ok: true, result: { ok: true, listRevision: 0, devices: [] } }))
        if (message.method === 'operation-continue') {
            calls.push(message)
            queueMicrotask(() => emit({ type: 'response', requestId: message.requestId, ok: true, result: { ok: true, operationId: message.payload.operationId } }))
        }
        return true
    }
    /** @returns {object} Closes the in-memory transport. */
    transport.close = () => ({ confirmed: true })
    /** @returns {EventEmitter} Starts a simulated native service, without a process or device. */
    function transportFactory() {
        queueMicrotask(() => emit({ type: 'handshake', protocolVersion: 1, serviceVersion: 'continuation-test', platform: 'darwin', mode: 'native', privileged: true, platformCapability: { state: 'available' } }))
        return transport
    }
    const client = new DeviceServiceClient({ executable: '/private/test/openrdx-hardware', platform: 'darwin', maxRestarts: 0, transportFactory })
    try {
        await client.start()
        const request = { operationId: 'op:continue-wire', stage: 'firmware-awaiting-bootloader' }
        assert.deepEqual(await client.continueOperation(request), { ok: true, operationId: request.operationId })
        assert.deepEqual(calls[0].payload, request)
        assert.equal((await client.continueOperation({ ...request, stage: 'firmware-staging' })).ok, false)
        assert.equal(calls.length, 1)
    } finally {
        await client.stop()
    }
})
