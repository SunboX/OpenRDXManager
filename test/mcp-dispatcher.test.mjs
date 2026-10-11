// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { dispatchApplicationRequest } from '../src/main/application-dispatcher.mjs'
import { McpOperationStore } from '../src/main/mcp/operation-store.mjs'
import { IpcChannel } from '../src/shared/ipc-contract.mjs'

test('shared dispatch rejects unknown routes, unsafe payloads, and invalid service responses', async () => {
    const services = { app: { getInfo: () => ({ ok: true, app: { name: 'Manager', version: '1', platform: 'darwin' }, secret: 'never-return' }) } }
    assert.deepEqual(await dispatchApplicationRequest(services, 'arbitrary', {}), { ok: false, reason: 'unknown-route' })
    assert.deepEqual(await dispatchApplicationRequest(services, IpcChannel.APP_GET, { command: 'anything' }), { ok: false, reason: 'invalid-request' })
    assert.deepEqual(await dispatchApplicationRequest(services, IpcChannel.APP_GET, JSON.parse('{"__proto__":{}}')), { ok: false, reason: 'prototype-control-key' })
    assert.deepEqual(await dispatchApplicationRequest(services, IpcChannel.APP_GET, {}), { ok: false, reason: 'invalid-service-response' })
})

test('MCP dispatch observes the same busy and stale-device checks as GUI requests', async () => {
    let dispatched = 0
    const context = { activeOperation: null, serviceMode: 'native', hardwareReady: true, hasPrivilege: true, platformCapability: { state: 'available' }, device: { id: 'rdx:1', revision: 4, capabilities: { 'self-test': { state: 'available' } } } }
    const services = {
        operations: {
            getContext: () => context,
            start: () => {
                dispatched++
                return { ok: true, operationId: 'op:1' }
            }
        }
    }
    assert.deepEqual(await dispatchApplicationRequest(services, IpcChannel.OPERATIONS_START, { kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 3 }), { ok: false, reason: 'stale-device-revision' })
    context.activeOperation = { operationId: 'op:gui' }
    assert.deepEqual(await dispatchApplicationRequest(services, IpcChannel.OPERATIONS_START, { kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 4 }), { ok: false, reason: 'operation-in-progress' })
    assert.equal(dispatched, 0)
    context.activeOperation = null
    assert.deepEqual(await dispatchApplicationRequest(services, IpcChannel.OPERATIONS_START, { kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 4 }), { ok: true, operationId: 'op:1' })
    assert.equal(dispatched, 1)
})

test('operation history publishes only strict public events and returns detached terminal results', () => {
    const store = new McpOperationStore()
    const events = []
    const unsubscribe = store.subscribe((event) => events.push(event))
    const terminal = { operationId: 'op:1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 1, state: 'succeeded', stage: 'complete' }
    assert.equal(store.publish({ ...terminal, secret: 'never-return' }), false)
    assert.deepEqual(store.get('op:1'), { ok: false, reason: 'operation-not-found' })
    assert.equal(store.publish(terminal), true)
    const result = store.get('op:1')
    result.operation.stage = 'tampered'
    events[0].stage = 'tampered'
    assert.equal(store.get('op:1').operation.stage, 'complete')
    unsubscribe()
    for (let index = 2; index <= 130; index++) store.publish({ ...terminal, operationId: `op:${index}` })
    assert.equal(store.list().operations.length, 128)
    assert.equal(events.length, 1)
    assert.deepEqual(store.get('op:1'), { ok: false, reason: 'operation-not-found' })
})
