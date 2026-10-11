// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { createMcpEventPublisher } from '../src/main/mcp/application-integration.mjs'
import { McpOperationStore } from '../src/main/mcp/operation-store.mjs'
import { scheduleAfterMcpResponse, runMcpResponseScope } from '../src/main/mcp/response-actions.mjs'
import { OperationCoordinator } from '../src/main/operation-coordinator.mjs'
import { createMcpToolRegistry } from '../src/main/mcp/tool-registry.mjs'
import { dispatchApplicationRequest } from '../src/main/application-dispatcher.mjs'
import { IpcChannel } from '../src/shared/ipc-contract.mjs'

test('MCP observes only accepted public events and the GUI keeps receiving the same terminal result', () => {
    const gui = []
    const changed = []
    const operationStore = new McpOperationStore()
    const publisher = createMcpEventPublisher({
        operationStore,
        ipcController: {
            publishOperationEvent: (event) => {
                gui.push(event)
                return true
            }
        },
        getController: () => ({ notifyResource: (uri) => changed.push(uri) })
    })
    const event = { operationId: 'op:1', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 1, state: 'succeeded', stage: 'complete' }
    assert.equal(publisher.publishOperationEvent({ ...event, secret: 'omit' }), false)
    assert.equal(publisher.publishOperationEvent(event), true)
    assert.deepEqual(gui, [event])
    assert.equal(operationStore.get('op:1').operation.state, 'succeeded')
    assert.deepEqual(changed, ['openrdx://operations', 'openrdx://operations/op%3A1', 'openrdx://activity', 'openrdx://support-summary'])
})

test('GUI and agent starts share the real coordinator lock and accepted terminal history', async () => {
    const store = new McpOperationStore()
    const coordinator = new OperationCoordinator({
        getDevice: () => ({ id: 'rdx:1', revision: 7, mediaState: 'present', capabilities: { 'self-test': { state: 'available' } } }),
        getPlatformCapability: () => ({ state: 'available' }),
        getServiceMode: () => 'native',
        hasPrivilege: () => true,
        isHardwareReady: () => true,
        dispatch: async () => ({ ok: true })
    })
    coordinator.subscribe((event) => store.publish(event))
    const services = { operations: { getContext: coordinator.getContext.bind(coordinator), start: coordinator.start.bind(coordinator) } }
    const tools = createMcpToolRegistry({ services, operationStore: store })
    const selfTest = tools.find((tool) => tool.name === 'rdx_self_test')
    const request = { deviceId: 'rdx:1', deviceRevision: 7 }
    const results = await Promise.all([dispatchApplicationRequest(services, IpcChannel.OPERATIONS_START, { ...request, kind: 'self-test' }), selfTest.execute(request)])
    assert.equal(results.filter((result) => result.ok).length, 1)
    assert.equal(results.find((result) => !result.ok).reason, 'operation-in-progress')
    const accepted = results.find((result) => result.ok)
    await new Promise(setImmediate)
    const terminal = { operationId: accepted.operationId, ...request, kind: 'self-test', state: 'succeeded', stage: 'complete' }
    assert.equal(coordinator.handleServiceEvent({ ...terminal, deviceRevision: 6 }), false)
    assert.notEqual(store.get(accepted.operationId).operation.state, 'succeeded')
    assert.equal(coordinator.handleServiceEvent({ ...terminal, state: 'started', stage: 'diagnostic-running' }), true)
    assert.equal(coordinator.handleServiceEvent({ ...terminal, state: 'progress', stage: 'diagnostic-cleanup', progress: 0.9, cancellationState: 'closed' }), true)
    assert.equal(coordinator.handleServiceEvent(terminal), true)
    assert.equal(store.get(accepted.operationId).operation.state, 'succeeded')
    assert.equal(coordinator.getActiveOperation(), null)
    assert.equal((await selfTest.execute(request)).ok, true)
})

test('MCP shutdown actions are request-scoped and cannot run before response completion', async () => {
    const actions = []
    let quit = false
    assert.equal(
        scheduleAfterMcpResponse(() => {
            quit = true
        }),
        false
    )
    await runMcpResponseScope(actions, async () => {
        assert.equal(
            scheduleAfterMcpResponse(() => {
                quit = true
            }),
            true
        )
        assert.equal(quit, false)
    })
    assert.equal(quit, false)
    assert.equal(actions.length, 1)
    actions[0]()
    assert.equal(quit, true)
})
