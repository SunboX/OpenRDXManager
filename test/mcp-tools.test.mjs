// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { createMcpToolRegistry, MCP_OPERATION_TOOLS, MCP_ROUTE_COVERAGE } from '../src/main/mcp/tool-registry.mjs'
import { APPLICATION_ROUTES } from '../src/main/application-dispatcher.mjs'
import { McpOperationStore } from '../src/main/mcp/operation-store.mjs'
import { OperationKind } from '../src/shared/schemas.mjs'

test('all operation kinds and numbered application features are discoverable to agents', async () => {
    const registry = createMcpToolRegistry({ services: {}, operationStore: new McpOperationStore() })
    assert.deepEqual(Object.keys(MCP_OPERATION_TOOLS).sort(), Object.values(OperationKind).sort())
    for (const name of Object.values(MCP_OPERATION_TOOLS))
        assert.ok(
            registry.some((tool) => tool.name === name),
            name
        )
    const coverage = await registry.find((tool) => tool.name === 'rdx_capabilities').execute({})
    assert.equal(coverage.features.length, 25)
    assert.equal(coverage.features.find((feature) => feature.documentNumber === 6).mapping.type, 'evidence-state')
    assert.equal(new Set(registry.map((tool) => tool.name)).size, registry.length)
    assert.deepEqual(Object.keys(MCP_ROUTE_COVERAGE).sort(), APPLICATION_ROUTES.map((route) => route.channel).sort())
    assert.equal(registry.find((tool) => tool.name === 'rdx_updates_check').annotations.openWorldHint, true)
    assert.equal(registry.find((tool) => tool.name === 'rdx_manufacturing_restore').annotations.destructiveHint, true)
    assert.equal(registry.find((tool) => tool.name === 'rdx_manufacturing_list').annotations.readOnlyHint, true)
})

test('agent state includes active scan reservations and unavailable service reasons without internal endpoints', async () => {
    const registry = createMcpToolRegistry({ services: {}, operationStore: new McpOperationStore(), getReadiness: () => ({ status: 'unavailable', reason: 'service-handshake-timeout', endpoint: '/private/helper.socket' }), getActiveOperation: () => ({ operationId: 'op:scan', kind: 'scan', stage: 'scan-running', generation: 9, cancellationRequested: false, irreversible: false }) })
    const status = await registry.find((entry) => entry.name === 'rdx_service_status').execute({})
    assert.equal(status.reason, 'service-handshake-timeout')
    assert.equal('endpoint' in status, false)
    const active = (await registry.find((entry) => entry.name === 'rdx_operations_list').execute({})).activeOperation
    assert.equal(active.kind, 'scan')
    assert.equal(active.operationId, 'op:scan')
    assert.equal('generation' in active, false)
})

test('tools reject forged operation variants and return hardware limits without guessing values', async () => {
    let dispatched = false
    const services = {
        operations: {
            start: () => {
                dispatched = true
            },
            getContext: () => ({ serviceMode: 'native', hardwareReady: true, activeOperation: null, device: { id: 'rdx:1', revision: 1, capabilities: { 'self-test': { state: 'evidence-incomplete' } } } })
        }
    }
    const registry = createMcpToolRegistry({ services, operationStore: new McpOperationStore() })
    const tool = registry.find((tool) => tool.name === 'rdx_self_test')
    assert.deepEqual(await tool.execute({ kind: 'format', deviceId: 'rdx:1', deviceRevision: 1 }), { ok: false, reason: 'invalid-request' })
    assert.deepEqual(await tool.execute({ deviceId: 'rdx:1', deviceRevision: 1 }), { ok: false, reason: 'evidence-incomplete' })
    assert.equal(dispatched, false)
    assert.equal(tool.annotations.readOnlyHint, false)
    assert.equal(registry.find((entry) => entry.name === 'rdx_format').annotations.destructiveHint, true)
})

test('tools contain service exceptions and keep firmware paths in the explicit registration workflow', async () => {
    const registry = createMcpToolRegistry({
        services: {},
        operationStore: new McpOperationStore(),
        firmwareFiles: {
            registerFirmwarePath: () => {
                throw new Error('secret path')
            }
        }
    })
    const tool = registry.find((entry) => entry.name === 'rdx_firmware_register')
    assert.deepEqual(await tool.execute({ path: '/local/image.BIN' }), { ok: false, reason: 'service-failure' })
    assert.deepEqual(await tool.execute({ path: '/local/image.BIN', rawCdb: [] }), { ok: false, reason: 'invalid-request' })
})

test('continuation tool requires an explicit invocation for one exact operator power-cycle gate', async () => {
    const calls = []
    const services = {
        operations: {
            continue: async (request) => {
                calls.push(request)
                return { ok: true, operationId: request.operationId }
            }
        }
    }
    const registry = createMcpToolRegistry({ services, operationStore: new McpOperationStore() })
    const tool = registry.find((entry) => entry.name === 'rdx_operation_continue')
    assert.ok(tool)
    assert.equal(tool.description, 'Acknowledge the requested USB power cycle only after the operator has reconnected the dock; exact operation and awaiting stage required.')
    assert.equal(tool.annotations.readOnlyHint, false)
    assert.equal(tool.annotations.destructiveHint, true, 'continuation may release the next firmware write')
    assert.deepEqual(calls, [], 'discovery cannot acknowledge a power cycle')
    for (const stage of ['firmware-awaiting-bootloader', 'firmware-awaiting-bootstrap']) {
        const request = { operationId: 'op:mcp-continue', stage }
        assert.deepEqual(await tool.execute(request), { ok: true, operationId: request.operationId })
        assert.deepEqual(calls.at(-1), request)
    }
    assert.deepEqual(await tool.execute({ operationId: 'op:mcp-continue', stage: 'firmware-staging' }), { ok: false, reason: 'invalid-request' })
    assert.deepEqual(await tool.execute({ operationId: 'op:mcp-continue', stage: 'firmware-awaiting-bootstrap', rawCdb: [] }), { ok: false, reason: 'invalid-request' })
    assert.equal(calls.length, 2)
})

test('recovery tools use closed selections and explicit physical acknowledgments', async () => {
    const calls = []
    const status = { state: 'running', revision: 1, attemptId: 'recovery:test', stage: 'recovery-awaiting-power-cycle', awaitingAcknowledgment: true }
    const registry = createMcpToolRegistry({
        services: {
            recovery: {
                list: async () => ({ ok: true, targets: [], bundles: [], status }),
                status: async () => ({ ok: true, status }),
                start: async (request) => {
                    calls.push(request)
                    return { ok: true, status }
                },
                continue: async (request) => {
                    calls.push(request)
                    return { ok: true, status }
                }
            }
        },
        operationStore: new McpOperationStore()
    })
    for (const name of ['rdx_recovery_list', 'rdx_recovery_status']) {
        const tool = registry.find((entry) => entry.name === name)
        assert.equal(tool.annotations.readOnlyHint, true)
        assert.equal((await tool.execute({})).ok, true)
    }
    const start = registry.find((entry) => entry.name === 'rdx_recovery_start')
    const proceed = registry.find((entry) => entry.name === 'rdx_recovery_continue')
    for (const tool of [start, proceed]) {
        assert.equal(tool.annotations.destructiveHint, true)
        assert.equal(tool.annotations.readOnlyHint, false)
        assert.equal(tool.annotations.idempotentHint, false)
    }
    const selection = { bundleId: 'migration-abc-0', targetToken: 'recovery-target:abc', acknowledged: true }
    const gate = { attemptId: status.attemptId, stage: status.stage, acknowledged: true }
    for (const request of [
        { ...selection, acknowledged: false },
        { ...selection, acknowledged: undefined },
        { ...selection, locationId: 2097152 },
        { ...selection, path: '/private/profile' }
    ])
        assert.deepEqual(await start.execute(request), { ok: false, reason: 'invalid-request' })
    for (const request of [
        { ...gate, acknowledged: false },
        { ...gate, stage: 'recovery-programming-bootstrap' },
        { ...gate, rawCdb: [] }
    ])
        assert.deepEqual(await proceed.execute(request), { ok: false, reason: 'invalid-request' })
    assert.deepEqual(calls, [])
    assert.deepEqual(await start.execute(selection), { ok: true, status })
    assert.deepEqual(await proceed.execute(gate), { ok: true, status })
    assert.deepEqual(calls, [selection, gate])
})
