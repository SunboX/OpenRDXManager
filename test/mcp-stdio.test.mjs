// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { applicationMetadata } from '../src/main/application-metadata.mjs'
import test from 'node:test'
import { Client } from '@modelcontextprotocol/client'
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio'
import { fileURLToPath } from 'node:url'
import { McpHttpServer } from '../src/main/mcp/server.mjs'
import { McpOperationStore } from '../src/main/mcp/operation-store.mjs'
import { createMcpToolRegistry } from '../src/main/mcp/tool-registry.mjs'
import { validateBridgeEndpoint } from '../src/main/mcp/stdio-bridge.mjs'
import { spawn } from 'node:child_process'

test('stdio bridge rejects remote URLs and credential-bearing or unexpected paths', () => {
    for (const url of ['https://example.com/mcp', 'http://0.0.0.0:48170/mcp', 'http://127.0.0.1:48170/mcp?token=secret', 'http://user:pass@127.0.0.1:48170/mcp', 'http://127.0.0.1:48170/other']) assert.throws(() => validateBridgeEndpoint(url))
    assert.equal(validateBridgeEndpoint('http://127.0.0.1:48170/mcp').href, 'http://127.0.0.1:48170/mcp')
})

test('bridge exits when its client loses stdout even if the paused stdin cannot deliver EOF', { timeout: 8000 }, async (context) => {
    const token = 'd'.repeat(64)
    const server = new McpHttpServer({ token, tools: createMcpToolRegistry({ services: {}, operationStore: new McpOperationStore() }) })
    const endpoint = await server.start(0)
    context.after(() => server.stop())
    const child = spawn(process.execPath, [fileURLToPath(new URL('../scripts/mcp-stdio.mjs', import.meta.url))], { env: { ...process.env, OPENRDX_MCP_URL: endpoint, OPENRDX_MCP_TOKEN: token }, stdio: ['pipe', 'pipe', 'pipe'] })
    context.after(() => {
        if (child.exitCode === null) child.kill('SIGTERM')
    })
    const exited = new Promise((resolve) => child.once('exit', resolve))
    let stderr = ''
    child.stderr.on('data', (chunk) => {
        stderr += chunk
    })
    const initialized = new Promise((resolve) => child.stdout.once('data', resolve))
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'lost-output-test', version: '1' } } })}\n`)
    await initialized
    child.stdout.destroy()
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} })}\n`)
    child.stdin.end()
    let timer
    try {
        await Promise.race([
            exited,
            new Promise((_, reject) => {
                timer = setTimeout(() => reject(new Error('Bridge retained upstream after output loss')), 2000)
            })
        ])
    } finally {
        clearTimeout(timer)
    }
    assert.equal(stderr.includes(token), false)
})

test('bridge releases upstream when framing fails before initialization', { timeout: 8000 }, async (context) => {
    const token = 'e'.repeat(64)
    const server = new McpHttpServer({ token, tools: createMcpToolRegistry({ services: {}, operationStore: new McpOperationStore() }) })
    const endpoint = await server.start(0)
    context.after(() => server.stop())
    const child = spawn(process.execPath, [fileURLToPath(new URL('../scripts/mcp-stdio.mjs', import.meta.url))], { env: { ...process.env, OPENRDX_MCP_URL: endpoint, OPENRDX_MCP_TOKEN: token }, stdio: ['pipe', 'pipe', 'pipe'] })
    context.after(() => {
        if (child.exitCode === null) child.kill('SIGTERM')
    })
    const exited = new Promise((resolve) => child.once('exit', resolve))
    child.stdin.on('error', () => {})
    child.stdout.resume()
    child.stderr.resume()
    child.stdin.end('x'.repeat(11 * 1024 * 1024))
    let timer
    try {
        await Promise.race([
            exited,
            new Promise((_, reject) => {
                timer = setTimeout(() => reject(new Error('Opening bridge leaked its upstream connection')), 2000)
            })
        ])
    } finally {
        clearTimeout(timer)
    }
})

for (const mode of ['legacy', 'auto'])
    test(`real ${mode} stdio bridge attaches and relays subscribed operation resources`, async (context) => {
        const token = 'c'.repeat(64)
        const services = { app: { getInfo: () => ({ ok: true, app: { name: 'Shared manager', version: '1', platform: 'linux' } }) } }
        const operationStore = new McpOperationStore()
        const event = { operationId: 'op:stdio', kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 1, state: 'started', stage: 'diagnostic-running' }
        operationStore.publish(event)
        const server = new McpHttpServer({ token, tools: createMcpToolRegistry({ services, operationStore }) })
        const endpoint = await server.start(0)
        context.after(() => server.stop())
        const transport = new StdioClientTransport({ command: process.execPath, args: [fileURLToPath(new URL('../scripts/mcp-stdio.mjs', import.meta.url))], env: { OPENRDX_MCP_URL: endpoint, OPENRDX_MCP_TOKEN: token }, stderr: 'pipe' })
        let stderr = ''
        transport.stderr?.on('data', (chunk) => {
            stderr += chunk
        })
        const client = new Client({ name: 'stdio-test', version: '1' }, mode === 'auto' ? { versionNegotiation: { mode } } : {})
        context.after(() => client.close())
        await client.connect(transport)
        assert.deepEqual(client.getServerVersion(), applicationMetadata)
        assert.ok((await client.listTools()).tools.some((tool) => tool.name === 'rdx_firmware_update'))
        assert.equal((await client.callTool({ name: 'rdx_app_info', arguments: {} })).structuredContent.app.name, 'Shared manager')
        assert.equal(JSON.parse((await client.readResource({ uri: 'openrdx://app' })).contents[0].text).app.platform, 'linux')
        const uri = 'openrdx://operations/op%3Astdio'
        assert.equal(JSON.parse((await client.readResource({ uri })).contents[0].text).operation.state, 'started')
        let timer
        const received = new Promise((resolve, reject) => {
            timer = setTimeout(() => reject(new Error('Bridge operation update not delivered')), 3000)
            client.setNotificationHandler('notifications/resources/updated', ({ params }) => {
                if (params.uri === uri) resolve(params.uri)
            })
        })
        context.after(() => clearTimeout(timer))
        const subscription = mode === 'auto' ? await client.listen({ resourceSubscriptions: [uri] }) : null
        if (mode === 'legacy') await client.subscribeResource({ uri })
        operationStore.publish({ ...event, state: 'succeeded', stage: 'complete' })
        if (mode === 'auto') {
            // Evict the subscribed identity before the first collection notification.
            for (let index = 0; index < 128; index++) operationStore.publish({ ...event, operationId: `op:new-${index}` })
        }
        server.notifyResource('openrdx://operations')
        assert.equal(await received, uri)
        clearTimeout(timer)
        const latest = JSON.parse((await client.readResource({ uri }, { cacheMode: 'bypass' })).contents[0].text)
        if (mode === 'auto') assert.equal(latest.reason, 'operation-not-found')
        else assert.equal(latest.operation.state, 'succeeded')
        await subscription?.close()
        await client.close()
        assert.equal(stderr.includes(token), false)
        assert.equal(stderr, '')
    })
