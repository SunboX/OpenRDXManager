// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { applicationMetadata } from '../src/main/application-metadata.mjs'
import test from 'node:test'
import { request } from 'node:http'
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client'
import { McpHttpServer } from '../src/main/mcp/server.mjs'
import { createMcpToolRegistry } from '../src/main/mcp/tool-registry.mjs'
import { McpOperationStore } from '../src/main/mcp/operation-store.mjs'
import { scheduleAfterMcpResponse } from '../src/main/mcp/response-actions.mjs'

const token = 'f'.repeat(64)

/** @param {object} context - Node test context. @returns {Promise<object>} Bound real endpoint with a controlled app service. */
async function fixture(context) {
    const operationStore = new McpOperationStore()
    const services = { app: { getInfo: () => ({ ok: true, app: { name: 'OpenRDXManager', version: '0.1.0', platform: 'darwin' } }) } }
    const server = new McpHttpServer({ token, tools: createMcpToolRegistry({ services, operationStore }) })
    const endpoint = await server.start(0)
    context.after(() => server.stop())
    return { server, endpoint }
}

/** @param {string} endpoint - Bound URL. @param {object} headers - Test request headers. @param {string} body - Request body. @returns {Promise<number>} HTTP status, including invalid Host cases. */
function post(endpoint, headers = {}, body = '{}') {
    return new Promise((resolve, reject) => {
        const req = request(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers } }, (res) => {
            res.resume()
            res.on('end', () => resolve(res.statusCode))
        })
        req.on('error', reject)
        req.end(body)
    })
}

test('real SDK clients discover and call tools and read resources through authenticated HTTP', async (context) => {
    const { endpoint } = await fixture(context)
    const client = new Client({ name: 'test-client', version: '1' })
    context.after(() => client.close())
    await client.connect(new StreamableHTTPClientTransport(new URL(endpoint), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }))
    assert.deepEqual(client.getServerVersion(), applicationMetadata)
    assert.equal(client.getServerCapabilities().resources.subscribe, false)
    assert.equal(client.getServerCapabilities().resources.listChanged, false)
    assert.ok((await client.listTools()).tools.some((entry) => entry.name === 'rdx_format'))
    const info = await client.callTool({ name: 'rdx_app_info', arguments: {} })
    assert.equal(info.structuredContent.app.name, 'OpenRDXManager')
    assert.ok((await client.listResources()).resources.some((entry) => entry.uri === 'openrdx://app'))
    const resource = await client.readResource({ uri: 'openrdx://app' })
    assert.equal(JSON.parse(resource.contents[0].text).app.platform, 'darwin')
    const failed = await client.callTool({ name: 'rdx_devices_list', arguments: {} })
    assert.equal(failed.isError, true)
    assert.equal(failed.structuredContent.reason, 'service-unavailable')
})

test('HTTP rejects missing credentials, hostile Host and Origin, invalid JSON, and oversized bodies', async (context) => {
    const { endpoint } = await fixture(context)
    assert.equal(await post(endpoint), 401)
    assert.equal(await post(endpoint, { Authorization: 'Bearer incorrect' }), 401)
    const auth = { Authorization: `Bearer ${token}` }
    assert.equal(await post(endpoint, { ...auth, Host: 'attacker.example' }), 403)
    assert.equal(await post(endpoint, { ...auth, Origin: 'https://attacker.example' }), 403)
    assert.equal(await post(endpoint, { ...auth, Origin: 'null' }), 403)
    assert.equal(await post(endpoint, auth, '{invalid'), 400)
    assert.equal(await post(endpoint, auth, 'x'.repeat(65537)), 413)
})

test('closing the server releases its port and does not mutate retained operation state', async (context) => {
    const { server, endpoint } = await fixture(context)
    await server.stop()
    await server.stop()
    await assert.rejects(fetch(endpoint), /fetch failed/)
})

test('modern clients negotiate explicitly and receive resource change subscriptions', async (context) => {
    const { server, endpoint } = await fixture(context)
    const client = new Client({ name: 'modern-test', version: '1' }, { versionNegotiation: { mode: 'auto' } })
    context.after(() => client.close())
    await client.connect(new StreamableHTTPClientTransport(new URL(endpoint), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }))
    assert.equal((await client.callTool({ name: 'rdx_app_info', arguments: {} })).structuredContent.app.name, 'OpenRDXManager')
    let timer
    const received = new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error('Resource update was not delivered')), 2000)
        client.setNotificationHandler('notifications/resources/updated', ({ params }) => resolve(params.uri))
    })
    context.after(() => clearTimeout(timer))
    const subscription = await client.listen({ resourceSubscriptions: ['openrdx://operations'] })
    context.after(() => subscription.close())
    server.notifyResource('openrdx://operations')
    assert.equal(await received, 'openrdx://operations')
    clearTimeout(timer)
})

test('application exit delivers its MCP result before closing the endpoint', async (context) => {
    let stopped
    const stoppedPromise = new Promise((resolve) => {
        stopped = resolve
    })
    const server = new McpHttpServer({
        token,
        tools: createMcpToolRegistry({
            services: {},
            operationStore: new McpOperationStore(),
            desktop: {
                /** @returns {object} Models the production guarded desktop exit boundary. */
                exit() {
                    return {
                        ok: scheduleAfterMcpResponse(async () => {
                            await server.stop()
                            stopped()
                        })
                    }
                }
            }
        })
    })
    const endpoint = await server.start(0)
    context.after(() => server.stop())
    const client = new Client({ name: 'exit-test', version: '1' })
    context.after(() => client.close())
    await client.connect(new StreamableHTTPClientTransport(new URL(endpoint), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }))
    assert.deepEqual((await client.callTool({ name: 'rdx_app_exit', arguments: {} })).structuredContent, { ok: true })
    await stoppedPromise
    await assert.rejects(fetch(endpoint), /fetch failed/)
})

test('completed HTTP responses contain asynchronous deferred-action failures and still run later actions', async (context) => {
    const finished = Promise.withResolvers()
    const server = new McpHttpServer({
        token,
        tools: createMcpToolRegistry({
            services: {},
            operationStore: new McpOperationStore(),
            desktop: {
                /** @returns {object} Schedules controlled failing actions at the real HTTP response boundary. */
                exit() {
                    scheduleAfterMcpResponse(async () => {
                        throw new Error('controlled asynchronous action failure')
                    })
                    scheduleAfterMcpResponse(() => {
                        throw new Error('controlled synchronous action failure')
                    })
                    return { ok: scheduleAfterMcpResponse(finished.resolve) }
                }
            }
        })
    })
    const endpoint = await server.start(0)
    context.after(() => server.stop())
    const client = new Client({ name: 'deferred-action-test', version: '1' })
    context.after(() => client.close())
    await client.connect(new StreamableHTTPClientTransport(new URL(endpoint), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }))
    assert.deepEqual((await client.callTool({ name: 'rdx_app_exit', arguments: {} })).structuredContent, { ok: true })
    await finished.promise
    assert.ok((await client.listTools()).tools.length > 0)
})

test('chunked oversized requests receive a bounded rejection', async (context) => {
    const { endpoint } = await fixture(context)
    const status = await new Promise((resolve, reject) => {
        const req = request(endpoint, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', 'Transfer-Encoding': 'chunked' } }, (res) => {
            res.resume()
            res.on('end', () => resolve(res.statusCode))
        })
        req.on('error', reject)
        req.write('x'.repeat(32768))
        req.end('x'.repeat(32769))
    })
    assert.equal(status, 413)
})
