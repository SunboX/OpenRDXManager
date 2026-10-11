// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { applicationMetadata } from '../application-metadata.mjs'

import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client'
import { Server, ProtocolError, ProtocolErrorCode } from '@modelcontextprotocol/server'
import { serveStdio, StdioServerTransport } from '@modelcontextprotocol/server/stdio'
import { readPrivateText } from './private-files.mjs'

/** @param {string} value - Client-configured endpoint. @returns {URL} Exact local HTTP endpoint. @throws {TypeError} For remote, credential-bearing, or unexpected URLs. */
export function validateBridgeEndpoint(value) {
    const url = new URL(value)
    if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(url.hostname) || !url.port || url.username || url.password || url.search || url.hash || url.pathname !== '/mcp') throw new TypeError('Bridge requires a local MCP endpoint')
    return url
}

/** @param {Function} action - Fixed upstream SDK request. @returns {Promise<object>} Result or sanitized protocol failure. */
async function forward(action) {
    try {
        return await action()
    } catch {
        throw new ProtocolError(ProtocolErrorCode.InternalError, 'OpenRDXManager request failed; check the running application')
    }
}

/**
 * Attaches an SDK-based stdio server to the already-running application's HTTP endpoint.
 * The bridge owns no device runtime, never executes commands, and never writes application logs to stdout.
 * @param {{url:string,token?:string,tokenFile?:string,transport?:object}} options - Local endpoint, environment/file credentials, and optional stdio transport.
 * @returns {Promise<{close:Function}>} Owned protocol lifecycle.
 * @throws {Error} When configuration/authentication or the running endpoint is unavailable.
 */
export async function startStdioBridge(options) {
    const url = validateBridgeEndpoint(options.url)
    const token = options.token ?? (await readPrivateText(options.tokenFile, 65)).trim()
    if (!/^[a-f0-9]{64}$/.test(token)) throw new TypeError('Invalid MCP credentials')
    const upstream = new Client({ name: `${applicationMetadata.name}-stdio-bridge`, version: applicationMetadata.version }, { versionNegotiation: { mode: 'auto' } })
    const downstreams = new Map()
    let subscription
    let stdio
    const wire = options.transport ?? new StdioServerTransport(process.stdin, process.stdout, { maxBufferSize: 65_536 })
    let closing

    /** @returns {Promise<void>} Attempts both protocol legs and releases session bookkeeping even if teardown rejects. */
    async function closeProtocols() {
        try {
            await subscription?.close()
        } finally {
            try {
                await upstream.close()
            } finally {
                try {
                    await stdio?.close()
                } finally {
                    downstreams.clear()
                }
            }
        }
    }

    /** @returns {Promise<void>} Releases both protocol legs even when the downstream transport fails before stdin EOF. */
    function close() {
        closing ??= closeProtocols()
        return closing
    }

    /** @returns {Promise<void>} Observes teardown errors for detached disconnects and preserves startup errors. */
    async function closeAfterFailure() {
        try {
            await close()
        } catch {
            // Disconnects cannot recover this session; callers retain the original failure.
        }
    }
    try {
        await upstream.connect(new StreamableHTTPClientTransport(url, { requestInit: { headers: { Authorization: `Bearer ${token}` }, redirect: 'error' } }), { timeout: 5000 })
        const resources = (await upstream.listResources()).resources
        const tools = (await upstream.listTools()).tools
        const toolMap = new Map(tools.map((tool) => [tool.name, tool]))
        const known = new Map()
        // Seed identities before observing changes so a first removal/eviction
        // still invalidates an already subscribed per-device/operation URI.
        for (const collection of ['operations', 'devices']) {
            const result = await upstream.readResource({ uri: `openrdx://${collection}` })
            const entries = JSON.parse(result.contents[0].text)[collection] ?? []
            known.set(collection, new Set(entries.slice(0, 128).map((entry) => `openrdx://${collection}/${encodeURIComponent(collection === 'operations' ? entry.operationId : entry.id)}`)))
        }
        /** @param {string} uri - Accepted upstream resource change. @returns {Promise<void>} Relays invalidation; downstream SDK filters modern subscriptions. */
        async function publish(uri) {
            for (const [server, state] of downstreams) {
                if (state.era !== 'modern' && !state.subscribed.has(uri)) continue
                try {
                    await server.sendResourceUpdated({ uri })
                } catch {
                    // One disconnected subscriber must not interrupt other clients.
                }
            }
        }
        upstream.setNotificationHandler('notifications/resources/updated', async ({ params }) => {
            await publish(params.uri)
            // Subscribe upstream to bounded collection resources, then fan out their
            // invalidations to current and just-removed template identities.
            const collection = params.uri === 'openrdx://operations' ? 'operations' : params.uri === 'openrdx://devices' ? 'devices' : null
            if (collection === null) return
            try {
                const result = await upstream.readResource({ uri: params.uri }, { cacheMode: 'bypass' })
                const value = JSON.parse(result.contents[0].text)
                const entries = value[collection] ?? []
                const current = new Set(entries.slice(0, 128).map((entry) => `${params.uri}/${encodeURIComponent(collection === 'operations' ? entry.operationId : entry.id)}`))
                for (const uri of new Set([...(known.get(collection) ?? []), ...current])) await publish(uri)
                known.set(collection, current)
            } catch {
                /* The collection invalidation still tells clients to refresh. */
            }
        })
        subscription = await upstream.listen({ resourceSubscriptions: resources.map((resource) => resource.uri) })
        stdio = serveStdio(
            ({ era }) => {
                const server = new Server(applicationMetadata, { capabilities: { tools: {}, resources: { subscribe: true } } })
                const state = { era, subscribed: new Set() }
                downstreams.set(server, state)
                server.onclose = () => {
                    downstreams.delete(server)
                }
                server.setRequestHandler('tools/list', () => ({ tools }))
                server.setRequestHandler('tools/call', async ({ params }) => {
                    if (!toolMap.has(params.name)) throw new ProtocolError(ProtocolErrorCode.InvalidParams, 'Unknown OpenRDXManager tool')
                    const result = await forward(() => upstream.callTool({ name: params.name, arguments: params.arguments ?? {} }))
                    return server.projectCallToolResult(result, toolMap.get(params.name).outputSchema)
                })
                server.setRequestHandler('resources/list', () => forward(() => upstream.listResources()))
                server.setRequestHandler('resources/templates/list', () => forward(() => upstream.listResourceTemplates()))
                server.setRequestHandler('resources/read', ({ params }) => forward(() => upstream.readResource({ uri: params.uri }, { cacheMode: 'bypass' })))
                server.setRequestHandler('resources/subscribe', async ({ params }) => {
                    if (state.subscribed.size >= 128) throw new ProtocolError(ProtocolErrorCode.InvalidParams, 'Subscription limit reached')
                    await forward(() => upstream.readResource({ uri: params.uri }, { cacheMode: 'bypass' }))
                    state.subscribed.add(params.uri)
                    return {}
                })
                server.setRequestHandler('resources/unsubscribe', ({ params }) => {
                    state.subscribed.delete(params.uri)
                    return {}
                })
                return server
            },
            { transport: wire, maxSubscriptions: 16 }
        )
        const sdkClose = wire.onclose
        // Observe the actual wire, including failures before initialization.
        // SDK probe instances may close during negotiation without losing it.
        wire.onclose = () => {
            try {
                sdkClose?.()
            } finally {
                void closeAfterFailure()
            }
        }
    } catch (error) {
        await closeAfterFailure()
        throw error
    }
    return { close }
}
