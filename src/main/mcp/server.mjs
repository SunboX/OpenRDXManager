// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createServer } from 'node:http'
import { timingSafeEqual } from 'node:crypto'
import { createMcpHandler } from '@modelcontextprotocol/server'
import { toNodeHandler } from '@modelcontextprotocol/node'
import { createSdkServer } from './sdk-server.mjs'
import { runMcpResponseScope } from './response-actions.mjs'

const MAX_BODY_BYTES = 65_536
const MAX_REQUESTS = 32

/** @param {object} response - Node response. @param {number} status - HTTP status. @param {string} reason - Fixed public failure. @returns {void} Ends the response without echoing request data. */
function reject(response, status, reason) {
    if (response.destroyed || response.headersSent) return
    response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', Connection: 'close' })
    response.end(JSON.stringify({ error: reason }))
}

/** @param {Function} action - Main-owned action admitted after a complete HTTP response. @returns {Promise<void>} Contains synchronous and asynchronous action failures at the detached response boundary. */
async function runAfterResponseAction(action) {
    try {
        await action()
    } catch {
        // Desktop lifecycle retains its own safety checks after the response ends.
    }
}

/** Authenticated loopback MCP listener; owns protocol connections, never device work. */
export class McpHttpServer {
    #token
    #tools
    #handler = null
    #server = null
    #endpoint = null
    #requests = 0
    #sockets = new Set()
    #stopping = null

    /** @param {{token:string,tools:object[]}} options - Secret and main-owned registry. @throws {TypeError} For invalid startup configuration. */
    constructor({ token, tools }) {
        if (typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token) || !Array.isArray(tools)) throw new TypeError('Invalid MCP server configuration')
        this.#token = Buffer.from(`Bearer ${token}`)
        this.#tools = tools
    }

    /** @param {number} port - Local TCP port; zero selects an ephemeral test port. @returns {Promise<string>} Endpoint after binding. @throws {Error} For bind failures or duplicate start. */
    async start(port) {
        if (this.#server !== null || !Number.isInteger(port) || port < 0 || port > 65535) throw new TypeError('Invalid MCP listener state')
        this.#handler = createMcpHandler(({ era }) => createSdkServer(this.#tools, era), { maxSubscriptions: 16 })
        const handle = toNodeHandler(this.#handler)
        this.#server = createServer((request, response) => {
            void this.#handle(request, response, handle)
        })
        this.#server.maxConnections = 64
        this.#server.headersTimeout = 10_000
        this.#server.requestTimeout = 15_000
        this.#server.on('connection', (socket) => {
            this.#sockets.add(socket)
            socket.once('close', () => this.#sockets.delete(socket))
        })
        try {
            await new Promise((resolve, rejectBind) => {
                this.#server.once('error', rejectBind)
                this.#server.listen(port, '127.0.0.1', () => {
                    this.#server.removeListener('error', rejectBind)
                    resolve()
                })
            })
        } catch (error) {
            await this.stop()
            throw error
        }
        const address = this.#server.address()
        this.#endpoint = `http://127.0.0.1:${address.port}/mcp`
        return this.#endpoint
    }

    /** @param {object} request - Incoming HTTP request. @param {object} response - Outgoing response. @param {Function} handle - SDK Node adapter. @returns {Promise<void>} Bounded authenticated dispatch; failures contain no request data. */
    async #handle(request, response, handle) {
        try {
            const endpoint = this.#endpoint === null ? null : new URL(this.#endpoint)
            if (endpoint === null || this.#stopping !== null) return reject(response, 503, 'server-stopping')
            const allowedHosts = [`127.0.0.1:${endpoint.port}`, `localhost:${endpoint.port}`]
            if (!allowedHosts.includes(request.headers.host)) return reject(response, 403, 'invalid-host')
            const origin = request.headers.origin
            if (origin !== undefined && !allowedHosts.some((host) => origin === `http://${host}`)) return reject(response, 403, 'invalid-origin')
            const candidate = Buffer.from(request.headers.authorization ?? '')
            if (candidate.length !== this.#token.length || !timingSafeEqual(candidate, this.#token)) return reject(response, 401, 'unauthorized')
            if (request.url !== '/mcp') return reject(response, 404, 'not-found')
            if (!['POST', 'GET', 'DELETE'].includes(request.method)) return reject(response, 405, 'method-not-allowed')
            if (this.#requests >= MAX_REQUESTS) return reject(response, 429, 'request-limit')
            this.#requests++
            let counted = true
            /** @returns {void} Releases the slot once even when an SSE peer disconnects. */
            const release = () => {
                if (counted) {
                    counted = false
                    this.#requests--
                }
            }
            response.once('close', release)
            response.once('finish', release)
            response.setHeader('Cache-Control', 'no-store')
            let body
            if (request.method === 'POST') {
                if (request.headers['content-type']?.split(';')[0].trim().toLowerCase() !== 'application/json') return reject(response, 415, 'unsupported-content-type')
                if (Number(request.headers['content-length']) > MAX_BODY_BYTES) return reject(response, 413, 'request-too-large')
                const chunks = []
                let size = 0
                const timeout = setTimeout(() => request.destroy(), 10_000)
                try {
                    for await (const chunk of request) {
                        size += chunk.length
                        if (size > MAX_BODY_BYTES) return reject(response, 413, 'request-too-large')
                        chunks.push(chunk)
                    }
                } finally {
                    clearTimeout(timeout)
                }
                try {
                    body = JSON.parse(Buffer.concat(chunks).toString('utf8'))
                } catch {
                    return reject(response, 400, 'invalid-json')
                }
            }
            // The SDK owns version negotiation and subscription wire semantics.
            const afterResponse = []
            response.once('finish', () => {
                // A normal exit response must reach the client before Electron
                // closes the endpoint. Failed/disconnected responses do not quit.
                setImmediate(() => {
                    for (const action of afterResponse) {
                        void runAfterResponseAction(action)
                    }
                })
            })
            await runMcpResponseScope(afterResponse, () => handle(request, response, body))
        } catch {
            reject(response, 500, 'server-failure')
        }
    }

    /** @param {string} uri - Known public resource URI. @returns {void} Announces accepted application state changes to subscribed clients. */
    notifyResource(uri) {
        if (typeof uri === 'string' && uri.startsWith('openrdx://')) this.#handler?.notify.resourceUpdated(uri)
    }

    /** @returns {Promise<void>} Idempotently closes protocol connections without cancelling native operations. */
    stop() {
        this.#stopping ??= this.#close()
        return this.#stopping
    }

    /** @returns {Promise<void>} Releases HTTP/SSE resources even with a disconnected or stalled client. */
    async #close() {
        this.#endpoint = null
        const closed = this.#server === null ? Promise.resolve() : new Promise((resolve) => this.#server.close(resolve))
        await this.#handler?.close()
        for (const socket of this.#sockets) socket.destroy()
        await closed
        this.#server = null
        this.#handler = null
    }
}
