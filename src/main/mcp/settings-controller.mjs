// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { join } from 'node:path'
import { mcpSettingsSchema, mcpSettingsUpdateSchema } from '../../shared/mcp-schemas.mjs'
import { hasOwnPrototypeControlKey } from '../../shared/boundary-validation.mjs'
import { loadMcpToken, preparePrivateDirectory, readPrivateText, writePrivateText } from './private-files.mjs'

/** Serializes durable opt-in and loopback listener lifecycle while keeping credentials in main. */
export class McpSettingsController {
    #options
    #settings = { enabled: false, port: 48170 }
    #state = { status: 'disabled', endpoint: null }
    #server = null
    #queue = Promise.resolve()
    #closing = false

    /** @param {{directory:string,createServer:Function,copyText:Function,bridgePath:string}} options - Main-only filesystem and runtime dependencies. @throws {TypeError} For missing dependencies. */
    constructor(options) {
        if (typeof options?.directory !== 'string' || typeof options.createServer !== 'function' || typeof options.copyText !== 'function' || typeof options.bridgePath !== 'string') throw new TypeError('Invalid MCP settings configuration')
        this.#options = options
    }

    /** @returns {Promise<object>} Loads preferences and starts only an explicitly enabled endpoint. Corrupt configuration defaults to disabled. */
    load() {
        return this.#serialize(async () => {
            try {
                await preparePrivateDirectory(this.#options.directory)
                try {
                    const parsed = mcpSettingsSchema.safeParse(JSON.parse(await readPrivateText(join(this.#options.directory, 'settings.json'))))
                    if (parsed.success) this.#settings = parsed.data
                } catch {
                    /* Absent or invalid preferences never opt the user in. */
                }
                await this.#apply()
            } catch {
                this.#state = { status: 'error', endpoint: null, reason: 'mcp-settings-unavailable' }
            }
            return this.getStatus()
        })
    }

    /** @returns {Promise<object>} Detached non-secret configured/runtime status. */
    async getStatus() {
        return { ok: true, ...this.#settings, ...this.#state }
    }

    /** @param {unknown} request - Exact local settings patch. @returns {Promise<object>} Persisted configuration and actual bind status, or safe rejection. */
    async update(request) {
        if (hasOwnPrototypeControlKey(request)) return { ok: false, reason: 'invalid-request' }
        const parsed = mcpSettingsUpdateSchema.safeParse(request)
        if (!parsed.success) return { ok: false, reason: 'invalid-request' }
        return this.#serialize(async () => {
            if (this.#closing) return { ok: false, reason: 'server-stopping' }
            const next = { ...this.#settings, ...parsed.data }
            try {
                await preparePrivateDirectory(this.#options.directory)
                await writePrivateText(this.#options.directory, 'settings.json', `${JSON.stringify(next)}\n`)
            } catch {
                return { ok: false, reason: 'mcp-settings-write-failed' }
            }
            const changed = next.enabled !== this.#settings.enabled || next.port !== this.#settings.port
            this.#settings = next
            if (changed || this.#state.status === 'error') await this.#apply()
            return this.getStatus()
        })
    }

    /** @returns {Promise<object>} Copies an executable stdio client configuration without copying bearer-token contents. */
    copyConfiguration() {
        return this.#serialize(async () => {
            if (this.#state.status !== 'listening') return { ok: false, reason: 'mcp-not-listening' }
            const configuration = { mcpServers: { OpenRDXManager: { command: 'node', args: [this.#options.bridgePath], env: { OPENRDX_MCP_URL: this.#state.endpoint, OPENRDX_MCP_TOKEN_FILE: join(this.#options.directory, 'token') } } } }
            try {
                await this.#options.copyText(JSON.stringify(configuration, null, 2))
                return { ok: true }
            } catch {
                return { ok: false, reason: 'mcp-copy-failed' }
            }
        })
    }

    /** @param {string} uri - Public resource identity. @returns {void} Forwards accepted state updates only to the active endpoint. */
    notifyResource(uri) {
        this.#server?.notifyResource(uri)
    }

    /** @returns {Promise<void>} Ends protocol access during application shutdown; persisted opt-in is retained. */
    stop() {
        this.#closing = true
        return this.#serialize(() => this.#stopListener())
    }

    /** @param {Function} transaction - One filesystem/lifecycle operation. @returns {Promise<*>} Serialized result; a failure cannot poison future updates. */
    #serialize(transaction) {
        const previous = this.#queue

        /** @returns {Promise<*>} Runs one transaction only after its predecessor has settled. */
        async function executeTransaction() {
            await previous
            return await transaction()
        }

        const result = executeTransaction()

        /** @returns {Promise<void>} Releases the queue even if this caller receives a rejection. */
        async function releaseQueue() {
            try {
                await result
            } catch {
                // Each caller owns its failure; later transactions remain usable.
            }
        }

        this.#queue = releaseQueue()
        return result
    }

    /** @returns {Promise<void>} Stops the current endpoint, leaving the device runtime alone. */
    async #stopListener() {
        const server = this.#server
        this.#server = null
        try {
            await server?.stop()
        } finally {
            this.#state = { status: 'disabled', endpoint: null }
        }
    }

    /** @returns {Promise<void>} Applies saved preferences and converts filesystem/bind failures into non-secret status. */
    async #apply() {
        await this.#stopListener()
        if (!this.#settings.enabled || this.#closing) return
        try {
            const token = await loadMcpToken(this.#options.directory)
            this.#server = this.#options.createServer({ token })
            const endpoint = await this.#server.start(this.#settings.port)
            this.#state = { status: 'listening', endpoint }
        } catch (error) {
            try {
                await this.#stopListener()
            } catch {
                // Preserve the startup failure after best-effort listener cleanup.
            }
            this.#state = { status: 'error', endpoint: null, reason: error.code === 'EADDRINUSE' ? 'mcp-port-in-use' : 'mcp-start-failed' }
        }
    }
}
