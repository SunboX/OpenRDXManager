// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { applicationMetadata } from '../application-metadata.mjs'

import { McpServer, ResourceTemplate } from '@modelcontextprotocol/server'

/** Fixed resources and corresponding read tools; URI names never select files. */
export const MCP_RESOURCES = Object.freeze([
    ['app', 'rdx_app_info'],
    ['devices', 'rdx_devices_list'],
    ['capabilities', 'rdx_capabilities'],
    ['operations', 'rdx_operations_list'],
    ['settings', 'rdx_settings_get'],
    ['activity', 'rdx_logs_list'],
    ['support-summary', 'rdx_summary_read'],
    ['help', 'rdx_help'],
    ['service', 'rdx_service_status'],
    ['mcp', 'rdx_mcp_status']
])

/** @param {object} value - Already validated public service result. @returns {object} Structured MCP tool result, preserving application failures. */
export function mcpToolResult(value) {
    return { content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value, ...(value.ok === false ? { isError: true } : {}) }
}

/** @param {URL} uri - Registered resource URI. @param {object} value - Validated public result. @returns {object} MCP JSON resource result. */
function resourceResult(uri, value) {
    return { contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify(value) }] }
}

/** @param {unknown} value - SDK template capture (still URI-encoded). @returns {string|null} Decoded opaque ID for strict tool validation, or null for invalid encoding. */
function resourceIdentity(value) {
    if (typeof value !== 'string') return null
    try {
        return decodeURIComponent(value)
    } catch {
        return null
    }
}

/** @param {object[]} tools - Strict main-owned tool registry. @param {string} [era='modern'] - SDK negotiated HTTP era; legacy stateless clients poll. @returns {McpServer} Lightweight SDK instance sharing the application's services. */
export function createSdkServer(tools, era = 'modern') {
    const server = new McpServer(applicationMetadata, { capabilities: { tools: { listChanged: false }, resources: { subscribe: era === 'modern', listChanged: false } }, instructions: 'Use rdx_devices_list and rdx_capabilities first. Preserve reported/unavailable values. Obtain user authorization before destructive actions. Tools share the GUI operation lock. Use operation IDs to inspect completion; a disconnected client does not cancel device work.' })
    const byName = new Map(tools.map((entry) => [entry.name, entry]))
    for (const entry of tools) {
        server.registerTool(entry.name, { description: entry.description, inputSchema: entry.inputSchema, annotations: entry.annotations }, async (request) => mcpToolResult(await entry.execute(request)))
    }
    for (const [name, toolName] of MCP_RESOURCES) {
        server.registerResource(name, `openrdx://${name}`, { mimeType: 'application/json', description: byName.get(toolName).description }, async (uri) => resourceResult(uri, await byName.get(toolName).execute({})))
    }
    server.registerResource('device', new ResourceTemplate('openrdx://devices/{deviceId}', { list: undefined }), { mimeType: 'application/json', description: 'Complete public snapshot for one opaque RDX device identity.' }, async (uri, { deviceId }) => resourceResult(uri, await byName.get('rdx_device_get').execute({ deviceId: resourceIdentity(deviceId) })))
    server.registerResource('operation', new ResourceTemplate('openrdx://operations/{operationId}', { list: undefined }), { mimeType: 'application/json', description: 'Latest accepted progress or terminal result for an operation.' }, async (uri, { operationId }) => resourceResult(uri, await byName.get('rdx_operation_get').execute({ operationId: resourceIdentity(operationId) })))
    return server
}
