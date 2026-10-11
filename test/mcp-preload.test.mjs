// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { createPreloadApi } from '../src/preload-api.mjs'
import { registerIpcHandlers } from '../src/main/ipc-controller.mjs'

test('MCP desktop controls remain behind trusted IPC and exact preload schemas', async () => {
    const handlers = new Map()
    const status = { ok: true, enabled: false, port: 48170, status: 'disabled', endpoint: null }
    const calls = []
    registerIpcHandlers({
        ipcMain: { handle: (channel, handler) => handlers.set(channel, handler), removeHandler: (channel) => handlers.delete(channel) },
        services: {
            isTrustedSender: (event) => event.trusted === true,
            mcp: {
                getStatus: () => status,
                update: (request) => {
                    calls.push(request)
                    return status
                },
                copyConfiguration: () => ({ ok: true })
            }
        }
    })
    const api = createPreloadApi({ invoke: (channel, request) => handlers.get(channel)({ trusted: true }, request), on() {}, removeListener() {} })
    assert.ok(api.mcp)
    assert.deepEqual(await api.mcp.getStatus(), status)
    assert.deepEqual(await api.mcp.update({ enabled: true }), status)
    assert.deepEqual(await api.mcp.copyConfiguration(), { ok: true })
    for (const request of [{ enabled: true, host: '0.0.0.0' }, { port: 80 }, { enabled: 'true' }, { token: 'secret' }]) await assert.rejects(api.mcp.update(request), /Invalid OpenRDX request/)
    assert.deepEqual(await handlers.get('openrdx:mcp:update')({ trusted: false }, { enabled: true }), { ok: false, reason: 'untrusted-sender' })
    assert.deepEqual(calls, [{ enabled: true }])
})
