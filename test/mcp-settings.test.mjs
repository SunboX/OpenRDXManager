// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { createSymlinkFixture } from './helpers/symlink-fixture.mjs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { McpSettingsController } from '../src/main/mcp/settings-controller.mjs'
import { ownWindowsFixture } from './helpers/windows-fixture-owner.mjs'

/** @param {object} context - Test lifecycle. @param {Function} [createServer] - Optional controlled server. @returns {Promise<object>} Isolated persisted controller and observations. */
async function fixture(context, createServer) {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-mcp-settings-'))
    context.after(() => rm(directory, { recursive: true, force: true }))
    await ownWindowsFixture(directory)
    const copies = []
    const events = []
    const options = {
        directory,
        bridgePath: '/app/scripts/mcp-stdio.mjs',
        copyText: (text) => copies.push(text),
        createServer:
            createServer ??
            (() => ({
                start: async (port) => {
                    events.push(`start:${port}`)
                    return `http://127.0.0.1:${port}/mcp`
                },
                stop: async () => events.push('stop'),
                notifyResource() {}
            }))
    }
    const controller = new McpSettingsController(options)
    context.after(() => controller.stop())
    return { directory, copies, events, controller, options }
}

test('MCP defaults disabled, persists opt-in and never returns credentials in status or copied config', async (context) => {
    const { controller, directory, copies, events, options } = await fixture(context)
    assert.deepEqual(await controller.load(), { ok: true, enabled: false, port: 48170, status: 'disabled', endpoint: null })
    assert.deepEqual(events, [])
    assert.equal((await controller.update({ enabled: true, port: 48171 })).status, 'listening')
    const token = (await readFile(join(directory, 'token'), 'utf8')).trim()
    assert.match(token, /^[a-f0-9]{64}$/)
    if (process.platform !== 'win32') assert.equal((await stat(join(directory, 'token'))).mode & 0o777, 0o600)
    assert.equal(JSON.stringify(await controller.getStatus()).includes(token), false)
    assert.deepEqual(await controller.copyConfiguration(), { ok: true })
    assert.equal(copies[0].includes(token), false)
    const copied = JSON.parse(copies[0]).mcpServers.OpenRDXManager
    assert.equal(copied.env.OPENRDX_MCP_TOKEN_FILE, join(directory, 'token'))
    await controller.stop()
    const restored = new McpSettingsController(options)
    context.after(() => restored.stop())
    assert.equal((await restored.load()).status, 'listening')
    assert.equal((await readFile(join(directory, 'token'), 'utf8')).trim(), token)
    assert.equal((await restored.update({ enabled: false })).status, 'disabled')
})

test('MCP rejects unknown settings and serializes changes with exact listener lifecycle', async (context) => {
    const { controller, events } = await fixture(context)
    await controller.load()
    for (const request of [{}, { host: '0.0.0.0' }, { enabled: 'yes' }, { port: 0 }, { port: 65536 }, { token: 'value' }]) assert.deepEqual(await controller.update(request), { ok: false, reason: 'invalid-request' })
    await Promise.all([controller.update({ enabled: true }), controller.update({ port: 48172 }), controller.update({ enabled: false })])
    assert.deepEqual(events, ['start:48170', 'stop', 'start:48172', 'stop'])
})

test('a failed listener stop rejects its transaction without poisoning later queued settings', async (context) => {
    let stops = 0
    const { controller } = await fixture(context, () => ({
        start: async (port) => `http://127.0.0.1:${port}/mcp`,
        /** @returns {Promise<void>} Rejects the first teardown while leaving later transactions available. */
        async stop() {
            stops++
            throw new Error('controlled listener stop failure')
        }
    }))
    await controller.load()
    assert.equal((await controller.update({ enabled: true })).status, 'listening')

    const failed = controller.update({ port: 48171 })
    const next = controller.update({ enabled: false })
    await assert.rejects(failed, /controlled listener stop failure/)
    assert.deepEqual(await next, { ok: true, enabled: false, port: 48171, status: 'disabled', endpoint: null })
    assert.equal(stops, 1)
})

test('bind errors remain visible without crashing the application or losing saved opt-in', async (context) => {
    const { controller } = await fixture(context, () => ({
        start: async () => {
            const error = new Error('private detail')
            error.code = 'EADDRINUSE'
            throw error
        },
        stop: async () => {}
    }))
    await controller.load()
    const status = await controller.update({ enabled: true })
    assert.equal(status.status, 'error')
    assert.equal(status.reason, 'mcp-port-in-use')
    assert.equal(JSON.stringify(status).includes('private detail'), false)
    assert.equal(status.enabled, true)
})

test('a credential symlink cannot enable the endpoint or change its target', async (context) => {
    const { controller, directory, events } = await fixture(context)
    const target = join(directory, 'external-secret')
    await writeFile(target, 'a'.repeat(64))
    if (!(await createSymlinkFixture(context, target, join(directory, 'token')))) return
    await controller.load()
    const result = await controller.update({ enabled: true })
    assert.equal(result.status, 'error')
    assert.equal(events.length, 0)
    assert.equal(await readFile(target, 'utf8'), 'a'.repeat(64))
    assert.ok((await readdir(directory)).includes('token'))
})
