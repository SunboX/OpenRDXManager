// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdtemp, mkdir, readdir, rm, stat, symlink, writeFile, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ManufacturingWireClient } from '../src/main/manufacturing-wire-client.mjs'
import { ManufacturingFolderService } from '../src/main/manufacturing-folder-service.mjs'
import { registerIpcHandlers } from '../src/main/ipc-controller.mjs'
import { createPreloadApi } from '../src/preload-api.mjs'

test('the folder intent opens the actual backup directory without copies or renderer path authority', async () => {
    const root = await mkdtemp(join(tmpdir(), 'openrdx-folder-'))
    const directory = join(root, 'manufacturing-backups')
    const opened = []
    try {
        const folder = new ManufacturingFolderService({
            directory,
            prepare: async () => ({ ok: true }),
            openPath: async (path) => {
                opened.push(path)
                return ''
            }
        })
        const handlers = new Map()
        const ipc = registerIpcHandlers({ ipcMain: { handle: (channel, handler) => handlers.set(channel, handler), removeHandler: (channel) => handlers.delete(channel) }, services: { isTrustedSender: (event) => event.trusted === true, manufacturing: { openFolder: folder.open.bind(folder) } } })
        const api = createPreloadApi({ invoke: (channel, request) => handlers.get(channel)({ trusted: true }, request), on() {}, removeListener() {} })
        const handler = handlers.get('openrdx:manufacturing:open-folder')
        assert.deepEqual(await handler({ trusted: false }, {}), { ok: false, reason: 'untrusted-sender' })
        assert.deepEqual(await handler({ trusted: true }, { path: '/tmp/elsewhere' }), { ok: false, reason: 'invalid-request' })
        await assert.rejects(api.manufacturing.openFolder({ path: '/tmp/elsewhere' }), /Invalid OpenRDX request/)
        assert.deepEqual(opened, [])
        assert.deepEqual(await api.manufacturing.openFolder(), { ok: true })
        await writeFile(join(directory, 'existing.bin'), 'unchanged')
        assert.deepEqual(await api.manufacturing.openFolder(), { ok: true })
        assert.deepEqual(opened, [directory, directory])
        assert.deepEqual(await readdir(root), ['manufacturing-backups'])
        assert.deepEqual(await readdir(directory), ['existing.bin'])
        assert.equal(await readFile(join(directory, 'existing.bin'), 'utf8'), 'unchanged')
        if (process.platform !== 'win32') assert.equal((await stat(directory)).mode & 0o777, 0o700)
        ipc.dispose()
    } finally {
        await rm(root, { recursive: true, force: true })
    }
})

test('folder opening rejects symlinks and sanitizes system failures', async () => {
    const root = await mkdtemp(join(tmpdir(), 'openrdx-folder-'))
    const directory = join(root, 'manufacturing-backups')
    let opened = 0
    try {
        await mkdir(join(root, 'elsewhere'), { mode: 0o700 })
        await symlink(join(root, 'elsewhere'), directory, 'junction')
        const folder = new ManufacturingFolderService({
            directory,
            prepare: async () => ({ ok: true }),
            openPath: async () => {
                opened += 1
                return ''
            }
        })
        assert.deepEqual(await folder.open(), { ok: false, reason: 'manufacturing-folder-open-failed' })
        assert.equal(opened, 0)
        for (const openPath of [
            async () => 'private OS error /secret/path',
            async () => {
                throw new Error('private OS error')
            }
        ]) {
            assert.deepEqual(await new ManufacturingFolderService({ directory: join(root, 'elsewhere'), prepare: async () => ({ ok: true }), openPath }).open(), { ok: false, reason: 'manufacturing-folder-open-failed' })
        }
    } finally {
        await rm(root, { recursive: true, force: true })
    }
})

test('opening waits for relocation, rejects duplicates, and retries failed preparation', async () => {
    const root = await mkdtemp(join(tmpdir(), 'openrdx-folder-'))
    const directory = join(root, 'manufacturing-backups')
    const pending = Promise.withResolvers()
    let prepared = 0
    let opened = 0
    const folder = new ManufacturingFolderService({
        directory,
        prepare: async () => {
            prepared += 1
            return prepared === 1 ? pending.promise : { ok: true }
        },
        openPath: async () => {
            opened += 1
            return ''
        }
    })
    try {
        const opening = folder.open()
        assert.deepEqual(await folder.open(), { ok: false, reason: 'operation-in-progress' })
        assert.equal(opened, 0)
        assert.deepEqual(await readdir(root), [])
        pending.resolve({ ok: false, reason: 'manufacturing-storage-unavailable' })
        assert.deepEqual(await opening, { ok: false, reason: 'manufacturing-folder-open-failed' })
        assert.deepEqual(await readdir(root), [])
        assert.deepEqual(await folder.open(), { ok: true })
        assert.deepEqual(await folder.open(), { ok: true })
        assert.equal(prepared, 2)
        assert.equal(opened, 2)
    } finally {
        await rm(root, { recursive: true, force: true })
    }
})

test('folder preparation sends a fixed path-free native intent and validates its response', async () => {
    const calls = []
    const wire = new ManufacturingWireClient(async (method, payload, schema) => {
        calls.push({ method, payload })
        assert.equal(schema.safeParse({ ok: true }).success, true)
        assert.equal(schema.safeParse({ ok: true, path: '/untrusted' }).success, false)
        return { ok: true }
    })
    assert.deepEqual(await wire.prepareFolder(), { ok: true })
    assert.deepEqual(calls, [{ method: 'manufacturing-prepare-folder', payload: {} }])
})
