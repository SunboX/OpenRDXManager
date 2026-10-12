// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { link, lstat, mkdir, mkdtemp, open, rename, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

/** @param {object} context - Node test lifecycle. @returns {Promise<string>} Temporary runtime root. */
async function fixture(context) {
    const root = await mkdtemp(join(tmpdir(), 'openrdx-inventory-'))
    context.after(() => rm(root, { recursive: true, force: true }))
    await mkdir(join(root, 'resources'), { recursive: true })
    await writeFile(join(root, 'OpenRDXManager.exe'), 'sealed-executable')
    await writeFile(join(root, 'resources', 'app.asar'), 'sealed-javascript')
    return root
}

test('runtime inventory pins every file and detects JavaScript tampering', async (context) => {
    const { createRuntimeInventory, verifyRuntimeInventory } = await import('../scripts/local-trust-inventory.mjs')
    const root = await fixture(context)
    const inventory = await createRuntimeInventory({ root, platform: 'windows' })
    assert.equal(inventory.schemaVersion, 1)
    assert.equal(inventory.files.length, 2)
    assert.equal(inventory.files.find((file) => file.path === 'resources/app.asar').sha256, createHash('sha256').update('sealed-javascript').digest('hex'))
    await verifyRuntimeInventory({ root, inventory })
    await writeFile(join(root, 'resources', 'app.asar'), 'modified-javascript')
    await assert.rejects(verifyRuntimeInventory({ root, inventory }), /runtime-inventory-mismatch/)
})

test('inventory rejects duplicates, traversal and unknown fields before opening content', async (context) => {
    const { createRuntimeInventory, verifyRuntimeInventory } = await import('../scripts/local-trust-inventory.mjs')
    const root = await fixture(context)
    const inventory = await createRuntimeInventory({ root, platform: 'windows' })
    await assert.rejects(verifyRuntimeInventory({ root, inventory: { ...inventory, files: [...inventory.files, inventory.files[0]] } }), /runtime-inventory-invalid/)
    await assert.rejects(verifyRuntimeInventory({ root, inventory: { ...inventory, files: [{ ...inventory.files[0], path: '../outside' }] } }), /runtime-inventory-invalid/)
    await assert.rejects(verifyRuntimeInventory({ root, inventory: { ...inventory, trusted: true } }), /runtime-inventory-invalid/)
})

test('macOS inventory pins bounded framework links and rejects escaping links', async (context) => {
    const { createRuntimeInventory, verifyRuntimeInventory } = await import('../scripts/local-trust-inventory.mjs')
    const root = await fixture(context)
    await symlink('resources', join(root, 'FrameworkAlias'))
    const readCodeIdentity = async () => 'a'.repeat(40)
    const inventory = await createRuntimeInventory({ root, platform: 'macos', readCodeIdentity })
    assert.deepEqual(inventory.links, [{ path: 'FrameworkAlias', target: 'resources' }])
    await verifyRuntimeInventory({ root, inventory })
    await symlink('../outside', join(root, 'Escape'))
    await assert.rejects(createRuntimeInventory({ root, platform: 'macos', readCodeIdentity }), /runtime-inventory-unsafe-link/)
})

test('Windows inventory rejects linked runtime files and excludes only its own regular inventory', { skip: process.platform === 'win32' }, async (context) => {
    const { createRuntimeInventory } = await import('../scripts/local-trust-inventory.mjs')
    const root = await fixture(context)
    await mkdir(join(root, 'resources/local-trust'))
    await writeFile(join(root, 'resources/local-trust/runtime.json'), 'previous-inventory')
    assert.equal((await createRuntimeInventory({ root, platform: 'windows' })).files.length, 2)
    await symlink('app.asar', join(root, 'resources/alias'))
    await assert.rejects(createRuntimeInventory({ root, platform: 'windows' }), /runtime-inventory-unsafe-link/)
})

test('Windows inventory hashes stable files even when pathname stats omit the volume identity', { skip: process.platform !== 'win32' }, async (context) => {
    const { createRuntimeInventory, verifyRuntimeInventory } = await import('../scripts/local-trust-inventory.mjs')
    const root = await fixture(context)
    const path = join(root, 'OpenRDXManager.exe')
    const handle = await open(path, 'r')
    let opened
    try {
        opened = await handle.stat({ bigint: true })
    } finally {
        await handle.close()
    }
    const named = await lstat(path, { bigint: true })
    assert.equal(opened.ino, named.ino)
    assert.equal(opened.size, named.size)
    const inventory = await createRuntimeInventory({ root, platform: 'windows' })
    assert.deepEqual(
        inventory.files.find((entry) => entry.path === 'OpenRDXManager.exe'),
        {
            path: 'OpenRDXManager.exe',
            size: 17,
            sha256: '50f6470d614db04f6a288b9562b9c562c8c5f3d58085fe79548ac31cbf87a1be'
        }
    )
    await verifyRuntimeInventory({ root, inventory })
})

test('inventory rejects hard-linked runtime content', async (context) => {
    const { createRuntimeInventory } = await import('../scripts/local-trust-inventory.mjs')
    const root = await fixture(context)
    await link(join(root, 'OpenRDXManager.exe'), join(root, 'alias.exe'))
    await assert.rejects(createRuntimeInventory({ root, platform: 'windows' }), /runtime-inventory-unsafe-file/)
})

test('inventory rejects a pathname replaced with different same-length content while reading', async (context) => {
    const { createRuntimeInventory } = await import('../scripts/local-trust-inventory.mjs')
    const root = await fixture(context)
    const path = join(root, 'OpenRDXManager.exe')
    const probe = await open(path, 'r')
    const prototype = Object.getPrototypeOf(probe)
    const read = prototype.read
    await probe.close()
    let replaced = false
    context.mock.method(prototype, 'read', async function (...args) {
        const result = await read.apply(this, args)
        if (!replaced && result.bytesRead !== 0) {
            replaced = true
            await rename(path, join(root, 'original.exe'))
            await writeFile(path, 'changed-file-data')
        }
        return result
    })
    await assert.rejects(createRuntimeInventory({ root, platform: 'windows' }), /runtime-inventory-file-changed/)
})

test('Windows inventory rejects a reopened pathname on a different volume even with the same inode', { skip: process.platform !== 'win32' }, async (context) => {
    const { createRuntimeInventory } = await import('../scripts/local-trust-inventory.mjs')
    const root = await fixture(context)
    const probe = await open(join(root, 'OpenRDXManager.exe'), 'r')
    const prototype = Object.getPrototypeOf(probe)
    const stat = prototype.stat
    await probe.close()
    let reader
    // Real I/O cannot deterministically arrange matching file IDs on two volumes.
    // Change only the reopened handle's volume in otherwise real filesystem stats.
    context.mock.method(prototype, 'stat', async function (...args) {
        const result = await stat.apply(this, args)
        reader ??= this.fd
        if (this.fd !== reader) result.dev += 1n
        return result
    })
    await assert.rejects(createRuntimeInventory({ root, platform: 'windows' }), /runtime-inventory-file-changed/)
})
