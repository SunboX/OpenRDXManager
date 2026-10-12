// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
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
