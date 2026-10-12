// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createRuntimeInventory } from '../scripts/local-trust-inventory.mjs'
import { buildWindowsRemover, windowsRemoverIdentity } from '../scripts/build-windows-remover.mjs'

test('remover preserves builder registry identity and rejects alternate application identities', () => {
    assert.deepEqual(windowsRemoverIdentity({ appId: 'com.openrdx.manager' }), {
        guid: '90b8ea5e-76ba-5742-9d4e-ef4ede9d890a',
        installKey: 'Software\\90b8ea5e-76ba-5742-9d4e-ef4ede9d890a',
        uninstallKey: 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\90b8ea5e-76ba-5742-9d4e-ef4ede9d890a'
    })
    assert.throws(() => windowsRemoverIdentity({ appId: 'unrelated.app' }), /windows-remover-identity-invalid/u)
})

test('remover compilation stages only the compiled regular executable and rejects absent output', async () => {
    const root = await mkdtemp(join(tmpdir(), 'openrdx-remover-build-'))
    try {
        const destination = join(root, 'Uninstall OpenRDXManager.exe')
        await buildWindowsRemover({
            root,
            projectRoot: root,
            appId: 'com.openrdx.manager',
            version: '1.0.1',
            resolveCompiler: async () => ({ path: '/unused-compiler' }),
            compile: async (_compiler, args) => {
                const output = args.find((arg) => arg.startsWith('-DOUTPUT_FILE='))?.slice('-DOUTPUT_FILE='.length)
                await writeFile(output, 'compiled-fixture')
            }
        })
        assert.equal(await readFile(destination, 'utf8'), 'compiled-fixture')
        const inventory = await createRuntimeInventory({ root, platform: 'windows' })
        assert.ok(inventory.files.some((file) => file.path === 'Uninstall OpenRDXManager.exe'))
        await assert.rejects(buildWindowsRemover({ root, projectRoot: root, appId: 'com.openrdx.manager', version: '1.0.1', resolveCompiler: async () => ({ path: '/unused-compiler' }), compile: async () => {} }), /ENOENT/u)
        assert.equal(await readFile(destination, 'utf8'), 'compiled-fixture', 'A failed rebuild must preserve the last complete remover')
    } finally {
        await rm(root, { recursive: true, force: true })
    }
})
