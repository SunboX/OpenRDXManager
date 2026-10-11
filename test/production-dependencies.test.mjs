// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { collectProductionDependencyPaths } from '../scripts/production-dependencies.mjs'

/** Creates a locked mixed dependency tree. @param {object} context - Cleanup owner. @returns {Promise<string>} Isolated project root. */
async function createDependencyFixture(context) {
    const root = await mkdtemp(join(tmpdir(), 'openrdx-production-tree-'))
    context.after(async () => rm(root, { recursive: true, force: true }))
    await writeFile(join(root, 'package.json'), JSON.stringify({ dependencies: { '@sdk/client': '1' }, optionalDependencies: { optional: '1' } }))
    await writeFile(join(root, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/@sdk/client': {}, 'node_modules/@sdk/client/node_modules/transitive': {}, 'node_modules/dev-tool': { dev: true }, 'node_modules/optional': { optional: true } } }))
    for (const directory of ['node_modules/@sdk/client', 'node_modules/@sdk/client/node_modules/transitive', 'node_modules/dev-tool']) await mkdir(join(root, directory), { recursive: true })
    return root
}

test('locked production closure preserves nested SDK dependencies and omits dev-only/missing optional packages', async (context) => {
    const root = await createDependencyFixture(context)
    assert.deepEqual(await collectProductionDependencyPaths(root), ['node_modules/@sdk/client', 'node_modules/@sdk/client/node_modules/transitive'])
    await mkdir(join(root, 'node_modules/optional'))
    assert.ok((await collectProductionDependencyPaths(root)).includes('node_modules/optional'))
})

test('a missing required production dependency fails before bundle assembly', async (context) => {
    const root = await createDependencyFixture(context)
    await rm(join(root, 'node_modules/@sdk/client/node_modules/transitive'), { recursive: true })
    await assert.rejects(collectProductionDependencyPaths(root), /ENOENT/u)
})

test('manifest-required dependencies cannot disappear behind an optional lock marker', async (context) => {
    const root = await createDependencyFixture(context)
    const lock = JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8'))
    lock.packages['node_modules/@sdk/client'].optional = true
    await writeFile(join(root, 'package-lock.json'), JSON.stringify(lock))
    await rm(join(root, 'node_modules/@sdk/client'), { recursive: true })
    await assert.rejects(collectProductionDependencyPaths(root), /ENOENT/u)
})

test('the dependency lock must cover all required manifest roots without path traversal', async (context) => {
    const root = await createDependencyFixture(context)
    const lock = JSON.parse(await readFile(join(root, 'package-lock.json'), 'utf8'))
    lock.packages['node_modules/../outside'] = {}
    await writeFile(join(root, 'package-lock.json'), JSON.stringify(lock))
    await assert.rejects(collectProductionDependencyPaths(root), /production-dependency-path-invalid/u)
    delete lock.packages['node_modules/../outside']
    delete lock.packages['node_modules/@sdk/client']
    await writeFile(join(root, 'package-lock.json'), JSON.stringify(lock))
    await assert.rejects(collectProductionDependencyPaths(root), /production-dependency-lock-mismatch/u)
})
