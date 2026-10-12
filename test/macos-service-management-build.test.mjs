// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { buildMacOsServiceManagementAddon } from '../scripts/build-macos-service-management.mjs'

const projectRoot = fileURLToPath(new URL('..', import.meta.url))
const require = createRequire(import.meta.url)

test('builds a zero-argument ServiceManagement addon with closed status output', { skip: process.platform !== 'darwin' }, async (context) => {
    const outputRoot = await mkdtemp(join(tmpdir(), 'openrdx-service-management-'))
    context.after(async () => rm(outputRoot, { force: true, recursive: true }))
    const outputPath = join(outputRoot, 'openrdx-service-management.node')

    assert.equal(await buildMacOsServiceManagementAddon({ outputPath, projectRoot }), outputPath)
    const addon = require(outputPath)
    const methods = ['installationMode', 'openApprovalSettings', 'registerService', 'status', 'unregisterService']
    for (const method of methods) assert.equal(typeof addon[method], 'function')
    assert.equal(addon.installationMode(), 'local')
    assert.equal(addon.registerService(), 'installer-required')
    assert.equal(addon.unregisterService(), 'installer-required')
    assert.equal(addon.status(), 'installer-required')

    for (const method of methods) {
        assert.throws(() => addon[method]('unexpected'), TypeError)
    }
})

test('rejects unsafe addon output paths before invoking a compiler', async () => {
    await assert.rejects(buildMacOsServiceManagementAddon({ outputPath: 'relative.node', projectRoot }), /macos-service-management-output-invalid/)
    await assert.rejects(buildMacOsServiceManagementAddon({ outputPath: projectRoot, projectRoot }), /macos-service-management-output-invalid/)
})
