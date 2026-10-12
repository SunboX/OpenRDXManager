// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { stageWindowsElevationHelper } from '../scripts/installer-local-trust.mjs'
import { createRuntimeInventory, verifyRuntimeInventory } from '../scripts/local-trust-inventory.mjs'

test('Windows enrollment pins the exact elevation helper later injected by NSIS', async (context) => {
    const temporary = await mkdtemp(join(tmpdir(), 'openrdx-elevate-pin-'))
    context.after(async () => rm(temporary, { recursive: true, force: true }))
    const root = join(temporary, 'runtime')
    await mkdir(root)
    await writeFile(join(root, 'OpenRDXManager.exe'), 'manager')
    const source = join(temporary, 'elevate.exe')
    await writeFile(source, 'verified toolset elevation helper')
    await stageWindowsElevationHelper({ root, resolveHelper: async () => source })
    const inventory = await createRuntimeInventory({ root, platform: 'windows' })
    assert.ok(inventory.files.some((entry) => entry.path === 'resources/elevate.exe'))
    assert.deepEqual(await readFile(join(root, 'resources/elevate.exe')), await readFile(source))
    await verifyRuntimeInventory({ root, inventory })
    await writeFile(join(root, 'resources/elevate.exe'), 'different later injected helper')
    await assert.rejects(verifyRuntimeInventory({ root, inventory }))
})
