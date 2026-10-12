// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { expectedInstallerNames, verifyReleaseAssets } from '../scripts/release-assets.mjs'

test('release collection requires all sixteen installers including macOS system packages', async (context) => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-release-'))
    context.after(() => rm(directory, { recursive: true, force: true }))
    const names = expectedInstallerNames('1.2.3')
    assert.equal(new Set(names).size, 16)
    for (const arch of ['x64', 'arm64']) assert.ok(names.includes(`OpenRDXManager-1.2.3-mac-${arch}.pkg`))
    for (const name of names) await writeFile(join(directory, name), `installer:${name}`)
    const result = await verifyReleaseAssets({ directory, version: '1.2.3' })
    assert.equal(result.installers.length, 16)
    assert.equal((await readFile(join(directory, 'SHA256SUMS.txt'), 'utf8')).trim().split('\n').length, 16)
    await rm(join(directory, names[0]))
    await assert.rejects(verifyReleaseAssets({ directory, version: '1.2.3' }), /missing-installers/)
})

test('release collection rejects empty installers and assets from a different version', async (context) => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-release-'))
    context.after(() => rm(directory, { recursive: true, force: true }))
    for (const name of expectedInstallerNames('1.2.3')) await writeFile(join(directory, name), 'installer')
    await writeFile(join(directory, 'OpenRDXManager-0.0.1-win-x64.exe'), 'stale')
    await assert.rejects(verifyReleaseAssets({ directory, version: '1.2.3' }), /unexpected-installer/)
    await rm(join(directory, 'OpenRDXManager-0.0.1-win-x64.exe'))
    await writeFile(join(directory, expectedInstallerNames('1.2.3')[0]), '')
    await assert.rejects(verifyReleaseAssets({ directory, version: '1.2.3' }), /invalid-installer/)
})
