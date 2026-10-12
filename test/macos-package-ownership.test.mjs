// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { promisify } from 'node:util'
import { normalizeMacOsPackageScriptOwners, readRootPackageScripts } from '../scripts/macos-package-ownership.mjs'

const execute = promisify(execFile)

test('unsigned PKG scripts have root headers, unchanged bytes and an unchanged payload', { skip: process.platform !== 'darwin' }, async (context) => {
    const stage = await mkdtemp(join(tmpdir(), 'openrdx-pkg-ownership-'))
    context.after(async () => rm(stage, { recursive: true, force: true }))
    const payload = join(stage, 'payload')
    const scripts = join(stage, 'scripts')
    await mkdir(payload)
    await mkdir(scripts, { mode: 0o755 })
    await writeFile(join(payload, 'fixture'), 'payload unchanged')
    const contents = { preinstall: '#!/bin/sh\nexit 0\n', postinstall: '#!/bin/sh\nexit 0\n', 'openrdx-local-install': 'sealed installer bytes', 'pending-runtime.json': '{"fixture":"history only"}\n' }
    for (const [name, content] of Object.entries(contents)) {
        await writeFile(join(scripts, name), content)
        await chmod(join(scripts, name), name.endsWith('.json') ? 0o600 : 0o755)
    }
    const packagePath = join(stage, 'test.pkg')
    await execute('/usr/bin/pkgbuild', ['--root', payload, '--scripts', scripts, '--identifier', 'com.openrdx.test.ownership', '--version', '1', '--ownership', 'recommended', packagePath])
    const before = join(stage, 'before')
    await mkdir(before)
    await execute('/usr/bin/xar', ['-xf', packagePath, 'Bom', 'Payload', 'PackageInfo'], { cwd: before })
    await normalizeMacOsPackageScriptOwners({ packagePath, scripts, scratch: join(stage, 'normalize') })
    const after = join(stage, 'after')
    await mkdir(after)
    await execute('/usr/bin/xar', ['-xf', packagePath], { cwd: after })
    for (const name of ['Bom', 'Payload', 'PackageInfo']) assert.deepEqual(await readFile(join(after, name)), await readFile(join(before, name)))
    const entries = readRootPackageScripts(await readFile(join(after, 'Scripts')))
    assert.equal(entries.length, 5)
    for (const entry of entries.filter((entry) => entry.name !== '.')) {
        assert.equal(entry.sha256, createHash('sha256').update(contents[entry.name]).digest('hex'))
    }
    const expanded = join(stage, 'expanded')
    await execute('/usr/sbin/pkgutil', ['--expand', packagePath, expanded])
    assert.equal(await readFile(join(expanded, 'Scripts/pending-runtime.json'), 'utf8'), contents['pending-runtime.json'])
    await execute('/usr/sbin/installer', ['-pkginfo', '-pkg', packagePath])
})

test('CPIO ownership validation rejects malformed or unbounded script data', () => {
    assert.throws(() => readRootPackageScripts(Buffer.from('not gzip')))
})
