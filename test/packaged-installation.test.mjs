// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { resolvePackagedExecutable, resolvePackagedSmokeProcessTimeout, verifyPackagedElectronFuses } from '../scripts/verify-packaged-app.mjs'

test('the external installed macOS auth verifier outlives its bounded smoke gate', () => {
    assert.equal(resolvePackagedSmokeProcessTimeout({ platform: 'darwin', installed: true, requireService: true }), 90_000)
    for (const options of [
        { platform: 'darwin', installed: true, requireService: false },
        { platform: 'darwin', installed: false, requireService: true },
        { platform: 'win32', installed: true, requireService: true },
        { platform: 'linux', installed: true, requireService: true }
    ])
        assert.equal(resolvePackagedSmokeProcessTimeout(options), 60_000)
})

test('installed verification selects the native fixed enrollment paths for both architectures', () => {
    for (const arch of ['arm64', 'x64']) {
        assert.equal(resolvePackagedExecutable({ platform: 'darwin', arch, installed: true }), '/Applications/OpenRDXManager.app/Contents/MacOS/OpenRDXManager')
        assert.equal(resolvePackagedExecutable({ platform: 'win32', arch, installed: true }), 'C:\\Program Files\\OpenRDXManager\\OpenRDXManager.exe')
        assert.equal(resolvePackagedExecutable({ platform: 'linux', arch, installed: true }), '/opt/OpenRDXManager/OpenRDXManager')
    }
    assert.throws(() => resolvePackagedExecutable({ platform: 'freebsd', arch: 'x64', installed: true }), /unsupported-packaged-platform/u)
})

test('actual fuse bytes reject every executable startup bypass and missing integrity protection', async (context) => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-fuse-check-'))
    context.after(async () => rm(directory, { recursive: true, force: true }))
    const executable = join(directory, 'runtime')
    // Electron's public fuse wire format: sentinel, version, length, ASCII states.
    const wire = Buffer.concat([Buffer.from('dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX'), Buffer.from([1, 8]), Buffer.from('01001111')])
    await writeFile(executable, wire)
    await verifyPackagedElectronFuses(executable)
    for (const index of [0, 2, 3, 4, 5]) {
        const changed = Buffer.from(wire)
        changed[34 + index] = index < 4 ? 49 : 48
        await writeFile(executable, changed)
        await assert.rejects(verifyPackagedElectronFuses(executable), /packaged-electron-fuse-invalid/u)
    }
    await writeFile(executable, 'no fuse wire')
    await assert.rejects(verifyPackagedElectronFuses(executable))
})
