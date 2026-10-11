// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import path from 'node:path'
import test from 'node:test'
import { resolveMcpBridgePath } from '../src/main/mcp/bridge-path.mjs'

for (const paths of [path.posix, path.win32]) {
    const root = paths === path.win32 ? 'C:\\Program Files\\OpenRDXManager\\resources' : '/Applications/Andrés Manager.app/Contents/Resources'
    test(`external Node bridge resolves outside ASAR with ${paths === path.win32 ? 'Windows' : 'POSIX'} paths`, () => {
        const archive = paths.join(root, 'app.asar')
        assert.equal(resolveMcpBridgePath(archive, paths), paths.join(root, 'app.asar.unpacked', 'scripts', 'mcp-stdio.mjs'))
        assert.equal(resolveMcpBridgePath(paths.join(root, 'app'), paths), paths.join(root, 'app', 'scripts', 'mcp-stdio.mjs'))
    })
}

test('bridge resolver rejects relative and malformed application roots', () => {
    for (const invalid of [null, '', 'relative/app.asar', '/app\0.asar']) assert.throws(() => resolveMcpBridgePath(invalid), /mcp-application-path-invalid/u)
})
