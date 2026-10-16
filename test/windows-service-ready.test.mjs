// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { join } from 'node:path'
import test from 'node:test'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

test('Windows service prelude uses real bounded private pipes and retires cancelled I/O', { skip: process.platform !== 'win32' }, async () => {
    const fixture = join(process.cwd(), 'native/windows-client-addon/build/Release/openrdx_windows_ready_test.exe')
    const { stdout, stderr } = await execFileAsync(fixture, [], { timeout: 10_000, maxBuffer: 64 * 1024, windowsHide: true })
    assert.equal(stderr, '')
    assert.match(stdout, /service-ready Windows private pipes: .* PASS/u)
    assert.match(stdout, /service-ready parser: .* PASS/u)
})
