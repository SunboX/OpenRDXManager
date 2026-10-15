// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import test from 'node:test'

const execute = promisify(execFile)
const base = new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/', import.meta.url)

/**
 * Compiles and runs a consumed pure Rust module without Windows actions.
 * @param {string} basename Fixed checked-in module, never an external execution target.
 * @returns {Promise<void>} Resolves after its behavior tests pass; rejects compile/test failures.
 */
async function runModule(basename) {
    const model = fileURLToPath(new URL(basename, base))
    const root = await mkdtemp(join(tmpdir(), 'openrdx-manager-source-'))
    try {
        const source = join(root, 'proof.rs')
        const binary = join(root, process.platform === 'win32' ? 'proof.exe' : 'proof')
        await writeFile(source, `#[path=${JSON.stringify(model)}]\nmod protocol;\n`)
        await execute('rustc', ['--edition=2024', '--test', source, '-o', binary], { timeout: 30_000, maxBuffer: 65_536 })
        let result
        try {
            result = await execute(binary, ['--test-threads=2'], { timeout: 30_000, maxBuffer: 65_536 })
        } catch (error) {
            // Only this host-only pure model emits assertions; no native token data is executed here.
            assert.fail(`Host model behavioral failure:\n${error.stdout ?? 'model execution unavailable'}`)
        }
        assert.match(result.stdout, /test result: ok\./u)
    } finally {
        await rm(root, { recursive: true, force: true })
    }
}

/** Actual consumed admission/lifecycle functions, not source-regex assertions. */
test('ordinary Manager source model rejects unknown, stale, ambiguous and changed evidence', async () => {
    await runModule('manager_source_protocol.rs')
})

/** Actual native formatter validates privacy and the unchanged total transcript bound. */
test('ordinary Manager source formatter rejects private and malformed evidence within existing bounds', async () => {
    await runModule('manager_source_output.rs')
})
