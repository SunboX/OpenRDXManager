// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { runVisualProcess } from './helpers/visual-process.mjs'

test('visual runtime timeout rejects and reaps a child that handles SIGTERM', async (context) => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-visual-timeout-'))
    context.after(() => rm(directory, { recursive: true, force: true }))
    const pidPath = join(directory, 'owned-pid')
    // Allow two seconds for slow Windows/ARM Node startup before this real
    // deadline. The harmless fixture ends itself after six seconds even on RED;
    // PID evidence is written only after its SIGTERM handler is installed.
    const source = `
        process.on('SIGTERM', () => {})
        require('node:fs').writeFileSync(${JSON.stringify(pidPath)}, String(process.pid))
        setTimeout(() => process.exit(0), 6000)
    `
    await assert.rejects(runVisualProcess(process.execPath, ['-e', source], { timeoutMs: 2000 }), (error) => {
        assert.equal(error.killed, true)
        // Windows reports forced termination as an exit code on some Node
        // versions; POSIX reports the exact uncatchable termination signal.
        assert.ok(error.signal === 'SIGKILL' || (process.platform === 'win32' && Number.isInteger(error.code) && error.code !== 0))
        return true
    })
    const pid = Number(await readFile(pidPath, 'utf8'))
    assert.ok(Number.isInteger(pid) && pid > 0)
    assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' })
})

test('visual runtime launch failures reject after the owned child closes', async () => {
    await assert.rejects(runVisualProcess(join(tmpdir(), 'openrdx-absent-visual-runtime'), []), { code: 'ENOENT' })
})

test('visual runtime preserves arguments, environment, output and ordinary failures', async () => {
    const source = `console.log(JSON.stringify({ args: process.argv.slice(1), marker: process.env.OPENRDX_OWNED_VISUAL_PROBE })); console.error('owned-stderr')`
    const output = await runVisualProcess(process.execPath, ['-e', source, 'space argument', 'ümlaut'], { env: { ...process.env, OPENRDX_OWNED_VISUAL_PROBE: 'fixture-only' } })
    assert.deepEqual(JSON.parse(output.stdout), { args: ['space argument', 'ümlaut'], marker: 'fixture-only' })
    assert.equal(output.stderr.trim(), 'owned-stderr')
    await assert.rejects(runVisualProcess(process.execPath, ['-e', "console.error('owned-failure'); process.exit(7)"]), (error) => {
        assert.equal(error.code, 7)
        assert.match(error.stderr, /owned-failure/)
        return true
    })
})
