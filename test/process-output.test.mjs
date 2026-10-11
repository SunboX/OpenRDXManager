// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter, once } from 'node:events'
import { spawn } from 'node:child_process'
import test from 'node:test'
import { containBrokenConsolePipes } from '../src/main/process-output.mjs'

test('console output contains EPIPE without suppressing other failures', () => {
    const stream = new EventEmitter()
    containBrokenConsolePipes([stream, stream])
    assert.equal(stream.listenerCount('error'), 1)
    stream.emit('error', Object.assign(new Error('closed'), { code: 'EPIPE' }))
    assert.throws(() => stream.emit('error', Object.assign(new Error('other'), { code: 'EIO' })), /other/)
})

test('closing a real launch pipe leaves the child alive through later console output', { timeout: 10000 }, async () => {
    const moduleUrl = new URL('../src/main/process-output.mjs', import.meta.url).href
    const source = `import { containBrokenConsolePipes } from ${JSON.stringify(moduleUrl)};
        containBrokenConsolePipes(); process.send('ready');
        process.on('message', () => { console.log('after launcher closes');
            setTimeout(() => { process.send('alive'); process.disconnect(); }, 100); });`
    const child = spawn(process.execPath, ['--input-type=module', '--eval', source], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] })
    const exit = once(child, 'exit')
    try {
        assert.deepEqual(await once(child, 'message'), ['ready', undefined])
        child.stdout.destroy()
        const alive = once(child, 'message')
        child.send('write')
        assert.equal((await alive)[0], 'alive')
        assert.equal((await exit)[0], 0)
    } finally {
        if (child.exitCode === null) child.kill()
    }
})
