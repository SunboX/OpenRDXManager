// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { waitForInstallerResult } from '../src/main/installer-startup.mjs'

test('installer startup waits through absent and partially written signals and acknowledges success', async () => {
    const results = [null, '', 'ready']
    let sleeps = 0
    const acknowledgments = []
    await waitForInstallerResult('signal', {
        async read() {
            const result = results.shift()
            if (result === null) throw Object.assign(new Error(), { code: 'ENOENT' })
            return result
        },
        async sleep() {
            sleeps += 1
        },
        async acknowledge(...args) {
            acknowledgments.push(args)
        }
    })
    assert.equal(sleeps, 2)
    assert.deepEqual(acknowledgments, [['signal.ack', 'received', { flag: 'r+' }]])
})

test('failed, invalid, denied and missing installer signals never release startup', async () => {
    for (const result of ['failed', 'unexpected', 'denied', 'missing']) {
        await assert.rejects(
            waitForInstallerResult('signal', {
                attempts: 2,
                async sleep() {},
                async read() {
                    if (result === 'denied' || result === 'missing') throw Object.assign(new Error(), { code: result === 'denied' ? 'EACCES' : 'ENOENT' })
                    return result
                },
                async acknowledge() {
                    assert.fail('Failed setup must not be acknowledged')
                }
            })
        )
    }
})

test('installer signals success only after native verification, before releasing its temporary directory', async () => {
    const hook = await readFile(new URL('../resources/installer/windows-service.nsh', import.meta.url), 'utf8')
    assert.match(hook, /ExecShellAsUser[^\n]*--installer-result-file=/u)
    assert.ok(hook.indexOf('--action verify') < hook.indexOf('FileWrite $R8 "ready"'))
    assert.ok(hook.indexOf('FileWrite $R8 "ready"') < hook.indexOf('openrdx_manager_signal_wait:'))
    const main = await readFile(new URL('../src/main.mjs', import.meta.url), 'utf8')
    assert.ok(main.indexOf('await waitForInstallerResult') < main.indexOf('const serviceReadiness = await serviceRuntime.start()'))
})
