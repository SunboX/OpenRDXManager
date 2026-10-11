// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createRequire } from 'node:module'
import { link, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import test from 'node:test'

import { EventLogger } from '../src/main/event-logger.mjs'
import { createLogFileSecurity } from '../src/main/log-file-security.mjs'
import { WindowsLogSecurityAdapter } from '../src/main/windows-log-security-adapter.mjs'
import { createApplicationServiceRuntime } from '../src/main/service-runtime.mjs'

const require = createRequire(import.meta.url)
const execFileAsync = promisify(execFile)
const windows = { skip: process.platform !== 'win32', timeout: 30_000 }
const addonPath = fileURLToPath(new URL('../out/native/windows/openrdx-windows-client.node', import.meta.url))
const aclScript = fileURLToPath(new URL('./helpers/windows-log-acl.ps1', import.meta.url))

/** @param {object} context - Test cleanup owner. @returns {Promise<object>} Independent native logger fixture without hardware access. */
async function fixture(context) {
    const temporary = await mkdtemp(join(tmpdir(), 'openrdx-private-log-'))
    const directory = join(temporary, 'logs-André')
    context.after(async () => await rm(temporary, { recursive: true, force: true }))
    const adapter = new WindowsLogSecurityAdapter({ directory, addonPath })
    return { temporary, directory, adapter, security: createLogFileSecurity({ platform: 'win32', windowsSecurityAdapter: adapter }), addon: require(addonPath), current: join(directory, 'RDXManager.jsonl'), backup: join(directory, '_RDXManager.bak') }
}

/** @param {string} path - Controlled test path. @param {string} [mode] - Inspection or deliberate ACL tampering. @returns {Promise<object|undefined>} Independent Windows ACL evidence. */
async function acl(path, mode = 'inspect') {
    const { stdout } = await execFileAsync('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['-NoProfile', '-File', aclScript, path, mode], { windowsHide: true, timeout: 10_000 })
    return mode === 'inspect' ? JSON.parse(stdout) : undefined
}

test('native Windows logs create and independently verify private directory/file ACLs', windows, async (context) => {
    const state = await fixture(context)
    await state.security.prepareDirectory(state.directory)
    let handle = await state.security.openAppend(state.current)
    try {
        await handle.writeFile('private log\n', { encoding: 'utf8' })
        assert.equal((await handle.stat()).size, 12)
    } finally {
        await handle.close()
    }
    assert.equal((await acl(state.directory)).private, true)
    assert.equal((await acl(state.current)).private, true)
    handle = await state.security.openRead(state.current)
    try {
        const output = Buffer.alloc(32)
        assert.equal((await handle.read(output, 2, 20, 0)).bytesRead, 12)
        assert.equal(output.subarray(2, 14).toString(), 'private log\n')
        await assert.rejects(handle.read(output, -1, 4, 0), /read-invalid/)
    } finally {
        await handle.close()
    }
    await assert.rejects(handle.stat(), /handle-closed/)
})

test('native logger persists, rotates and lists real redacted events without synthetic proofs', windows, async (context) => {
    const state = await fixture(context)
    const logger = new EventLogger({ directory: state.directory, platform: 'win32', windowsSecurityAdapter: state.adapter, maxBytes: 300 })
    context.after(async () => await logger.close())
    assert.equal(await logger.writeCritical({ event: 'first', messageKey: 'activity.first', detail: 'a'.repeat(80), password: 'NEVER-RETAIN' }), true)
    assert.equal(await logger.writeCritical({ event: 'second', messageKey: 'activity.second', detail: 'b'.repeat(80) }), true)
    const listed = await logger.list()
    assert.equal(listed.ok, true)
    assert.equal(listed.entries.length, 2)
    assert.doesNotMatch((await readFile(state.current, 'utf8')) + (await readFile(state.backup, 'utf8')), /NEVER-RETAIN/)
    assert.equal((await acl(state.backup)).private, true)
    assert.deepEqual(await logger.close(), { ok: true })
})

test('native Windows rotation never overwrites an existing backup', windows, async (context) => {
    const state = await fixture(context)
    await state.security.prepareDirectory(state.directory)
    const handle = await state.security.openAppend(state.current)
    await handle.writeFile('current')
    await handle.close()
    await writeFile(state.backup, 'keep backup')
    await assert.rejects(state.security.renameFile(state.current, state.backup))
    assert.equal(await readFile(state.backup, 'utf8'), 'keep backup')
    assert.equal(await readFile(state.current, 'utf8'), 'current')
    await state.security.removeFile(state.backup)
    await state.security.renameFile(state.current, state.backup)
    assert.equal(await readFile(state.backup, 'utf8'), 'current')
    await state.security.removeFile(state.backup)
    await state.security.removeFile(state.backup)
})

test('native Windows logger rejects hard-linked files before touching contents or ACLs', windows, async (context) => {
    const state = await fixture(context)
    await state.security.prepareDirectory(state.directory)
    const outside = join(state.temporary, 'unrelated.txt')
    await writeFile(outside, 'outside evidence')
    const before = await acl(outside)
    await link(outside, state.current)
    await assert.rejects(state.security.openAppend(state.current), /unsafe-object/)
    assert.equal(await readFile(outside, 'utf8'), 'outside evidence')
    assert.deepEqual(await acl(outside), before)
})

test('native Windows logger rejects final and ancestor directory junctions', windows, async (context) => {
    const state = await fixture(context)
    const outside = join(state.temporary, 'outside')
    await mkdir(outside)
    await symlink(outside, state.directory, 'junction')
    await assert.rejects(state.security.prepareDirectory(state.directory), /unsafe-object/)
    await assert.rejects(readFile(join(outside, 'RDXManager.jsonl')), { code: 'ENOENT' })
    const nested = new WindowsLogSecurityAdapter({ directory: join(state.directory, 'nested'), addonPath })
    await assert.rejects(nested.ensurePrivateDirectory({ path: join(state.directory, 'nested'), requireReparseRejection: true, requireUserOnlyDacl: true }), /unsafe-object/)
    await assert.rejects(readFile(join(outside, 'nested', 'RDXManager.jsonl')), { code: 'ENOENT' })
})

test('native Windows handles pin ancestors until close and serialize concurrent logger reads', windows, async (context) => {
    const state = await fixture(context)
    await state.security.prepareDirectory(state.directory)
    const handle = await state.security.openAppend(state.current)
    await handle.writeFile('retained')
    await assert.rejects(rename(state.directory, join(state.temporary, 'moved')))
    const pendingRead = state.security.openRead(state.current)
    await handle.close()
    const reader = await pendingRead
    assert.equal((await reader.stat()).size, 8)
    await reader.close()
    await rename(state.directory, join(state.temporary, 'moved'))
})

test('native Windows logger hardens owned existing files but rejects ACL drift on retained handles', windows, async (context) => {
    const state = await fixture(context)
    await mkdir(state.directory)
    await writeFile(state.current, 'existing')
    await acl(state.current, 'make-public')
    await assert.doesNotReject(state.security.prepareDirectory(state.directory), 'prepare existing directory')
    let handle
    await assert.doesNotReject(async () => {
        handle = await state.security.openAppend(state.current)
    }, 'open and harden existing file')
    await handle.close()
    assert.equal((await acl(state.current)).private, true)
    let retained
    await assert.doesNotReject(async () => {
        retained = await state.security.openAppend(state.current)
    }, 'reopen hardened file')
    try {
        await acl(state.current, 'make-public')
        await assert.rejects(retained.stat(), /dacl-unverified/)
    } finally {
        await retained.close()
    }
})

test('native Windows log factory rejects traversal, streams, UNC paths and forged receivers', windows, async (context) => {
    const { addon } = await fixture(context)
    for (const directory of ['relative', 'C:\\', 'C:\\logs\\..\\elsewhere', 'C:\\logs:stream', 'C:\\logs\\NUL', 'C:\\logs\\trailing.', '\\\\server\\logs', 'C:\\logs\0ignored']) {
        assert.throws(() => addon.createLogSecurity(directory))
    }
    const root = addon.createLogSecurity('C:\\controlled-unused-logs')
    assert.throws(() => root.prepare.call({}), /receiver-invalid/)
    assert.throws(() => root.openRead('not-a-boolean'))
})

test('Windows application runtime supplies real private logging by default and preserves explicit denial', windows, async (context) => {
    const state = await fixture(context)
    const appPath = fileURLToPath(new URL('../', import.meta.url))
    for (const allowed of [true, false]) {
        const runtime = createApplicationServiceRuntime({
            appPath,
            resourcesPath: appPath,
            isPackaged: false,
            platform: 'win32',
            logDirectory: state.directory,
            services: {},
            ipcController: { publishDeviceEvent() {}, publishOperationEvent() {} },
            ...(allowed ? {} : { windowsSecurityAdapter: null })
        })
        try {
            assert.equal(await runtime.logger.writeCritical({ event: 'runtime-logging-check', messageKey: 'activity.check' }), allowed)
        } finally {
            await runtime.logger.close()
        }
    }
    assert.equal((await acl(state.current)).private, true)
})
