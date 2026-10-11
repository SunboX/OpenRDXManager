// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { createLogFileSecurity } from '../src/main/log-file-security.mjs'
import { WindowsLogSecurityAdapter } from '../src/main/windows-log-security-adapter.mjs'

const directory = 'C:\\controlled\\logs'
const current = `${directory}\\RDXManager.jsonl`
const backup = `${directory}\\_RDXManager.bak`
const proof = { noFollowVerified: true, reparsePoint: false, userOnlyDacl: true }

/** @param {object} [overrides] - Explicit native fault injection. @returns {object} Hardware-free adapter and recorded native calls. */
function fixture(overrides = {}) {
    const calls = []
    const file = {
        /** @returns {Promise<object>} Controlled regular-file proof. */
        async stat() {
            return { size: 3, regular: true }
        },
        /** @returns {Promise<Buffer>} Controlled bounded contents. */
        async read() {
            return Buffer.from('log')
        },
        /** @param {Buffer} bytes - Copied log bytes. @returns {Promise<void>} Records append. */
        async append(bytes) {
            calls.push(['append', bytes.toString()])
        },
        /** @returns {Promise<void>} Records exact cleanup. */
        async close() {
            calls.push('close')
        }
    }
    const root = {
        /** @returns {Promise<object>} Controlled directory proof. */
        async prepare() {
            calls.push('prepare')
            return { ...proof, directory: true }
        },
        /** @returns {Promise<object>} Controlled current-file owner. */
        async openAppend() {
            calls.push('open')
            return { ...proof, handle: file }
        },
        /** @param {boolean} isBackup - Narrow file selector. @returns {Promise<object>} Controlled read owner. */
        async openRead(isBackup) {
            calls.push(['read', isBackup])
            return { ...proof, handle: file }
        },
        /** @returns {Promise<object>} Controlled removal proof. */
        async removeBackup() {
            calls.push('remove')
            return { ...proof, removed: true }
        },
        /** @returns {Promise<object>} Controlled rotation proof. */
        async rotate() {
            calls.push('rotate')
            return proof
        },
        ...overrides
    }
    const adapter = new WindowsLogSecurityAdapter({
        directory,
        addonPath: 'C:\\fixed\\client.node',
        /** @param {string} path - Main-owned native path. @returns {object} Explicit fake factory. */
        loadAddon(path) {
            calls.push(['load', path])
            return {
                /** @param {string} path - Main-owned directory. @returns {object} Test-only native root. */
                createLogSecurity(path) {
                    calls.push(['root', path])
                    return root
                }
            }
        }
    })
    return { adapter, file, root, calls, security: createLogFileSecurity({ platform: 'win32', windowsSecurityAdapter: adapter }) }
}

test('Windows adapter validates fixed paths and full security requirements before loading native code', async () => {
    const { adapter, calls, security } = fixture()
    await assert.rejects(adapter.ensurePrivateDirectory({ path: directory }), /proof-required/)
    await assert.rejects(security.prepareDirectory('C:\\elsewhere'), /path-invalid/)
    await assert.rejects(security.openAppend(backup), /arguments-invalid/)
    await assert.rejects(security.openRead(`${current}:stream`), /arguments-invalid/)
    await assert.rejects(security.removeFile(current), /path-invalid/)
    await assert.rejects(security.renameFile(backup, current), /path-invalid/)
    assert.deepEqual(calls, [])
    await security.prepareDirectory(directory)
    await security.prepareDirectory(directory)
    assert.equal(calls.filter((call) => Array.isArray(call) && call[0] === 'load').length, 1)
})

test('Windows adapter retains FIFO ownership across file lifetimes and asynchronous close', async () => {
    const { file, security, calls } = fixture()
    const handle = await security.openAppend(current)
    const closed = Promise.withResolvers()
    file.close = async () => {
        await closed.promise
        calls.push('closed')
    }
    const pendingRemove = security.removeFile(backup)
    const pendingRotate = security.renameFile(current, backup)
    await Promise.resolve()
    assert.equal(calls.includes('remove'), false)
    const close = handle.close()
    assert.equal(handle.close(), close)
    await assert.rejects(handle.stat(), /handle-closed/)
    await Promise.resolve()
    assert.equal(calls.includes('remove'), false)
    closed.resolve()
    await close
    await pendingRemove
    await pendingRotate
    assert.deepEqual(calls.slice(-3), ['closed', 'remove', 'rotate'])
})

test('Windows adapter bounds queued ownership and releases admission after native failures', async () => {
    const { root, security } = fixture()
    const handle = await security.openAppend(current)
    const pending = Array.from({ length: 63 }, () => security.prepareDirectory(directory))
    await assert.rejects(security.prepareDirectory(directory), /resource-limit/)
    await handle.close()
    await Promise.all(pending)
    root.openAppend = async () => {
        throw new Error('controlled-open-failure')
    }
    await assert.rejects(security.openAppend(current), /controlled-open-failure/)
    await security.prepareDirectory(directory)
})

test('Windows adapter close is published before native reentry and releases a failed close', async () => {
    const { file, security } = fixture()
    const handle = await security.openAppend(current)
    let reentered
    file.close = () => {
        reentered = handle.close()
        throw new Error('controlled-close-failure')
    }
    const closing = handle.close()
    await assert.rejects(closing, /controlled-close-failure/)
    assert.equal(reentered, closing)
    await security.prepareDirectory(directory)
})

test('Windows adapter preserves native proof rejection and bounds descriptor I/O', async () => {
    const { file, root, security } = fixture()
    const handle = await security.openRead(current)
    try {
        const output = Buffer.alloc(8)
        assert.equal((await handle.read(output, 2, 3, 0)).bytesRead, 3)
        assert.equal(output.subarray(2, 5).toString(), 'log')
        await assert.rejects(handle.read(output, 7, 3, 0), /read-invalid/)
        await assert.rejects(handle.writeFile('x', { encoding: 'utf16le' }), /write-invalid/)
        file.stat = async () => ({ regular: false, size: 0 })
        await assert.rejects(handle.stat(), /stat-unverified/)
        file.read = async () => Buffer.alloc(4)
        await assert.rejects(handle.read(output, 0, 3, 0), /read-unverified/)
    } finally {
        await handle.close()
    }
    root.openAppend = async () => ({ ...proof, userOnlyDacl: false, handle: file })
    await assert.rejects(security.openAppend(current), /handle-unverified/)
    await security.prepareDirectory(directory)
})

test('Windows adapter never replaces an absent native implementation with synthetic proof', async () => {
    const adapter = new WindowsLogSecurityAdapter({ directory, addonPath: 'C:\\missing.node', loadAddon: () => ({}) })
    const security = createLogFileSecurity({ platform: 'win32', windowsSecurityAdapter: adapter })
    await assert.rejects(security.prepareDirectory(directory), /security-unavailable/)
    await assert.rejects(security.prepareDirectory(directory), /security-unavailable/)
})
