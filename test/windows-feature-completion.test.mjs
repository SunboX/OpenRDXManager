// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdtemp, readdir, rm, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { ManufacturingFolderService } from '../src/main/manufacturing-folder-service.mjs'
import { windowsManufacturingDirectory } from '../src/main/windows-manufacturing-directory.mjs'
import { isNativeDiagnosticCode } from '../src/main/device-service-transport.mjs'

test('Windows backup folder resolves the same fixed native known-folder store', () => {
    const directory = 'C:\\ProgramData\\OpenRDXManager\\manufacturing-backups'
    const queries = []
    const load = (path) => {
        queries.push(path)
        return {
            manufacturingBackupDirectory: (...args) => {
                assert.deepEqual(args, [])
                return directory
            }
        }
    }
    assert.equal(windowsManufacturingDirectory('native-addon', load), directory)
    assert.deepEqual(queries, ['native-addon'])
    for (const invalid of ['relative', '\\\\server\\share\\OpenRDXManager\\manufacturing-backups', 'C:\\wrong', null]) {
        assert.throws(() => windowsManufacturingDirectory('native-addon', () => ({ manufacturingBackupDirectory: () => invalid })), /manufacturing-folder-unavailable/u)
    }
})

test('Windows folder opening cannot create a falsely prepared unprotected backup directory', async () => {
    const root = await mkdtemp(join(tmpdir(), 'openrdx-folder-native-'))
    try {
        const folder = new ManufacturingFolderService({
            directory: () => join(root, 'missing'),
            createDirectory: false,
            prepare: async () => ({ ok: true }),
            openPath: async () => {
                throw new Error('must not open')
            }
        })
        assert.deepEqual(await folder.open(), { ok: false, reason: 'manufacturing-folder-open-failed' })
        assert.deepEqual(await readdir(root), [])
    } finally {
        await rm(root, { recursive: true, force: true })
    }
})

test('Windows diagnostic breadcrumbs accept only fixed self-test outcome codes', () => {
    for (const code of ['succeeded', 'no-media', 'invalid-command', 'invalid-field', 'medium-error', 'hardware-error', 'unit-attention', 'check-condition', 'not-sent', 'timeout', 'access-denied', 'native-error', 'invalid-sense', 'unexpected-sense', 'scsi-status', 'invalid-transfer']) {
        assert.equal(isNativeDiagnosticCode(`windows-self-test-${code}`), true)
        assert.equal(isNativeDiagnosticCode(`windows-self-test-${code} private-value`), false)
    }
    assert.equal(isNativeDiagnosticCode('windows-self-test-raw-sense'), false)
})

test('Windows backup hooks preserve native durable storage and no generic command API', async () => {
    const platform = await readFile(new URL('../native/rdx-service/src/platform/mod.rs', import.meta.url), 'utf8')
    const native = await readFile(new URL('../native/rdx-service/windows-native/src/manufacturing_storage.rs', import.meta.url), 'utf8')
    const acl = await readFile(new URL('../native/rdx-service/windows-native/src/manufacturing_storage/acl.rs', import.meta.url), 'utf8')
    assert.ok((platform.match(/cfg\(any\(target_os = "macos", target_os = "linux", windows\)\)/gu) ?? []).length >= 4)
    assert.match(native, /FILE_FLAG_WRITE_THROUGH/u)
    assert.match(native, /file\.sync_all\(\)/u)
    assert.match(native, /CREATE_NEW/u)
    assert.match(native, /FILE_ATTRIBUTE_REPARSE_POINT/u)
    assert.match(native, /nNumberOfLinks != 1/u)
    assert.match(acl, /O:BAD:P\(A;;FA;;;SY\)\(A;;FA;;;BA\)\(A;;FA;;;LS\)/u)
    assert.doesNotMatch(acl, /SetSecurityInfo|SetNamedSecurityInfo/u)
})
