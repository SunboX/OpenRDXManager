// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { runRestrictedTokenProbe } from '../scripts/verify-windows-restricted-token-probe.mjs'

const prefix = 'openrdx-token-object-lineage'
const role = 'token'
const stats = ['source-query-ok', 'source-layout-valid', 'derived-query-ok', 'derived-layout-valid', 'actual-query-ok', 'actual-layout-valid', ...['source-derived', 'source-actual', 'derived-actual'].flatMap((pair) => ['known', 'id-equal', 'logon-equal', 'modified-equal'].map((part) => `${pair}-${part}`))]
const profile = ['profile-valid', ...['baseline', 'expected', 'actual'].flatMap((object) => ['grant-absent', 'grant-single', 'grant-duplicate'].map((part) => `${object}-${part}`)), ...['baseline', 'expected'].flatMap((object) => ['acl-bytes-equal', 'ace-sequence-equal', 'header-equal', 'padding-equal'].map((part) => `${object}-${part}`)), 'old-aces-retained', 'denials-equal', 'one-addition', 'owner-preserved', 'group-preserved', 'label-preserved', 'control-preserved']

/** @returns {string} Fixed synthetic diagnostics inside the existing live token read phase. */
function output() {
    const values = Object.fromEntries([...stats, ...profile, 'descriptor-query-ok', 'fresh-proof', 'actual-open-ok', 'full-properties-known', 'full-properties-equal'].map((key) => [key, true]))
    for (const pair of ['source-derived', 'source-actual']) values[`${pair}-id-equal`] = false
    for (const object of ['baseline', 'expected', 'actual']) {
        values[`${object}-grant-absent`] = object === 'baseline'
        values[`${object}-grant-single`] = object !== 'baseline'
        values[`${object}-grant-duplicate`] = false
    }
    // The actual ACL is one grant larger than baseline, while matching the expected ACL exactly.
    for (const part of ['acl-bytes-equal', 'ace-sequence-equal', 'header-equal']) values[`baseline-${part}`] = false
    const row = `${prefix} row=${role} phase=read ${Object.entries(values)
        .map(([key, value]) => `${key}=${value}`)
        .join(' ')}\n`
    return `openrdx-token-object-dacl-matrix-stage row=${role} phase=read status=begin\n${row}openrdx-token-object-dacl-matrix-stage row=${role} phase=read status=failed reason=EvidenceIncomplete\n`
}

test('closed lineage and profile facts survive original native failure without authority', async () => {
    const result = await runRestrictedTokenProbe({ mode: 'object-dacl-controls', execute: async () => ({ exitCode: 101, stdout: output(), stderr: '' }) })
    assert.equal(result.exitCode, 101)
    assert.equal(result.passed, false)
    assert.equal(
        result.objectMatrix.some((line) => line.startsWith(prefix)),
        true
    )
})

test('unavailable comparisons are distinguished from inequality and cannot manufacture known values', async () => {
    const unknown = output().replace('actual-query-ok=true', 'actual-query-ok=false').replace('actual-layout-valid=true', 'actual-layout-valid=false').replaceAll('source-actual-known=true', 'source-actual-known=false').replaceAll('derived-actual-known=true', 'derived-actual-known=false').replaceAll('derived-actual-id-equal=true', 'derived-actual-id-equal=false').replaceAll('source-actual-logon-equal=true', 'source-actual-logon-equal=false').replaceAll('source-actual-modified-equal=true', 'source-actual-modified-equal=false').replaceAll('derived-actual-logon-equal=true', 'derived-actual-logon-equal=false').replaceAll('derived-actual-modified-equal=true', 'derived-actual-modified-equal=false')
    const result = await runRestrictedTokenProbe({ mode: 'object-dacl-controls', execute: async () => ({ exitCode: 101, stdout: unknown, stderr: '' }) })
    assert.equal(result.passed, false)
    assert.equal(
        result.objectMatrix.some((line) => line.includes('actual-query-ok=false')),
        true
    )
})

test('raw fields, duplicate/orphan/wrong scopes and nontransitive object identity are rejected privately', async () => {
    for (const source of [output().replace(`${prefix} row=token`, `${prefix} row=thread`), output().replace('source-derived-id-equal=false', 'source-derived-id-equal=true'), output().replace('source-query-ok=true', 'source-query-ok=secret-sid'), output() + `${prefix} row=token phase=read private-mask=true\n`, output().replace('full-properties-equal=true', 'full-properties-equal=secret'), output().replace('source-layout-valid=true', 'source-layout-valid=true source-layout-valid=true')]) {
        const result = await runRestrictedTokenProbe({ mode: 'object-dacl-controls', execute: async () => ({ exitCode: 101, stdout: source, stderr: 'secret path' }) })
        assert.equal(result.passed, false)
        assert.equal(result.objectMatrix.length, 0)
        assert.equal(JSON.stringify(result).includes('secret'), false)
    }
})

test('host ACL profile and opaque identity regressions execute checked-in Rust modules', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-lineage-'))
    try {
        const root = new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/', import.meta.url)
        const driver = join(directory, 'lineage.rs'),
            binary = join(directory, process.platform === 'win32' ? 'lineage.exe' : 'lineage')
        await writeFile(driver, ['mandatory_label', 'object_acl', 'process_descriptor', 'token_identity'].map((module) => `#[path=${JSON.stringify(fileURLToPath(new URL(`${module}.rs`, root)))}] mod ${module};`).join('\n'))
        const execute = promisify(execFile)
        await execute('rustc', ['--edition=2024', '--test', driver, '-o', binary], { timeout: 30_000 })
        const profile = await execute(binary, ['process_descriptor::token_acl_profile::tests::', '--test-threads=2'], { timeout: 30_000 })
        const identity = await execute(binary, ['token_identity::tests::', '--test-threads=2'], { timeout: 30_000 })
        assert.match(profile.stdout, /4 passed; 0 failed/u)
        assert.match(identity.stdout, /3 passed; 0 failed/u)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})

test('observer contains no setter and runs before the unchanged exact guard on the fixed four token rows', async () => {
    const root = new URL('../native/rdx-service/windows-native/src/service_acl/windows_impl/restricted_token_probe/medium/', import.meta.url)
    const observer = await readFile(new URL('token_lineage.rs', root), 'utf8')
    const statistics = await readFile(new URL('token_statistics.rs', root), 'utf8')
    const matrix = await readFile(new URL('object_dacl_controls.rs', root), 'utf8')
    assert.doesNotMatch(observer, /SetKernelObjectSecurity|SetTokenInformation|AdjustTokenPrivileges|Impersonate|TOKEN_WRITE_DAC|TOKEN_DUPLICATE/u)
    assert.match(observer, /OpenProcessToken\(child.process.0, TOKEN_QUERY \| TOKEN_READ_CONTROL/u)
    assert.match(observer, /"actual-open-ok"/u)
    assert.match(observer, /prove_child_quiet/u)
    assert.match(observer, /SourceSnapshot::read/u)
    assert.match(statistics, /size_of::<TOKEN_STATISTICS>\(\)/u)
    assert.match(statistics, /align_of::<TOKEN_STATISTICS>\(\)/u)
    assert.match(matrix, /if row.objects\(\)\[2\] \{\s+token_lineage::observe/u)
    assert.match(matrix, /expected.readback\(name, "read", state.child\(\)\?\)\?;\s+observer/u)
})

test('unknown layout, false proof, invalid profile and inconsistent relative grants cannot become observations', async () => {
    for (const source of [output().replace('source-layout-valid=true', 'source-layout-valid=false'), output().replace('fresh-proof=true', 'fresh-proof=false'), output().replace('profile-valid=true', 'profile-valid=false'), output().replace('baseline-grant-absent=true baseline-grant-single=false', 'baseline-grant-absent=false baseline-grant-single=true')]) {
        const result = await runRestrictedTokenProbe({ mode: 'object-dacl-controls', execute: async () => ({ exitCode: 101, stdout: source, stderr: '' }) })
        assert.equal(result.objectMatrix.length, 0)
        assert.equal(result.passed, false)
    }
})

test('grouped and legacy individual calls retain identical closed facts and failure authority', async () => {
    const grouped = output()
    const individual = grouped.replace(/^openrdx-token-object-lineage row=token phase=read (.+)$/mu, (_line, pairs) =>
        pairs
            .split(' ')
            .map((pair) => `${prefix} row=token phase=read ${pair}`)
            .join('\n')
    )
    const results = []
    for (const stdout of [grouped, individual]) results.push(await runRestrictedTokenProbe({ mode: 'object-dacl-controls', execute: async () => ({ exitCode: 101, stdout, stderr: '' }) }))
    /** @param {{objectMatrix: string[]}} result Sanitized wrapper result. @returns {string[]} Sorted fixed key/value facts, independent of batching. */
    function facts(result) {
        return result.objectMatrix
            .filter((line) => line.startsWith(`${prefix} `))
            .flatMap((line) => line.split(' ').slice(3))
            .sort()
    }
    assert.deepEqual(facts(results[0]), facts(results[1]))
    assert.ok(facts(results[0]).length > 0)
    for (const result of results) {
        assert.equal(result.passed, false)
        assert.equal(result.exitCode, 101)
    }
})

test('contradictory ACL equality and relative additions are rejected without forwarding facts', async () => {
    const valid = output().replace('baseline-acl-bytes-equal=true', 'baseline-acl-bytes-equal=false').replace('baseline-ace-sequence-equal=true', 'baseline-ace-sequence-equal=false').replace('baseline-header-equal=true', 'baseline-header-equal=false')
    const contradictions = [valid.replace('baseline-acl-bytes-equal=false', 'baseline-acl-bytes-equal=true'), valid.replace('baseline-ace-sequence-equal=false', 'baseline-ace-sequence-equal=true'), valid.replace('expected-ace-sequence-equal=true', 'expected-ace-sequence-equal=false'), valid.replace('expected-header-equal=true', 'expected-header-equal=false'), valid.replace('expected-padding-equal=true', 'expected-padding-equal=false'), valid.replace('old-aces-retained=true', 'old-aces-retained=false'), valid.replace('denials-equal=true', 'denials-equal=false')]
    const rejected = []
    for (const stdout of contradictions) {
        const result = await runRestrictedTokenProbe({ mode: 'object-dacl-controls', execute: async () => ({ exitCode: 101, stdout, stderr: '' }) })
        assert.equal(result.passed, false)
        assert.equal(result.exitCode, 101)
        rejected.push(result.objectMatrix.length === 0)
    }
    assert.deepEqual(
        rejected,
        contradictions.map(() => true)
    )
})

test('missing comparison evidence remains unknown rather than inferred equality', async () => {
    const available = output().replace('baseline-header-equal=false ', '')
    const retained = await runRestrictedTokenProbe({ mode: 'object-dacl-controls', execute: async () => ({ exitCode: 101, stdout: available, stderr: '' }) })
    assert.ok(retained.objectMatrix.some((line) => line.startsWith(prefix)))
    assert.equal(retained.passed, false)
    for (const stdout of [output().replace('expected-header-equal=true ', ''), output().replace('old-aces-retained=true ', ''), output().replace('denials-equal=true ', '')]) {
        const result = await runRestrictedTokenProbe({ mode: 'object-dacl-controls', execute: async () => ({ exitCode: 101, stdout, stderr: '' }) })
        assert.equal(result.objectMatrix.length, 0)
        assert.equal(result.exitCode, 101)
    }
})
