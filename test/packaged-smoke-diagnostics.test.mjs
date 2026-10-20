// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { access, mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import * as verifier from '../scripts/verify-packaged-app.mjs'
import { EventLogger } from '../src/main/event-logger.mjs'
import { WindowsLogSecurityAdapter } from '../src/main/windows-log-security-adapter.mjs'
import { ownWindowsFixture } from './helpers/windows-fixture-owner.mjs'

test('firmware acceptance rejects an older executable ignoring the flag and partial version matches', () => {
    assert.doesNotThrow(() => verifier.assertPackagedFirmwareReadback('OpenRDXManager installed firmware verification passed: revision=0111\r\n', '0111'))
    for (const output of ['OpenRDXManager installed device discovery passed: count=1 selected=matched', 'OpenRDXManager installed firmware verification passed: revision=0110', 'OpenRDXManager installed firmware verification passed: revision=01110', 'prefix OpenRDXManager installed firmware verification passed: revision=0111']) assert.throws(() => verifier.assertPackagedFirmwareReadback(output, '0111'), /installed-firmware-verification-marker-missing/u)
})

test('installed auth failure exports actual lifecycle envelopes before deleting the profile and preserves the error', async () => {
    assert.equal(typeof verifier.withPackagedSmokeProfile, 'function')
    const failure = new Error('controlled-smoke-failure')
    const output = []
    let ownedProfile
    await assert.rejects(
        verifier.withPackagedSmokeProfile(
            async (profile) => {
                ownedProfile = profile
                await ownWindowsFixture(profile)
                const directory = join(profile, 'logs')
                const windowsSecurityAdapter = process.platform === 'win32' ? new WindowsLogSecurityAdapter({ directory, addonPath: fileURLToPath(new URL('../out/native/windows/openrdx-windows-client.node', import.meta.url)) }) : undefined
                const logger = new EventLogger({ directory, windowsSecurityAdapter, now: () => new Date('2026-10-18T12:00:00.000Z') })
                assert.equal(await logger.write({ event: 'service-lifecycle', status: 'handshaking', messageKey: 'activity.service', secret: 'private-secret', path: '/private/path', devices: [{ serial: 'private-serial' }] }), true)
                assert.equal(await logger.write({ event: 'service-handshake-start', messageKey: 'activity.service' }), true)
                assert.equal(await logger.write({ event: 'service-lifecycle', status: 'unavailable', reason: 'service-handshake-timeout', messageKey: 'activity.service' }), true)
                await logger.close()
                throw failure
            },
            { installed: true, requireService: true, writeDiagnostic: (line) => output.push(line) }
        ),
        (error) => error === failure
    )
    await assert.rejects(access(ownedProfile), { code: 'ENOENT' })
    const records = JSON.parse(output[0].slice(output[0].indexOf('[')))
    assert.deepEqual(records, [
        { occurredAt: '2026-10-18T12:00:00.000Z', event: 'service-lifecycle', status: 'handshaking' },
        { occurredAt: '2026-10-18T12:00:00.000Z', event: 'service-handshake-start' },
        { occurredAt: '2026-10-18T12:00:00.000Z', event: 'service-lifecycle', status: 'unavailable', reason: 'service-handshake-timeout' }
    ])
    assert.doesNotMatch(output.join(''), /private|devices|serial|messageKey|activity:/u)
})

test('an installed endpoint permission failure remains visible as its closed public reason', async () => {
    const output = []
    await assert.rejects(
        verifier.withPackagedSmokeProfile(
            async (profile) => {
                await mkdir(join(profile, 'logs'))
                await writeFile(join(profile, 'logs', 'RDXManager.jsonl'), JSON.stringify({ occurredAt: '2026-10-18T12:00:00.000Z', event: 'service-lifecycle', details: { status: 'unavailable', reason: 'insufficient-permission' } }) + '\n')
                throw new Error('controlled-permission-failure')
            },
            { installed: true, requireService: true, writeDiagnostic: (line) => output.push(line) }
        )
    )
    assert.deepEqual(JSON.parse(output[0].slice(output[0].indexOf('['))), [{ occurredAt: '2026-10-18T12:00:00.000Z', event: 'service-lifecycle', status: 'unavailable', reason: 'insufficient-permission' }])
})

test('diagnostic export bounds file reads and records and drops unknown fields, statuses, reasons and timestamps', async () => {
    assert.equal(typeof verifier.withPackagedSmokeProfile, 'function')
    const output = []
    await assert.rejects(
        verifier.withPackagedSmokeProfile(
            async (profile) => {
                await mkdir(join(profile, 'logs'))
                const valid = { occurredAt: '2026-10-18T12:00:01.000Z', event: 'service-lifecycle', details: { status: 'unavailable', reason: 'service-handshake-timeout', payload: 'private-payload' } }
                const rejected = [
                    { ...valid, event: 'device-list' },
                    { ...valid, occurredAt: '/private/time' },
                    { ...valid, details: { status: '/private/status' } },
                    { ...valid, details: { status: 'unavailable', reason: '/private/reason' } },
                    { ...valid, details: { status: 'unavailable', reason: 'arbitrary-reason' } }
                ]
                await writeFile(join(profile, 'logs', 'RDXManager.jsonl'), `${'private-prefix'.repeat(10_000)}\n${[...Array.from({ length: 100 }, () => valid), ...rejected].map((entry) => JSON.stringify(entry)).join('\n')}\n{broken-json\n`)
                throw new Error('controlled-failure')
            },
            { installed: true, requireService: true, writeDiagnostic: (line) => output.push(line) }
        )
    )
    assert.equal(output.length, 1)
    assert.ok(Buffer.byteLength(output[0]) <= 8192)
    const records = JSON.parse(output[0].slice(output[0].indexOf('[')))
    assert.equal(records.length, 32)
    assert.ok(records.every((entry) => entry.event === 'service-lifecycle' && entry.status === 'unavailable' && entry.reason === 'service-handshake-timeout'))
    assert.doesNotMatch(output[0], /private|arbitrary|payload|broken-json/u)
})

test('success and ordinary smoke failures never export profiles; unavailable diagnostics preserve auth failures', async () => {
    assert.equal(typeof verifier.withPackagedSmokeProfile, 'function')
    const output = []
    for (const options of [
        { installed: false, requireService: false },
        { installed: true, requireService: false }
    ]) {
        const failure = new Error('controlled-ordinary-failure')
        await assert.rejects(
            verifier.withPackagedSmokeProfile(
                async () => {
                    throw failure
                },
                { ...options, writeDiagnostic: (line) => output.push(line) }
            ),
            (error) => error === failure
        )
    }
    assert.equal(await verifier.withPackagedSmokeProfile(async () => 'success', { installed: true, requireService: true, writeDiagnostic: (line) => output.push(line) }), 'success')
    assert.deepEqual(output, [])
    const failure = new Error('controlled-auth-failure')
    await assert.rejects(
        verifier.withPackagedSmokeProfile(
            async () => {
                throw failure
            },
            {
                installed: true,
                requireService: true,
                writeDiagnostic() {
                    throw new Error('diagnostic-sink-failed')
                }
            }
        ),
        (error) => error === failure
    )
})

test('only the bounded tail of a large lifecycle file is eligible for export', async () => {
    const output = []
    await assert.rejects(
        verifier.withPackagedSmokeProfile(
            async (profile) => {
                await mkdir(join(profile, 'logs'))
                const stale = { occurredAt: '2026-10-18T11:00:00.000Z', event: 'service-lifecycle', details: { status: 'starting' } }
                const latest = { occurredAt: '2026-10-18T12:00:00.000Z', event: 'service-lifecycle', details: { status: 'unavailable', reason: 'service-handshake-timeout' } }
                await writeFile(join(profile, 'logs', 'RDXManager.jsonl'), `${JSON.stringify(stale)}\n${'padding'.repeat(20_000)}\n${JSON.stringify(latest)}\n`)
                throw new Error('controlled-failure')
            },
            { installed: true, requireService: true, writeDiagnostic: (line) => output.push(line) }
        )
    )
    assert.deepEqual(JSON.parse(output[0].slice(output[0].indexOf('['))), [{ occurredAt: '2026-10-18T12:00:00.000Z', event: 'service-lifecycle', status: 'unavailable', reason: 'service-handshake-timeout' }])
})
