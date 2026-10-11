// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { EventEmitter } from 'node:events'

import { SPTI_DIAGNOSTIC_PREFIX, SptiDiagnosticLog, parseSptiDiagnostic } from '../src/main/spti-diagnostics.mjs'
import { DEVICE_SERVICE_ARGUMENTS, createChildProcessTransportFactory } from '../src/main/device-service-transport.mjs'

/** @param {object} overrides - Synthetic envelope fields. @returns {string} Header-only fixture. */
function line(overrides = {}) {
    return SPTI_DIAGNOSTIC_PREFIX + JSON.stringify({ v: 1, seq: 1, phase: 'submit', frame: '12000000FE00', dir: 1, requested: 254, completed: null, status: null, sense: null, reported: 0, copied: 0, returned: null, host: 'pending', ...overrides })
}

/** @param {object} overrides - Synthetic result fields. @returns {string} Completed read fixture. */
function complete(overrides = {}) {
    return line({ phase: 'complete', host: 'device', returned: 308, completed: 254, status: 0, ...overrides })
}

/** @returns {object} Side-effect-free child with stderr events, no hardware or subprocess. */
function child() {
    const result = new EventEmitter()
    result.stdin = new EventEmitter()
    result.stdin.writable = true
    result.stdout = new EventEmitter()
    result.stderr = new EventEmitter()
    /** @returns {void} No real pipe needs draining. */
    result.stderr.resume = () => {}
    return result
}

test('diagnostics admit only exact bounded metadata and safe header families', () => {
    assert.equal(parseSptiDiagnostic(line()).frame, '12000000FE00')
    for (const frame of ['12018300FE00', '4D00C00000000000FE00', '5A00C00000000000FE00', '12000000FE00000000000000']) assert.ok(parseSptiDiagnostic(line({ frame })))
    assert.ok(parseSptiDiagnostic(line({ frame: '3B040000100000029E00', dir: 0, requested: 670 })))
    assert.ok(parseSptiDiagnostic(line({ frame: '3B050000000000000000', dir: 2, requested: 0 })))
    for (const overrides of [{ payload: 'secret' }, { frame: 'B50000000000000000000000' }, { frame: '3B040100000000100000', dir: 0, requested: 4096 }, { frame: '12000000FE0001' }, { frame: '12000000fe00' }, { seq: 0 }, { seq: 257 }, { dir: 3 }, { requested: 4097 }, { completed: 1 }, { status: 0 }, { host: 'device' }, { copied: 1 }, { v: 2 }]) assert.equal(parseSptiDiagnostic(line(overrides)), null, JSON.stringify(overrides))
    for (const invalid of [null, 1, 'junk', SPTI_DIAGNOSTIC_PREFIX + '{}', SPTI_DIAGNOSTIC_PREFIX + 'x'.repeat(513)]) assert.equal(parseSptiDiagnostic(invalid), null)
})

test('completion decoding requires consistent bounds and closed sense fields', () => {
    const sense = { format: 112, code: 5, asc: 36, ascq: 0, field: { inHeader: true, offset: 7, bit: 3 } }
    assert.ok(parseSptiDiagnostic(complete({ status: 2, sense, reported: 18, copied: 18 })))
    assert.ok(parseSptiDiagnostic(complete({ completed: 0xffffffff })))
    assert.ok(parseSptiDiagnostic(complete({ host: 'io-error', completed: null, status: null })))
    for (const overrides of [{ sense }, { status: 2, sense, reported: 18, copied: 17 }, { copied: 14, reported: 13 }, { returned: -1 }, { completed: 2 ** 32 }, { status: 256 }, { host: 'anything' }, { reported: 253 }, { status: 2, sense: { ...sense, payload: 'secret' }, reported: 18, copied: 18 }, { status: 2, sense: { ...sense, format: 114 }, reported: 18, copied: 18 }]) assert.equal(parseSptiDiagnostic(complete(overrides)), null)
})

test('logger correlates each completion with one immutable submitted header and generation', async () => {
    const records = []
    const log = new SptiDiagnosticLog({
        logger: {
            /** @param {object} value - Safe record. @returns {Promise<void>} Retains synthetic evidence. */
            async write(value) {
                records.push(value)
            },
            /** @returns {Promise<void>} No filesystem is used. */
            async close() {}
        }
    })
    assert.equal(await log.record(complete(), 1), false)
    assert.equal(await log.record(line(), 0), false)
    assert.equal(await log.record(line(), 5), false)
    assert.equal(await log.record(line(), 1), true)
    assert.equal(await log.record(line(), 1), false)
    assert.equal(await log.record(complete({ frame: '12018300FE00' }), 1), false)
    assert.equal(await log.record(complete(), 2), false)
    assert.equal(await log.record(complete(), 1), true)
    assert.equal(await log.record(complete(), 1), false)
    assert.equal(await log.record(line(), 2), true)
    assert.equal(records.length, 3)
    await log.close()
    assert.equal(await log.record(complete(), 2), false)
})

test('optional logging I/O failure disables capture without throwing', async () => {
    for (const throws of [true, false]) {
        let calls = 0
        const log = new SptiDiagnosticLog({
            logger: {
                /** @returns {Promise<object>} Simulates a private-storage failure. */
                async write() {
                    calls++
                    if (throws) throw new Error('private')
                    return false
                },
                /** @returns {Promise<void>} Simulates a close failure. */
                async close() {
                    throw new Error('private')
                }
            }
        })
        assert.equal(await log.record(line(), 1), false)
        assert.equal(await log.record(line({ seq: 2 }), 1), false)
        assert.equal(calls, 1)
        await log.close()
    }
})

test('session capture has a hard four-generation, 2048-record budget', async () => {
    let count = 0
    const log = new SptiDiagnosticLog({
        logger: {
            /** @returns {Promise<boolean>} Counts accepted fixture records. */
            async write() {
                count++
                return true
            },
            /** @returns {Promise<void>} No file is open. */
            async close() {}
        }
    })
    for (let generation = 1; generation <= 4; generation++) {
        for (let seq = 1; seq <= 256; seq++) {
            assert.equal(await log.record(line({ seq }), generation), true)
            assert.equal(await log.record(complete({ seq }), generation), true)
        }
    }
    assert.equal(count, 2048)
    assert.equal(await log.record(line(), 5), false)
    await log.close()
})

test('EventLogger preserves approved metadata without weakening its payload redaction', async () => {
    const lines = []
    const log = new SptiDiagnosticLog({
        directory: '/synthetic/spti',
        platform: 'linux',
        fileSecurity: {
            /** @returns {Promise<void>} No disk access. */
            async prepareDirectory() {},
            /** @returns {Promise<object>} In-memory private append handle. */
            async openAppend() {
                return {
                    /** @returns {Promise<object>} Empty fixture size. */
                    async stat() {
                        return { size: 0 }
                    },
                    /** @param {string} value - Serialized record. @returns {Promise<void>} Retains only output. */
                    async writeFile(value) {
                        lines.push(value)
                    },
                    /** @returns {Promise<void>} No disk handle. */
                    async close() {}
                }
            }
        }
    })
    assert.equal(await log.record(line(), 1), true)
    await log.close()
    assert.equal(lines.length, 1)
    assert.equal(JSON.parse(lines[0]).details.frame, '12000000FE00')
    assert.equal(JSON.parse(lines[0]).details.requested, 254)
})

test('transport defaults off, filters split/oversized records and confines the opt-in environment', async () => {
    for (const enabled of [false, true]) {
        const fake = child()
        const observed = []
        let environment
        const factory = createChildProcessTransportFactory({
            platform: 'win32',
            sptiDiagnostics: enabled,
            /** @param {string} value - Approved record. @param {number} generation - Child generation. @returns {Promise<void>} Records fixture. */
            async onSptiDiagnostic(value, generation) {
                observed.push({ value, generation })
            },
            /** @param {string} command - Test executable. @param {string[]} args - Fixed arguments. @param {object} options - Fixed environment. @returns {object} Fake child. */
            spawnProcess(command, args, options) {
                environment = options.env
                return fake
            }
        })
        factory({ command: process.platform === 'win32' ? 'C:\\test\\service.exe' : '/test/service', args: DEVICE_SERVICE_ARGUMENTS })
        const valid = line() + '\n'
        fake.stderr.emit('data', Buffer.from(valid.slice(0, 20)))
        fake.stderr.emit('data', Buffer.from(valid.slice(20)))
        fake.stderr.emit('data', Buffer.from('x'.repeat(2049)))
        fake.stderr.emit('data', Buffer.from(valid))
        fake.stderr.emit('data', Buffer.from(line({ payload: 'private' }) + '\n' + valid))
        assert.equal(observed.length, enabled ? 2 : 0)
        assert.equal(environment.OPENRDX_SPTI_DIAGNOSTICS, enabled ? '1' : undefined)
        if (enabled) assert.equal(observed[0].generation, 1)
    }
    assert.throws(() => createChildProcessTransportFactory({ sptiDiagnostics: true, platform: 'linux' }), /service-spti-options-invalid/)
    assert.throws(() => createChildProcessTransportFactory({ sptiDiagnostics: true, platform: 'win32' }), /service-spti-options-invalid/)
})
