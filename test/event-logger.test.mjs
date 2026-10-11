// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { lstat, mkdir, mkdtemp, open, readFile, rename, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import { EventLogger } from '../src/main/event-logger.mjs'
import { WindowsLogSecurityAdapter } from '../src/main/windows-log-security-adapter.mjs'
import { ownWindowsFixture } from './helpers/windows-fixture-owner.mjs'

/** Uses the production native Windows boundary for real filesystem tests.
 * @param {object} options - Isolated logger settings.
 * @returns {EventLogger} Logger with actual host-private storage, not synthetic ACL proof.
 */
function createHostLogger(options) {
    const windowsSecurityAdapter = process.platform === 'win32' ? new WindowsLogSecurityAdapter({ directory: options.directory, addonPath: fileURLToPath(new URL('../out/native/windows/openrdx-windows-client.node', import.meta.url)) }) : undefined
    return new EventLogger({ ...options, windowsSecurityAdapter })
}

/**
 * Creates one isolated EventLogger directory.
 * @returns {Promise<string>} Absolute temporary directory.
 */
async function createLogDirectory() {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-event-logger-'))
    await ownWindowsFixture(directory)
    return directory
}

/**
 * Removes one known isolated test directory.
 * @param {string} directory - Exact temporary directory created by this suite.
 * @returns {Promise<void>} Resolves after recursive test cleanup.
 */
async function removeLogDirectory(directory) {
    await rm(directory, { force: true, recursive: true })
}

/**
 * Creates a deterministic in-memory file boundary whose first append pauses.
 * @returns {{fileSecurity: object, entered: Promise<void>, release: () => void, lines: string[]}} Controlled logger boundary.
 */
function createBlockingFileSecurity() {
    const lines = []
    let enter
    let release
    let firstWrite = true
    const entered = new Promise((resolve) => {
        enter = resolve
    })
    const gate = new Promise((resolve) => {
        release = resolve
    })
    return {
        lines,
        entered,
        release,
        fileSecurity: {
            /** @returns {Promise<void>} Completes without touching a host directory. */
            async prepareDirectory() {},
            /** @returns {Promise<object>} Returns one controlled append handle. */
            async openAppend() {
                return {
                    /** @returns {Promise<{size: number}>} Reports current in-memory bytes. */
                    async stat() {
                        return { size: Buffer.byteLength(lines.join(''), 'utf8') }
                    },
                    /** @param {string} line - Sanitized JSONL line. @returns {Promise<void>} Appends after the controlled first-write gate. */
                    async writeFile(line) {
                        if (firstWrite) {
                            firstWrite = false
                            enter()
                            await gate
                        }
                        lines.push(line)
                    },
                    /** @returns {Promise<void>} Closes the synthetic handle. */
                    async close() {}
                }
            },
            /** @returns {Promise<void>} Removes no synthetic backup. */
            async removeFile() {},
            /** @returns {Promise<void>} Renames no synthetic current file. */
            async renameFile() {}
        }
    }
}

/**
 * Creates a deterministic timeout queue controlled directly by the test.
 * @returns {{timers: {setTimeout: Function, clearTimeout: Function}, fireNext: () => void, pendingCount: () => number}} Manual timers.
 */
function createManualTimers() {
    let nextId = 1
    const callbacks = new Map()
    return {
        timers: {
            /** @param {Function} callback - Timeout callback. @returns {number} Manual timer ID. */
            setTimeout(callback) {
                const id = nextId
                nextId += 1
                callbacks.set(id, callback)
                return id
            },
            /** @param {number} id - Manual timer ID. @returns {void} Clears it. */
            clearTimeout(id) {
                callbacks.delete(id)
            }
        },
        /** @returns {void} Fires the oldest pending timeout exactly once. */
        fireNext() {
            const next = callbacks.entries().next().value
            assert.notEqual(next, undefined)
            const [id, callback] = next
            callbacks.delete(id)
            callback()
        },
        /** @returns {number} Number of pending manual timeouts. */
        pendingCount() {
            return callbacks.size
        }
    }
}

/**
 * Creates one append boundary whose write settles only when directed by the test.
 * @returns {{fileSecurity: object, entered: Promise<void>, resolve: () => void, reject: () => void, openCount: () => number}} Controlled persistence.
 */
function createHangingFileSecurity() {
    let enter
    let resolveWrite
    let rejectWrite
    let opens = 0
    const entered = new Promise((resolve) => {
        enter = resolve
    })
    const write = new Promise((resolve, reject) => {
        resolveWrite = resolve
        rejectWrite = reject
    })
    return {
        entered,
        /** @returns {void} Resolves the detached write late. */
        resolve() {
            resolveWrite()
        },
        /** @returns {void} Rejects the detached write late. */
        reject() {
            rejectWrite(new Error('controlled-late-write-failure'))
        },
        /** @returns {number} Number of append handles opened. */
        openCount() {
            return opens
        },
        fileSecurity: {
            /** @returns {Promise<void>} Prepares no host directory. */
            async prepareDirectory() {},
            /** @returns {Promise<object>} Returns the one hanging append handle. */
            async openAppend() {
                opens += 1
                return {
                    /** @returns {Promise<{size: number}>} Reports an empty current file. */
                    async stat() {
                        return { size: 0 }
                    },
                    /** @returns {Promise<void>} Enters and then follows the controlled late result. */
                    async writeFile() {
                        enter()
                        return write
                    },
                    /** @returns {Promise<void>} Closes without host work. */
                    async close() {}
                }
            },
            /** @returns {Promise<void>} Removes no backup. */
            async removeFile() {},
            /** @returns {Promise<void>} Renames no current file. */
            async renameFile() {}
        }
    }
}

test('reserves count and byte capacity for priority records and reports priority saturation', async () => {
    assert.throws(() => new EventLogger({ directory: '/controlled/logger', maxPendingEntries: 1 }), /maxPendingEntries/)
    assert.throws(() => new EventLogger({ directory: '/controlled/logger', maxBytes: 512, maxPendingBytes: 1023 }), /maxPendingBytes/)

    const blockedProgress = createBlockingFileSecurity()
    const progressLogger = new EventLogger({
        directory: '/controlled/logger',
        fileSecurity: blockedProgress.fileSecurity,
        maxBytes: 4096,
        maxPendingBytes: 8192,
        maxPendingEntries: 3
    })
    const activeProgress = progressLogger.write({ event: 'operation-lifecycle', messageKey: 'activity.operation', operationId: 'op:active', state: 'progress', progress: 0.1 })
    await blockedProgress.entered
    const queuedProgress = progressLogger.write({ event: 'operation-lifecycle', messageKey: 'activity.operation', operationId: 'op:queued', state: 'progress', progress: 0.2 })
    const terminal = progressLogger.write({ event: 'operation-lifecycle', messageKey: 'activity.operation', operationId: 'op:active', state: 'failed', stage: 'diagnostic-cleanup' })
    blockedProgress.release()
    assert.deepEqual(await Promise.all([activeProgress, queuedProgress, terminal]), [true, true, true])
    assert.deepEqual(await progressLogger.close(), { ok: true })

    const blockedPriority = createBlockingFileSecurity()
    const failures = []
    const priorityLogger = new EventLogger({
        directory: '/controlled/logger',
        fileSecurity: blockedPriority.fileSecurity,
        maxBytes: 512,
        maxPendingBytes: 1024,
        maxPendingEntries: 2,
        onFailure(reason) {
            failures.push(reason)
        }
    })
    const activeAudit = priorityLogger.write({ event: 'audit-record', messageKey: 'activity.audit', sequence: 1 })
    await blockedPriority.entered
    const queuedError = priorityLogger.write({ event: 'service-lifecycle', messageKey: 'activity.service', severity: 'error', status: 'unavailable' })
    assert.equal(await priorityLogger.write({ event: 'operation-lifecycle', messageKey: 'activity.operation', operationId: 'op:lost-terminal', state: 'failed', stage: 'diagnostic-cleanup' }), false)
    assert.deepEqual(failures, ['event-log-priority-overflow'])
    assert.equal(await priorityLogger.write({ event: 'audit-after-loss', messageKey: 'activity.audit' }), false)
    blockedPriority.release()
    assert.deepEqual(await Promise.all([activeAudit, queuedError]), [true, true])
    assert.deepEqual(await priorityLogger.flush(), { ok: false, reason: 'event-log-priority-overflow' })
    assert.deepEqual(await priorityLogger.close(), { ok: false, reason: 'event-log-priority-overflow' })
})

test('diagnostic bursts retain the latest breadcrumb without starving ordered audit records', async () => {
    const blocked = createBlockingFileSecurity()
    const failures = []
    const logger = new EventLogger({
        directory: '/controlled/logger',
        fileSecurity: blocked.fileSecurity,
        maxBytes: 4096,
        maxPendingBytes: 8192,
        maxPendingEntries: 5,
        onFailure: (reason) => failures.push(reason)
    })
    const first = logger.writeCritical({ event: 'audit-start', messageKey: 'activity.audit' })
    await blocked.entered
    const writes = []
    for (let index = 0; index < 1024; index += 1) {
        writes.push(logger.write({ event: 'service-diagnostic', messageKey: 'activity.service', severity: 'info', nativeDiagnostic: index % 2 === 0 ? 'scsi-worker-native-enter' : 'scsi-worker-native-return' }))
    }
    const audit = logger.writeCritical({ event: 'audit-middle', messageKey: 'activity.audit' })
    const last = logger.write({ event: 'service-diagnostic', messageKey: 'activity.service', severity: 'info', nativeDiagnostic: 'scsi-worker-response-read-return' })
    blocked.release()
    try {
        assert.deepEqual(failures, [])
        assert.equal(await first, true)
        assert.equal(await audit, true)
        assert.equal(await last, true)
        assert.ok((await Promise.all(writes)).every(Boolean))
        assert.deepEqual(await logger.flush(), { ok: true })
        assert.deepEqual(
            blocked.lines.map((line) => {
                const record = JSON.parse(line)
                return record.details.nativeDiagnostic ?? record.event
            }),
            ['audit-start', 'scsi-worker-native-return', 'audit-middle', 'scsi-worker-response-read-return']
        )
    } finally {
        await logger.close()
    }
})

test('diagnostic warnings, errors and explicit audits are preserved between info breadcrumbs', async () => {
    const blocked = createBlockingFileSecurity()
    const logger = new EventLogger({ directory: '/controlled/logger', fileSecurity: blocked.fileSecurity })
    const writes = [logger.writeCritical({ event: 'audit-start', messageKey: 'activity.audit' })]
    await blocked.entered
    const diagnostic = { event: 'service-diagnostic', messageKey: 'activity.service' }
    for (const severity of ['warning', 'error', 'info']) {
        writes.push(logger.write({ ...diagnostic, severity: 'info', nativeDiagnostic: 'scsi-worker-native-enter' }))
        const record = { ...diagnostic, severity, nativeDiagnostic: 'scsi-worker-native-return' }
        writes.push(severity === 'info' ? logger.writeCritical(record) : logger.write(record))
        writes.push(logger.write({ ...diagnostic, severity: 'info', nativeDiagnostic: 'scsi-worker-response-read-return' }))
        writes.push(logger.writeCritical({ event: 'audit-end', messageKey: 'activity.audit' }))
    }
    blocked.release()
    try {
        assert.ok((await Promise.all(writes)).every(Boolean))
        assert.deepEqual(
            blocked.lines.map((line) => JSON.parse(line).severity),
            ['info', 'info', 'warning', 'info', 'info', 'info', 'error', 'info', 'info', 'info', 'info', 'info', 'info']
        )
    } finally {
        await logger.close()
    }
})

test('coalesces progress only at the contiguous queue tail without crossing audit order', async () => {
    const blocked = createBlockingFileSecurity()
    const logger = new EventLogger({
        directory: '/controlled/logger',
        fileSecurity: blocked.fileSecurity,
        maxBytes: 4096,
        maxPendingBytes: 8192,
        maxPendingEntries: 5
    })
    const writes = [logger.write({ event: 'audit-start', messageKey: 'activity.audit', sequence: 0 })]
    await blocked.entered
    writes.push(logger.write({ event: 'operation-lifecycle', messageKey: 'activity.operation', operationId: 'op:ordered', state: 'progress', progress: 0.1, sequence: 1 }))
    writes.push(logger.write({ event: 'audit-middle', messageKey: 'activity.audit', sequence: 2 }))
    writes.push(logger.write({ event: 'operation-lifecycle', messageKey: 'activity.operation', operationId: 'op:ordered', state: 'progress', progress: 0.3, sequence: 3 }))

    blocked.release()
    assert.deepEqual(await Promise.all(writes), [true, true, true, true])
    assert.deepEqual(await logger.close(), { ok: true })
    const records = blocked.lines.map((line) => JSON.parse(line))
    assert.deepEqual(
        records.map((record) => [record.event, record.details.sequence]),
        [
            ['audit-start', 0],
            ['operation-lifecycle', 1],
            ['audit-middle', 2],
            ['operation-lifecycle', 3]
        ]
    )
})

test('bounds a hanging persistence, closes with a typed timeout, and contains late settlement', async () => {
    for (const lateOutcome of ['resolve', 'reject']) {
        const hanging = createHangingFileSecurity()
        const manual = createManualTimers()
        const failures = []
        const logger = new EventLogger({
            directory: '/controlled/logger',
            fileSecurity: hanging.fileSecurity,
            maxBytes: 512,
            maxPendingBytes: 1024,
            maxPendingEntries: 2,
            onFailure(reason) {
                failures.push(reason)
            },
            persistenceTimeoutMs: 100,
            timers: manual.timers
        })
        const active = logger.write({ event: 'audit-record', messageKey: 'activity.audit', sequence: 1 })
        await hanging.entered
        const queued = logger.write({ event: 'service-lifecycle', messageKey: 'activity.service', severity: 'error', status: 'unavailable' })
        const firstClose = logger.close()
        assert.equal(logger.close(), firstClose)
        assert.equal(manual.pendingCount(), 1)
        manual.fireNext()

        assert.deepEqual(await Promise.all([active, queued]), [false, false], lateOutcome)
        assert.deepEqual(await firstClose, { ok: false, reason: 'event-log-persistence-timeout' }, lateOutcome)
        assert.deepEqual(failures, ['event-log-persistence-timeout'], lateOutcome)
        assert.equal(hanging.openCount(), 1, lateOutcome)
        assert.equal(await logger.write({ event: 'late-record', messageKey: 'activity.late' }), false, lateOutcome)

        hanging[lateOutcome]()
        await new Promise(setImmediate)
        assert.deepEqual(await logger.close(), { ok: false, reason: 'event-log-persistence-timeout' }, lateOutcome)
        assert.deepEqual(failures, ['event-log-persistence-timeout'], lateOutcome)
    }
})

test('coalesces a blocked operation-progress flood within count and byte bounds while preserving priority order', async () => {
    const blocked = createBlockingFileSecurity()
    let nextId = 1
    const logger = new EventLogger({
        directory: '/controlled/logger',
        fileSecurity: blocked.fileSecurity,
        idFactory: createId,
        maxBytes: 4096,
        maxPendingBytes: 8192,
        maxPendingEntries: 5,
        now: createTime
    })
    const writes = [logger.write(progressEvent(0))]
    await blocked.entered
    for (let index = 1; index <= 2000; index += 1) {
        writes.push(logger.write(progressEvent(index)))
    }
    writes.push(logger.write({ event: 'operation-lifecycle', messageKey: 'activity.operation', operationId: 'op:flood', state: 'succeeded', stage: 'complete' }), logger.write({ event: 'service-lifecycle', messageKey: 'activity.service', severity: 'error', status: 'unavailable' }), logger.write({ event: 'audit-record', messageKey: 'activity.audit', sequence: 1 }))

    blocked.release()
    assert.equal((await Promise.all(writes)).every(Boolean), true)
    await logger.close()

    const records = blocked.lines.map((line) => JSON.parse(line))
    assert.equal(records.length <= 5, true)
    assert.deepEqual(
        records.slice(-3).map((record) => record.event),
        ['operation-lifecycle', 'service-lifecycle', 'audit-record']
    )
    assert.equal(records.filter((record) => record.details.state === 'progress').length <= 2, true)
    assert.equal(
        records.some((record) => record.details.sequence === 2000),
        true
    )
    assert.doesNotMatch(blocked.lines.join(''), /flood-secret/)

    /** @param {number} sequence - Progress sequence. @returns {object} One coalescible lifecycle event. */
    function progressEvent(sequence) {
        return { event: 'operation-lifecycle', messageKey: 'activity.operation', operationId: 'op:flood', state: 'progress', stage: 'firmware-writing', sequence, payload: 'flood-secret' }
    }

    /** @returns {string} Deterministic activity identifier. */
    function createId() {
        const id = `activity:flood-${nextId}`
        nextId += 1
        return id
    }

    /** @returns {Date} Deterministic log timestamp. */
    function createTime() {
        return new Date('2026-08-27T08:00:00.000Z')
    }
})

test('close is idempotent, drains accepted work once, and rejects later writes', async () => {
    const blocked = createBlockingFileSecurity()
    const logger = new EventLogger({ directory: '/controlled/logger', fileSecurity: blocked.fileSecurity })
    const write = logger.write({ event: 'audit-record', messageKey: 'activity.audit' })
    await blocked.entered

    const firstClose = logger.close()
    const secondClose = logger.close()
    assert.equal(firstClose, secondClose)
    assert.equal(await logger.write({ event: 'late-record', messageKey: 'activity.late' }), false)
    blocked.release()
    await firstClose

    assert.equal(await write, true)
    assert.equal(blocked.lines.length, 1)
})

test('redacts secret, command, path, and payload fields before persistence', async () => {
    const directory = await createLogDirectory()
    try {
        const logger = createHostLogger({ directory, idFactory: createId, now: createTime })
        await logger.write({
            event: 'authenticate',
            deviceId: 'rdx:1',
            messageKey: 'activity.authenticate',
            password: 'never-log-me',
            rawCdb: [0x1d, 0x04],
            osPath: '/dev/rdx-private',
            data: [83, 69, 67, 82, 69, 84],
            diagnostic: 'failure:path=/dev/rdx-embedded-private',
            nested: { authorizationToken: 'token-secret', firmwareBytes: [1, 2, 3], note: 'safe-note' }
        })

        const log = await readFile(join(directory, 'RDXManager.jsonl'), 'utf8')
        assert.doesNotMatch(log, /never-log-me|token-secret|rdx-private|rdx-embedded-private|0x1d|firmwareBytes|83,69,67,82,69,84/)
        assert.match(log, /\[REDACTED\]/)
        assert.match(log, /safe-note/)
        assert.doesNotThrow(() => JSON.parse(log.trim()))
    } finally {
        await removeLogDirectory(directory)
    }

    /** @returns {string} Deterministic activity identifier. */
    function createId() {
        return 'activity:1'
    }

    /** @returns {Date} Deterministic log timestamp. */
    function createTime() {
        return new Date('2026-08-25T12:00:00.000Z')
    }
})

test('rotates sanitized JSONL deterministically to _RDXManager.bak', async () => {
    const directory = await createLogDirectory()
    let nextId = 1
    try {
        const logger = createHostLogger({ directory, idFactory: createId, maxBytes: 260, now: createTime })
        await logger.write({ event: 'first', messageKey: 'activity.first', password: 'first-secret', detail: 'a'.repeat(80) })
        await logger.write({ event: 'second', messageKey: 'activity.second', password: 'second-secret', detail: 'b'.repeat(80) })

        const [current, backup] = await Promise.all([readFile(join(directory, 'RDXManager.jsonl'), 'utf8'), readFile(join(directory, '_RDXManager.bak'), 'utf8')])
        assert.match(current, /activity\.second/)
        assert.match(backup, /activity\.first/)
        assert.doesNotMatch(current + backup, /first-secret|second-secret/)
        assert.doesNotThrow(() => JSON.parse(current.trim()))
        assert.doesNotThrow(() => JSON.parse(backup.trim()))
    } finally {
        await removeLogDirectory(directory)
    }

    /** @returns {string} Deterministic incrementing activity identifier. */
    function createId() {
        const id = `activity:${nextId}`
        nextId += 1
        return id
    }

    /** @returns {Date} Deterministic log timestamp. */
    function createTime() {
        return new Date('2026-08-25T12:00:00.000Z')
    }
})

test('serializes concurrent writes as complete JSON lines and returns bounded activity entries', async () => {
    const directory = await createLogDirectory()
    let nextId = 1
    try {
        const logger = createHostLogger({ directory, idFactory: createId, maxBytes: 100_000, now: createTime })
        const writes = []
        for (let index = 0; index < 20; index += 1) {
            writes.push(logger.write({ event: 'operation', messageKey: 'activity.operation', severity: index === 19 ? 'warning' : 'info', supportCorrelationId: `support:${index}` }))
        }
        await Promise.all(writes)

        const lines = (await readFile(join(directory, 'RDXManager.jsonl'), 'utf8')).trim().split('\n')
        const parsed = lines.map(parseJsonLine)
        const listed = await logger.list()

        assert.equal(parsed.length, 20)
        assert.equal(listed.ok, true)
        assert.equal(listed.entries.length, 20)
        assert.deepEqual(listed.entries.at(-1), {
            id: 'activity:20',
            occurredAt: '2026-08-25T12:00:00.000Z',
            severity: 'warning',
            messageKey: 'activity.operation',
            supportCorrelationId: 'support:19'
        })
    } finally {
        await removeLogDirectory(directory)
    }

    /**
     * Parses one independently persisted JSON line.
     * @param {string} line - One JSONL record.
     * @returns {object} Parsed record.
     */
    function parseJsonLine(line) {
        return JSON.parse(line)
    }

    /** @returns {string} Deterministic incrementing activity identifier. */
    function createId() {
        const id = `activity:${nextId}`
        nextId += 1
        return id
    }

    /** @returns {Date} Deterministic log timestamp. */
    function createTime() {
        return new Date('2026-08-25T12:00:00.000Z')
    }
})

test('disabled optional logging suppresses activity but durably audits its setting', async () => {
    const directory = await createLogDirectory()
    try {
        const logger = createHostLogger({ directory, enabled: false })

        assert.deepEqual(await logger.setEnabled({ enabled: false }), { ok: true })
        assert.equal(await logger.write({ event: 'ignored', password: 'never-persist' }), false)
        const listing = await logger.list()
        assert.equal(listing.ok, true)
        assert.equal(listing.entries.length, 1)
        const persisted = JSON.parse(await readFile(join(directory, 'RDXManager.jsonl'), 'utf8'))
        assert.equal(persisted.event, 'logging-setting')
        assert.equal(persisted.details.enabled, false)
        assert.equal(JSON.stringify(persisted).includes('never-persist'), false)
    } finally {
        await removeLogDirectory(directory)
    }
})

test('redaction never invokes event accessors before persistence', async () => {
    const directory = await createLogDirectory()
    let accessorCalls = 0
    try {
        const logger = createHostLogger({ directory })
        const event = {}
        for (const key of ['event', 'messageKey', 'severity', 'supportCorrelationId', 'password']) {
            Object.defineProperty(event, key, {
                enumerable: true,
                /**
                 * Fails if logger redaction evaluates an untrusted accessor.
                 * @throws {Error} Always throws the controlled accessor failure.
                 */
                get() {
                    accessorCalls += 1
                    throw new Error('controlled secret accessor')
                }
            })
        }

        assert.equal(await logger.write(event), true)
        assert.equal(accessorCalls, 0)
        const log = await readFile(join(directory, 'RDXManager.jsonl'), 'utf8')
        assert.doesNotMatch(log, /controlled secret accessor/)
        assert.match(log, /\[REDACTED\]/)
    } finally {
        await removeLogDirectory(directory)
    }
})

test('bounds a single sanitized entry to the configured rotation size', async () => {
    const directory = await createLogDirectory()
    try {
        const logger = createHostLogger({ directory, idFactory: createId, maxBytes: 260, now: createTime })
        assert.equal(await logger.write({ event: 'bounded', messageKey: 'activity.bounded', detail: 'x'.repeat(10_000) }), true)
        await logger.flush()

        const metadata = await stat(join(directory, 'RDXManager.jsonl'))
        assert.equal(metadata.size <= 260, true)
    } finally {
        await removeLogDirectory(directory)
    }

    /** @returns {string} Deterministic short activity identifier. */
    function createId() {
        return 'activity:bounded'
    }

    /** @returns {Date} Deterministic log timestamp. */
    function createTime() {
        return new Date('2026-08-25T12:00:00.000Z')
    }
})

test('enforces private modes and refuses symlinked logger-owned files', { skip: process.platform === 'win32' ? 'POSIX mode contract; Windows ACL/reparse checks run in windows-log-security-native.test.mjs' : false }, async () => {
    const directory = await createLogDirectory()
    const outside = join(directory, '..', `openrdx-sensitive-${process.pid}.txt`)
    try {
        await writeFile(outside, 'must-remain-unchanged', { mode: 0o644 })
        await symlink(outside, join(directory, 'RDXManager.jsonl'))
        const logger = new EventLogger({ directory })

        assert.equal(await logger.write({ event: 'blocked', messageKey: 'activity.blocked' }), false)
        assert.equal(await readFile(outside, 'utf8'), 'must-remain-unchanged')
        assert.deepEqual(await logger.list(), { ok: true, entries: [] })
        assert.equal((await stat(directory)).mode & 0o777, 0o700)

        await rm(join(directory, 'RDXManager.jsonl'))
        assert.equal(await logger.write({ event: 'private', messageKey: 'activity.private' }), true)
        assert.equal((await stat(join(directory, 'RDXManager.jsonl'))).mode & 0o777, 0o600)
    } finally {
        await rm(outside, { force: true })
        await removeLogDirectory(directory)
    }
})

test('hardens an existing backup during list and never follows a backup symlink', { skip: process.platform === 'win32' ? 'POSIX mode contract; Windows ACL/reparse checks run in windows-log-security-native.test.mjs' : false }, async () => {
    const directory = await createLogDirectory()
    const outside = join(directory, '..', `openrdx-backup-sensitive-${process.pid}.txt`)
    try {
        await writeFile(outside, '{"id":"activity:outside"}\n', { mode: 0o644 })
        await symlink(outside, join(directory, '_RDXManager.bak'))
        const logger = new EventLogger({ directory })

        assert.deepEqual(await logger.list(), { ok: true, entries: [] })
        assert.equal(await readFile(outside, 'utf8'), '{"id":"activity:outside"}\n')

        await rm(join(directory, '_RDXManager.bak'))
        await writeFile(join(directory, '_RDXManager.bak'), '', { mode: 0o666 })
        await logger.list()
        assert.equal((await stat(join(directory, '_RDXManager.bak'))).mode & 0o777, 0o600)
    } finally {
        await rm(outside, { force: true })
        await removeLogDirectory(directory)
    }
})

test('fails closed on Windows when native handle and DACL verification are unavailable', async () => {
    const directory = await createLogDirectory()
    try {
        const logger = new EventLogger({ directory, platform: 'win32' })

        assert.equal(await logger.write({ event: 'blocked', messageKey: 'activity.blocked' }), false)
        assert.deepEqual(await logger.list(), { ok: true, entries: [] })
        await assert.rejects(() => readFile(join(directory, 'RDXManager.jsonl'), 'utf8'), /ENOENT/)
    } finally {
        await removeLogDirectory(directory)
    }
})

test('requires injected Windows reparse, no-follow handle, and user-only DACL proof', async () => {
    const directory = await createLogDirectory()
    const calls = []
    let nextId = 1
    try {
        const windowsSecurityAdapter = {
            /** @param {object} request - Directory proof request. @returns {Promise<object>} Controlled secure directory proof. */
            async ensurePrivateDirectory(request) {
                calls.push({ method: 'directory', request })
                await mkdir(request.path, { recursive: true })
                return { directory: true, reparsePoint: false, userOnlyDacl: true }
            },
            /** @param {object} request - Verified file-open request. @returns {Promise<object>} Controlled verified handle proof. */
            async openVerifiedFile(request) {
                calls.push({ method: 'open', request: { ...request } })
                const handle = await open(request.path, request.access === 'append' ? 'a+' : 'r')
                return { handle, noFollowVerified: true, reparsePoint: false, userOnlyDacl: true }
            },
            /** @param {object} request - Verified removal request. @returns {Promise<object>} Controlled removal proof. */
            async removeVerifiedFile(request) {
                calls.push({ method: 'remove', request })
                try {
                    const metadata = await lstat(request.path)
                    if (!metadata.isFile() || metadata.isSymbolicLink()) return { removed: false, reparsePoint: metadata.isSymbolicLink(), userOnlyDacl: false }
                    await rm(request.path)
                } catch (error) {
                    if (error?.code !== 'ENOENT') throw error
                }
                return { removed: true, reparsePoint: false, userOnlyDacl: true }
            },
            /** @param {object} request - Verified rename request. @returns {Promise<object>} Controlled rename proof. */
            async renameVerifiedFile(request) {
                calls.push({ method: 'rename', request })
                await rename(request.from, request.to)
                return { noFollowVerified: true, reparsePoint: false, userOnlyDacl: true }
            }
        }
        const logger = new EventLogger({ directory, idFactory: createId, maxBytes: 260, now: createTime, platform: 'win32', windowsSecurityAdapter })

        assert.equal(await logger.write({ event: 'windows-first', messageKey: 'activity.windows', detail: 'a'.repeat(80) }), true)
        assert.equal(await logger.write({ event: 'windows-second', messageKey: 'activity.windows', detail: 'b'.repeat(80) }), true)
        assert.equal((await logger.list()).entries.length, 2)
        assert.equal(
            calls.some((call) => call.method === 'directory' && call.request.requireReparseRejection === true && call.request.requireUserOnlyDacl === true),
            true
        )
        assert.equal(
            calls.some((call) => call.method === 'open' && call.request.requireNoFollowHandle === true && call.request.requireUserOnlyDacl === true),
            true
        )
        assert.equal(
            calls.some((call) => call.method === 'remove' && call.request.requireReparseRejection === true && call.request.requireUserOnlyDacl === true),
            true
        )
        assert.equal(
            calls.some((call) => call.method === 'rename' && call.request.requireNoFollowHandle === true && call.request.requireReparseRejection === true && call.request.requireUserOnlyDacl === true),
            true
        )
    } finally {
        await removeLogDirectory(directory)
    }

    /** @returns {string} Deterministic incrementing activity identity. */
    function createId() {
        const id = `activity:windows-${nextId}`
        nextId += 1
        return id
    }

    /** @returns {Date} Deterministic log timestamp. */
    function createTime() {
        return new Date('2026-08-25T12:00:00.000Z')
    }
})

test('rejects Windows rotation when native rename proof is incomplete', async () => {
    const directory = await createLogDirectory()
    let nextId = 1
    try {
        const windowsSecurityAdapter = {
            /** @param {object} request - Directory proof request. @returns {Promise<object>} Controlled secure directory proof. */
            async ensurePrivateDirectory(request) {
                await mkdir(request.path, { recursive: true })
                return { directory: true, reparsePoint: false, userOnlyDacl: true }
            },
            /** @param {object} request - Verified file-open request. @returns {Promise<object>} Controlled verified handle proof. */
            async openVerifiedFile(request) {
                const handle = await open(request.path, request.access === 'append' ? 'a+' : 'r')
                return { handle, noFollowVerified: true, reparsePoint: false, userOnlyDacl: true }
            },
            /** @param {object} request - Verified removal request. @returns {Promise<object>} Controlled secure absence proof. */
            async removeVerifiedFile(request) {
                try {
                    await rm(request.path)
                } catch (error) {
                    if (error?.code !== 'ENOENT') throw error
                }
                return { removed: true, reparsePoint: false, userOnlyDacl: true }
            },
            /** @returns {Promise<object>} Deliberately incomplete native rename proof. */
            async renameVerifiedFile() {
                return { noFollowVerified: false, reparsePoint: false, userOnlyDacl: true }
            }
        }
        const logger = new EventLogger({ directory, idFactory: createId, maxBytes: 260, now: createTime, platform: 'win32', windowsSecurityAdapter })

        assert.equal(await logger.write({ event: 'windows-first', messageKey: 'activity.windows', detail: 'a'.repeat(80) }), true)
        assert.equal(await logger.write({ event: 'windows-second', messageKey: 'activity.windows', detail: 'b'.repeat(80) }), false)
        assert.match(await readFile(join(directory, 'RDXManager.jsonl'), 'utf8'), /windows-first/)
        await assert.rejects(() => readFile(join(directory, '_RDXManager.bak'), 'utf8'), /ENOENT/)
    } finally {
        await removeLogDirectory(directory)
    }

    /** @returns {string} Deterministic incrementing activity identity. */
    function createId() {
        const id = `activity:windows-incomplete-${nextId}`
        nextId += 1
        return id
    }

    /** @returns {Date} Deterministic log timestamp. */
    function createTime() {
        return new Date('2026-08-25T12:00:00.000Z')
    }
})

test('rejects forced Windows rotation when backup removal proof is incomplete', async () => {
    const directory = await createLogDirectory()
    let nextId = 1
    let renameCalled = false
    try {
        const windowsSecurityAdapter = {
            /** @param {object} request - Directory proof request. @returns {Promise<object>} Controlled secure directory proof. */
            async ensurePrivateDirectory(request) {
                await mkdir(request.path, { recursive: true })
                return { directory: true, reparsePoint: false, userOnlyDacl: true }
            },
            /** @param {object} request - Verified file-open request. @returns {Promise<object>} Controlled verified handle proof. */
            async openVerifiedFile(request) {
                const handle = await open(request.path, request.access === 'append' ? 'a+' : 'r')
                return { handle, noFollowVerified: true, reparsePoint: false, userOnlyDacl: true }
            },
            /** @returns {Promise<object>} Deliberately incomplete native removal proof. */
            async removeVerifiedFile() {
                return { removed: false, reparsePoint: true, userOnlyDacl: false }
            },
            /** @returns {Promise<object>} Records any unsafe continuation into rename. */
            async renameVerifiedFile() {
                renameCalled = true
                return { noFollowVerified: true, reparsePoint: false, userOnlyDacl: true }
            }
        }
        const logger = new EventLogger({ directory, idFactory: createId, maxBytes: 260, now: createTime, platform: 'win32', windowsSecurityAdapter })

        assert.equal(await logger.write({ event: 'windows-first', messageKey: 'activity.windows', detail: 'a'.repeat(80) }), true)
        assert.equal(await logger.write({ event: 'windows-second', messageKey: 'activity.windows', detail: 'b'.repeat(80) }), false)
        assert.equal(renameCalled, false)
        assert.match(await readFile(join(directory, 'RDXManager.jsonl'), 'utf8'), /windows-first/)

        /** @returns {Promise<string>} Attempts to read the backup that rotation must not create. */
        function readMissingBackup() {
            return readFile(join(directory, '_RDXManager.bak'), 'utf8')
        }
        await assert.rejects(readMissingBackup, /ENOENT/)
    } finally {
        await removeLogDirectory(directory)
    }

    /** @returns {string} Deterministic incrementing activity identity. */
    function createId() {
        const id = `activity:windows-remove-incomplete-${nextId}`
        nextId += 1
        return id
    }

    /** @returns {Date} Deterministic log timestamp. */
    function createTime() {
        return new Date('2026-08-25T12:00:00.000Z')
    }
})

test('rejects a Windows file handle that cannot prove reparse-safe user-only access', async () => {
    const directory = await createLogDirectory()
    let opened = false
    try {
        const windowsSecurityAdapter = {
            /** @returns {Promise<object>} Controlled safe directory proof. */
            async ensurePrivateDirectory() {
                return { directory: true, reparsePoint: false, userOnlyDacl: true }
            },
            /** @returns {Promise<object>} Returns deliberately unsafe file proof. */
            async openVerifiedFile() {
                opened = true
                return { handle: null, noFollowVerified: false, reparsePoint: true, userOnlyDacl: false }
            },
            /** @returns {Promise<object>} Unused controlled proof. */
            async removeVerifiedFile() {
                return { removed: true, reparsePoint: false, userOnlyDacl: true }
            },
            /** @returns {Promise<object>} Unused controlled proof. */
            async renameVerifiedFile() {
                return { noFollowVerified: true, reparsePoint: false, userOnlyDacl: true }
            }
        }
        const logger = new EventLogger({ directory, platform: 'win32', windowsSecurityAdapter })

        assert.equal(await logger.write({ event: 'blocked', messageKey: 'activity.blocked' }), false)
        assert.equal(opened, true)
        await assert.rejects(() => readFile(join(directory, 'RDXManager.jsonl'), 'utf8'), /ENOENT/)
    } finally {
        await removeLogDirectory(directory)
    }
})
