// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { access, mkdtemp, readFile, realpath, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { createPlatformVerificationReport, probeNativeService, runBoundedCommand, writePlatformVerificationReport } from '../scripts/verify-native-platform.mjs'

const projectRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

/** @returns {object} Literal host evidence for report-contract tests. */
function fixtureEvidence() {
    return {
        generatedAt: '2026-08-28T12:00:00.000Z',
        platform: { os: 'darwin', arch: 'arm64' },
        tools: { node: 'v22.16.0', npm: '10.9.2', rustc: 'rustc 1.95.0', cargo: 'cargo 1.95.0' },
        build: { command: 'npm run build:runtime', passed: true, exitCode: 0, durationMs: 12 },
        tests: { command: 'npm run native:quality', passed: true, exitCode: 0, durationMs: 34 },
        nativeService: {
            smokePassed: true,
            handshake: { status: 'ready', mode: 'native', hardwareReady: false, platformCapability: { state: 'insufficient-permission', reason: 'privileged-service-unavailable' } },
            discoveredDeviceCount: 0
        }
    }
}

/** @returns {void} Proves runtime evidence cannot be mistaken for physical acceptance. */
function separatesRuntimeFromHardwareProof() {
    const report = createPlatformVerificationReport(fixtureEvidence())

    assert.equal(report.nativeService.smokePassed, true)
    assert.equal(report.nativeService.discoveredDeviceCount, 0)
    assert.equal(report.hardware.verified, false)
    assert.deepEqual(report.hardware.operations, [])
    assert.equal(Object.hasOwn(report.nativeService, 'operations'), false)
}

test('platform report separates native runtime from hardware proof', separatesRuntimeFromHardwareProof)

/** @returns {void} Proves even positive service readiness never manufactures acceptance evidence. */
function neverPromotesServiceReadinessToHardwareProof() {
    const evidence = fixtureEvidence()
    evidence.nativeService.handshake.hardwareReady = true
    evidence.nativeService.discoveredDeviceCount = 2
    const report = createPlatformVerificationReport(evidence)

    assert.equal(report.nativeService.handshake.hardwareReady, true)
    assert.equal(report.nativeService.discoveredDeviceCount, 2)
    assert.deepEqual(report.hardware, { verified: false, operations: [] })
}

test('report never promotes discovered hardware to verified operations', neverPromotesServiceReadinessToHardwareProof)

/** @returns {void} Proves raw command and native path fields cannot enter persisted evidence. */
function stripsUnreviewedDiagnosticFields() {
    const evidence = fixtureEvidence()
    evidence.build.stdout = 'unreviewed-build-output'
    evidence.tests.stderr = 'unreviewed-test-output'
    evidence.nativeService.handshake.devicePath = '/dev/rdx-untrusted'
    const report = createPlatformVerificationReport(evidence)

    assert.equal(Object.hasOwn(report.build, 'stdout'), false)
    assert.equal(Object.hasOwn(report.tests, 'stderr'), false)
    assert.equal(Object.hasOwn(report.nativeService.handshake, 'devicePath'), false)
}

test('report persists only reviewed evidence fields', stripsUnreviewedDiagnosticFields)

/** @returns {void} Proves an impossible discovery count fails rather than weakening the schema. */
function rejectsInvalidDiscoveryCounts() {
    const evidence = fixtureEvidence()
    evidence.nativeService.discoveredDeviceCount = -1
    /** @returns {object} Attempts the invalid report creation. */
    function createInvalidReport() {
        return createPlatformVerificationReport(evidence)
    }
    assert.throws(createInvalidReport, /platform-verification-evidence-invalid/)
}

test('report rejects an invalid discovered-device count', rejectsInvalidDiscoveryCounts)

/** @returns {void} Proves native diagnostic strings remain bounded and machine-readable. */
function rejectsUnboundedHandshakeEvidence() {
    const evidence = fixtureEvidence()
    evidence.nativeService.handshake.platformCapability.reason = 'x'.repeat(257)
    /** @returns {object} Attempts report creation with an oversized native reason. */
    function createInvalidReport() {
        return createPlatformVerificationReport(evidence)
    }
    assert.throws(createInvalidReport, /platform-verification-evidence-invalid/)
}

test('report rejects unbounded native handshake evidence', rejectsUnboundedHandshakeEvidence)

/** @returns {Promise<void>} Proves generated evidence stays below the ignored verification root. */
async function writesOnlyToGeneratedVerificationDirectory() {
    const temporaryProject = await mkdtemp(join(tmpdir(), 'openrdx-platform-report-'))
    try {
        const report = createPlatformVerificationReport(fixtureEvidence())
        const reportPath = await writePlatformVerificationReport({ projectRoot: temporaryProject, report })

        assert.equal(reportPath, join(await realpath(temporaryProject), 'out', 'verification', 'darwin-arm64.json'))
        assert.deepEqual(JSON.parse(await readFile(reportPath, 'utf8')), report)
        await assert.rejects(access(join(temporaryProject, 'darwin-arm64.json')))
    } finally {
        await rm(temporaryProject, { force: true, recursive: true })
    }
}

test('verification writer stays under generated out directory', writesOnlyToGeneratedVerificationDirectory)

/** @returns {Promise<void>} Proves awaited process completion preserves both output streams and the exact failure status. */
async function preservesCompletedCommandEvidence() {
    for (const exitCode of [0, 7]) {
        const source = `process.stdout.write('verification-output'); process.stderr.write('verification-error'); process.exitCode = ${exitCode}`
        const result = await runBoundedCommand({ command: process.execPath, args: ['-e', source], cwd: projectRoot, timeoutMs: 5_000 })

        assert.equal(result.passed, exitCode === 0)
        assert.equal(result.timedOut, false)
        assert.equal(result.exitCode, exitCode)
        assert.equal(result.stdout, 'verification-output')
        assert.equal(result.stderr, 'verification-error')
    }
}

test('verification command completion preserves output and failure status', preservesCompletedCommandEvidence)

/** @returns {Promise<void>} Proves a spawn error settles as failed evidence without waiting for the deadline. */
async function resolvesUnlaunchableCommands() {
    const result = await runBoundedCommand({ command: join(projectRoot, 'missing-verification-executable'), cwd: projectRoot, timeoutMs: 5_000 })

    assert.equal(result.passed, false)
    assert.equal(result.timedOut, false)
    assert.equal(result.exitCode, null)
    assert.equal(result.stdout, '')
    assert.equal(result.stderr, '')
}

test('verification command launch errors produce failed evidence', resolvesUnlaunchableCommands)

/** @returns {Promise<void>} Proves awaited completion retains the shared stdout/stderr output cap. */
async function boundsCombinedCommandOutput() {
    const source = 'process.stdout.write(Buffer.alloc(8 * 1024 * 1024, 97)); process.stderr.write(Buffer.alloc(12 * 1024 * 1024, 98)); setInterval(() => {}, 1_000)'
    const result = await runBoundedCommand({ command: process.execPath, args: ['-e', source], cwd: projectRoot, timeoutMs: 5_000 })

    assert.equal(result.passed, false)
    assert.equal(result.timedOut, false)
    assert.equal(result.exitCode, process.platform === 'win32' ? 1 : null)
    assert.equal(Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr), 16 * 1024 * 1024)
}

test('verification command output is bounded across both streams', boundsCombinedCommandOutput)

/** @returns {Promise<void>} Proves hung checks terminate and retain no success claim. */
async function boundsHungVerificationCommands() {
    const result = await runBoundedCommand({ command: process.execPath, args: ['-e', 'setInterval(() => {}, 1_000)'], cwd: projectRoot, timeoutMs: 100 })

    assert.equal(result.passed, false)
    assert.equal(result.timedOut, true)
    assert.equal(result.exitCode, process.platform === 'win32' ? 1 : null)
}

test('verification commands fail closed at their deadline', boundsHungVerificationCommands)

/** @param {number} processId - Candidate child PID. @returns {boolean} True while the process remains observable. */
function isProcessAlive(processId) {
    try {
        process.kill(processId, 0)
        return true
    } catch {
        return false
    }
}

/** @returns {Promise<void>} Proves a timed-out check cannot leave its spawned command tree running. */
async function terminatesTimedOutCommandTrees() {
    const parentSource = `
        const { spawn } = require('node:child_process')
        const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' })
        process.stdout.write(String(child.pid) + '\\n')
        setInterval(() => {}, 1000)
    `
    const result = await runBoundedCommand({ command: process.execPath, args: ['-e', parentSource], cwd: projectRoot, timeoutMs: 200 })
    const descendantId = Number(result.stdout.trim())
    try {
        assert.equal(Number.isInteger(descendantId), true)
        assert.equal(isProcessAlive(descendantId), false)
    } finally {
        if (Number.isInteger(descendantId) && isProcessAlive(descendantId)) process.kill(descendantId, 'SIGKILL')
    }
}

test('verification timeout terminates the complete command tree', terminatesTimedOutCommandTrees)

/** @returns {Promise<void>} Proves the staged native service returns real bounded handshake and discovery evidence. */
async function probesTheRealNativeServiceWithoutOperations() {
    const result = await probeNativeService({ projectRoot, timeoutMs: 5_000 })

    assert.equal(result.smokePassed, true)
    assert.equal(result.handshake.status, 'ready')
    assert.equal(result.handshake.mode, 'native')
    assert.equal(Number.isInteger(result.discoveredDeviceCount), true)
    assert.equal(result.discoveredDeviceCount >= 0, true)
    assert.equal(Object.hasOwn(result, 'operations'), false)
}

test('native probe reports a real handshake and discovered count', probesTheRealNativeServiceWithoutOperations)
