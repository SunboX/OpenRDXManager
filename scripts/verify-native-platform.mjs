// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile, spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { lstat, mkdir, realpath, rename, rm, writeFile } from 'node:fs/promises'
import { arch as hostArch } from 'node:os'
import { delimiter, dirname, isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import { getNativeServiceBuildPaths } from './build-native-service.mjs'
import { DeviceServiceClient, createChildProcessTransportFactory } from '../src/main/device-service-client.mjs'

const defaultProjectRoot = fileURLToPath(new URL('..', import.meta.url))
const execFileAsync = promisify(execFile)
const maximumOutputBytes = 16 * 1024 * 1024
const toolTimeoutMs = 10_000
const buildTimeoutMs = 15 * 60_000
const testTimeoutMs = 30 * 60_000
const serviceTimeoutMs = 5_000
const supportedPlatforms = new Set(['darwin', 'linux', 'win32'])

/**
 * Runs one fixed executable without a shell and fails closed at a bounded
 * deadline or output limit.
 * @param {{command: string, args?: string[], cwd: string, timeoutMs: number, echoOutput?: boolean, toolDirectory?: string|null}} options - Exact executable invocation.
 * @returns {Promise<{passed: boolean, timedOut: boolean, exitCode: number|null, durationMs: number, stdout: string, stderr: string}>} Bounded process evidence.
 */
export async function runBoundedCommand({ command, args = [], cwd, timeoutMs, echoOutput = false, toolDirectory = null }) {
    if (typeof command !== 'string' || command.length === 0 || !Array.isArray(args) || !isAbsolute(cwd) || !Number.isInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > testTimeoutMs || typeof echoOutput !== 'boolean' || (toolDirectory !== null && !isAbsolute(toolDirectory))) {
        throw new TypeError('platform-verification-command-invalid')
    }
    const startedAt = Date.now()
    const stdoutChunks = []
    const stderrChunks = []
    let capturedBytes = 0
    let outputExceeded = false
    let timedOut = false
    const child = spawn(command, args, {
        cwd,
        detached: process.platform !== 'win32',
        env: createChildEnvironment(toolDirectory),
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true
    })
    /** @param {Buffer[]} destination - Target output chunks. @param {Buffer|string} chunk - New child output. @returns {void} Captures or terminates at the shared bound. */
    function captureOutput(destination, chunk) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
        const availableBytes = maximumOutputBytes - capturedBytes
        if (availableBytes > 0) {
            const captured = buffer.length <= availableBytes ? buffer : buffer.subarray(0, availableBytes)
            destination.push(captured)
            capturedBytes += captured.length
        }
        if (buffer.length > availableBytes && !outputExceeded) {
            outputExceeded = true
            terminateProcessTree(child)
        }
    }
    /** @param {Buffer|string} chunk - Standard output chunk. @returns {void} Captures bounded stdout. */
    function handleStdout(chunk) {
        captureOutput(stdoutChunks, chunk)
    }
    /** @param {Buffer|string} chunk - Standard error chunk. @returns {void} Captures bounded stderr. */
    function handleStderr(chunk) {
        captureOutput(stderrChunks, chunk)
    }
    /** @returns {void} Terminates the complete check process tree at its deadline. */
    function handleTimeout() {
        timedOut = true
        terminateProcessTree(child)
    }
    const timeout = setTimeout(handleTimeout, timeoutMs)
    child.stdout.on('data', handleStdout)
    child.stderr.on('data', handleStderr)
    let exitCode = null
    try {
        // Node's event promise rejects on launch errors and removes its listeners.
        const [completedExitCode] = await once(child, 'close')
        exitCode = completedExitCode
    } catch {
        // An unlaunchable executable is failed evidence, not a verifier crash.
    } finally {
        clearTimeout(timeout)
        child.stdout.removeListener('data', handleStdout)
        child.stderr.removeListener('data', handleStderr)
    }
    const stdout = Buffer.concat(stdoutChunks).toString('utf8')
    const stderr = Buffer.concat(stderrChunks).toString('utf8')
    if (echoOutput) publishCommandOutput(stdout, stderr)
    return { passed: !timedOut && !outputExceeded && exitCode === 0, timedOut, exitCode: Number.isInteger(exitCode) ? exitCode : null, durationMs: Date.now() - startedAt, stdout, stderr }
}

/**
 * Terminates one verifier-owned process tree. POSIX checks own a fresh process
 * group; Windows uses the platform's fixed tree-kill utility.
 * @param {import('node:child_process').ChildProcess} child - Exact spawned check.
 * @returns {void}
 */
function terminateProcessTree(child) {
    if (!Number.isInteger(child.pid) || child.pid < 1) return
    if (process.platform !== 'win32') {
        try {
            process.kill(-child.pid, 'SIGKILL')
        } catch {
            child.kill('SIGKILL')
        }
        return
    }
    void terminateWindowsProcessTree(child)
}

/**
 * Awaits Windows tree termination before falling back to the exact direct child.
 * @param {import('node:child_process').ChildProcess} child - Exact spawned check.
 * @returns {Promise<void>} Resolves after the bounded tree-kill attempt and fallback.
 */
async function terminateWindowsProcessTree(child) {
    try {
        await execFileAsync('taskkill.exe', ['/pid', String(child.pid), '/t', '/f'], { timeout: 5_000, windowsHide: true })
    } catch {
        // Missing or failed taskkill still falls back to the direct child below.
    } finally {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL')
    }
}

/**
 * Adds an already-installed Cargo sibling directory only to this child. This
 * covers package-manager layouts where `cargo-fmt` is installed but unlinked.
 * @param {string|null} toolDirectory - Canonical Cargo tool directory.
 * @returns {NodeJS.ProcessEnv} Child-only environment.
 */
function createChildEnvironment(toolDirectory) {
    if (toolDirectory === null) return process.env
    const searchPathKey = findSearchPathKey()
    return { ...process.env, [searchPathKey]: `${toolDirectory}${delimiter}${process.env[searchPathKey] ?? ''}` }
}

/** @returns {string} Existing cross-platform process search-path key. */
function findSearchPathKey() {
    /** @param {string} key - Environment key. @returns {boolean} True for the platform search path. */
    function isSearchPathKey(key) {
        return key.toLowerCase() === 'path'
    }
    return Object.keys(process.env).find(isSearchPathKey) ?? (process.platform === 'win32' ? 'Path' : 'PATH')
}

/**
 * Resolves the directory containing the real Cargo binary without invoking a
 * shell or accepting an arbitrary caller-provided executable.
 * @returns {Promise<string|null>} Canonical Cargo sibling directory, if found.
 */
async function resolveCargoToolDirectory() {
    const searchPath = process.env[findSearchPathKey()] ?? ''
    const executableName = process.platform === 'win32' ? 'cargo.exe' : 'cargo'
    for (const directory of searchPath.split(delimiter)) {
        if (!isAbsolute(directory)) continue
        try {
            const executable = await realpath(join(directory, executableName))
            const metadata = await lstat(executable)
            if (metadata.isFile()) return dirname(executable)
        } catch {
            // Continue to the next fixed search-path directory.
        }
    }
    return null
}

/**
 * Uses npm's current JavaScript entrypoint through the running Node executable.
 * This avoids `.cmd` shell semantics on Windows and keeps every argument fixed.
 * @returns {Promise<{command: string, prefixArgs: string[]}>} Shell-free npm invocation.
 */
async function resolveNpmInvocation() {
    const npmEntrypoint = process.env.npm_execpath
    if (typeof npmEntrypoint !== 'string' || !isAbsolute(npmEntrypoint)) throw new Error('platform-verification-npm-entrypoint-unavailable')
    const canonicalEntrypoint = await realpath(npmEntrypoint)
    const metadata = await lstat(canonicalEntrypoint)
    if (!metadata.isFile()) throw new Error('platform-verification-npm-entrypoint-unavailable')
    return { command: process.execPath, prefixArgs: [canonicalEntrypoint] }
}

/**
 * Relays bounded command output for interactive native verification without
 * persisting it into the machine-readable report.
 * @param {string} stdout - Bounded standard output.
 * @param {string} stderr - Bounded standard error.
 * @returns {void}
 */
function publishCommandOutput(stdout, stderr) {
    if (stdout.length > 0) process.stdout.write(stdout)
    if (stderr.length > 0) process.stderr.write(stderr)
}

/**
 * Starts the exact staged service, completes its strict handshake, performs
 * only the read-only device-list request, and shuts it down gracefully.
 * @param {{projectRoot?: string, timeoutMs?: number}} [options] - Controlled project and per-request deadline.
 * @returns {Promise<{smokePassed: boolean, handshake: object, discoveredDeviceCount: number}>} Native service evidence.
 */
export async function probeNativeService({ projectRoot = defaultProjectRoot, timeoutMs = serviceTimeoutMs } = {}) {
    if (!isAbsolute(projectRoot) || !supportedPlatforms.has(process.platform) || !Number.isInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 30_000) {
        throw new TypeError('platform-verification-service-probe-invalid')
    }
    const executable = getNativeServiceBuildPaths({ projectRoot, platform: process.platform }).runtimePath
    const transportFactory = createChildProcessTransportFactory({
        forceKillTimeoutMs: 500,
        platform: process.platform,
        shutdownTimeoutMs: 500
    })
    const client = new DeviceServiceClient({
        executable,
        handshakeTimeoutMs: timeoutMs,
        maxRestarts: 0,
        platform: process.platform,
        requestTimeoutMs: timeoutMs,
        transportFactory
    })
    try {
        const state = await client.start()
        if (state.status !== 'ready') {
            return {
                smokePassed: false,
                handshake: { status: state.status, reason: state.reason ?? 'service-unavailable' },
                discoveredDeviceCount: 0
            }
        }
        const list = await client.list()
        if (list.ok !== true) {
            return {
                smokePassed: false,
                handshake: createHandshakeEvidence(state),
                discoveredDeviceCount: 0
            }
        }
        return {
            smokePassed: true,
            handshake: createHandshakeEvidence(state),
            discoveredDeviceCount: list.devices.length
        }
    } finally {
        await client.stop()
    }
}

/**
 * Reduces one strict client state to non-sensitive handshake evidence.
 * @param {object} state - Ready DeviceServiceClient state.
 * @returns {object} Path-free handshake evidence.
 */
function createHandshakeEvidence(state) {
    return {
        status: state.status,
        mode: state.mode,
        hardwareReady: state.hardwareReady === true,
        platformCapability: clonePlatformCapability(state.platformCapability)
    }
}

/**
 * Copies only the public capability fields admitted by the native handshake.
 * @param {object} capability - Strict client capability.
 * @returns {object} Stable capability evidence.
 */
function clonePlatformCapability(capability) {
    return {
        state: capability.state,
        ...(typeof capability.reason === 'string' ? { reason: capability.reason } : {})
    }
}

/**
 * Builds the stable report while unconditionally keeping physical acceptance
 * empty. Discovery and readiness can never promote hardware proof here.
 * @param {object} evidence - Reviewed host, tool, build, test, and service evidence.
 * @returns {object} Machine-readable platform report.
 */
export function createPlatformVerificationReport(evidence) {
    const validEvidence = evidence !== null && typeof evidence === 'object' && typeof evidence.generatedAt === 'string' && !Number.isNaN(Date.parse(evidence.generatedAt)) && supportedPlatforms.has(evidence.platform?.os) && typeof evidence.platform?.arch === 'string' && /^[a-z0-9_-]{1,32}$/u.test(evidence.platform.arch) && evidence.tools !== null && typeof evidence.tools === 'object' && [evidence.tools.node, evidence.tools.npm, evidence.tools.rustc, evidence.tools.cargo].every(isReportableToolVersion) && isCheckEvidence(evidence.build) && isCheckEvidence(evidence.tests) && typeof evidence.nativeService?.smokePassed === 'boolean' && isHandshakeEvidence(evidence.nativeService.handshake) && Number.isInteger(evidence.nativeService.discoveredDeviceCount) && evidence.nativeService.discoveredDeviceCount >= 0 && evidence.nativeService.discoveredDeviceCount <= 128
    if (!validEvidence) throw new TypeError('platform-verification-evidence-invalid')
    return {
        schemaVersion: 1,
        generatedAt: evidence.generatedAt,
        platform: { os: evidence.platform.os, arch: evidence.platform.arch },
        tools: { node: evidence.tools.node, npm: evidence.tools.npm, rustc: evidence.tools.rustc, cargo: evidence.tools.cargo },
        build: cloneCheckEvidence(evidence.build),
        tests: cloneCheckEvidence(evidence.tests),
        nativeService: {
            smokePassed: evidence.nativeService.smokePassed === true,
            handshake: cloneHandshakeEvidence(evidence.nativeService.handshake),
            discoveredDeviceCount: evidence.nativeService.discoveredDeviceCount
        },
        hardware: { verified: false, operations: [] }
    }
}

/** @param {unknown} version - Candidate tool version. @returns {boolean} True for a usable version or explicit unavailable value. */
function isReportableToolVersion(version) {
    return version === null || (typeof version === 'string' && version.length > 0 && version.length <= 256)
}

/** @param {unknown} evidence - Candidate build/test result. @returns {boolean} True for one bounded stable check. */
function isCheckEvidence(evidence) {
    return evidence !== null && typeof evidence === 'object' && typeof evidence.command === 'string' && evidence.command.length > 0 && evidence.command.length <= 128 && typeof evidence.passed === 'boolean' && (evidence.exitCode === null || Number.isInteger(evidence.exitCode)) && Number.isInteger(evidence.durationMs) && evidence.durationMs >= 0 && (evidence.timedOut === undefined || typeof evidence.timedOut === 'boolean')
}

/** @param {unknown} handshake - Candidate service handshake. @returns {boolean} True for bounded path-free handshake evidence. */
function isHandshakeEvidence(handshake) {
    if (handshake === null || typeof handshake !== 'object' || !isStableEvidenceToken(handshake.status)) return false
    if (handshake.reason !== undefined && !isStableEvidenceToken(handshake.reason)) return false
    if (handshake.mode !== undefined && !isStableEvidenceToken(handshake.mode)) return false
    if (handshake.hardwareReady !== undefined && typeof handshake.hardwareReady !== 'boolean') return false
    if (handshake.platformCapability === undefined) return true
    const capability = handshake.platformCapability
    return capability !== null && typeof capability === 'object' && isStableEvidenceToken(capability.state) && (capability.reason === undefined || isStableEvidenceToken(capability.reason))
}

/** @param {unknown} value - Candidate stable native token. @returns {boolean} True for a bounded lowercase token. */
function isStableEvidenceToken(value) {
    return typeof value === 'string' && /^[a-z0-9][a-z0-9-]{0,127}$/u.test(value)
}

/** @param {object} evidence - Validated check evidence. @returns {object} Allowlisted persisted check fields. */
function cloneCheckEvidence(evidence) {
    return {
        command: evidence.command,
        passed: evidence.passed,
        exitCode: evidence.exitCode,
        durationMs: evidence.durationMs,
        ...(evidence.timedOut === true ? { timedOut: true } : {})
    }
}

/** @param {object} handshake - Validated native handshake evidence. @returns {object} Allowlisted path-free handshake fields. */
function cloneHandshakeEvidence(handshake) {
    return {
        status: handshake.status,
        ...(typeof handshake.reason === 'string' ? { reason: handshake.reason } : {}),
        ...(typeof handshake.mode === 'string' ? { mode: handshake.mode } : {}),
        ...(typeof handshake.hardwareReady === 'boolean' ? { hardwareReady: handshake.hardwareReady } : {}),
        ...(handshake.platformCapability === undefined ? {} : { platformCapability: clonePlatformCapability(handshake.platformCapability) })
    }
}

/**
 * Atomically writes one report below the generated and ignored verification
 * directory, rejecting linked output directory components.
 * @param {{projectRoot?: string, report: object}} options - Controlled project and report.
 * @returns {Promise<string>} Absolute generated report path.
 */
export async function writePlatformVerificationReport({ projectRoot = defaultProjectRoot, report }) {
    if (!isAbsolute(projectRoot) || report?.platform === undefined || typeof report.platform.os !== 'string' || typeof report.platform.arch !== 'string') {
        throw new TypeError('platform-verification-write-invalid')
    }
    const canonicalRoot = resolve(await realpath(projectRoot))
    const outDirectory = await ensurePlainDirectory(canonicalRoot, 'out')
    const verificationDirectory = await ensurePlainDirectory(outDirectory, 'verification')
    const reportName = `${safeFileComponent(report.platform.os)}-${safeFileComponent(report.platform.arch)}.json`
    const reportPath = join(verificationDirectory, reportName)
    const temporaryPath = join(verificationDirectory, `.${reportName}.${randomUUID()}.tmp`)
    try {
        await writeFile(temporaryPath, `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 })
        await rename(temporaryPath, reportPath)
    } finally {
        await rm(temporaryPath, { force: true })
    }
    return reportPath
}

/**
 * Resolves or creates one direct non-link child directory.
 * @param {string} parent - Canonical parent directory.
 * @param {string} name - Fixed child basename.
 * @returns {Promise<string>} Canonical child directory.
 */
async function ensurePlainDirectory(parent, name) {
    const candidate = join(parent, name)
    try {
        await mkdir(candidate, { mode: 0o700 })
    } catch (error) {
        if (error?.code !== 'EEXIST') throw error
    }
    const metadata = await lstat(candidate)
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error('platform-verification-output-invalid')
    const canonicalCandidate = resolve(await realpath(candidate))
    if (dirname(canonicalCandidate) !== parent) throw new Error('platform-verification-output-invalid')
    return canonicalCandidate
}

/**
 * Restricts the report basename to the stable platform/architecture alphabet.
 * @param {string} value - Platform or architecture name.
 * @returns {string} Safe basename component.
 */
function safeFileComponent(value) {
    if (!/^[a-z0-9_-]{1,32}$/u.test(value)) throw new TypeError('platform-verification-file-component-invalid')
    return value
}

/**
 * Collects fixed tool versions in parallel without storing arbitrary command
 * diagnostics in the report.
 * @param {string} projectRoot - Absolute project root.
 * @param {string|null} toolDirectory - Canonical Cargo sibling directory.
 * @param {{command: string, prefixArgs: string[]}} npmInvocation - Shell-free npm entrypoint.
 * @returns {Promise<{node: string|null, npm: string|null, rustc: string|null, cargo: string|null}>} Tool versions.
 */
async function collectToolVersions(projectRoot, toolDirectory, npmInvocation) {
    const [npmResult, rustcResult, cargoResult] = await Promise.all([runBoundedCommand({ command: npmInvocation.command, args: [...npmInvocation.prefixArgs, '--version'], cwd: projectRoot, timeoutMs: toolTimeoutMs, toolDirectory }), runBoundedCommand({ command: 'rustc', args: ['--version'], cwd: projectRoot, timeoutMs: toolTimeoutMs, toolDirectory }), runBoundedCommand({ command: 'cargo', args: ['--version'], cwd: projectRoot, timeoutMs: toolTimeoutMs, toolDirectory })])
    return {
        node: process.version,
        npm: firstOutputLine(npmResult),
        rustc: firstOutputLine(rustcResult),
        cargo: firstOutputLine(cargoResult)
    }
}

/**
 * Extracts one stable version line only after a command succeeds.
 * @param {object} result - Bounded command result.
 * @returns {string|null} First non-empty version line or null.
 */
function firstOutputLine(result) {
    if (result.passed !== true) return null
    return result.stdout.trim().split(/\r?\n/u)[0] || null
}

/**
 * Removes raw output from one executed check before report persistence.
 * @param {string} command - Human-readable fixed npm command.
 * @param {object} result - Bounded command result.
 * @returns {object} Stable check evidence.
 */
function createCheckEvidence(command, result) {
    return {
        command,
        passed: result.passed,
        exitCode: result.exitCode,
        durationMs: result.durationMs,
        ...(result.timedOut ? { timedOut: true } : {})
    }
}

/**
 * Runs the current host's fixed non-mutating native readiness sequence and
 * writes its report even when one gate fails.
 * @param {{projectRoot?: string}} [options] - Controlled project root.
 * @returns {Promise<{passed: boolean, report: object, reportPath: string}>} Verification outcome.
 */
export async function verifyNativePlatform({ projectRoot = defaultProjectRoot } = {}) {
    if (!isAbsolute(projectRoot) || !supportedPlatforms.has(process.platform)) throw new TypeError('platform-verification-host-invalid')
    const canonicalRoot = resolve(await realpath(projectRoot))
    const toolDirectory = await resolveCargoToolDirectory()
    const npmInvocation = await resolveNpmInvocation()
    const tools = await collectToolVersions(canonicalRoot, toolDirectory, npmInvocation)
    const buildResult = await runBoundedCommand({ command: npmInvocation.command, args: [...npmInvocation.prefixArgs, 'run', 'build:runtime'], cwd: canonicalRoot, timeoutMs: buildTimeoutMs, echoOutput: true, toolDirectory })
    const testResult = await runBoundedCommand({ command: npmInvocation.command, args: [...npmInvocation.prefixArgs, 'run', 'native:quality'], cwd: canonicalRoot, timeoutMs: testTimeoutMs, echoOutput: true, toolDirectory })
    let nativeService
    if (buildResult.passed) {
        try {
            nativeService = await probeNativeService({ projectRoot: canonicalRoot, timeoutMs: serviceTimeoutMs })
        } catch (error) {
            nativeService = {
                smokePassed: false,
                handshake: { status: 'unavailable', reason: stableFailureReason(error) },
                discoveredDeviceCount: 0
            }
        }
    } else {
        nativeService = {
            smokePassed: false,
            handshake: { status: 'skipped', reason: 'build-failed' },
            discoveredDeviceCount: 0
        }
    }
    const report = createPlatformVerificationReport({
        generatedAt: new Date().toISOString(),
        platform: { os: process.platform, arch: hostArch() },
        tools,
        build: createCheckEvidence('npm run build:runtime', buildResult),
        tests: createCheckEvidence('npm run native:quality', testResult),
        nativeService
    })
    const reportPath = await writePlatformVerificationReport({ projectRoot: canonicalRoot, report })
    /** @param {unknown} version - Reported tool version. @returns {boolean} True for one non-empty version. */
    function isAvailableToolVersion(version) {
        return typeof version === 'string' && version.length > 0
    }
    const toolsReady = Object.values(tools).every(isAvailableToolVersion)
    return { passed: toolsReady && report.build.passed && report.tests.passed && report.nativeService.smokePassed, report, reportPath }
}

/**
 * Reduces an unexpected local failure to a stable, non-sensitive reason.
 * @param {unknown} error - Local exception.
 * @returns {string} Stable failure reason.
 */
function stableFailureReason(error) {
    if (error instanceof Error && /^[a-z0-9-]{1,64}$/u.test(error.message)) return error.message
    return 'native-service-probe-failed'
}

/** @returns {boolean} True only when Node launched this file as the entrypoint. */
function isDirectExecution() {
    return process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)
}

/** @returns {Promise<void>} Runs the CLI and sets its terminal process status. */
async function main() {
    try {
        const result = await verifyNativePlatform()
        process.stdout.write(`Native platform report: ${result.reportPath}\n`)
        process.exitCode = result.passed ? 0 : 1
    } catch (error) {
        process.stderr.write(`Native platform verification failed: ${stableFailureReason(error)}\n`)
        process.exitCode = 1
    }
}

if (isDirectExecution()) await main()
