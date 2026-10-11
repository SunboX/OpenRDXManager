// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { spawn } from 'node:child_process'
import { EventEmitter } from 'node:events'
import { isAbsolute, join, resolve } from 'node:path'

import { createPrivilegedEndpointTransportFactory } from './device-service-endpoint.mjs'
import { SPTI_DIAGNOSTIC_PREFIX, parseSptiDiagnostic } from './spti-diagnostics.mjs'

/** Current framed service protocol version. */
export const SERVICE_PROTOCOL_VERSION = 1
/** Default maximum JSON payload bytes for one service frame. */
export const DEFAULT_MAX_FRAME_BYTES = 65_536
/** Default bounded service restart backoff. */
export const DEFAULT_RESTART_BACKOFF_MS = Object.freeze([100, 500, 2_000])
/** Fixed native-service arguments that no renderer request can influence. */
export const DEVICE_SERVICE_ARGUMENTS = Object.freeze(['--service-mode', 'stdio', '--protocol-version', String(SERVICE_PROTOCOL_VERSION)])
/** Closed diagnostic vocabulary emitted by the trusted native executable. */
const NATIVE_DIAGNOSTIC_CODES = new Set([
    'firmware-transfer-attempt-one',
    'firmware-transfer-attempt-two',
    'firmware-transfer-first-chunk-failed',
    'firmware-transfer-intermediate-chunk-failed',
    'firmware-transfer-final-chunk-failed',
    'firmware-transfer-complete',
    'firmware-transfer-retry-eligible',
    'firmware-transfer-retry-suppressed',
    'firmware-transfer-incomplete',
    'firmware-device-rejected',
    'firmware-command-unsupported',
    'firmware-command-invalid',
    'firmware-device-not-ready',
    'firmware-hardware-failure',
    'firmware-write-protected',
    'firmware-unit-attention',
    'firmware-transport-unavailable',
    'firmware-transport-invalid',
    'firmware-signature-error',
    'windows-self-test-succeeded',
    'windows-self-test-no-media',
    'windows-self-test-invalid-command',
    'windows-self-test-invalid-field',
    'windows-self-test-medium-error',
    'windows-self-test-hardware-error',
    'windows-self-test-unit-attention',
    'windows-self-test-check-condition',
    'windows-self-test-not-sent',
    'windows-self-test-timeout',
    'windows-self-test-access-denied',
    'windows-self-test-native-error',
    'windows-self-test-invalid-sense',
    'windows-self-test-unexpected-sense',
    'windows-self-test-scsi-status',
    'windows-self-test-invalid-transfer',
    'windows-safe-eject-binding-failed',
    'windows-safe-eject-allow-os-succeeded',
    'windows-safe-eject-allow-os-failed',
    'windows-safe-eject-allow-device-succeeded',
    'windows-safe-eject-allow-device-failed',
    'windows-safe-eject-ioctl-succeeded',
    'windows-safe-eject-ioctl-failed',
    'eject-preflight-enter',
    'eject-preflight-return',
    'eject-stage-advance-enter',
    'eject-stage-advance-return',
    'eject-scsi-enter',
    'eject-scsi-return',
    'eject-release-scsi-enter',
    'eject-release-scsi-return',
    'eject-invalidate-mapping-enter',
    'eject-invalidate-mapping-return',
    'eject-pin-media-enter',
    'eject-pin-media-return',
    'eject-unmount-enter',
    'eject-unmount-return',
    'eject-rematch-enter',
    'eject-rematch-return',
    'eject-release-authority-enter',
    'eject-release-authority-return',
    'eject-authority-reopen-enter',
    'eject-authority-enumerate-enter',
    'eject-authority-enumerate-return',
    'eject-authority-select-return',
    'eject-authority-open-enter',
    'eject-authority-open-return',
    'eject-authority-reopen-return',
    'eject-media-rematch-enter',
    'eject-media-rematch-return',
    'eject-media-rematch-stale',
    'eject-media-rematch-timed-out',
    'eject-readback-enter',
    'eject-readback-waiting',
    'eject-readback-departed',
    'eject-readback-failed',
    'eject-readback-timed-out',
    'eject-da-unmount-enter',
    'eject-da-unmount-return',
    'eject-da-eject-enter',
    'eject-da-eject-return',
    'macos-da-direct-succeeded',
    'macos-da-direct-already-unmounted',
    'macos-da-direct-access-denied',
    'macos-da-direct-busy',
    'macos-da-direct-device-removed',
    'macos-da-direct-resource-limit',
    'macos-da-direct-timed-out',
    'macos-da-direct-failed',
    'macos-da-pinned-authority-missing',
    'macos-da-pinned-raw-disk-mismatch',
    'macos-da-pinned-raw-identity-mismatch',
    'macos-da-pinned-media-missing',
    'macos-da-pinned-media-object-mismatch',
    'macos-da-pinned-media-id-unavailable',
    'macos-da-pinned-media-id-mismatch',
    'macos-da-pinned-authority-succeeded',
    'macos-da-registry-busy',
    'macos-da-context-unavailable',
    'macos-eject-raw-authority-released',
    'macos-diskutil-unmount-enter',
    'macos-diskutil-unmount-succeeded',
    'macos-diskutil-unmount-exit-nonzero',
    'macos-diskutil-unmount-busy',
    'macos-diskutil-unmount-spawn-failed',
    'macos-diskutil-unmount-timed-out',
    'macos-diskutil-unmount-target-invalid',
    'macos-diskutil-eject-enter',
    'macos-diskutil-eject-succeeded',
    'macos-diskutil-eject-exit-nonzero',
    'macos-diskutil-eject-spawn-failed',
    'macos-diskutil-eject-timed-out',
    'macos-diskutil-eject-target-invalid',
    'macos-diskutil-eject-target-revalidated',
    'macos-diskutil-unmount-target-revalidated',
    'macos-diskutil-unmount-target-identity-changed',
    'macos-diskutil-eject-target-identity-changed',
    'usb-release-bridge-enter',
    'usb-release-bridge-return',
    'usb-release-pipes-return',
    'usb-release-interface-enter',
    'usb-release-interface-return',
    'usb-release-device-enter',
    'usb-release-device-return',
    'usb-release-pool-return',
    'usb-release-lease-free-enter',
    'usb-release-lease-free-return',
    'scsi-release-usb-return',
    'scsi-release-lease-free-enter',
    'scsi-release-lease-free-return',
    'scsi-worker-command-write-enter',
    'scsi-worker-command-write-return',
    'scsi-worker-command-write-error',
    'scsi-worker-native-enter',
    'scsi-worker-native-return',
    'scsi-worker-response-write-enter',
    'scsi-worker-response-write-return',
    'scsi-worker-response-write-error',
    'scsi-worker-response-read-enter',
    'scsi-worker-response-read-return',
    'scsi-worker-response-read-error',
    'service-exit-code-zero',
    'service-exit-code-nonzero',
    'service-exit-sigpipe',
    'service-exit-sigkill',
    'service-exit-sigterm',
    'service-exit-sigabrt',
    'service-exit-sigsegv',
    'service-exit-sigbus',
    'service-exit-signal-other',
    'service-exit-evidence-unknown'
])
const NATIVE_DIAGNOSTIC_PREFIX = 'openrdx-hardware: trace '
const MAX_NATIVE_DIAGNOSTIC_BUFFER_BYTES = 2_048

/**
 * Validates one fixed native breadcrumb without accepting arbitrary stderr.
 * @param {unknown} value - Candidate breadcrumb code.
 * @returns {boolean} True only for a closed diagnostic code.
 */
export function isNativeDiagnosticCode(value) {
    return typeof value === 'string' && NATIVE_DIAGNOSTIC_CODES.has(value)
}

/**
 * Converts raw child termination fields into a fixed non-sensitive diagnostic.
 * @param {number|null|undefined} exitCode - Child numeric exit code, when available.
 * @param {string|null|undefined} signalCode - Child terminating signal, when available.
 * @returns {string} One allowlisted termination classification.
 */
function classifyServiceTermination(exitCode, signalCode) {
    const signals = {
        SIGPIPE: 'service-exit-sigpipe',
        SIGKILL: 'service-exit-sigkill',
        SIGTERM: 'service-exit-sigterm',
        SIGABRT: 'service-exit-sigabrt',
        SIGSEGV: 'service-exit-sigsegv',
        SIGBUS: 'service-exit-sigbus'
    }
    if (typeof signalCode === 'string') return signals[signalCode] ?? 'service-exit-signal-other'
    if (Number.isInteger(exitCode)) return exitCode === 0 ? 'service-exit-code-zero' : 'service-exit-code-nonzero'
    return 'service-exit-evidence-unknown'
}

/**
 * Encodes one bounded structured service message as length-prefixed UTF-8 JSON.
 * @param {object} message - Main-owned service message.
 * @param {number} maxFrameBytes - Maximum payload bytes.
 * @returns {Buffer} Framed message.
 * @throws {RangeError} When serialized payload exceeds the bound.
 */
export function encodeServiceFrame(message, maxFrameBytes) {
    const payload = Buffer.from(JSON.stringify(message), 'utf8')
    if (payload.length === 0 || payload.length > maxFrameBytes) {
        throw new RangeError('service-frame-too-large')
    }
    const frame = Buffer.allocUnsafe(payload.length + 4)
    frame.writeUInt32BE(payload.length, 0)
    payload.copy(frame, 4)
    return frame
}

/** Stateful bounded decoder for the native service's length-framed JSON. */
export class FramedJsonDecoder {
    #buffer = Buffer.alloc(0)
    #maxFrameBytes

    /**
     * Creates an empty decoder with an exact payload bound.
     * @param {number} maxFrameBytes - Maximum accepted payload bytes.
     */
    constructor(maxFrameBytes) {
        this.#maxFrameBytes = maxFrameBytes
    }

    /**
     * Appends one transport chunk and returns every complete parsed message.
     * @param {unknown} chunk - Candidate binary transport chunk.
     * @returns {object[]} Complete parsed JSON objects.
     * @throws {Error} For non-binary, oversized, malformed, or non-object frames.
     */
    push(chunk) {
        if (!Buffer.isBuffer(chunk) && !(chunk instanceof Uint8Array)) {
            throw new Error('service-malformed-data')
        }
        const nextChunk = Buffer.from(chunk)
        const frameStorageBound = this.#maxFrameBytes + 4
        if (nextChunk.length > frameStorageBound * 64 || this.#buffer.length > frameStorageBound || this.#buffer.length + nextChunk.length > frameStorageBound * 65) {
            throw new Error('service-malformed-data')
        }
        this.#buffer = Buffer.concat([this.#buffer, nextChunk])
        const messages = []
        while (this.#buffer.length >= 4) {
            const length = this.#buffer.readUInt32BE(0)
            if (length === 0 || length > this.#maxFrameBytes) {
                throw new Error('service-malformed-data')
            }
            if (this.#buffer.length < length + 4) {
                break
            }
            const payload = this.#buffer.subarray(4, length + 4)
            this.#buffer = this.#buffer.subarray(length + 4)
            let message
            try {
                message = JSON.parse(payload.toString('utf8'))
            } catch {
                throw new Error('service-malformed-data')
            }
            if (message === null || typeof message !== 'object' || Array.isArray(message)) {
                throw new Error('service-malformed-data')
            }
            messages.push(message)
        }
        return messages
    }
}

/**
 * Maps a supported runtime platform to its packaged resource folder.
 * @param {string} platform - Node platform identifier.
 * @returns {string} Native resource folder.
 * @throws {RangeError} When the platform is unsupported.
 */
function platformResourceFolder(platform) {
    switch (platform) {
        case 'darwin':
            return 'macos'
        case 'win32':
            return 'windows'
        case 'linux':
            return 'linux'
        default:
            throw new RangeError('unsupported-platform')
    }
}

/**
 * Resolves the native binary from application/resource roots owned by main.
 * No renderer path or working-directory assumption participates.
 * @param {{appPath: string, resourcesPath: string, isPackaged: boolean, platform: string}} options - Electron runtime roots.
 * @returns {string} Absolute expected native-service executable path.
 * @throws {TypeError|RangeError} For invalid roots or unsupported platforms.
 */
export function resolveDeviceServiceExecutable({ appPath, resourcesPath, isPackaged, platform }) {
    if (typeof appPath !== 'string' || typeof resourcesPath !== 'string' || typeof isPackaged !== 'boolean' || !isAbsolute(appPath) || !isAbsolute(resourcesPath)) {
        throw new TypeError('service-resource-root-invalid')
    }
    const executableName = platform === 'win32' ? 'openrdx-hardware.exe' : 'openrdx-hardware'
    const platformFolder = platformResourceFolder(platform)
    if (isPackaged && platform === 'darwin') return resolve(resourcesPath, '..', 'Library', 'LaunchServices', executableName)
    return isPackaged ? join(resourcesPath, 'native', platformFolder, executableName) : resolve(appPath, 'out', 'native', platformFolder, executableName)
}

/** Child-process adapter that exposes only the minimal framed transport API. */
class ChildProcessTransport extends EventEmitter {
    #child
    #closePromise = null
    #closed = false
    #exitObserved = false
    #failed = false
    #inFlight = null
    #maxQueueBytes
    #maxQueueCount
    #nativeDiagnosticCode = null
    #terminationRecorded = false
    #forceKillTimeoutMs
    #queue = []
    #queueBytes = 0
    #shutdownTimeoutMs
    #stderrBuffer = Buffer.alloc(0)
    #stderrDiscarding = false
    #sptiDiagnostics
    #sptiCount = 0
    #waitingDrain = false

    /**
     * Wraps one spawned native child while discarding raw stderr payloads.
     * @param {object} child - Node ChildProcess instance.
     * @param {{maxQueueCount: number, maxQueueBytes: number, shutdownTimeoutMs: number, forceKillTimeoutMs: number, sptiDiagnostics?: boolean}} bounds - Fixed transport bounds and explicit header-only capture opt-in.
     */
    constructor(child, bounds) {
        super()
        this.#child = child
        this.#sptiDiagnostics = bounds.sptiDiagnostics === true
        this.#maxQueueCount = bounds.maxQueueCount
        this.#maxQueueBytes = bounds.maxQueueBytes
        this.#shutdownTimeoutMs = bounds.shutdownTimeoutMs
        this.#forceKillTimeoutMs = bounds.forceKillTimeoutMs

        /**
         * Forwards binary stdout only to the bounded protocol decoder.
         * @param {Buffer} chunk - Native stdout chunk.
         * @returns {void} Completes after forwarding.
         */
        const handleData = (chunk) => this.emit('data', chunk)

        /**
         * Converts process errors to a signal without forwarding error details.
         * @returns {void} Completes after generic failure notification.
         */
        const handleError = () => this.#signalFailure('error')

        /** Records termination evidence while stdio is still allowed to drain. */
        const handleExit = (exitCode, signalCode) => {
            this.#exitObserved = true
            this.#recordTermination(exitCode, signalCode)
        }

        /**
         * Publishes process termination only after every stdio pipe has closed.
         * @returns {void} Completes after the final stderr breadcrumb is available.
         */
        const handleClose = (exitCode, signalCode) => {
            this.#exitObserved = true
            this.#recordTermination(exitCode, signalCode)
            this.#signalFailure('exit')
        }

        /** Resumes the serialized writer after native stdin drains. */
        const handleDrain = () => {
            this.#waitingDrain = false
            this.#pump()
        }

        /** Contains EPIPE and every other stdin failure. */
        const handleStdinError = () => this.#signalFailure('error')

        child.stdout?.on('data', handleData)
        child.on('error', handleError)
        child.on('exit', handleExit)
        child.on('close', handleClose)
        child.stdin?.on('drain', handleDrain)
        child.stdin?.on('error', handleStdinError)
        child.stderr?.on?.('data', (chunk) => this.#consumeStderr(chunk))
        child.stderr?.resume()
    }

    /** @returns {true} Declares support for the versioned shutdown request. */
    get supportsGracefulShutdown() {
        return true
    }

    /**
     * Writes one framed request to native stdin.
     * @param {Buffer} frame - Bounded service frame.
     * @returns {{ok: true}|{ok: false, reason: string}} Stable queue admission.
     */
    write(frame) {
        if (this.#closed || this.#failed || this.#child.stdin?.writable !== true) {
            return { ok: false, reason: 'service-unavailable' }
        }
        if (!Buffer.isBuffer(frame) || frame.length === 0 || this.#queue.length + (this.#inFlight === null ? 0 : 1) >= this.#maxQueueCount || this.#queueBytes + frame.length > this.#maxQueueBytes) {
            return { ok: false, reason: 'service-saturated' }
        }
        this.#queue.push(Buffer.from(frame))
        this.#queueBytes += frame.length
        this.#pump()
        return { ok: true }
    }

    /**
     * Requests clean process termination without logging process details.
     * @returns {Promise<{confirmed: boolean, reason?: string}>} Resolves only with explicit teardown confidence.
     */
    async close() {
        if (this.#closePromise !== null) return this.#closePromise
        this.#closed = true
        this.#queue.length = 0
        this.#queueBytes = this.#inFlight?.length ?? 0
        this.#child.stdin?.end()
        if (this.#hasTerminationEvidence()) {
            return { confirmed: true }
        }
        /**
         * Registers the three bounded exit waits for this exact child generation.
         * @param {(result: {confirmed: boolean, reason?: string}) => void} resolveClose - Close result resolver.
         * @returns {void} Completes after exit and escalation handlers are armed.
         */
        const awaitChildExit = (resolveClose) => {
            let settled = false
            let eofTimer = null
            let forceTimer = null
            let terminateTimer = null
            const eofGraceMs = Math.ceil(this.#shutdownTimeoutMs / 2)
            const terminateGraceMs = Math.max(1, this.#shutdownTimeoutMs - eofGraceMs)

            /**
             * Resolves this close waiter exactly once with observed-exit confidence.
             * @param {{confirmed: boolean, reason?: string}} result - Stable teardown result.
             * @returns {void} Completes after clearing all bounded timers.
             */
            const settle = (result) => {
                if (!settled) {
                    settled = true
                    if (eofTimer !== null) clearTimeout(eofTimer)
                    if (forceTimer !== null) clearTimeout(forceTimer)
                    if (terminateTimer !== null) clearTimeout(terminateTimer)
                    resolveClose(result)
                }
            }

            /** Confirms teardown only from the child process exit event. */
            const observeExit = () => settle({ confirmed: true })

            /** Records terminal uncertainty after SIGKILL receives no exit event. */
            const markUnconfirmed = () => settle({ confirmed: false, reason: 'service-teardown-unconfirmed' })

            /** Sends SIGKILL only after both EOF and SIGTERM grace periods expire. */
            const force = () => {
                try {
                    this.#child.kill('SIGKILL')
                } catch {
                    // Exit confidence still requires child termination evidence.
                }
                if (this.#hasTerminationEvidence()) {
                    settle({ confirmed: true })
                    return
                }
                forceTimer = setTimeout(markUnconfirmed, this.#forceKillTimeoutMs)
            }

            /** Sends SIGTERM only after the stdin EOF grace period expires. */
            const terminate = () => {
                try {
                    this.#child.kill('SIGTERM')
                } catch {
                    // Exit confidence still requires child termination evidence.
                }
                if (this.#hasTerminationEvidence()) {
                    settle({ confirmed: true })
                    return
                }
                terminateTimer = setTimeout(force, terminateGraceMs)
            }

            this.#child.once('exit', observeExit)
            if (this.#hasTerminationEvidence()) {
                settle({ confirmed: true })
                return
            }
            eofTimer = setTimeout(terminate, eofGraceMs)
        }
        this.#closePromise = new Promise(awaitChildExit)
        return this.#closePromise
    }

    /**
     * Recognizes every ChildProcess termination form without treating signal
     * delivery alone as exit proof.
     * @returns {boolean} True after an exit event, numeric code, or signal exit.
     */
    #hasTerminationEvidence() {
        return this.#exitObserved || (this.#child.exitCode !== null && this.#child.exitCode !== undefined) || (this.#child.signalCode !== null && this.#child.signalCode !== undefined)
    }

    /**
     * Serializes one bounded frame at a time and honors callback plus drain.
     * @returns {void} Completes after starting or declining the next write.
     */
    #pump() {
        if (this.#closed || this.#failed || this.#inFlight !== null || this.#waitingDrain || this.#queue.length === 0) {
            return
        }
        const frame = this.#queue.shift()
        this.#inFlight = frame

        /**
         * Completes the exact in-flight frame or fails the transport once.
         * @param {Error|null|undefined} error - Optional native write error.
         * @returns {void} Completes after accounting and the next pump.
         */
        const handleWrite = (error) => {
            if (this.#inFlight !== frame) return
            this.#inFlight = null
            this.#queueBytes -= frame.length
            if (error) {
                this.#signalFailure('error')
                return
            }
            this.#pump()
        }
        try {
            const accepted = this.#child.stdin.write(frame, handleWrite)
            this.#waitingDrain = accepted === false
        } catch {
            handleWrite(new Error('service-write-failed'))
        }
    }

    /**
     * Retains complete allowlisted breadcrumbs and explicitly opted-in safe headers.
     * @param {unknown} chunk - Candidate child stderr bytes.
     * @returns {void} Completes after discarding raw and partial hostile data.
     */
    #consumeStderr(chunk) {
        if (!Buffer.isBuffer(chunk) && !(chunk instanceof Uint8Array)) return
        const bytes = Buffer.from(chunk)
        if (bytes.length > 65_536) {
            this.#stderrBuffer = Buffer.alloc(0)
            this.#stderrDiscarding = true
            return
        }
        let offset = 0
        while (offset < bytes.length) {
            const newline = bytes.indexOf(0x0a, offset)
            const end = newline < 0 ? bytes.length : newline
            const part = bytes.subarray(offset, end)
            if (this.#stderrBuffer.length + part.length > MAX_NATIVE_DIAGNOSTIC_BUFFER_BYTES) this.#stderrDiscarding = true
            if (!this.#stderrDiscarding) this.#stderrBuffer = Buffer.concat([this.#stderrBuffer, part])
            offset = newline < 0 ? bytes.length : newline + 1
            if (newline < 0) {
                if (this.#stderrDiscarding) this.#stderrBuffer = Buffer.alloc(0)
                break
            }
            const line = this.#stderrDiscarding ? '' : this.#stderrBuffer.toString('utf8').replace(/\r$/, '')
            this.#stderrBuffer = Buffer.alloc(0)
            this.#stderrDiscarding = false
            if (this.#sptiDiagnostics && this.#sptiCount < 512 && line.startsWith(SPTI_DIAGNOSTIC_PREFIX) && parseSptiDiagnostic(line) !== null) {
                this.#sptiCount += 1
                this.emit('spti-diagnostic', line)
                continue
            }
            if (!line.startsWith(NATIVE_DIAGNOSTIC_PREFIX)) continue
            const code = line.slice(NATIVE_DIAGNOSTIC_PREFIX.length)
            if (!isNativeDiagnosticCode(code)) continue
            this.#nativeDiagnosticCode = code
            this.emit('diagnostic', { code })
        }
    }

    /**
     * Publishes exactly one sanitized termination diagnostic per child generation.
     * @param {number|null|undefined} exitCode - Child numeric exit code, when available.
     * @param {string|null|undefined} signalCode - Child terminating signal, when available.
     * @returns {void} Completes after retaining the fixed classification.
     */
    #recordTermination(exitCode, signalCode) {
        if (this.#terminationRecorded) return
        this.#terminationRecorded = true
        const code = classifyServiceTermination(exitCode, signalCode)
        this.#nativeDiagnosticCode = code
        this.emit('diagnostic', { code })
    }

    /**
     * Emits one generic terminal signal across stdin/error/exit races.
     * @param {'error'|'exit'} signal - First observed terminal condition.
     * @returns {void} Completes after once-only notification.
     */
    #signalFailure(signal) {
        if (this.#failed || this.#closed) return
        this.#failed = true
        this.#queue.length = 0
        this.#queueBytes = 0
        this.#inFlight = null
        this.emit(signal, this.#nativeDiagnosticCode === null ? {} : { diagnosticCode: this.#nativeDiagnosticCode })
    }
}

/**
 * Returns the fixed minimal child environment for one supported host.
 * @param {string} platform - Node platform identifier.
 * @returns {Readonly<Record<string, string>>} Deterministic environment.
 */
function createServiceEnvironment(platform) {
    return Object.freeze(platform === 'win32' ? { LANG: 'C', LC_ALL: 'C', PATH: 'C:\\Windows\\System32', SystemRoot: 'C:\\Windows' } : { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' })
}

/**
 * Creates the production child-process transport factory with fixed stdio and
 * main-owned arguments. It never falls back to a no-device success.
 * The optional `sptiDiagnostics` boolean is Windows-only and requires an awaitable
 * `onSptiDiagnostic(line, generation)` sink; neither is inherited from ambient state.
 * @param {{spawnProcess?: (command: string, args: string[], options: object) => object, platform?: 'darwin'|'win32'|'linux', elevateDevelopmentService?: boolean, maxQueueCount?: number, maxQueueBytes?: number, shutdownTimeoutMs?: number, forceKillTimeoutMs?: number}} [options] - Injectable launcher/platform plus bounded writer and teardown settings. Queue count is 1..1024 (default 64), aggregate queued bytes are 64..16,777,216 (default 1,048,576), the 1..10,000 ms shutdown bound (default 1,000 ms) is divided between EOF and SIGTERM grace, and the final SIGKILL evidence wait is independently bounded (default 1,000 ms).
 * @returns {(launch: {command: string, args: readonly string[]}) => ChildProcessTransport} Transport factory.
 * @throws {TypeError} When any platform, queue, or teardown option exceeds its fixed bound.
 */
export function createChildProcessTransportFactory(options = {}) {
    const spawnProcess = typeof options.spawnProcess === 'function' ? options.spawnProcess : spawn
    const platform = options.platform ?? process.platform
    const elevateDevelopmentService = options.elevateDevelopmentService ?? false
    const sptiDiagnostics = options.sptiDiagnostics ?? false
    if (typeof sptiDiagnostics !== 'boolean' || (sptiDiagnostics && (platform !== 'win32' || typeof options.onSptiDiagnostic !== 'function'))) throw new TypeError('service-spti-options-invalid')
    let diagnosticGeneration = 0
    const maxQueueCount = options.maxQueueCount ?? 64
    const maxQueueBytes = options.maxQueueBytes ?? 1_048_576
    const shutdownTimeoutMs = options.shutdownTimeoutMs ?? 1_000
    const forceKillTimeoutMs = options.forceKillTimeoutMs ?? 1_000
    if (!['darwin', 'win32', 'linux'].includes(platform) || typeof elevateDevelopmentService !== 'boolean' || (elevateDevelopmentService && platform === 'win32') || !Number.isInteger(maxQueueCount) || maxQueueCount < 1 || maxQueueCount > 1024 || !Number.isInteger(maxQueueBytes) || maxQueueBytes < 64 || maxQueueBytes > 16_777_216 || !Number.isInteger(shutdownTimeoutMs) || shutdownTimeoutMs < 1 || shutdownTimeoutMs > 10_000 || !Number.isInteger(forceKillTimeoutMs) || forceKillTimeoutMs < 1 || forceKillTimeoutMs > 10_000) {
        throw new TypeError('service-transport-bounds-invalid')
    }

    /**
     * Spawns the exact resolved executable with the exact fixed argument tuple.
     * @param {{command: string, args: readonly string[]}} launch - Main-owned launch descriptor.
     * @returns {ChildProcessTransport} Minimal child transport.
     */
    function createTransport(launch) {
        if (!isAbsolute(launch.command) || launch.args !== DEVICE_SERVICE_ARGUMENTS) {
            throw new TypeError('service-launch-contract-invalid')
        }
        const command = elevateDevelopmentService ? '/usr/bin/sudo' : launch.command
        const args = elevateDevelopmentService ? ['-n', '--', launch.command, ...launch.args] : [...launch.args]
        const child = spawnProcess(command, args, {
            env: { ...createServiceEnvironment(platform), ...(sptiDiagnostics ? { OPENRDX_SPTI_DIAGNOSTICS: '1' } : {}) },
            stdio: ['pipe', 'pipe', 'pipe'],
            windowsHide: true
        })
        const transport = new ChildProcessTransport(child, { forceKillTimeoutMs, maxQueueBytes, maxQueueCount, shutdownTimeoutMs, sptiDiagnostics })
        const generation = ++diagnosticGeneration
        /** @param {string} line - Already allowlisted metadata. @returns {Promise<void>} Contains optional sink failures. */
        async function handleSptiDiagnostic(line) {
            try {
                await options.onSptiDiagnostic(line, generation)
            } catch {
                /* Never change native operation outcomes for optional tracing. */
            }
        }
        if (sptiDiagnostics) transport.on('spti-diagnostic', handleSptiDiagnostic)
        return transport
    }

    return createTransport
}

/**
 * Selects the only permitted service transport for the runtime context.
 * Packaged production connects to the privileged endpoint and never spawns or
 * falls back; explicit development/tests retain the bounded stdio child.
 * Development alone forwards the explicit `sptiDiagnostics`/`onSptiDiagnostic`
 * capture options; packaged runtimes ignore both without opening a diagnostic sink.
 * @param {{isPackaged: boolean, platform?: 'darwin'|'win32'|'linux', elevateDevelopmentService?: boolean, spawnProcess?: Function, connectEndpoint?: Function, connectTimeoutMs?: number, teardownTimeoutMs?: number, maxBufferedBytes?: number, timers?: {setTimeout: Function, clearTimeout: Function}, verifyWindowsServerIdentity?: Function, windowsClientAddonPath?: string}} options - Main-owned runtime and injectable boundary.
 * @returns {Function} Exact transport factory for this runtime.
 * @throws {TypeError} When the production/development selector is ambiguous.
 */
export function createDeviceServiceTransportFactory(options) {
    if (typeof options?.isPackaged !== 'boolean') {
        throw new TypeError('service-runtime-mode-invalid')
    }
    if (options.isPackaged) {
        return createPrivilegedEndpointTransportFactory({
            connectEndpoint: options.connectEndpoint,
            connectTimeoutMs: options.connectTimeoutMs,
            maxBufferedBytes: options.maxBufferedBytes,
            platform: options.platform,
            teardownTimeoutMs: options.teardownTimeoutMs,
            timers: options.timers,
            verifyWindowsServerIdentity: options.verifyWindowsServerIdentity,
            windowsClientAddonPath: options.windowsClientAddonPath
        })
    }
    return createChildProcessTransportFactory({
        elevateDevelopmentService: options.elevateDevelopmentService,
        platform: options.platform,
        spawnProcess: options.spawnProcess,
        sptiDiagnostics: options.sptiDiagnostics,
        onSptiDiagnostic: options.onSptiDiagnostic
    })
}

/** Deterministic phase-one transport that proves protocol readiness but no hardware. */
class NoDeviceTransport extends EventEmitter {
    #closed = false
    #decoder
    #maxFrameBytes
    #listRevision = 0
    #platform
    #schedule

    /**
     * Creates a no-device protocol adapter for one host platform.
     * @param {{platform: 'darwin'|'win32'|'linux', maxFrameBytes: number, schedule: (callback: Function) => void}} options - Adapter dependencies.
     */
    constructor({ platform, maxFrameBytes, schedule }) {
        super()
        this.#platform = platform
        this.#maxFrameBytes = maxFrameBytes
        this.#decoder = new FramedJsonDecoder(maxFrameBytes)
        this.#schedule = schedule
    }

    /**
     * Decodes one main request and schedules a deterministic bounded response.
     * @param {Buffer} frame - Main-owned framed request.
     * @returns {boolean} True while the adapter remains open.
     */
    write(frame) {
        if (this.#closed) {
            return false
        }
        let messages
        try {
            messages = this.#decoder.push(frame)
        } catch {
            this.#scheduleError()
            return false
        }
        for (const message of messages) {
            this.#handleMessage(message)
        }
        return true
    }

    /**
     * Closes the adapter without emitting an unexpected crash.
     * @returns {{confirmed: true}} Confirms deterministic in-memory closure.
     */
    close() {
        this.#closed = true
        return { confirmed: true }
    }

    /**
     * Handles only the fixed handshake and narrow published request methods.
     * @param {object} message - Decoded main-owned message.
     * @returns {void} Completes after scheduling a response or generic error.
     */
    #handleMessage(message) {
        if (message.type === 'handshake-request' && message.protocolVersion === SERVICE_PROTOCOL_VERSION && Object.keys(message).length === 2) {
            this.#scheduleMessage({
                type: 'handshake',
                protocolVersion: SERVICE_PROTOCOL_VERSION,
                serviceVersion: 'phase1-no-device',
                platform: this.#platform,
                mode: 'no-device',
                privileged: false,
                platformCapability: { state: 'transport-unavailable', reason: 'native-service-not-implemented' }
            })
            return
        }
        if (message.type !== 'request' || message.protocolVersion !== SERVICE_PROTOCOL_VERSION || typeof message.requestId !== 'string' || typeof message.method !== 'string') {
            this.#scheduleError()
            return
        }

        switch (message.method) {
            case 'devices-list':
                this.#scheduleResponse(message.requestId, { ok: true, listRevision: this.#listRevision, devices: [] })
                break
            case 'devices-scan':
                this.#listRevision += 1
                this.#scheduleMessage({ type: 'event', channel: 'device', event: { type: 'list', listRevision: this.#listRevision, devices: [] } })
                this.#scheduleResponse(message.requestId, { ok: true })
                break
            case 'operation-start':
            case 'operation-cancel':
                this.#scheduleResponse(message.requestId, { ok: false, reason: 'transport-unavailable' })
                break
            default:
                this.#scheduleResponse(message.requestId, { ok: false, reason: 'unsupported-request' })
        }
    }

    /**
     * Schedules one successful wire response containing a strict public result.
     * @param {string} requestId - Matching request identity.
     * @param {object} result - Safe public response.
     * @returns {void} Completes after scheduling.
     */
    #scheduleResponse(requestId, result) {
        this.#scheduleMessage({ type: 'response', requestId, ok: true, result })
    }

    /**
     * Schedules one framed inbound message after the client's current write turn.
     * @param {object} message - Safe service message.
     * @returns {void} Completes after scheduling.
     */
    #scheduleMessage(message) {
        const frame = encodeServiceFrame(message, this.#maxFrameBytes)

        /**
         * Emits the prepared frame only if the adapter is still open.
         * @returns {void} Completes after conditional delivery.
         */
        const deliver = () => {
            if (!this.#closed) {
                this.emit('data', frame)
            }
        }
        this.#schedule(deliver)
    }

    /**
     * Schedules a generic transport failure without retaining raw input.
     * @returns {void} Completes after scheduling.
     */
    #scheduleError() {
        /** Emits only a generic transport error. */
        const deliverError = () => this.emit('error')
        this.#schedule(deliverError)
    }
}

/**
 * Creates the explicit phase-one no-device transport factory. This is a
 * deliberate adapter, never a fallback for failed native executable launch.
 * @param {{platform?: 'darwin'|'win32'|'linux', maxFrameBytes?: number, schedule?: (callback: Function) => void}} [options] - Deterministic adapter options.
 * @returns {(launch: {command: string, args: readonly string[]}) => NoDeviceTransport} Transport factory.
 */
export function createNoDeviceTransportFactory(options = {}) {
    const platform = options.platform ?? process.platform
    const maxFrameBytes = options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES
    const schedule = typeof options.schedule === 'function' ? options.schedule : queueMicrotask
    if (!['darwin', 'win32', 'linux'].includes(platform)) {
        throw new RangeError('unsupported-platform')
    }

    /**
     * Creates one adapter only for the same immutable launch contract as native.
     * @param {{command: string, args: readonly string[]}} launch - Main-owned launch descriptor.
     * @returns {NoDeviceTransport} New deterministic adapter.
     */
    function createTransport(launch) {
        if (!isAbsolute(launch.command) || launch.args !== DEVICE_SERVICE_ARGUMENTS) {
            throw new TypeError('service-launch-contract-invalid')
        }
        return new NoDeviceTransport({ platform, maxFrameBytes, schedule })
    }

    return createTransport
}
