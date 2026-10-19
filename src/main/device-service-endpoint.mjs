// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { EventEmitter } from 'node:events'
import { connect as connectSocket } from 'node:net'

import { createMacOsNativeEndpointConnector } from './macos-native-endpoint.mjs'
import { createWindowsNativeEndpointConnector } from './windows-native-endpoint.mjs'

const ENDPOINTS = Object.freeze({
    darwin: 'openrdx-macos-native',
    linux: '/run/openrdx/openrdx-hardware.sock',
    win32: String.raw`\\.\pipe\OpenRDXHardwareService`
})
const NATIVE_ENDPOINT_FAILURE_REASONS = new Set(['service-not-installed', 'insufficient-permission', 'service-identity-unverified'])

/** Transport for one access-controlled native-service socket or named pipe. */
class PrivilegedEndpointTransport extends EventEmitter {
    #closePromise = null
    #closed = false
    #connectTimer
    #failed = false
    #identityVerified
    #maxBufferedBytes
    #ready = false
    #socket
    #terminalCloseObserved = false
    #teardownTimeoutMs
    #timers
    #verifyServerIdentity

    /**
     * Owns one already-created local endpoint socket and bounded lifecycle.
     * @param {object} socket - Node stream connected to the fixed local endpoint.
     * @param {{connectTimeoutMs: number, teardownTimeoutMs: number, maxBufferedBytes: number, platform: 'darwin'|'win32'|'linux', timers: {setTimeout: Function, clearTimeout: Function}, verifyWindowsServerIdentity?: Function}} bounds - Fixed lifecycle, identity, and buffering bounds.
     */
    constructor(socket, bounds) {
        super()
        if (socket === null || typeof socket !== 'object' || typeof socket.write !== 'function' || typeof socket.end !== 'function' || typeof socket.destroy !== 'function' || typeof socket.on !== 'function' || typeof socket.once !== 'function') {
            throw new TypeError('service-endpoint-socket-invalid')
        }
        this.#socket = socket
        this.#maxBufferedBytes = bounds.maxBufferedBytes
        this.#teardownTimeoutMs = bounds.teardownTimeoutMs
        this.#timers = bounds.timers
        this.#identityVerified = bounds.platform === 'linux'
        this.#verifyServerIdentity = bounds.platform === 'darwin' ? (socket) => socket.serverIdentityVerified?.() === true : bounds.verifyWindowsServerIdentity
        if (bounds.platform !== 'linux') socket.pause?.()

        /** @param {Buffer} chunk - Native framed response bytes. @returns {void} Forwards the bytes without interpretation. */
        const handleData = (chunk) => {
            if (this.#closed || this.#failed) return
            if (!this.#identityVerified) {
                this.#signalFailure({ reason: 'service-identity-unverified' })
                return
            }
            this.emit('data', chunk)
        }
        /** @returns {Promise<void>} Verifies native server authority before admitting protocol bytes. */
        const handleConnect = async () => {
            if (this.#closed || this.#failed || socket.destroyed === true) return
            if (bounds.platform !== 'linux') {
                let verified = false
                try {
                    // macOS native connect already proves the retained socket;
                    // preserve ordering when the addon delivers immediate data.
                    verified = bounds.platform === 'darwin' ? this.#verifyServerIdentity(socket) === true : (await this.#verifyServerIdentity?.(socket)) === true
                } catch {
                    verified = false
                }
                if (!verified) {
                    this.#signalFailure({ reason: 'service-identity-unverified' })
                    return
                }
                if (this.#closed || this.#failed || socket.destroyed === true) return
                this.#identityVerified = true
                socket.resume?.()
            }
            this.#clearConnectTimer()
            this.#ready = true
            this.emit('ready')
        }
        /** @param {object} [error] - Optional local socket error. @returns {void} Converts failure into one sanitized transport signal. */
        const handleFailure = (error) => this.#signalFailure(error)
        /** @returns {void} Records terminal transport evidence independently of destroy intent. */
        const handleClose = () => {
            if (this.#terminalCloseObserved) return
            this.#terminalCloseObserved = true
            this.#clearConnectTimer()
            if (!this.#closed) this.#signalFailure()
        }

        socket.on('data', handleData)
        socket.once('connect', handleConnect)
        socket.once('error', handleFailure)
        socket.once('close', handleClose)
        this.#connectTimer = this.#timers.setTimeout(handleFailure, bounds.connectTimeoutMs)
    }

    /** @returns {true} Declares support for the unchanged protocol shutdown request. */
    get supportsGracefulShutdown() {
        return true
    }

    /** @returns {boolean} True only after the local endpoint is connected and identity-gated. */
    get isReady() {
        return this.#ready
    }

    /**
     * Writes one already-framed bounded request to the local endpoint.
     * @param {Buffer} frame - Length-prefixed service request.
     * @returns {{ok: true}|{ok: false, reason: string}} Stable admission result.
     */
    write(frame) {
        const buffered = Number.isSafeInteger(this.#socket.writableLength) ? this.#socket.writableLength : 0
        if (!this.#ready || this.#closed || this.#failed || this.#socket.destroyed === true) {
            return { ok: false, reason: 'service-unavailable' }
        }
        if (!Buffer.isBuffer(frame) || frame.length === 0 || frame.length > this.#maxBufferedBytes || buffered + frame.length > this.#maxBufferedBytes) {
            return { ok: false, reason: 'service-saturated' }
        }
        try {
            const accepted = this.#socket.write(frame)
            // Node Unix sockets use false for accepted backpressure. The direct
            // native addon has no queue and uses false only for a failed write.
            if (!this.#identityVerified || (accepted === false && this.#verifyServerIdentity !== undefined)) {
                this.#signalFailure()
                return { ok: false, reason: 'service-unavailable' }
            }
            return { ok: true }
        } catch {
            this.#signalFailure()
            return { ok: false, reason: 'service-unavailable' }
        }
    }

    /**
     * Ends the connection and waits a bounded interval for close evidence.
     * @returns {Promise<{confirmed: boolean, reason?: string}>} Teardown confidence.
     */
    close() {
        if (this.#terminalCloseObserved) return Promise.resolve({ confirmed: true })
        if (this.#closePromise !== null) return this.#closePromise
        this.#closed = true
        this.#clearConnectTimer()
        this.#closePromise = new Promise((resolve) => {
            let settled = false
            /** @param {{confirmed: boolean, reason?: string}} result - Sanitized teardown result. @returns {void} Resolves once. */
            const settle = (result) => {
                if (settled) return
                settled = true
                this.#timers.clearTimeout(timer)
                if (result.confirmed !== true) this.#closePromise = null
                resolve(result)
            }
            /** @returns {void} Forces local release after the endpoint close bound. */
            const expire = () => {
                this.#socket.destroy()
                settle({ confirmed: false, reason: 'service-teardown-unconfirmed' })
            }
            const timer = this.#timers.setTimeout(expire, this.#teardownTimeoutMs)
            this.#socket.once('close', () => {
                this.#terminalCloseObserved = true
                settle({ confirmed: true })
            })
            this.#socket.end()
        })
        return this.#closePromise
    }

    /** @returns {void} Clears the current connection deadline. */
    #clearConnectTimer() {
        if (this.#connectTimer !== null) {
            this.#timers.clearTimeout(this.#connectTimer)
            this.#connectTimer = null
        }
    }

    /** @param {object} [error] - Optional native socket error. @returns {void} Publishes one sanitized endpoint failure at most once. */
    #signalFailure(error) {
        if (this.#closed || this.#failed) return
        this.#failed = true
        this.#clearConnectTimer()
        this.#socket.destroy()
        const reason = NATIVE_ENDPOINT_FAILURE_REASONS.has(error?.reason) ? error.reason : error?.code === 'ENOENT' ? 'service-not-installed' : ['EACCES', 'EPERM'].includes(error?.code) ? 'insufficient-permission' : 'service-exited'
        this.emit('error', { reason })
    }
}

/**
 * Returns the fixed production endpoint for one supported host.
 * @param {'darwin'|'win32'|'linux'} platform - Node platform identifier.
 * @returns {string} macOS native logical token (sealed mode selects its path), or the fixed Unix path/pipe name on other hosts.
 * @throws {RangeError} For unsupported hosts.
 */
export function resolvePrivilegedServiceEndpoint(platform) {
    const endpoint = ENDPOINTS[platform]
    if (endpoint === undefined) throw new RangeError('unsupported-platform')
    return endpoint
}

/**
 * Creates a production-only fixed local endpoint transport factory.
 * @param {{platform?: 'darwin'|'win32'|'linux', connectEndpoint?: Function, connectTimeoutMs?: number, teardownTimeoutMs?: number, maxBufferedBytes?: number, timers?: {setTimeout: Function, clearTimeout: Function}, verifyWindowsServerIdentity?: Function, windowsClientAddonPath?: string, macosClientAddonPath?: string}} [options] - Main-owned connection dependencies, identity verifier, and bounds.
 * @returns {(launch: {command: string, args: readonly string[]}) => PrivilegedEndpointTransport} Endpoint-only factory.
 * @throws {TypeError|RangeError} For invalid bounds or platform.
 */
export function createPrivilegedEndpointTransportFactory(options = {}) {
    const platform = options.platform ?? process.platform
    const nativeWindowsConnector = platform === 'win32' && options.connectEndpoint === undefined ? createWindowsNativeEndpointConnector({ addonPath: options.windowsClientAddonPath }) : null
    const nativeMacOsConnector = platform === 'darwin' && options.connectEndpoint === undefined ? createMacOsNativeEndpointConnector({ addonPath: options.macosClientAddonPath }) : null
    const connectEndpoint = options.connectEndpoint ?? nativeWindowsConnector ?? nativeMacOsConnector ?? connectSocket
    // Native clients verify the complete runtime before seven-second peer proof.
    // Windows also waits up to 45s for the service's independent runtime proof
    // and backend preparation. Retain one second of outer watchdog margin;
    // the protocol deadline starts only after verified transport readiness.
    const maximumConnectTimeoutMs = platform === 'win32' ? 98_000 : platform === 'darwin' ? 53_000 : 10_000
    const connectTimeoutMs = options.connectTimeoutMs ?? (platform === 'linux' ? 2_000 : maximumConnectTimeoutMs)
    const teardownTimeoutMs = options.teardownTimeoutMs ?? 1_000
    const maxBufferedBytes = options.maxBufferedBytes ?? 1_048_576
    const timers = options.timers ?? Object.freeze({ setTimeout, clearTimeout })
    const verifyWindowsServerIdentity = options.verifyWindowsServerIdentity ?? (nativeWindowsConnector === null ? undefined : (socket) => socket.serverIdentityVerified())
    const path = resolvePrivilegedServiceEndpoint(platform)
    if (typeof connectEndpoint !== 'function' || (verifyWindowsServerIdentity !== undefined && typeof verifyWindowsServerIdentity !== 'function') || !Number.isInteger(connectTimeoutMs) || connectTimeoutMs < 1 || connectTimeoutMs > maximumConnectTimeoutMs || !Number.isInteger(teardownTimeoutMs) || teardownTimeoutMs < 1 || teardownTimeoutMs > 10_000 || !Number.isInteger(maxBufferedBytes) || maxBufferedBytes < 64 || maxBufferedBytes > 16_777_216 || typeof timers.setTimeout !== 'function' || typeof timers.clearTimeout !== 'function') {
        throw new TypeError('service-endpoint-bounds-invalid')
    }

    /**
     * Connects only to the selected fixed endpoint; launch command/arguments are
     * never executed. Windows passes the main-owned executable identity only to
     * the direct native verifier; a missing endpoint cannot become a child fallback.
     * @returns {PrivilegedEndpointTransport} Owned bounded endpoint transport.
     */
    function createTransport(launch) {
        const socket = connectEndpoint(platform === 'darwin' ? { endpoint: path } : platform === 'win32' ? { path, expectedExecutable: launch?.command } : { path })
        socket.setNoDelay?.(true)
        return new PrivilegedEndpointTransport(socket, {
            connectTimeoutMs,
            maxBufferedBytes,
            teardownTimeoutMs,
            timers,
            platform,
            verifyWindowsServerIdentity
        })
    }

    return createTransport
}
