// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { EventEmitter } from 'node:events'
import { createRequire } from 'node:module'
import { isAbsolute } from 'node:path'

const require = createRequire(import.meta.url)

/** Narrow EventEmitter adapter around the handle-free Windows N-API boundary. */
class WindowsNativeEndpointSocket extends EventEmitter {
    #connection = null
    #destroyRequested = false
    #errorEmitted = false
    #identityVerified = false
    #nativeClosed = false

    /**
     * Loads one fixed packaged addon and begins exact service verification.
     * @param {{addonPath: string, expectedExecutable: string, loadAddon?: Function}} options - Main-owned absolute native paths and an optional test loader.
     */
    constructor(options) {
        super()
        this.destroyed = false
        this.writableLength = 0
        if (!isAbsolute(options.addonPath) || !isAbsolute(options.expectedExecutable)) {
            throw new TypeError('windows-client-path-invalid')
        }
        const loadAddon = options.loadAddon ?? require
        if (typeof loadAddon !== 'function') throw new TypeError('windows-client-addon-loader-invalid')
        const addon = loadAddon(options.addonPath)
        if (addon === null || typeof addon !== 'object' || typeof addon.connect !== 'function') {
            throw new TypeError('windows-client-addon-invalid')
        }
        /** @param {{type: string, data?: Buffer, reason?: string}} event - Sanitized native transport event. @returns {void} Forwards only the fixed event vocabulary. */
        const handleEvent = (event) => {
            if (this.#nativeClosed || event === null || typeof event !== 'object') return
            if (event.type === 'connect') {
                if (this.#destroyRequested || this.#errorEmitted || this.#identityVerified) return
                this.#identityVerified = true
                this.emit('connect')
            } else if (event.type === 'data' && !this.#destroyRequested && this.#identityVerified && Buffer.isBuffer(event.data)) {
                this.emit('data', event.data)
            } else if (event.type === 'error') {
                if (this.#errorEmitted) return
                this.#errorEmitted = true
                const allowed = new Set(['service-not-installed', 'insufficient-permission', 'service-identity-unverified', 'service-exited'])
                const error = new Error('windows-client-native-failure')
                error.reason = allowed.has(event.reason) ? event.reason : 'service-exited'
                this.emit('error', error)
            } else if (event.type === 'close') {
                this.#nativeClosed = true
                this.#identityVerified = false
                this.destroyed = true
                this.emit('close')
            } else {
                this.destroy()
                if (!this.#errorEmitted) {
                    this.#errorEmitted = true
                    const error = new Error('windows-client-native-contract-invalid')
                    error.reason = 'service-identity-unverified'
                    this.emit('error', error)
                }
            }
        }
        this.#connection = addon.connect(options.expectedExecutable, handleEvent)
        if (this.#connection === null || typeof this.#connection !== 'object' || typeof this.#connection.write !== 'function' || typeof this.#connection.destroy !== 'function' || typeof this.#connection.end !== 'function') {
            this.#connection = null
            throw new TypeError('windows-client-addon-contract-invalid')
        }
    }

    /** @returns {boolean} True only after the native SCM/PID/file/token proof. */
    serverIdentityVerified() {
        return this.#identityVerified
    }

    /** @param {Buffer} frame - One bounded framed request. @returns {boolean} Native bounded-write result. */
    write(frame) {
        return this.destroyed || !this.#identityVerified || !Buffer.isBuffer(frame) ? false : this.#connection.write(frame) === true
    }

    /** @returns {void} Requests bounded native cancellation and close. */
    destroy() {
        if (this.#destroyRequested || this.#nativeClosed) return
        this.#destroyRequested = true
        this.destroyed = true
        this.#connection?.destroy()
    }

    /** @returns {void} Ends the exact native connection. */
    end() {
        if (this.destroyed) return
        this.#connection?.end()
    }

    /** @returns {void} Named pipes do not expose a TCP delay mode. */
    setNoDelay() {}

    /** @returns {void} Native reads start only after exact identity proof. */
    pause() {}

    /** @returns {void} Native reads are already identity-gated. */
    resume() {}
}

/**
 * Creates the production Windows named-pipe connector backed by N-API.
 * @param {{addonPath: string, loadAddon?: Function}} options - Fixed packaged addon path and optional test loader.
 * @returns {(options: {path: string, expectedExecutable: string}) => WindowsNativeEndpointSocket} Narrow connector.
 */
export function createWindowsNativeEndpointConnector(options) {
    if (options === null || typeof options !== 'object' || !isAbsolute(options.addonPath) || (options.loadAddon !== undefined && typeof options.loadAddon !== 'function')) {
        throw new TypeError('windows-client-addon-path-invalid')
    }
    /** @param {{path: string, expectedExecutable: string}} connection - Fixed endpoint and service identity. @returns {WindowsNativeEndpointSocket} Owned native adapter. */
    function connect(connection) {
        if (connection?.path !== String.raw`\\.\pipe\OpenRDXHardwareService` || !isAbsolute(connection.expectedExecutable)) {
            throw new TypeError('windows-client-endpoint-invalid')
        }
        return new WindowsNativeEndpointSocket({ addonPath: options.addonPath, expectedExecutable: connection.expectedExecutable, loadAddon: options.loadAddon })
    }
    return connect
}
