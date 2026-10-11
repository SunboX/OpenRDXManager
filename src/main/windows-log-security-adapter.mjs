// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createRequire } from 'node:module'
import { win32 } from 'node:path'

const require = createRequire(import.meta.url)
const maximumRead = 16 * 1024 * 1024 + 16_384 + 1

/** Serializes ownership across complete file lifetimes, including asynchronous reads. */
export class WindowsLogSecurityAdapter {
    #directory
    #current
    #backup
    #addonPath
    #loadAddon
    #root = null
    #tail = Promise.resolve()
    #pending = 0

    /**
     * Captures main-owned roots without loading native code or touching files.
     * @param {{directory: string, addonPath: string, loadAddon?: Function}} options - Fixed logger directory and staged addon.
     */
    constructor({ directory, addonPath, loadAddon = require }) {
        if (typeof directory !== 'string' || typeof addonPath !== 'string' || typeof loadAddon !== 'function') throw new TypeError('windows-log-configuration-invalid')
        this.#directory = directory
        this.#current = win32.join(directory, 'RDXManager.jsonl')
        this.#backup = win32.join(directory, '_RDXManager.bak')
        this.#addonPath = addonPath
        this.#loadAddon = loadAddon
    }

    /** @returns {object} Lazily loads the main-owned native implementation; absence fails closed. */
    #native() {
        if (this.#root === null) {
            const addon = this.#loadAddon(this.#addonPath)
            if (typeof addon?.createLogSecurity !== 'function') throw new Error('windows-log-security-unavailable')
            this.#root = addon.createLogSecurity(this.#directory)
        }
        return this.#root
    }

    /** @returns {Promise<Function>} Acquires bounded FIFO ownership until the returned release function runs. */
    async #acquire() {
        if (this.#pending >= 64) throw new Error('windows-log-resource-limit')
        const previous = this.#tail
        const { promise, resolve } = Promise.withResolvers()
        this.#tail = promise
        this.#pending += 1
        await previous
        let released = false
        /** @returns {void} Releases ownership exactly once, even after cleanup failure. */
        const release = () => {
            if (released) return
            released = true
            this.#pending -= 1
            resolve()
        }
        return release
    }

    /** @param {object} request - Exact platform proof request. @returns {void} Rejects relaxed security requirements. */
    #requireProof(request) {
        if (request?.requireReparseRejection !== true || request.requireUserOnlyDacl !== true) throw new Error('windows-log-proof-required')
    }

    /** @param {object} request - Exact directory and security requirements. @returns {Promise<object>} Native directory proof. */
    async ensurePrivateDirectory(request) {
        this.#requireProof(request)
        if (request.path !== this.#directory) throw new Error('windows-log-path-invalid')
        const release = await this.#acquire()
        try {
            return await this.#native().prepare()
        } finally {
            release()
        }
    }

    /** @param {object} request - Fixed filename, narrow access and complete proof requirements. @returns {Promise<object>} Native proof with a FileHandle-compatible wrapper. */
    async openVerifiedFile(request) {
        this.#requireProof(request)
        const append = request.access === 'append'
        if (request.requireNoFollowHandle !== true || !['append', 'read'].includes(request.access) || request.create !== append || (request.path !== this.#current && request.path !== this.#backup) || (append && request.path !== this.#current)) throw new Error('windows-log-arguments-invalid')
        const release = await this.#acquire()
        try {
            const root = this.#native()
            const proof = append ? await root.openAppend() : await root.openRead(request.path === this.#backup)
            if (proof?.handle === null || typeof proof?.handle !== 'object') throw new Error('windows-log-handle-unverified')
            // The lease stays held until the caller closes the descriptor, so log
            // listing cannot race a critical append or exact-handle rotation.
            return { ...proof, handle: new WindowsLogHandle(proof.handle, release) }
        } catch (error) {
            release()
            throw error
        }
    }

    /** @param {object} request - Exact backup path and security requirements. @returns {Promise<object>} Verified removal or absence. */
    async removeVerifiedFile(request) {
        this.#requireProof(request)
        if (request.path !== this.#backup) throw new Error('windows-log-path-invalid')
        const release = await this.#acquire()
        try {
            return await this.#native().removeBackup()
        } finally {
            release()
        }
    }

    /** @param {object} request - Exact current-to-backup rotation and security requirements. @returns {Promise<object>} Native non-replacing rename proof. */
    async renameVerifiedFile(request) {
        this.#requireProof(request)
        if (request.from !== this.#current || request.to !== this.#backup || request.requireNoFollowHandle !== true) throw new Error('windows-log-path-invalid')
        const release = await this.#acquire()
        try {
            return await this.#native().rotate()
        } finally {
            release()
        }
    }
}

/** Adapts opaque native handles to the minimal asynchronous EventLogger contract. */
class WindowsLogHandle {
    #native
    #release
    #closePromise = null

    /** @param {object} native - Exact opaque file owner. @param {Function} release - Full-lifetime serialization release. */
    constructor(native, release) {
        this.#native = native
        this.#release = release
    }

    /** @returns {void} Rejects new I/O as soon as close is requested. */
    #requireOpen() {
        if (this.#closePromise !== null) throw new Error('windows-log-handle-closed')
    }

    /** @returns {Promise<object>} Verified regular-file metadata without a native handle. */
    async stat() {
        this.#requireOpen()
        const metadata = await this.#native.stat()
        if (metadata?.regular !== true || !Number.isSafeInteger(metadata.size) || metadata.size < 0) throw new Error('windows-log-stat-unverified')
        return {
            size: metadata.size,
            /** @returns {boolean} Reflects the native type proof for this exact descriptor. */
            isFile() {
                return true
            }
        }
    }

    /** @param {Buffer} buffer - Caller-owned output. @param {number} offset - Output start. @param {number} length - Bounded read size. @param {number} position - File offset. @returns {Promise<object>} Copied bounded read result. */
    async read(buffer, offset, length, position) {
        this.#requireOpen()
        if (!Buffer.isBuffer(buffer) || !Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || !Number.isSafeInteger(position) || offset < 0 || length < 0 || position < 0 || length > maximumRead || position > maximumRead || offset > buffer.length || length > buffer.length - offset) throw new Error('windows-log-read-invalid')
        const bytes = await this.#native.read(length, position)
        if (!Buffer.isBuffer(bytes) || bytes.length > length) throw new Error('windows-log-read-unverified')
        bytes.copy(buffer, offset)
        return { bytesRead: bytes.length, buffer }
    }

    /** @param {string|Buffer} data - Already-redacted log bytes. @param {{encoding?: string}} [options] - UTF-8 encoding only. @returns {Promise<void>} Resolves only after native append and FlushFileBuffers. */
    async writeFile(data, options = {}) {
        this.#requireOpen()
        if ((typeof data !== 'string' && !Buffer.isBuffer(data)) || (options.encoding !== undefined && options.encoding !== 'utf8') || Buffer.byteLength(data) > maximumRead) throw new Error('windows-log-write-invalid')
        await this.#native.append(Buffer.from(data))
    }

    /** @returns {Promise<void>} Shares one close, releasing serialization only after native cleanup settles. */
    close() {
        if (this.#closePromise !== null) return this.#closePromise
        /** @returns {Promise<void>} Closes the exact descriptor even when its owner is failing. */
        const closeOwnedHandle = async () => {
            // Publish close ownership before an injected implementation can reenter.
            await Promise.resolve()
            try {
                await this.#native.close()
            } finally {
                this.#release()
            }
        }
        this.#closePromise = closeOwnedHandle()
        return this.#closePromise
    }
}
