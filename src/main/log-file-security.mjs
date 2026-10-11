// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { constants } from 'node:fs'
import { chmod, lstat, mkdir, open, rename, rm } from 'node:fs/promises'

/**
 * Closes an optional owned descriptor without replacing the primary I/O outcome.
 * @param {object|undefined|null} handle - Open handle or absent descriptor.
 * @returns {Promise<void>} Resolves after best-effort cleanup, including close failure.
 */
export async function closeLogHandle(handle) {
    try {
        await handle?.close?.()
    } catch {
        // Cleanup failure must not hide rejected security proof or persistence failure.
    }
}

/**
 * Checks whether an I/O error means an owned path is absent.
 * @param {unknown} error - Candidate filesystem error.
 * @returns {boolean} True only for ENOENT.
 */
function isMissing(error) {
    return error !== null && typeof error === 'object' && error.code === 'ENOENT'
}

/**
 * Checks the minimal FileHandle surface required by EventLogger.
 * @param {unknown} handle - Candidate verified file handle.
 * @returns {boolean} True when descriptor operations are present.
 */
function isUsableHandle(handle) {
    return handle !== null && typeof handle === 'object' && typeof handle.stat === 'function' && typeof handle.close === 'function' && typeof handle.read === 'function' && typeof handle.writeFile === 'function'
}

/** POSIX descriptor implementation using O_NOFOLLOW and enforced owner modes. */
class PosixLogFileSecurity {
    /**
     * Creates and verifies the logger directory without following a final symlink.
     * @param {string} directory - Exact main-owned log directory.
     * @returns {Promise<void>} Resolves after directory verification and chmod.
     */
    async prepareDirectory(directory) {
        await mkdir(directory, { mode: 0o700, recursive: true })
        const metadata = await lstat(directory)
        if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
            throw new Error('unsafe-log-directory')
        }
        await chmod(directory, 0o700)
    }

    /**
     * Opens and verifies an append descriptor with no-follow semantics.
     * @param {string} path - Exact logger-owned current path.
     * @returns {Promise<import('node:fs/promises').FileHandle>} Private regular-file handle.
     */
    async openAppend(path) {
        const handle = await open(path, constants.O_CREAT | constants.O_APPEND | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600)
        try {
            const metadata = await handle.stat()
            if (!metadata.isFile()) throw new Error('unsafe-log-file')
            await handle.chmod(0o600)
            return handle
        } catch (error) {
            await closeLogHandle(handle)
            throw error
        }
    }

    /**
     * Opens and hardens an existing read descriptor without following symlinks.
     * @param {string} path - Exact logger-owned current or backup path.
     * @returns {Promise<import('node:fs/promises').FileHandle>} Private regular-file handle.
     */
    async openRead(path) {
        const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
        try {
            const metadata = await handle.stat()
            if (!metadata.isFile()) throw new Error('unsafe-log-file')
            await handle.chmod(0o600)
            return handle
        } catch (error) {
            await closeLogHandle(handle)
            throw error
        }
    }

    /**
     * Removes an existing backup only after no-follow type verification.
     * @param {string} path - Exact logger-owned backup path.
     * @returns {Promise<void>} Resolves after absence or verified removal.
     */
    async removeFile(path) {
        try {
            const metadata = await lstat(path)
            if (!metadata.isFile() || metadata.isSymbolicLink()) throw new Error('unsafe-log-file')
            await chmod(path, 0o600)
            await rm(path)
        } catch (error) {
            if (!isMissing(error)) throw error
        }
    }

    /**
     * Renames one verified owned file and reopens the target without following.
     * @param {string} from - Exact verified current path.
     * @param {string} to - Exact absent backup path.
     * @returns {Promise<void>} Resolves after target verification.
     */
    async renameFile(from, to) {
        await rename(from, to)
        const handle = await this.openRead(to)
        await handle.close()
    }
}

/**
 * Windows security boundary. Node does not expose a portable no-follow Windows
 * handle flag or DACL builder, so a native main-owned adapter must return proof
 * for each exact path/handle. Absence or incomplete proof fails closed.
 */
class WindowsLogFileSecurity {
    #adapter

    /**
     * Creates the Windows verifier around a packaged native adapter.
     * @param {unknown} adapter - Injected Windows handle/DACL implementation.
     */
    constructor(adapter) {
        this.#adapter = adapter
    }

    /**
     * Creates/verifies a non-reparse directory with a user-only DACL.
     * @param {string} directory - Exact main-owned log directory.
     * @returns {Promise<void>} Resolves only with complete native proof.
     */
    async prepareDirectory(directory) {
        const adapter = this.#requireAdapter()
        const proof = await adapter.ensurePrivateDirectory({ path: directory, requireReparseRejection: true, requireUserOnlyDacl: true })
        if (proof?.directory !== true || proof.reparsePoint !== false || proof.userOnlyDacl !== true) {
            throw new Error('windows-log-directory-unverified')
        }
    }

    /**
     * Opens an append handle with native reparse and DACL proof.
     * @param {string} path - Exact logger-owned current path.
     * @returns {Promise<object>} Verified file handle.
     */
    async openAppend(path) {
        return this.#openVerified(path, 'append', true)
    }

    /**
     * Opens a read handle with native reparse and DACL proof.
     * @param {string} path - Exact logger-owned current or backup path.
     * @returns {Promise<object>} Verified file handle.
     */
    async openRead(path) {
        return this.#openVerified(path, 'read', false)
    }

    /**
     * Removes a backup only with native reparse/DACL verification.
     * @param {string} path - Exact logger-owned backup path.
     * @returns {Promise<void>} Resolves only after verified absence/removal.
     */
    async removeFile(path) {
        const adapter = this.#requireAdapter()
        const proof = await adapter.removeVerifiedFile({ path, requireReparseRejection: true, requireUserOnlyDacl: true })
        if (proof?.removed !== true || proof.reparsePoint !== false || proof.userOnlyDacl !== true) {
            throw new Error('windows-log-remove-unverified')
        }
    }

    /**
     * Renames one Windows log while retaining native no-follow and DACL proof.
     * @param {string} from - Exact current path.
     * @param {string} to - Exact backup path.
     * @returns {Promise<void>} Resolves only with target proof.
     */
    async renameFile(from, to) {
        const adapter = this.#requireAdapter()
        const proof = await adapter.renameVerifiedFile({ from, to, requireNoFollowHandle: true, requireReparseRejection: true, requireUserOnlyDacl: true })
        if (proof?.noFollowVerified !== true || proof.reparsePoint !== false || proof.userOnlyDacl !== true) {
            throw new Error('windows-log-rename-unverified')
        }
    }

    /**
     * Returns the complete adapter or rejects logging on Windows.
     * @returns {object} Complete injected native adapter.
     * @throws {Error} When native verification is unavailable.
     */
    #requireAdapter() {
        const adapter = this.#adapter
        if (adapter === null || typeof adapter !== 'object' || typeof adapter.ensurePrivateDirectory !== 'function' || typeof adapter.openVerifiedFile !== 'function' || typeof adapter.removeVerifiedFile !== 'function' || typeof adapter.renameVerifiedFile !== 'function') {
            throw new Error('windows-log-security-unavailable')
        }
        return adapter
    }

    /**
     * Validates the native proof attached to one exact Windows handle.
     * @param {string} path - Exact logger-owned file path.
     * @param {'append'|'read'} access - Narrow descriptor purpose.
     * @param {boolean} create - Whether creation is allowed.
     * @returns {Promise<object>} Verified usable handle.
     */
    async #openVerified(path, access, create) {
        const adapter = this.#requireAdapter()
        const proof = await adapter.openVerifiedFile({ access, create, path, requireNoFollowHandle: true, requireReparseRejection: true, requireUserOnlyDacl: true })
        if (proof?.noFollowVerified !== true || proof.reparsePoint !== false || proof.userOnlyDacl !== true || !isUsableHandle(proof.handle)) {
            await closeLogHandle(proof?.handle)
            throw new Error('windows-log-handle-unverified')
        }
        const metadata = await proof.handle.stat()
        if (!metadata.isFile()) {
            await closeLogHandle(proof.handle)
            throw new Error('unsafe-log-file')
        }
        return proof.handle
    }
}

/**
 * Creates the platform-specific logger file-security implementation.
 * @param {{platform?: string, windowsSecurityAdapter?: unknown}} [options] - Platform and optional native Windows adapter.
 * @returns {PosixLogFileSecurity|WindowsLogFileSecurity} Fail-closed platform boundary.
 * @throws {RangeError} When the host platform is unsupported.
 */
export function createLogFileSecurity(options = {}) {
    const platform = options.platform ?? process.platform
    if (platform === 'win32') return new WindowsLogFileSecurity(options.windowsSecurityAdapter ?? null)
    if (['darwin', 'linux'].includes(platform)) return new PosixLogFileSecurity()
    throw new RangeError('unsupported-log-platform')
}
