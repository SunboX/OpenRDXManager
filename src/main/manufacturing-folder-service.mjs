// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { lstat, mkdir } from 'node:fs/promises'

/** Opens the actual user-owned manufacturing backup directory in the system file manager. */
export class ManufacturingFolderService {
    #options
    #pending = false
    #prepared = false

    /** @param {{directory: string|Function, prepare: Function, openPath: Function, createDirectory?: boolean}} options - Main-owned location, native preparation gate, and shell boundary. Windows directories are created only by the private native store. */
    constructor(options) {
        this.#options = options
    }

    /** @returns {Promise<object>} Path-free result; failures never disable hardware or consume restore confirmations. */
    async open() {
        if (this.#pending) return { ok: false, reason: 'operation-in-progress' }
        this.#pending = true
        try {
            const { openPath, prepare } = this.#options
            if (!this.#prepared) {
                if ((await prepare()).ok !== true) return { ok: false, reason: 'manufacturing-folder-open-failed' }
                this.#prepared = true
            }
            const directory = typeof this.#options.directory === 'function' ? this.#options.directory() : this.#options.directory
            if (this.#options.createDirectory !== false) await mkdir(directory, { recursive: true, mode: 0o700 })
            const info = await lstat(directory)
            if (!info.isDirectory() || info.isSymbolicLink() || (process.platform !== 'win32' && (info.uid !== process.getuid() || (info.mode & 0o077) !== 0))) throw new Error('Private backup directory required')
            return (await openPath(directory)) === '' ? { ok: true } : { ok: false, reason: 'manufacturing-folder-open-failed' }
        } catch {
            return { ok: false, reason: 'manufacturing-folder-open-failed' }
        } finally {
            this.#pending = false
        }
    }
}
