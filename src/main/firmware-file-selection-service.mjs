// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomUUID } from 'node:crypto'
import { constants } from 'node:fs'
import { lstat, open, realpath } from 'node:fs/promises'
import { extname, isAbsolute } from 'node:path'

import { englishCatalog } from '../locales/en.mjs'
import { OpenRdxFirmwareManifestError, readOpenRdxFirmwareManifest } from './openrdx-firmware-manifest.mjs'

const ALLOWED_EXTENSIONS = new Set(['.BIP', '.BIN'])
const MAX_FIRMWARE_BYTES = 0xffffff
const MAX_PENDING_TOKENS = 16
const TOKEN_LIFETIME_MS = 5 * 60 * 1000

/** Main-owned local firmware chooser and opaque one-shot file authority. */
export class FirmwareFileSelectionService {
    #clock
    #lstat
    #open
    #pending = new Map()
    #randomUUID
    #realpath
    #showOpenDialog
    #translate

    /**
     * @param {{showOpenDialog?: (options: object) => Promise<object>, translate?: (key: string) => string, clock?: () => number, lstat?: Function, open?: Function, randomUUID?: () => string, realpath?: Function}} [options={}] - Injectable main-process file dependencies.
     */
    constructor(options = {}) {
        this.#clock = typeof options.clock === 'function' ? options.clock : Date.now
        this.#lstat = typeof options.lstat === 'function' ? options.lstat : lstat
        this.#open = typeof options.open === 'function' ? options.open : open
        this.#randomUUID = typeof options.randomUUID === 'function' ? options.randomUUID : randomUUID
        this.#realpath = typeof options.realpath === 'function' ? options.realpath : realpath
        this.#showOpenDialog = typeof options.showOpenDialog === 'function' ? options.showOpenDialog : null
        this.#translate = typeof options.translate === 'function' ? options.translate : (key) => englishCatalog[key] ?? key
    }

    /**
     * Opens one local-file dialog and returns only a bounded opaque token.
     * @returns {Promise<object>} Renderer-safe token response or stable failure.
     */
    async chooseFirmware() {
        if (this.#showOpenDialog === null) return { ok: false, reason: 'firmware-selection-unavailable' }
        this.#expireTokens()
        if (this.#pending.size >= MAX_PENDING_TOKENS) return { ok: false, reason: 'firmware-selection-capacity-exhausted' }

        let selection
        try {
            selection = await this.#showOpenDialog({
                buttonLabel: this.#translate('filePicker.firmware.open'),
                filters: [{ extensions: ['bin', 'BIN', 'bip', 'BIP'], name: this.#translate('filePicker.firmware.filterName') }],
                properties: ['openFile'],
                title: this.#translate('filePicker.firmware.title')
            })
        } catch {
            return { ok: false, reason: 'firmware-selection-failed' }
        }
        if (selection?.canceled === true) return { ok: false, reason: 'firmware-selection-cancelled' }
        if (!Array.isArray(selection?.filePaths) || selection.filePaths.length !== 1 || typeof selection.filePaths[0] !== 'string' || !isAbsolute(selection.filePaths[0])) {
            return { ok: false, reason: 'firmware-selection-invalid' }
        }
        const selected = await this.registerFirmwarePath(selection.filePaths[0])
        if (selected.ok !== true) return selected
        // Explain release pairing errors before accepting an operation. Claim time
        // repeats the same checks because either file can change after selection.
        const snapshot = await this.#snapshotFirmware(this.#pending.get(selected.fileToken))
        snapshot.bytes?.fill(0)
        if (snapshot.ok === false) {
            this.#pending.delete(selected.fileToken)
            return snapshot
        }
        return selected
    }

    /**
     * Validates one explicit main-owned local path and returns a bounded opaque token.
     * This method is never exposed through preload or IPC.
     * @param {unknown} selectedPath - Candidate absolute local firmware image path.
     * @returns {Promise<object>} Path-free main-only token response or stable failure.
     */
    async registerFirmwarePath(selectedPath) {
        this.#expireTokens()
        if (this.#pending.size >= MAX_PENDING_TOKENS) return { ok: false, reason: 'firmware-selection-capacity-exhausted' }
        if (typeof selectedPath !== 'string' || !isAbsolute(selectedPath)) return { ok: false, reason: 'firmware-selection-invalid' }
        const extension = extname(selectedPath).toUpperCase()
        if (!ALLOWED_EXTENSIONS.has(extension)) return { ok: false, reason: 'firmware-file-type-unsupported' }

        let metadata
        let canonicalPath
        try {
            metadata = await this.#lstat(selectedPath)
            if (!metadata.isFile() || metadata.isSymbolicLink() || !Number.isSafeInteger(metadata.size) || metadata.size <= 0 || metadata.size > MAX_FIRMWARE_BYTES) {
                return { ok: false, reason: 'firmware-file-invalid' }
            }
            canonicalPath = await this.#realpath(selectedPath)
            metadata = await this.#selectedHandleMetadata(selectedPath, canonicalPath, metadata)
        } catch {
            return { ok: false, reason: 'firmware-file-invalid' }
        }

        const token = `firmware:${this.#randomUUID()}`
        this.#pending.set(token, {
            canonicalPath,
            extension,
            expiresAt: this.#clock() + TOKEN_LIFETIME_MS,
            identity: this.#fileIdentity(metadata),
            size: metadata.size
        })
        return { ok: true, fileToken: token }
    }

    /**
     * Captures same-file authority through the same API used at claim time.
     * Windows pathname lstat may report dev=0 while handle stat reports the
     * volume ID. Keep that real volume ID in the token instead of dropping it
     * from subsequent replacement checks. Path checks remain separate guards.
     * @param {string} selectedPath - Original non-link local selection.
     * @param {string} canonicalPath - Resolved main-owned pathname.
     * @param {object} entry - Initial pathname metadata, not handle authority.
     * @returns {Promise<object>} Regular-file handle metadata after stable path checks.
     * @throws {Error} If the entry changes during selection or cannot be opened safely.
     */
    async #selectedHandleMetadata(selectedPath, canonicalPath, entry) {
        const file = await this.#open(canonicalPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0))
        try {
            const metadata = await file.stat()
            const currentEntry = await this.#lstat(selectedPath)
            const currentPath = await this.#realpath(selectedPath)
            if (!metadata.isFile() || !currentEntry.isFile() || currentEntry.isSymbolicLink() || currentPath !== canonicalPath || this.#fileIdentity(currentEntry) !== this.#fileIdentity(entry) || metadata.ino !== entry.ino || metadata.size !== entry.size || metadata.mtimeMs !== entry.mtimeMs) {
                throw new Error('firmware-selection-changed')
            }
            return metadata
        } finally {
            await file.close()
        }
    }

    /**
     * Atomically consumes, revalidates, and snapshots one main-owned token.
     * This method is never exposed through preload or IPC.
     * @param {unknown} token - Candidate opaque token from the validated operation request.
     * @returns {Promise<object>} Path-free main-only byte snapshot or stable failure.
     */
    async claimFirmwareFile(token) {
        if (typeof token !== 'string') return { ok: false, reason: 'firmware-file-token-invalid' }
        const record = this.#pending.get(token)
        this.#pending.delete(token)
        if (record === undefined || this.#clock() >= record.expiresAt) return { ok: false, reason: 'firmware-file-token-invalid' }
        return this.#snapshotFirmware(record)
    }

    /**
     * Reads and verifies a bounded image and its release metadata without consuming authority.
     * Callers must clear returned bytes after use; rejected snapshots are cleared here.
     * @param {object} record - Private same-file selection authority.
     * @returns {Promise<object>} Immutable bytes and metadata, or a path-free failure.
     */
    async #snapshotFirmware(record) {
        try {
            const file = await this.#open(record.canonicalPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
            try {
                const metadata = await file.stat()
                const canonicalPath = await this.#realpath(record.canonicalPath)
                if (!metadata.isFile() || canonicalPath !== record.canonicalPath || this.#fileIdentity(metadata) !== record.identity || metadata.size !== record.size) {
                    return { ok: false, reason: 'firmware-file-changed' }
                }
                const bytes = await this.#readExactFirmware(file, record.size)
                const finalMetadata = await file.stat()
                if (bytes === null || this.#fileIdentity(finalMetadata) !== record.identity) {
                    bytes?.fill(0)
                    return { ok: false, reason: 'firmware-file-changed' }
                }
                let openRdx
                try {
                    openRdx = await readOpenRdxFirmwareManifest(record.canonicalPath, bytes)
                } catch (error) {
                    bytes.fill(0)
                    return { ok: false, reason: error instanceof OpenRdxFirmwareManifestError ? error.code : 'firmware-openrdx-manifest-invalid' }
                }
                return { bytes, extension: record.extension, size: record.size, ...(openRdx === undefined ? {} : { openRdx }) }
            } finally {
                await file.close()
            }
        } catch {
            return { ok: false, reason: 'firmware-file-changed' }
        }
    }

    /**
     * Reads exactly one preflight-bounded snapshot and verifies immediate EOF.
     * @param {object} file - Main-owned non-following file handle.
     * @param {number} size - Exact validated positive image size.
     * @returns {Promise<Buffer|null>} Exact bytes or null after clearing partial data.
     */
    async #readExactFirmware(file, size) {
        const bytes = Buffer.alloc(size)
        let offset = 0
        try {
            while (offset < size) {
                const result = await file.read(bytes, offset, size - offset, offset)
                if (!Number.isSafeInteger(result?.bytesRead) || result.bytesRead <= 0 || result.bytesRead > size - offset) {
                    bytes.fill(0)
                    return null
                }
                offset += result.bytesRead
            }
            const extra = Buffer.alloc(1)
            const result = await file.read(extra, 0, 1, size)
            extra.fill(0)
            if (result?.bytesRead !== 0) {
                bytes.fill(0)
                return null
            }
            return bytes
        } catch {
            bytes.fill(0)
            return null
        }
    }

    /** @returns {void} Drops expired file authority without touching selected files. */
    #expireTokens() {
        const now = this.#clock()
        for (const [token, record] of this.#pending) {
            if (now >= record.expiresAt) this.#pending.delete(token)
        }
    }

    /** @param {object} metadata - Node file metadata. @returns {string} Stable same-file proof. */
    #fileIdentity(metadata) {
        return `${metadata.dev}:${metadata.ino}:${metadata.size}:${metadata.mtimeMs}`
    }
}
