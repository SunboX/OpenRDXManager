// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { lstat, open } from 'node:fs/promises'
import { basename, extname } from 'node:path'

const TEMPLATE_SHA256 = '73d528801aefc032d3a53637b035f65d72809151b2f127c6b2050e9bacc76f3b'
const MAX_MANIFEST_BYTES = 65536

/** Carries only a stable main-owned failure code, without filesystem details. */
export class OpenRdxFirmwareManifestError extends Error {
    /** @param {string} code - App-owned manifest failure code. Initializes path-free failure evidence. */
    constructor(code) {
        super(code)
        this.name = 'OpenRdxFirmwareManifestError'
        this.code = code
    }
}

/** @param {Buffer} bytes - Immutable snapshot. @returns {string} Lowercase SHA-256 identity. */
function digest(bytes) {
    return createHash('sha256').update(bytes).digest('hex')
}

/**
 * Reads JSON through a bounded, non-following regular-file handle.
 * @param {string} manifestPath - Main-owned same-stem sidecar path.
 * @returns {Promise<unknown>} Parsed JSON awaiting release validation.
 * @throws {Error} For unsafe, changing, unreadable, or malformed sidecars.
 */
async function readManifestJson(manifestPath) {
    const entry = await lstat(manifestPath)
    if (!entry.isFile()) throw new Error('OpenRDX manifest must be a regular file')
    // Nonblocking open also rejects a FIFO swapped in after the preliminary check.
    const file = await open(manifestPath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0))
    try {
        const before = await file.stat()
        if (!before.isFile() || before.size < 1 || before.size > MAX_MANIFEST_BYTES) throw new Error('Invalid OpenRDX manifest size')
        const buffer = Buffer.alloc(before.size + 1)
        let offset = 0
        while (offset < buffer.length) {
            const { bytesRead } = await file.read(buffer, offset, buffer.length - offset, offset)
            if (bytesRead === 0) break
            offset += bytesRead
        }
        const after = await file.stat()
        if (offset !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs) throw new Error('OpenRDX manifest changed during read')
        try {
            return JSON.parse(buffer.subarray(0, offset).toString('utf8'))
        } catch {
            throw new OpenRdxFirmwareManifestError('firmware-openrdx-manifest-malformed')
        }
    } finally {
        await file.close()
    }
}

/**
 * Verifies the same-stem manifest for a marked OpenRDX image.
 * Hashes provide image integrity and pairing, not vendor signature authentication.
 * Paths and unrelated release fields never cross the native registration boundary.
 * @param {string} imagePath - Canonical main-owned selected image path.
 * @param {Buffer} bytes - Already claimed immutable image snapshot.
 * @returns {Promise<object|undefined>} Verified path-free metadata, or undefined for vendor images.
 * @throws {OpenRdxFirmwareManifestError} With a stable missing, malformed, invalid, filename, or hash failure code.
 */
export async function readOpenRdxFirmwareManifest(imagePath, bytes) {
    if (!bytes.subarray(0x108, 0x110).equals(Buffer.from('OPENRDX1'))) return undefined
    const manifestPath = `${imagePath.slice(0, -extname(imagePath).length)}.json`
    let manifest
    try {
        manifest = await readManifestJson(manifestPath)
    } catch (error) {
        if (error instanceof OpenRdxFirmwareManifestError) throw error
        throw new OpenRdxFirmwareManifestError(error?.code === 'ENOENT' ? 'firmware-openrdx-manifest-missing' : 'firmware-openrdx-manifest-invalid')
    }
    // Only structurally valid metadata can identify a pairing or integrity error.
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest) || bytes.length !== 62110 || typeof manifest.container !== 'string' || /[/\\\0]/.test(manifest.container) || manifest.container_length !== bytes.length || manifest.authentication_scheme !== 'openrdx-sha256-v1' || manifest.requires_openrdx_receiver !== true || manifest.template_sha256 !== TEMPLATE_SHA256 || typeof manifest.release_version !== 'string' || !/^(?:0|[1-9][0-9]?)\.[0-9]{2}$/.test(manifest.release_version) || typeof manifest.container_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(manifest.container_sha256) || typeof manifest.boot_region_sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(manifest.boot_region_sha256)) {
        throw new OpenRdxFirmwareManifestError('firmware-openrdx-manifest-invalid')
    }
    if (manifest.container !== basename(imagePath)) throw new OpenRdxFirmwareManifestError('firmware-openrdx-manifest-filename-mismatch')
    if (manifest.container_sha256 !== digest(bytes) || manifest.boot_region_sha256 !== digest(bytes.subarray(0x18c, -4))) throw new OpenRdxFirmwareManifestError('firmware-openrdx-manifest-hash-mismatch')
    return { containerSha256: manifest.container_sha256, bootRegionSha256: manifest.boot_region_sha256, releaseVersion: manifest.release_version }
}
