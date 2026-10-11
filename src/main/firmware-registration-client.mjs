// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { actionResponseSchema } from '../shared/schemas.mjs'

const FIRMWARE_REGISTRATION_CHUNK_BYTES = 4096
const MAX_FIRMWARE_IMAGE_BYTES = 0xffffff

/**
 * Sends one modern image as an ordered bounded registration sequence.
 * @param {{registration: {fileToken: string, extension: string, bytes: Buffer, openRdx?: {containerSha256: string, bootRegionSha256: string, releaseVersion: string}}, request: Function}} options - Validated registration and strict client request boundary.
 * @returns {Promise<object>} Safe registration result.
 */
export async function registerFirmwareImageFrames(options) {
    const registration = options?.registration
    const tokenValid = typeof registration?.fileToken === 'string' && /^firmware:[A-Za-z0-9-]{1,54}$/.test(registration.fileToken)
    const bytes = registration?.bytes
    if (!tokenValid || registration?.extension !== '.BIN' || !Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_FIRMWARE_IMAGE_BYTES || typeof options?.request !== 'function') {
        return { ok: false, reason: 'invalid-request' }
    }
    let begun = false
    try {
        const begin = await options.request('firmware-registration-begin', { fileToken: registration.fileToken, extension: 'BIN', totalBytes: bytes.length, ...(registration.openRdx === undefined ? {} : { openRdx: registration.openRdx }) }, actionResponseSchema)
        if (begin.ok !== true) return begin
        begun = true
        for (let offset = 0; offset < bytes.length; offset += FIRMWARE_REGISTRATION_CHUNK_BYTES) {
            const chunk = bytes.subarray(offset, Math.min(offset + FIRMWARE_REGISTRATION_CHUNK_BYTES, bytes.length))
            const appended = await options.request('firmware-registration-chunk', { fileToken: registration.fileToken, offset, bytesBase64: chunk.toString('base64') }, actionResponseSchema)
            if (appended.ok !== true) return appended
        }
        const committed = await options.request('firmware-registration-commit', { fileToken: registration.fileToken }, actionResponseSchema)
        if (committed.ok === true) begun = false
        return committed
    } finally {
        if (begun) {
            await options.request('firmware-registration-abort', { fileToken: registration.fileToken }, actionResponseSchema)
        }
    }
}
