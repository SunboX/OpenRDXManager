// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { constants } from 'node:fs'
import { chmod, lstat, mkdir, open, rename, rm } from 'node:fs/promises'
import { randomBytes } from 'node:crypto'
import { join } from 'node:path'
import { loadWindowsMcpToken, prepareWindowsMcpDirectory, readWindowsMcpText, writeWindowsMcpSettings } from './windows-private-files.mjs'

/** @param {object} metadata - Descriptor/directory stat. @returns {boolean} Whether the current user owns this object where UIDs are supported. */
function isOwner(metadata) {
    return typeof process.getuid !== 'function' || metadata.uid === process.getuid()
}

/** @param {string} directory - Main-owned application directory. @returns {Promise<void>} Validates an actual owned directory and restricts POSIX access. @throws {Error} For unsafe filesystem state. */
export async function preparePrivateDirectory(directory) {
    if (process.platform === 'win32') return await prepareWindowsMcpDirectory(directory)
    await mkdir(directory, { recursive: true, mode: 0o700 })
    const metadata = await lstat(directory)
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || !isOwner(metadata)) throw new Error('unsafe-mcp-directory')
    if (process.platform !== 'win32') await chmod(directory, 0o700)
}

/** @param {string} path - Main-owned file path. @param {number} maximum - Maximum byte length. @returns {Promise<string>} Bounded UTF-8 content from an owned, non-symlink regular file. @throws {Error} On absence or unsafe metadata. */
export async function readPrivateText(path, maximum = 4096) {
    if (process.platform === 'win32') return await readWindowsMcpText(path, maximum)
    const metadata = await lstat(path)
    if (!metadata.isFile() || metadata.isSymbolicLink() || !isOwner(metadata)) throw new Error('unsafe-mcp-file')
    const file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
    try {
        const actual = await file.stat()
        if (!actual.isFile() || actual.dev !== metadata.dev || actual.ino !== metadata.ino || actual.size > maximum || !isOwner(actual) || (process.platform !== 'win32' && (actual.mode & 0o077) !== 0)) throw new Error('unsafe-mcp-file')
        const bytes = Buffer.alloc(maximum + 1)
        const result = await file.read(bytes, 0, bytes.length, 0)
        if (result.bytesRead > maximum) throw new Error('mcp-file-too-large')
        return bytes.subarray(0, result.bytesRead).toString('utf8')
    } finally {
        await file.close()
    }
}

/** @param {string} directory - Validated private directory. @param {string} name - Fixed application filename. @param {string} text - Content. @returns {Promise<void>} Atomically replaces one main-owned configuration file. */
export async function writePrivateText(directory, name, text) {
    if (process.platform === 'win32') return await writeWindowsMcpSettings(directory, name, text)
    const temporary = join(directory, `.mcp-${randomBytes(16).toString('hex')}.tmp`)
    try {
        const file = await open(temporary, 'wx', 0o600)
        try {
            await file.writeFile(text, 'utf8')
        } finally {
            await file.close()
        }
        await rename(temporary, join(directory, name))
    } finally {
        try {
            await rm(temporary, { force: true })
        } catch {
            // Cleanup must preserve the original write or rename result.
        }
    }
}

/** @param {string} directory - Validated private directory. @returns {Promise<string>} Durable 256-bit bearer token; races reuse the existing token. @throws {Error} For unsafe credential files. */
export async function loadMcpToken(directory) {
    if (process.platform === 'win32') return await loadWindowsMcpToken(directory)
    const path = join(directory, 'token')
    try {
        return validateToken(await readPrivateText(path, 65))
    } catch (error) {
        if (error.code !== 'ENOENT') throw error
    }
    try {
        const file = await open(path, 'wx', 0o600)
        try {
            await file.writeFile(`${randomBytes(32).toString('hex')}\n`, 'utf8')
        } finally {
            await file.close()
        }
    } catch (error) {
        if (error.code !== 'EEXIST') throw error
    }
    return validateToken(await readPrivateText(path, 65))
}

/** @param {string} text - Bounded credential file content. @returns {string} Canonical token. @throws {Error} On malformed credentials. */
function validateToken(text) {
    if (!/^[a-f0-9]{64}\n?$/.test(text)) throw new Error('invalid-mcp-token')
    return text.trim()
}
