// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { lstat, open, readlink, readdir, realpath } from 'node:fs/promises'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { promisify } from 'node:util'

const execute = promisify(execFile)
const SELF = 'resources/local-trust/runtime.json'
const MAX_BYTES = 1_048_576
const MAX_ENTRIES = 20_000

/** @param {string} path - Inventory relative path. @returns {boolean} Whether canonical confined path syntax is used. */
function canonicalPath(path) {
    return typeof path === 'string' && path.length > 0 && path.length <= 4096 && !/[\\:\u0000-\u001f]/u.test(path) && !path.startsWith('/') && path.split('/').every((part) => part !== '' && part !== '.' && part !== '..')
}

/** @param {object} value - Bounded object. @param {string[]} keys - Exact allowed keys. @returns {boolean} True for that exact property vocabulary. */
function exactKeys(value, keys) {
    return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key))
}

/** @param {object} inventory - Untrusted inventory input. @returns {void} Rejects malformed or ambiguous runtime policy. */
export function validateRuntimeInventory(inventory) {
    const invalid = () => {
        throw new Error('runtime-inventory-invalid')
    }
    if (!exactKeys(inventory, ['schemaVersion', 'platform', 'files', 'links', 'managerCdHash', 'helperCdHash']) || inventory.schemaVersion !== 1 || !['macos', 'windows'].includes(inventory.platform) || !Array.isArray(inventory.files) || !Array.isArray(inventory.links) || inventory.files.length === 0 || inventory.files.length + inventory.links.length > MAX_ENTRIES) invalid()
    if (Buffer.byteLength(JSON.stringify(inventory)) > MAX_BYTES) invalid()
    const codeHash = inventory.platform === 'macos' ? /^[a-f0-9]{40}$/u : /^$/u
    if (typeof inventory.managerCdHash !== 'string' || typeof inventory.helperCdHash !== 'string' || !codeHash.test(inventory.managerCdHash) || !codeHash.test(inventory.helperCdHash) || (inventory.platform === 'windows' && inventory.links.length !== 0)) invalid()
    const paths = new Set()
    for (const file of inventory.files) {
        if (!exactKeys(file, ['path', 'size', 'sha256']) || !canonicalPath(file.path) || paths.has(file.path) || !Number.isSafeInteger(file.size) || file.size < 0 || typeof file.sha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(file.sha256)) invalid()
        paths.add(file.path)
    }
    for (const link of inventory.links) {
        if (!exactKeys(link, ['path', 'target']) || !canonicalPath(link.path) || paths.has(link.path) || typeof link.target !== 'string' || link.target.length === 0 || link.target.length > 4096 || /[\\:\u0000-\u001f]/u.test(link.target) || isAbsolute(link.target)) invalid()
        paths.add(link.path)
    }
}

/** @param {string} root - Runtime root. @param {string} target - Resolved candidate. @returns {boolean} True when contained strictly inside the runtime. */
function inside(root, target) {
    const path = relative(root, target)
    return path !== '' && !isAbsolute(path) && path !== '..' && !path.startsWith(`..${sep}`)
}

/** @param {string} root - Canonical runtime root. @param {string} path - Literal relative link path. @param {string} target - Literal link target. @returns {Promise<void>} Rejects escaping or dangling framework links. */
async function verifyLink(root, path, target) {
    const lexical = resolve(dirname(join(root, path)), target)
    if (!inside(root, lexical)) throw new Error('runtime-inventory-unsafe-link')
    let canonical
    try {
        canonical = await realpath(join(root, path))
    } catch {
        throw new Error('runtime-inventory-unsafe-link')
    }
    if (!inside(root, canonical)) throw new Error('runtime-inventory-unsafe-link')
}

/** @param {string} path - Actual runtime file. @returns {Promise<{size: number, sha256: string}>} Stable regular-file content identity. */
async function fileDigest(path) {
    const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
    try {
        const before = await handle.stat({ bigint: true })
        if (!before.isFile() || before.nlink !== 1n || before.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('runtime-inventory-unsafe-file')
        const hash = createHash('sha256')
        const buffer = Buffer.allocUnsafe(1024 * 1024)
        let bytes = 0
        while (true) {
            const { bytesRead } = await handle.read(buffer, 0, buffer.length, null)
            if (bytesRead === 0) break
            hash.update(buffer.subarray(0, bytesRead))
            bytes += bytesRead
        }
        const after = await handle.stat({ bigint: true })
        const current = await lstat(path, { bigint: true })
        if (before.dev !== current.dev || before.ino !== current.ino || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs || BigInt(bytes) !== before.size) throw new Error('runtime-inventory-file-changed')
        return { size: bytes, sha256: hash.digest('hex') }
    } finally {
        await handle.close()
    }
}

/** @param {string} path - Final signed executable or bundle. @returns {Promise<string>} Exact 20-byte CodeDirectory hash. */
async function readCodeDirectoryHash(path) {
    const result = await execute('/usr/bin/codesign', ['--display', '--verbose=4', path], { maxBuffer: 1024 * 1024 })
    const matches = [...`${result.stdout}\n${result.stderr}`.matchAll(/^CDHash=([a-f0-9]{40})$/gmu)]
    if (matches.length !== 1) throw new Error('runtime-inventory-code-identity-invalid')
    return matches[0][1]
}

/**
 * Pins final packaged files after all executable resource editing and signing.
 * This build-time inventory is not enrollment; installers enforce system ownership.
 * @param {{root: string, platform: 'macos'|'windows', readCodeIdentity?: Function}} options - Final runtime and code-identity reader.
 * @returns {Promise<object>} Strict v1 content inventory.
 * @throws {Error} For unsafe files, links, oversized content policy or invalid signatures.
 */
export async function createRuntimeInventory({ root, platform, readCodeIdentity = readCodeDirectoryHash }) {
    if (!['macos', 'windows'].includes(platform)) throw new Error('runtime-inventory-invalid')
    const canonicalRoot = await realpath(root)
    const inventory = { schemaVersion: 1, platform, files: [], links: [], managerCdHash: '', helperCdHash: '' }
    /** @param {string} directory - Directory relative to the root. @returns {Promise<void>} Walks each directory without traversing links. */
    async function visit(directory) {
        for (const name of (await readdir(join(canonicalRoot, directory))).sort()) {
            const path = directory ? `${directory}/${name}` : name
            if (!canonicalPath(path)) throw new Error('runtime-inventory-invalid')
            const absolute = join(canonicalRoot, path)
            const info = await lstat(absolute)
            if (platform === 'windows' && path === SELF) {
                if (!info.isFile() || info.nlink !== 1) throw new Error('runtime-inventory-unsafe-file')
                continue
            }
            if (info.isSymbolicLink()) {
                if (platform !== 'macos') throw new Error('runtime-inventory-unsafe-link')
                const target = await readlink(absolute)
                await verifyLink(canonicalRoot, path, target)
                inventory.links.push({ path, target })
            } else if (info.isDirectory()) {
                await visit(path)
            } else if (info.isFile()) {
                inventory.files.push({ path, ...(await fileDigest(absolute)) })
            } else throw new Error('runtime-inventory-unsafe-file')
            if (inventory.files.length + inventory.links.length > MAX_ENTRIES) throw new Error('runtime-inventory-invalid')
        }
    }
    await visit('')
    if (platform === 'macos') {
        inventory.managerCdHash = await readCodeIdentity(canonicalRoot)
        inventory.helperCdHash = await readCodeIdentity(join(canonicalRoot, 'Contents/Library/LaunchServices/openrdx-hardware'))
    }
    validateRuntimeInventory(inventory)
    return inventory
}

/**
 * Verifies final runtime content for packaging diagnostics, without enrolling trust.
 * Native production verifiers additionally enforce protected system ownership.
 * @param {{root: string, inventory: object}} options - Packaged root and strict manifest.
 * @returns {Promise<void>} Resolves only if all recorded content still matches.
 * @throws {Error} For malformed policy, unsafe links or changed content.
 */
export async function verifyRuntimeInventory({ root, inventory }) {
    validateRuntimeInventory(inventory)
    const canonicalRoot = await realpath(root)
    for (const entry of inventory.files) {
        const actual = await fileDigest(join(canonicalRoot, entry.path))
        if (actual.size !== entry.size || actual.sha256 !== entry.sha256) throw new Error('runtime-inventory-mismatch')
    }
    for (const link of inventory.links) {
        const path = join(canonicalRoot, link.path)
        if (!(await lstat(path)).isSymbolicLink() || (await readlink(path)) !== link.target) throw new Error('runtime-inventory-mismatch')
        await verifyLink(canonicalRoot, link.path, link.target)
    }
}
