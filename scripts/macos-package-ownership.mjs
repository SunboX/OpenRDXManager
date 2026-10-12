// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { lstat, mkdir, readFile, rename, rm } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { promisify } from 'node:util'
import { gunzipSync } from 'node:zlib'

const execute = promisify(execFile)
const scriptNames = ['openrdx-local-install', 'pending-runtime.json', 'postinstall', 'preinstall']
const packageNames = ['Bom', 'PackageInfo', 'Payload', 'Scripts']

/**
 * Reads bounded old-character CPIO script metadata without executing/extracting it.
 * @param {Buffer} compressed - PKG Scripts gzip stream.
 * @returns {{name: string, sha256: string}[]} Exact root-owned script entries.
 * @throws {Error} For malformed archives, unsafe metadata or unexpected contents.
 */
export function readRootPackageScripts(compressed) {
    const data = gunzipSync(compressed, { maxOutputLength: 32 * 1024 * 1024 })
    const entries = []
    let offset = 0
    let trailer = false
    while (offset + 76 <= data.length) {
        const header = data.subarray(offset, offset + 76).toString('ascii')
        if (header.slice(0, 6) !== '070707' || !/^[0-7]+$/u.test(header.slice(6))) throw new Error('pkg-scripts-cpio-invalid')
        const mode = Number.parseInt(header.slice(18, 24), 8)
        const uid = Number.parseInt(header.slice(24, 30), 8)
        const gid = Number.parseInt(header.slice(30, 36), 8)
        const links = Number.parseInt(header.slice(36, 42), 8)
        const nameSize = Number.parseInt(header.slice(59, 65), 8)
        const size = Number.parseInt(header.slice(65, 76), 8)
        const start = offset + 76 + nameSize
        const end = start + size
        if (nameSize < 1 || nameSize > 128 || end > data.length || data[start - 1] !== 0) throw new Error('pkg-scripts-cpio-invalid')
        const literal = data.subarray(offset + 76, start - 1).toString('utf8')
        offset = end
        if (literal === 'TRAILER!!!') {
            if (size !== 0) throw new Error('pkg-scripts-cpio-invalid')
            trailer = true
            break
        }
        const name = literal.startsWith('./') ? literal.slice(2) : literal
        const expectedMode = name === '.' ? 0o40755 : name === 'pending-runtime.json' ? 0o100600 : 0o100755
        if (uid !== 0 || gid !== 0 || mode !== expectedMode || (name !== '.' && links !== 1) || (name === '.' && size !== 0)) throw new Error('pkg-scripts-ownership-invalid')
        if ((name !== '.' && !scriptNames.includes(name)) || entries.some((entry) => entry.name === name)) throw new Error('pkg-scripts-content-invalid')
        entries.push({ name, sha256: createHash('sha256').update(data.subarray(start, end)).digest('hex') })
    }
    if (!trailer || data.subarray(offset).some((byte) => byte !== 0) || entries.length !== 5 || !entries.some((entry) => entry.name === '.')) throw new Error('pkg-scripts-content-invalid')
    return entries
}

/** @param {string} path - Build-owned regular file. @returns {Promise<string>} SHA-256 without loading a large payload into memory. */
async function digest(path) {
    const metadata = await lstat(path)
    if (!metadata.isFile() || metadata.nlink !== 1) throw new Error('pkg-build-file-invalid')
    const hash = createHash('sha256')
    for await (const chunk of createReadStream(path)) hash.update(chunk)
    return hash.digest('hex')
}

/**
 * Sets explicit root script headers in an unsigned component PKG without sudo.
 * pkgbuild's --ownership option controls the payload, not its script archive.
 * Bom, Payload and PackageInfo remain byte-identical; XAR checksums are rebuilt.
 * @param {{packagePath: string, scripts: string, scratch: string}} options - Controlled build paths.
 * @returns {Promise<void>} Resolves after metadata, byte and parser verification.
 * @throws {Error} For unexpected members, changed payload bytes or invalid scripts.
 */
export async function normalizeMacOsPackageScriptOwners({ packagePath, scripts, scratch }) {
    const archive = resolve(packagePath)
    const raw = resolve(scratch)
    const listing = await execute('/usr/bin/xar', ['-tf', archive])
    if (JSON.stringify(listing.stdout.trim().split('\n').sort()) !== JSON.stringify(packageNames)) throw new Error('pkg-xar-members-invalid')
    await rm(raw, { recursive: true, force: true })
    await mkdir(raw, { recursive: true, mode: 0o755 })
    await execute('/usr/bin/xar', ['-xf', archive], { cwd: raw })
    const baseline = new Map()
    for (const name of ['Bom', 'Payload', 'PackageInfo']) baseline.set(name, await digest(join(raw, name)))
    await execute('/usr/bin/tar', ['--format=cpio', '--uid', '0', '--gid', '0', '-czf', join(raw, 'Scripts'), '-C', resolve(scripts), '.'], { env: { ...process.env, COPYFILE_DISABLE: '1' } })
    const entries = readRootPackageScripts(await readFile(join(raw, 'Scripts')))
    for (const entry of entries.filter((entry) => entry.name !== '.')) {
        if (entry.sha256 !== (await digest(join(scripts, entry.name)))) throw new Error('pkg-scripts-bytes-changed')
    }
    const rebuilt = join(raw, 'normalized.pkg')
    await execute('/usr/bin/xar', ['-cf', rebuilt, '--compression', 'none', ...packageNames], { cwd: raw })
    const check = join(raw, 'recheck')
    await mkdir(check)
    await execute('/usr/bin/xar', ['-xf', rebuilt], { cwd: check })
    for (const [name, original] of baseline) {
        if (original !== (await digest(join(check, name)))) throw new Error('pkg-payload-bytes-changed')
    }
    if (JSON.stringify(readRootPackageScripts(await readFile(join(check, 'Scripts')))) !== JSON.stringify(entries)) throw new Error('pkg-scripts-bytes-changed')
    await execute('/usr/sbin/installer', ['-pkginfo', '-pkg', rebuilt])
    await rename(rebuilt, archive)
}
