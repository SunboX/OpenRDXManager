// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createHash } from 'node:crypto'
import { lstat, readFile, readdir, writeFile } from 'node:fs/promises'
import { resolve, join } from 'node:path'
import { fileURLToPath } from 'node:url'

/** @param {string} version - Manifest release version. @returns {string[]} Complete six-platform installer inventory. @throws {TypeError} For unsafe version input. */
export function expectedInstallerNames(version) {
    if (!/^\d+\.\d+\.\d+(?:-[\w.-]+)?$/u.test(version)) throw new TypeError('invalid-release-version')
    return ['mac', 'win', 'linux'].flatMap((platform) => ['x64', 'arm64'].flatMap((architecture) => ({ mac: ['dmg', 'pkg', 'zip'], win: ['exe', 'zip'], linux: ['AppImage', 'deb', 'tar.gz'] })[platform].map((extension) => `OpenRDXManager-${version}-${platform}-${architecture}.${extension}`)))
}

/**
 * Rejects missing, stale, linked or empty installers before calculating release checksums.
 * Writes only the checksum inventory; release creation is a later workflow step.
 * @param {{directory: string, version: string}} options - Collected artifact directory and package version.
 * @returns {Promise<{installers: string[]}>} Complete verified inventory.
 * @throws {Error} When any required installer is absent or unsafe.
 */
export async function verifyReleaseAssets({ directory, version }) {
    const installers = expectedInstallerNames(version).sort()
    const actual = await readdir(directory)
    const missing = installers.filter((name) => !actual.includes(name))
    if (missing.length) throw new Error(`missing-installers: ${missing.join(', ')}`)
    for (const name of actual) {
        if (/\.(?:exe|dmg|pkg|zip|deb|AppImage|tar\.gz)$/u.test(name) && !installers.includes(name)) throw new Error(`unexpected-installer: ${name}`)
    }
    const checksums = []
    for (const name of installers) {
        const path = join(directory, name)
        const metadata = await lstat(path)
        if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size === 0) throw new Error(`invalid-installer: ${name}`)
        const hash = createHash('sha256')
            .update(await readFile(path))
            .digest('hex')
        checksums.push(`${hash}  ${name}`)
    }
    await writeFile(join(directory, 'SHA256SUMS.txt'), `${checksums.join('\n')}\n`)
    return { installers }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    const { version } = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))
    const inventory = await verifyReleaseAssets({ directory: resolve(process.argv[2] ?? 'dist/installers'), version })
    console.log(`Verified ${inventory.installers.length} installers for v${version}`)
}
