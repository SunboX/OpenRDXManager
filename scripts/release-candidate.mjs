// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { open, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import { isDeepStrictEqual } from 'node:util'
import { expectedInstallerNames } from './release-assets.mjs'
import { assertAcceptancePath, readAcceptanceFile, validateBuildRun } from './windows-release-acceptance.mjs'

/** @param {boolean} condition Required candidate fact. @returns {void} @throws {Error} Fixed public failure without input data. */
function requireFact(condition) {
    if (!condition) throw new Error('release-candidate-invalid')
}

/** Hashes a pinned regular single-link file without allocating its entire content. @param {string} path Explicit local asset path. @returns {Promise<{size:number,digest:string}>} Exact server-compatible metadata. @throws {Error} For linked, empty, changed or unreadable inputs. */
export async function releaseAssetMetadata(path) {
    await assertAcceptancePath(path)
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
    try {
        const before = await handle.stat()
        requireFact(before.isFile() && before.nlink === 1 && before.size > 0)
        const hash = createHash('sha256')
        for await (const chunk of handle.createReadStream({ autoClose: false })) hash.update(chunk)
        const after = await handle.stat()
        requireFact(before.size === after.size && before.mtimeMs === after.mtimeMs)
        return { size: before.size, digest: `sha256:${hash.digest('hex')}` }
    } finally {
        await handle.close()
    }
}

/**
 * Verifies one successful six-platform build's complete exact-version installer inventory.
 * Candidate code is never executed. Retained metadata binds the attempt, commit and
 * every installer digest across verification and publication; VM receipts are optional
 * diagnostic evidence and are not part of this publication contract.
 * @param {{run:object,repository:string,runId:string|number,sourceDirectory:string,installerDirectory:string,expectedCandidate?:object}} options Authenticated run, pinned source and downloaded assets.
 * @returns {Promise<object>} Closed candidate metadata including all sixteen asset hashes.
 * @throws {Error} For unsuccessful/foreign builds, stale attempts, unsafe files, missing assets or checksum changes.
 */
export async function verifyReleaseCandidate(options) {
    const build = validateBuildRun(options.run, { repository: options.repository, runId: options.runId })
    await assertAcceptancePath(options.sourceDirectory)
    await assertAcceptancePath(options.installerDirectory)
    const manifest = JSON.parse((await readAcceptanceFile(join(options.sourceDirectory, 'package.json'))).toString('utf8'))
    const installers = expectedInstallerNames(manifest.version).sort()
    const actual = await readdir(options.installerDirectory)
    requireFact(actual.filter((name) => /\.(?:exe|dmg|pkg|zip|deb|AppImage|tar\.gz)$/u.test(name)).every((name) => installers.includes(name)))
    const assets = {}
    const lines = []
    for (const name of installers) {
        assets[name] = await releaseAssetMetadata(join(options.installerDirectory, name))
        lines.push(`${assets[name].digest.slice(7)}  ${name}`)
    }
    const checksums = await readAcceptanceFile(join(options.installerDirectory, 'SHA256SUMS.txt'), 65536)
    requireFact(checksums.toString('utf8') === `${lines.join('\n')}\n`)
    assets['SHA256SUMS.txt'] = await releaseAssetMetadata(join(options.installerDirectory, 'SHA256SUMS.txt'))
    requireFact(assets['SHA256SUMS.txt'].digest === `sha256:${createHash('sha256').update(checksums).digest('hex')}`)
    const candidate = { schemaVersion: 1, repository: options.repository, runId: build.runId, runAttempt: build.runAttempt, sourceCommit: build.sourceCommit, version: manifest.version, installers, assets }
    if (options.expectedCandidate !== undefined) requireFact(isDeepStrictEqual(candidate, options.expectedCandidate))
    return candidate
}
