// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { lstat, readFile } from 'node:fs/promises'
import { join } from 'node:path'

/**
 * Collects the installed production closure from npm's lock, including hoisted
 * and nested dependencies. Missing optional packages are host-dependent; missing
 * required packages fail assembly. Returned paths retain npm's exact layout.
 * @param {string} projectRoot - Trusted project directory with an npm v2/v3 lock.
 * @returns {Promise<string[]>} Sorted relative package directories to copy whole.
 * @throws {Error} For invalid/mismatched locks or missing required packages.
 */
export async function collectProductionDependencyPaths(projectRoot) {
    const [manifestText, lockText] = await Promise.all([readFile(join(projectRoot, 'package.json'), 'utf8'), readFile(join(projectRoot, 'package-lock.json'), 'utf8')])
    const manifest = JSON.parse(manifestText)
    const lock = JSON.parse(lockText)
    if (![2, 3].includes(lock.lockfileVersion) || !lock.packages || typeof lock.packages !== 'object') throw new Error('production-dependency-lock-invalid')
    const requiredRoots = new Set(Object.keys(manifest.dependencies ?? {}).filter((name) => !Object.hasOwn(manifest.optionalDependencies ?? {}, name)))
    for (const name of requiredRoots) {
        const entry = lock.packages[`node_modules/${name}`]
        if (!entry || entry.dev === true) throw new Error('production-dependency-lock-mismatch')
    }
    const directories = []
    for (const [relativePath, entry] of Object.entries(lock.packages)) {
        if (!relativePath.startsWith('node_modules/')) continue
        if (!/^node_modules\/(?:@[a-zA-Z0-9._-]+\/)?[a-zA-Z0-9_-][a-zA-Z0-9._-]*(?:\/node_modules\/(?:@[a-zA-Z0-9._-]+\/)?[a-zA-Z0-9_-][a-zA-Z0-9._-]*)*$/u.test(relativePath)) throw new Error('production-dependency-path-invalid')
        if (entry.dev === true) continue
        try {
            if (!(await lstat(join(projectRoot, relativePath))).isDirectory()) throw new Error('production-dependency-directory-invalid')
        } catch (error) {
            if (error.code === 'ENOENT' && entry.optional === true && !requiredRoots.has(relativePath.slice('node_modules/'.length))) continue
            throw error
        }
        directories.push(relativePath)
    }
    return directories.sort()
}
