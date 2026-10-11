// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { mkdir } from 'node:fs/promises'
import { dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

import { build } from 'esbuild'

const entryPath = fileURLToPath(new URL('../src/preload.mjs', import.meta.url))
const outputPath = fileURLToPath(new URL('../out/preload.cjs', import.meta.url))

/**
 * Bundles the authored ESM preload and strict schemas into the single plain
 * script required by Electron's sandboxed preload runtime.
 * @returns {Promise<void>} Resolves after the generated preload is written.
 */
async function buildSandboxedPreload() {
    await mkdir(dirname(outputPath), { recursive: true })
    await build({
        bundle: true,
        entryPoints: [entryPath],
        external: ['electron'],
        format: 'cjs',
        legalComments: 'none',
        outfile: outputPath,
        platform: 'node',
        sourcemap: false,
        target: 'node22'
    })
}

await buildSandboxedPreload()
