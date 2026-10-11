// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createRequire } from 'node:module'
import { cp, mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { rcedit } from 'rcedit'

const project = fileURLToPath(new URL('..', import.meta.url))
const require = createRequire(import.meta.url)

/**
 * Creates a branded Windows development runtime without changing npm's Electron.
 * Cached builds reuse the binary until Electron, the application version or icon changes.
 * @returns {Promise<void>} Completes after PE metadata and the app icon are written.
 */
async function prepareWindowsRuntime() {
    if (process.platform !== 'win32') return
    const electron = require('electron')
    const source = await stat(electron)
    const icon = join(project, 'resources', 'icons', 'app-icon.ico')
    const iconInfo = await stat(icon)
    const metadata = JSON.parse(await readFile(join(project, 'package.json'), 'utf8'))
    const signature = JSON.stringify({ electronSize: source.size, electronModified: source.mtimeMs, iconModified: iconInfo.mtimeMs, version: metadata.version })
    const output = join(project, 'out', 'windows-runtime')
    const stamp = join(output, 'openrdx-runtime.json')
    try {
        if ((await readFile(stamp, 'utf8')) === signature && (await stat(join(output, 'OpenRDXManager.exe'))).isFile()) return
    } catch (error) {
        if (error.code !== 'ENOENT') throw error
    }
    await mkdir(output, { recursive: true })
    await cp(dirname(electron), output, { recursive: true, force: true })
    const executable = join(output, 'OpenRDXManager.exe')
    await rm(executable, { force: true })
    await rename(join(output, 'electron.exe'), executable)
    await rcedit(executable, { icon, 'file-version': metadata.version, 'product-version': metadata.version, 'version-string': { ProductName: 'OpenRDXManager', FileDescription: 'OpenRDXManager', InternalName: 'OpenRDXManager', OriginalFilename: 'OpenRDXManager.exe', CompanyName: 'OpenRDX' } })
    await writeFile(stamp, signature)
}

await prepareWindowsRuntime()
