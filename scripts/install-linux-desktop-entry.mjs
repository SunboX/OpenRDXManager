// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { access, chmod, copyFile, mkdir, rename, writeFile } from 'node:fs/promises'
import { constants } from 'node:fs'

import { getLinuxDesktopArtifactDirectory, getLinuxDesktopEntryPaths, renderLinuxDesktopEntry } from '../src/linux-desktop-entry.mjs'

/**
 * Installs a source-checkout launcher and app icon into the current user's XDG data directory.
 * @returns {Promise<void>} Resolves after both desktop integration files are atomically installed.
 * @throws {Error} When Electron is not installed or the current platform is not Linux.
 */
async function installLinuxDesktopEntry() {
    if (process.platform !== 'linux') throw new Error('linux-desktop-entry-platform-unsupported')
    const paths = getLinuxDesktopEntryPaths()
    await access(paths.electronPath, constants.X_OK)
    await mkdir(getLinuxDesktopArtifactDirectory(paths.desktopEntryPath), { recursive: true })
    await mkdir(getLinuxDesktopArtifactDirectory(paths.iconDestinationPath), { recursive: true })
    await copyFile(paths.iconSourcePath, paths.iconDestinationPath)
    const temporaryPath = `${paths.desktopEntryPath}.${process.pid}.tmp`
    await writeFile(temporaryPath, renderLinuxDesktopEntry(paths), { encoding: 'utf8', mode: 0o644 })
    await chmod(temporaryPath, 0o644)
    await rename(temporaryPath, paths.desktopEntryPath)
    process.stdout.write(`installed-linux-desktop-entry ${paths.desktopEntryPath}\n`)
}

await installLinuxDesktopEntry()
