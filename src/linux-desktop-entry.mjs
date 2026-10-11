// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { homedir } from 'node:os'
import { posix } from 'node:path'
import { fileURLToPath } from 'node:url'

import { getAppIconPath, linuxDesktopEntryId } from './app-icon.mjs'

const defaultAppRoot = fileURLToPath(new URL('..', import.meta.url))
// These are Linux target paths even when a contributor validates them on Windows.
const { dirname, isAbsolute, join, resolve } = posix

/**
 * Resolves the XDG user data directory used for desktop launchers and icons.
 * @param {NodeJS.ProcessEnv} [environment=process.env] - Environment supplying XDG_DATA_HOME.
 * @param {string} [homeDirectory=homedir()] - User home directory fallback.
 * @returns {string} Absolute XDG data directory.
 * @throws {TypeError} When the selected data directory is not absolute.
 */
export function resolveLinuxDesktopDataDirectory(environment = process.env, homeDirectory = homedir()) {
    const configuredDirectory = environment.XDG_DATA_HOME?.trim()
    const dataDirectory = configuredDirectory === undefined || configuredDirectory === '' ? join(homeDirectory, '.local', 'share') : configuredDirectory
    if (!isAbsolute(dataDirectory)) throw new TypeError('linux-desktop-data-directory-invalid')
    return resolve(dataDirectory)
}

/**
 * Resolves the source and destination paths needed for Linux desktop integration.
 * @param {{appRoot?: string, dataDirectory?: string}} [options] - Source application and XDG data roots.
 * @returns {{appRoot: string, desktopEntryPath: string, electronPath: string, iconDestinationPath: string, iconSourcePath: string}} Controlled launcher paths.
 * @throws {TypeError} When a supplied root is not absolute.
 */
export function getLinuxDesktopEntryPaths({ appRoot = defaultAppRoot, dataDirectory = resolveLinuxDesktopDataDirectory() } = {}) {
    if (!isAbsolute(appRoot) || !isAbsolute(dataDirectory)) throw new TypeError('linux-desktop-path-root-invalid')
    const resolvedAppRoot = resolve(appRoot)
    const resolvedDataDirectory = resolve(dataDirectory)
    return {
        appRoot: resolvedAppRoot,
        desktopEntryPath: join(resolvedDataDirectory, 'applications', `${linuxDesktopEntryId}.desktop`),
        electronPath: join(resolvedAppRoot, 'node_modules', 'electron', 'dist', 'electron'),
        iconDestinationPath: join(resolvedDataDirectory, 'icons', 'hicolor', '512x512', 'apps', `${linuxDesktopEntryId}.png`),
        iconSourcePath: getAppIconPath('linux')
    }
}

/**
 * Escapes one absolute argument for the freedesktop Exec field grammar.
 * @param {string} value - One executable or argument path.
 * @returns {string} Quoted desktop-entry argument.
 * @throws {TypeError} When the value is empty or not a string.
 */
function escapeExecArgument(value) {
    if (typeof value !== 'string' || value.length === 0) throw new TypeError('linux-desktop-exec-argument-invalid')
    return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"').replaceAll('$', '\\$').replaceAll('`', '\\`')}"`
}

/**
 * Renders the stable source-checkout launcher used by Linux desktop shells.
 * @param {{appRoot: string, electronPath: string}} options - Absolute Electron and application paths.
 * @returns {string} UTF-8 desktop entry contents.
 * @throws {TypeError} When either launcher path is not absolute.
 */
export function renderLinuxDesktopEntry({ appRoot, electronPath }) {
    if (!isAbsolute(appRoot) || !isAbsolute(electronPath)) throw new TypeError('linux-desktop-launcher-path-invalid')
    return `[Desktop Entry]\nVersion=1.0\nType=Application\nName=OpenRDXManager\nComment=Manage RDX devices\nExec=${escapeExecArgument(electronPath)} ${escapeExecArgument(appRoot)}\nIcon=${linuxDesktopEntryId}\nTerminal=false\nCategories=Utility;\nStartupNotify=true\nStartupWMClass=${linuxDesktopEntryId}\n`
}

/**
 * Returns the containing directory for one generated desktop artifact.
 * @param {string} path - Absolute desktop artifact path.
 * @returns {string} Absolute parent directory.
 */
export function getLinuxDesktopArtifactDirectory(path) {
    return dirname(path)
}
