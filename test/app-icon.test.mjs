// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { lstat, readFile } from 'node:fs/promises'
import { extname, isAbsolute } from 'node:path'
import test from 'node:test'

import { appIconPaths, getAppIconPath, linuxDesktopEntryId } from '../src/app-icon.mjs'
import { getLinuxDesktopEntryPaths, renderLinuxDesktopEntry, resolveLinuxDesktopDataDirectory } from '../src/linux-desktop-entry.mjs'
import { windowOptions } from '../src/window-options.mjs'

/** @param {Buffer} image - PNG bytes. @returns {{width: number, height: number, colorType: number}} Parsed IHDR fields. */
function readPngHeader(image) {
    assert.deepEqual(image.subarray(0, 8), Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))
    assert.equal(image.subarray(12, 16).toString('ascii'), 'IHDR')
    return { width: image.readUInt32BE(16), height: image.readUInt32BE(20), colorType: image.readUInt8(25) }
}

test('ships native app icon formats and selects the current platform asset', async () => {
    assert.equal(linuxDesktopEntryId, 'io.openrdx.OpenRDXManager')
    assert.equal(extname(getAppIconPath('darwin')), '.icns')
    assert.equal(extname(getAppIconPath('win32')), '.ico')
    assert.equal(extname(getAppIconPath('linux')), '.png')
    assert.throws(() => getAppIconPath('aix'), /app-icon-platform-unsupported/u)

    for (const path of Object.values(appIconPaths)) {
        assert.equal(isAbsolute(path), true)
        assert.equal((await lstat(path)).isFile(), true)
    }

    const png = await readFile(appIconPaths.linux)
    assert.deepEqual(readPngHeader(png), { width: 512, height: 512, colorType: 2 })

    const icon = await readFile(appIconPaths.win32)
    assert.equal(icon.readUInt16LE(0), 0)
    assert.equal(icon.readUInt16LE(2), 1)
    assert.equal(icon.readUInt16LE(4), 7)

    const icns = await readFile(appIconPaths.darwin)
    assert.equal(icns.subarray(0, 4).toString('ascii'), 'icns')
    assert.equal(icns.readUInt32BE(4), icns.length)

    assert.equal(windowOptions.icon, getAppIconPath(process.platform))
})

test('renders a Linux desktop launcher that matches the Electron desktop identity', () => {
    assert.equal(resolveLinuxDesktopDataDirectory({}, '/home/rdx'), '/home/rdx/.local/share')
    assert.equal(resolveLinuxDesktopDataDirectory({ XDG_DATA_HOME: '/var/xdg-data' }), '/var/xdg-data')
    assert.throws(() => resolveLinuxDesktopDataDirectory({ XDG_DATA_HOME: 'relative' }), /linux-desktop-data-directory-invalid/u)

    const paths = getLinuxDesktopEntryPaths({ appRoot: '/work/OpenRDXManager', dataDirectory: '/home/rdx/.local/share' })
    assert.equal(paths.desktopEntryPath, '/home/rdx/.local/share/applications/io.openrdx.OpenRDXManager.desktop')
    assert.equal(paths.iconDestinationPath, '/home/rdx/.local/share/icons/hicolor/512x512/apps/io.openrdx.OpenRDXManager.png')
    assert.equal(paths.electronPath, '/work/OpenRDXManager/node_modules/electron/dist/electron')

    const desktopEntry = renderLinuxDesktopEntry(paths)
    assert.match(desktopEntry, /^Exec="\/work\/OpenRDXManager\/node_modules\/electron\/dist\/electron" "\/work\/OpenRDXManager"$/mu)
    assert.match(desktopEntry, /^Icon=io\.openrdx\.OpenRDXManager$/mu)
    assert.match(desktopEntry, /^StartupWMClass=io\.openrdx\.OpenRDXManager$/mu)
})
