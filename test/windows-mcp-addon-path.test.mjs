// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { win32 } from 'node:path'
import test from 'node:test'
import { resolveWindowsMcpAddonPath } from '../src/main/mcp/windows-addon-path.mjs'

const resources = 'C:\\Program Files\\OpenRDXManager\\resources'
const addon = win32.join(resources, 'native', 'windows', 'openrdx-windows-client.node')

test('external Node resolves the trusted sibling addon from the unpacked application root', () => {
    for (const suffix of ['', '\\', '\\.']) assert.equal(resolveWindowsMcpAddonPath(win32.join(resources, 'app.asar.unpacked') + suffix, undefined, win32), addon)
})

test('Electron ASAR and source launches preserve their fixed native addon locations', () => {
    assert.equal(resolveWindowsMcpAddonPath(win32.join(resources, 'app.asar'), resources, win32), addon)
    const source = 'C:\\work\\Andrés\\OpenRDXManager'
    assert.equal(resolveWindowsMcpAddonPath(source, undefined, win32), win32.join(source, 'out', 'native', 'windows', 'openrdx-windows-client.node'))
    assert.equal(resolveWindowsMcpAddonPath(source + '\\app.asar.unpacked-other', undefined, win32), win32.join(source, 'app.asar.unpacked-other', 'out', 'native', 'windows', 'openrdx-windows-client.node'))
})
