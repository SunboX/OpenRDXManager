// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { isAbsolute } from 'node:path'
import test from 'node:test'

import { windowOptions } from '../src/window-options.mjs'

test('window uses a practical default size', () => {
    assert.equal(windowOptions.width, 1280)
    assert.equal(windowOptions.height, 800)
    assert.equal(windowOptions.minWidth, 1024)
    assert.equal(windowOptions.minHeight, 768)
    assert.equal(windowOptions.backgroundColor, '#050a13')
})

test('renderer uses secure Electron defaults explicitly', () => {
    assert.deepEqual(windowOptions.webPreferences, {
        contextIsolation: true,
        nodeIntegration: false,
        preload: windowOptions.webPreferences.preload,
        sandbox: true
    })
    assert.equal(isAbsolute(windowOptions.webPreferences.preload), true)
    assert.match(windowOptions.webPreferences.preload, /out[/\\]preload\.cjs$/)
    assert.equal(Object.isFrozen(windowOptions), true)
    assert.equal(Object.isFrozen(windowOptions.webPreferences), true)
})

test('window uses dark blue chrome with native window controls', () => {
    assert.equal(windowOptions.darkTheme, true)
    assert.equal(windowOptions.titleBarStyle, 'hidden')
    assert.deepEqual(windowOptions.titleBarOverlay, { color: '#081422', symbolColor: '#deedf7', height: 36 })
    assert.equal(Object.isFrozen(windowOptions.titleBarOverlay), true)
})
