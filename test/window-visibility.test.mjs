// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import { runInNewContext } from 'node:vm'

/**
 * Runs the exact production window factory with a hidden-constructor fixture.
 * @param {boolean} failLoad - Whether loading the trusted renderer fails.
 * @returns {Promise<{create: Function, calls: string[]}>} Factory and ordered effects, without Electron or hardware.
 */
async function windowFixture(failLoad = false) {
    const source = (await readFile(new URL('../src/main.mjs', import.meta.url), 'utf8')).replace(/\r\n/g, '\n')
    const start = source.indexOf('async function createWindow() {')
    const end = source.indexOf('\n}\n', start)
    assert.notEqual(start, -1)
    assert.notEqual(end, -1)
    const calls = []
    /** Models Windows suppressing the implicit first show from a hidden parent. */
    class HiddenWindow {
        /** @returns {HiddenWindow} Records a newly allocated invisible window. */
        constructor() {
            this.visible = false
            calls.push('create')
        }
        /** @returns {void} Records native menu configuration. */
        setMenuBarVisibility() {
            calls.push('menu')
        }
        /** @returns {Promise<void>} Loads the trusted local file, or rejects before exposure. */
        async loadFile() {
            calls.push('load')
            if (failLoad) throw new Error('load failed')
        }
        /** @returns {void} Explicitly makes the initialized window visible. */
        show() {
            this.visible = true
            calls.push('show')
        }
    }
    const create = runInNewContext(`${source.slice(start, end + 2)}\ncreateWindow`, {
        BrowserWindow: HiddenWindow,
        WindowFrameController: class {},
        settingsService: null,
        windowOptions: {},
        process: { platform: 'win32' },
        trustApplicationWindow: () => calls.push('trust'),
        trustedWebContents: new Set(),
        isSmokeTest: false,
        shutdownController: null,
        desktopLifecycle: null,
        htmlPath: 'trusted-local-renderer.html'
    })
    return { create, calls }
}

/** @returns {Promise<void>} Verifies a hidden constructor cannot leave a loaded app invisible. */
async function testExplicitlyShowsLoadedWindow() {
    const { create, calls } = await windowFixture()
    const window = await create()
    assert.equal(window.visible, true)
    assert.deepEqual(calls, ['create', 'menu', 'trust', 'load', 'show'])
}
test('explicitly shows the trusted window after loading even if its launcher hid the initial show', testExplicitlyShowsLoadedWindow)

/** @returns {Promise<void>} Verifies failed renderer loading never exposes an uninitialized window. */
async function testDoesNotShowFailedWindow() {
    const { create, calls } = await windowFixture(true)
    await assert.rejects(create(), /load failed/)
    assert.equal(calls.includes('show'), false)
}
test('does not show an uninitialized window when local renderer loading fails', testDoesNotShowFailedWindow)
