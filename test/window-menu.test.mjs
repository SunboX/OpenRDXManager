// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { registerWindowMenu } from '../src/main/window-menu.mjs'
import { mountWindowMenu } from '../src/preload-window-menu.mjs'
import { WindowMenuChannel } from '../src/shared/window-menu.mjs'

/** @param {object} [options] - Sender/platform overrides. @returns {object} Native menu boundary without launching Electron. */
function fixture({ platform = 'linux', trust = true } = {}) {
    const handlers = new Map()
    const popups = []
    const window = { isDestroyed: () => false, getContentBounds: () => ({ width: 1280, height: 800 }) }
    const items = [
        {
            label: '&File',
            submenu: {
                popup: (options) => {
                    popups.push(options)
                    options.callback()
                }
            }
        },
        { label: '&Edit', enabled: false, submenu: { popup: () => assert.fail('disabled popup') } },
        { label: 'Hidden', visible: false, submenu: {} }
    ]
    registerWindowMenu({
        platform,
        ipcMain: { handle: (channel, handler) => handlers.set(channel, handler) },
        Menu: { getApplicationMenu: () => ({ items }) },
        BrowserWindow: { fromWebContents: () => window },
        isTrustedSender: () => trust
    })
    return { handlers, popups, window }
}

test('private menu boundary exposes labels and opens only existing native submenus', async () => {
    const { handlers, popups, window } = fixture()
    assert.deepEqual(await handlers.get(WindowMenuChannel.list)({}), [
        { index: 0, label: 'File', enabled: true },
        { index: 1, label: 'Edit', enabled: false }
    ])
    assert.deepEqual(await handlers.get(WindowMenuChannel.open)({}, { index: 0, x: 8, y: 64 }), { ok: true })
    assert.equal(popups.length, 1)
    assert.equal(popups[0].window, window)
    assert.equal(popups[0].x, 8)
    assert.equal(popups[0].y, 64)
})

test('menu boundary rejects untrusted senders, macOS duplicates, invalid anchors and disabled items', async () => {
    for (const options of [{ trust: false }, { platform: 'darwin' }]) {
        const { handlers, popups } = fixture(options)
        assert.deepEqual(await handlers.get(WindowMenuChannel.list)({}), [])
        assert.deepEqual(await handlers.get(WindowMenuChannel.open)({}, { index: 0, x: 8, y: 64 }), { ok: false })
        assert.equal(popups.length, 0)
    }
    const { handlers, popups, window } = fixture()
    for (const request of [null, {}, { index: 0, x: 0, y: 64, path: '/tmp' }, { index: 1, x: 0, y: 64 }, { index: 2, x: 0, y: 64 }, { index: 9, x: 0, y: 64 }, { index: 0, x: -1, y: 64 }, { index: 0, x: 1280, y: 64 }, { index: 0, x: 0, y: 800 }, { index: 0, x: 0.1, y: 64 }]) {
        assert.deepEqual(await handlers.get(WindowMenuChannel.open)({}, request), { ok: false })
    }
    window.isDestroyed = () => true
    assert.deepEqual(await handlers.get(WindowMenuChannel.open)({}, { index: 0, x: 0, y: 64 }), { ok: false })
    assert.equal(popups.length, 0)
})

test('dark menu strip preserves native popup completion and keyboard navigation', async () => {
    const dom = new JSDOM('<nav class="window-menubar" role="menubar"></nav>')
    const { document, KeyboardEvent } = dom.window
    const opened = Promise.withResolvers()
    const requests = []
    await mountWindowMenu({
        document,
        transport: {
            /** @param {string} channel - Fixed channel. @param {object} request - Popup anchor. @returns {Promise<*>} Test menu labels or native popup completion. */
            async invoke(channel, request) {
                if (channel === WindowMenuChannel.list)
                    return [
                        { index: 0, label: 'File', enabled: true },
                        { index: 1, label: 'Edit', enabled: true }
                    ]
                assert.equal(channel, WindowMenuChannel.open)
                requests.push(request)
                return opened.promise
            }
        }
    })
    const [file, edit] = document.querySelectorAll('button')
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'F10', bubbles: true }))
    assert.equal(document.activeElement, file)
    file.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }))
    assert.equal(document.activeElement, edit)
    edit.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }))
    edit.click()
    assert.equal(requests.length, 1)
    assert.equal(requests[0].index, 1)
    assert.equal(edit.getAttribute('aria-expanded'), 'true')
    opened.resolve({ ok: true })
    await opened.promise
    await new Promise((resolve) => setImmediate(resolve))
    assert.equal(edit.getAttribute('aria-expanded'), 'false')
    dom.window.close()
})
