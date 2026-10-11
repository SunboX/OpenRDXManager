// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { WindowFrameController } from '../src/main/window-frame-controller.mjs'
import { mountWindowFrame } from '../src/preload-window-frame.mjs'
import { windowFrameChannel } from '../src/shared/window-frame.mjs'

/** @returns {object} Native state/event fixture with no real window or hardware access. */
function windowFixture() {
    const window = new EventEmitter()
    const contents = new EventEmitter()
    const messages = []
    Object.assign(window, {
        webContents: contents,
        maximized: false,
        fullscreen: false,
        destroyed: false,
        /** @returns {boolean} Current controlled native state. */
        isMaximized() {
            return this.maximized
        },
        /** @returns {boolean} Current controlled fullscreen state. */
        isFullScreen() {
            return this.fullscreen
        },
        /** @returns {boolean} Whether this test window has closed. */
        isDestroyed() {
            return this.destroyed
        }
    })
    /** @returns {boolean} Whether the owned test renderer has closed. */
    contents.isDestroyed = () => window.destroyed
    /** @param {string} channel - Fixed notification name. @param {string} state - Native state enum. @returns {void} Records notification without exposing a transport to renderer code. */
    contents.send = (channel, state) => messages.push({ channel, state })
    Object.defineProperty(window, 'webContents', {
        /** @returns {object} Mimics Electron's native getter throwing after destruction. */
        get() {
            if (window.destroyed) throw new TypeError('Object has been destroyed')
            return contents
        }
    })
    return { window, contents, messages }
}

test('native frame replays restored, maximized, restored and fullscreen states and cleans up on close', () => {
    const { window, contents, messages } = windowFixture()
    new WindowFrameController(window, 'win32')
    contents.emit('did-finish-load')
    window.maximized = true
    window.emit('maximize')
    contents.emit('did-finish-load')
    window.fullscreen = true
    window.emit('enter-full-screen')
    window.fullscreen = false
    window.emit('leave-full-screen')
    window.maximized = false
    window.emit('unmaximize')
    assert.deepEqual(
        messages.map(({ state }) => state),
        ['restored', 'maximized', 'maximized', 'restored', 'maximized', 'restored']
    )
    assert.ok(messages.every(({ channel }) => channel === windowFrameChannel))
    window.destroyed = true
    assert.doesNotThrow(() => window.emit('closed'))
    assert.equal(contents.listenerCount('did-finish-load'), 0)
    assert.equal(window.listenerCount('maximize'), 0)
    assert.equal(window.listenerCount('unmaximize'), 0)
    assert.equal(window.listenerCount('enter-full-screen'), 0)
    assert.equal(window.listenerCount('leave-full-screen'), 0)
})

test('non-Windows windows receive no native inset notifications', () => {
    const { window, contents, messages } = windowFixture()
    new WindowFrameController(window, 'darwin')
    window.emit('maximize')
    contents.emit('did-finish-load')
    assert.deepEqual(messages, [])
    assert.equal(window.listenerCount('closed'), 0)
})

test('isolated preload accepts only closed state enums and retains early state through DOM readiness', () => {
    const dom = new JSDOM('<!doctype html><html><body></body></html>')
    const transport = new EventEmitter()
    const dispose = mountWindowFrame({ document: dom.window.document, transport })
    const root = dom.window.document.documentElement
    assert.equal(root.getAttribute('data-window-frame'), null)
    transport.emit(windowFrameChannel, {}, 'maximized')
    dom.window.document.dispatchEvent(new dom.window.Event('DOMContentLoaded'))
    assert.equal(root.getAttribute('data-window-frame'), 'maximized')
    for (const invalid of [null, {}, { state: 'restored' }, false, 'maximized; color:red', 'fullscreen']) transport.emit(windowFrameChannel, {}, invalid)
    assert.equal(root.getAttribute('data-window-frame'), 'maximized')
    transport.emit(windowFrameChannel, {}, 'restored')
    assert.equal(root.getAttribute('data-window-frame'), 'restored')
    dispose()
    assert.equal(transport.listenerCount(windowFrameChannel), 0)
    dom.window.close()
})
