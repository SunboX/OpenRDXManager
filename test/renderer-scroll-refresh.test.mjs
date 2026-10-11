// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createStore } from '../src/renderer/store.mjs'

/**
 * Replays background discovery while reading any management area.
 * @param {import('node:test').TestContext} context - Cleanup owner.
 * @param {string} area - Management tab being read.
 * @returns {void} Verifies that refresh preserves the scroll owner and keyboard focus.
 */
function backgroundRefreshPreservesArea(context, area) {
    const dom = new JSDOM('<!doctype html><div id="app"></div>', { pretendToBeVisual: true })
    const { document } = dom.window
    const source = createFixtureState({ mode: 'one-device' })
    const store = createStore({ ...source, discovery: { ...source.discovery, epoch: 1, listRevision: 1 } })
    const root = document.querySelector('#app')
    const controller = mountApplication(root, { store })
    context.after(() => {
        controller.destroy()
        dom.window.close()
    })
    const tab = document.querySelector(`[data-area="${area}"]`)
    tab.click()
    const panel = document.querySelector('.area-panel')
    const focusTarget = area === 'utilities' ? document.querySelector('[data-feature="firmware"] h3') : document.querySelector(`[data-area="${area}"]`)
    focusTarget.focus()
    panel.scrollTop = 620
    const originalFocus = dom.window.HTMLElement.prototype.focus
    const focusCalls = []
    dom.window.HTMLElement.prototype.focus = function recordFocus(options) {
        focusCalls.push(options)
        originalFocus.call(this, options)
    }
    for (let index = 0; index < 3; index += 1) {
        store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
        assert.equal(store.getState().discovery.scanStatus, 'scanning')
        store.dispatch({ type: 'device/list-replaced', devices: store.getState().devices, epoch: 1, listRevision: index + 2 })
        store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
        assert.equal(store.getState().discovery.scanStatus, 'idle')
        assert.equal(document.querySelector('.area-panel'), panel, 'Background scans must retain the scrolling element')
        assert.equal(panel.scrollTop, 620)
        assert.equal(document.activeElement, focusTarget)
    }
    assert.ok(
        focusCalls.every((options) => options?.preventScroll === true),
        'Restoring background focus must not scroll the heading into view'
    )
}

for (const area of ['status', 'encryption', 'tests', 'utilities']) {
    test(`background scans preserve ${area} scroll and focus`, (context) => backgroundRefreshPreservesArea(context, area))
}
