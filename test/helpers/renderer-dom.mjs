// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { JSDOM } from 'jsdom'
import { mountApplication } from '../../src/renderer/app-controller.mjs'
import { createRendererIntentAdapter } from '../../src/renderer/intent-adapter.mjs'
import { createStore } from '../../src/renderer/store.mjs'

/**
 * Mounts the real renderer controller into an isolated browser DOM.
 * @param {object} state - Renderer fixture or derived state to display.
 * @param {object} [options] - Additional controller dependencies.
 * @returns {{dom: JSDOM, root: HTMLElement, controller: object, store: object}} Mounted DOM, controller, and store.
 */
export function createDashboardDom(state, options = {}) {
    const dom = new JSDOM('<!doctype html><html><body><div id="app"></div></body></html>', {
        url: 'file:///openrdxmanager/src/index.html',
        pretendToBeVisual: true
    })
    const root = dom.window.document.querySelector('#app')
    const store = createStore(state)
    const controller = mountApplication(root, { store, ...options })
    return { dom, root, controller, store }
}

/**
 * Creates an injected renderer intent adapter that records accepted intents.
 * @param {string[]} supportedIntents - Intent type allowlist.
 * @returns {{adapter: object, calls: object[]}} Adapter and received intent list.
 */
export function createRecordingIntentAdapter(supportedIntents) {
    const calls = []

    /**
     * Records a validated high-level renderer intent without external work.
     * @param {object} intent - Validated renderer intent payload.
     * @returns {boolean} True after the test adapter accepts the intent.
     */
    function invoke(intent) {
        calls.push(intent)
        return true
    }

    return { adapter: createRendererIntentAdapter({ supportedIntents, invoke }), calls }
}
