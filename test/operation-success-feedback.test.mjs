// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createStore } from '../src/renderer/store.mjs'

for (const [platform, kind] of ['win32', 'darwin', 'linux'].flatMap((platform) => ['volume-label-set', 'format', 'self-test'].map((kind) => [platform, kind]))) {
    test(`${platform} ${kind} leaves readable completion for eight seconds without retaining the operation lock`, (context) => {
        context.mock.timers.enable({ apis: ['setTimeout', 'Date'] })
        const dom = new JSDOM('<!doctype html><div id="app"></div>', { pretendToBeVisual: true })
        context.mock.method(dom.window.document, 'hasFocus', () => true)
        const fixture = createFixtureState({ mode: 'one-device' })
        const store = createStore({ ...fixture, activeArea: 'utilities' })
        const { document } = dom.window
        const controller = mountApplication(document.querySelector('#app'), { store, platform })
        context.after(() => {
            controller.destroy()
            dom.window.close()
        })
        store.dispatch({ type: 'operation/started', operationId: 'op:quick-completion', kind })
        assert.ok(document.querySelector('[data-operation-status]'))
        store.dispatch({ type: 'operation/succeeded', operationId: 'op:quick-completion' })
        const banner = document.querySelector('[data-operation-success]')
        assert.ok(banner, 'Even an immediate completion must leave a readable message')
        assert.match(banner.textContent, /completed/)
        assert.equal(banner.getAttribute('aria-live'), 'polite')
        assert.equal(store.getState().activeOperation, null, 'Presentation must not extend the hardware lock')
        assert.equal(document.querySelector('[data-operation-status]'), null, 'Finished work must not claim to remain in progress')
        context.mock.timers.tick(7_999)
        store.dispatch({ type: 'device/refreshed', device: { ...fixture.devices[0], revision: fixture.devices[0].revision + 1 } })
        assert.ok(document.querySelector('[data-operation-success]'), 'Refresh must preserve the completion message')
        context.mock.timers.tick(1)
        assert.equal(document.querySelector('[data-operation-success]'), null)
        assert.equal(store.getState().lastOperation.status, 'succeeded', 'History remains available after the message expires')
        store.dispatch({ type: 'device/refreshed', device: { ...fixture.devices[0], revision: fixture.devices[0].revision + 2 } })
        assert.equal(document.querySelector('[data-operation-success]'), null, 'Refresh must not restart an expired message')
    })
}
