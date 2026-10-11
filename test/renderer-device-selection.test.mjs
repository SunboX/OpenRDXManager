// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createDashboardDom, createRecordingIntentAdapter } from './helpers/renderer-dom.mjs'

test('a connected unselected drive offers selection instead of an empty discovery claim', (context) => {
    const fixture = createFixtureState({ mode: 'one-device' })
    const recorder = createRecordingIntentAdapter(['scan', 'operation'])
    const { dom, root, store, controller } = createDashboardDom({ ...fixture, selectedDeviceId: null, discovery: { ...fixture.discovery, diagnostics: { candidateCount: 3, acceptedCount: 1, rejections: [{ reason: 'candidate-validation-failed', count: 2 }] } } }, { intentAdapter: recorder.adapter })
    context.after(() => {
        controller.destroy()
        dom.window.close()
    })
    const main = root.querySelector('#main-content')
    assert.match(main.textContent, /Select an RDX drive/)
    assert.doesNotMatch(main.textContent, /No RDX drives detected|no RDX identity was validated/)
    assert.equal(main.querySelector('[data-discovery-diagnostics]'), null)
    assert.equal(store.getState().selectedDeviceId, null)
    assert.equal(root.querySelector('[role="tab"]'), null)
    main.querySelector('[data-action="manage-device"]').click()
    assert.equal(store.getState().selectedDeviceId, fixture.devices[0].id)
    assert.equal(root.querySelector('[data-area="status"]').getAttribute('aria-selected'), 'true')
    assert.match(root.querySelector('#main-content').textContent, /Selected device/)
    assert.deepEqual(recorder.calls, [], 'Local selection must not issue a device operation')
    const keys = [...root.querySelectorAll('[data-focus-key]')].map((element) => element.dataset.focusKey)
    assert.equal(new Set(keys).size, keys.length)
})

test('a returned drive requires reselection and restores its management panel when chosen', (context) => {
    const fixture = createFixtureState({ mode: 'one-device' })
    const first = fixture.devices[0]
    const { dom, root, store, controller } = createDashboardDom({ ...fixture, discovery: { ...fixture.discovery, epoch: 1, listRevision: 1, selectionInitialized: true } })
    context.after(() => {
        controller.destroy()
        dom.window.close()
    })
    store.dispatch({ type: 'device/removed', deviceId: first.id, deviceRevision: first.revision, epoch: 1, listRevision: 2 })
    assert.match(root.querySelector('#main-content').textContent, /No RDX drives detected/)
    store.dispatch({ type: 'device/list-replaced', epoch: 1, listRevision: 3, devices: [{ ...first, revision: first.revision + 1 }] })
    assert.equal(store.getState().selectedDeviceId, null, 'Do not automatically retarget a disconnected selection')
    assert.match(root.querySelector('#main-content').textContent, /Select an RDX drive/)
    assert.doesNotMatch(root.querySelector('#main-content').textContent, /No RDX drives detected/)
    root.querySelector('[data-device-rail] [data-action="manage-device"]').click()
    assert.equal(store.getState().selectedDeviceId, first.id)
    assert.equal(root.querySelector('[role="tab"][aria-selected="true"]').dataset.area, 'status')
    assert.match(root.querySelector('#main-content').textContent, new RegExp(first.serial))
})
