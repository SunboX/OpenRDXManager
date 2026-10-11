// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createStore } from '../src/renderer/store.mjs'

/**
 * Exercises real terminal rendering across reconnect revision changes and scans.
 * Refreshes must neither erase the confirmation early nor restart its timeout.
 * @param {import('node:test').TestContext} context - Owns isolated DOM cleanup.
 * @returns {void} Throws if verified completion disappears during refresh.
 */
function firmwareSuccessSurvivesRefresh(context) {
    context.mock.timers.enable({ apis: ['setTimeout', 'Date'] })
    const dom = new JSDOM('<!doctype html><div id="app"></div>', { pretendToBeVisual: true })
    context.mock.method(dom.window.document, 'hasFocus', () => true)
    const fixture = createFixtureState({ mode: 'one-device' })
    const device = { ...fixture.devices[0], media: null, mediaState: 'no-media' }
    const store = createStore({ ...fixture, activeArea: 'utilities', devices: [device] })
    const { document } = dom.window
    const controller = mountApplication(document.querySelector('#app'), { store })
    context.after(() => {
        controller.destroy()
        dom.window.close()
    })
    const operation = { operationId: 'op:firmware-success', kind: 'firmware-update', deviceId: device.id, deviceRevision: device.revision }
    store.dispatch({ type: 'operation/event', event: { ...operation, state: 'started', stage: 'firmware-validating' } })
    assert.equal(document.querySelector('[data-operation-success]'), null)
    store.dispatch({ type: 'operation/event', event: { ...operation, state: 'succeeded', stage: 'firmware-readback' } })
    const banner = document.querySelector('[data-operation-success]')
    assert.ok(banner, 'A verified firmware result must leave a visible confirmation')
    assert.equal(banner.getAttribute('role'), 'status')
    assert.equal(banner.getAttribute('aria-live'), 'polite')
    assert.match(banner.textContent, /Firmware update successful/)
    assert.ok(banner.querySelector('.ph-check-circle'))
    assert.equal(document.querySelector('[data-operation-status]'), null)

    context.mock.timers.tick(4_000)
    store.dispatch({ type: 'device/refreshed', device: { ...device, revision: device.revision + 1 } })
    assert.equal(store.getState().devices[0].revision, device.revision + 1)
    assert.ok(document.querySelector('[data-operation-success]'), 'Reconnect must not erase the confirmation')
    assert.ok(document.querySelector('[data-feature="firmware"] [data-result-status="succeeded"]'), 'The firmware card must retain its terminal result too')

    const modeControl = document.querySelector('[data-utility-mode]')
    modeControl.value = 'fixed'
    modeControl.focus()
    context.mock.timers.tick(3_999)
    assert.ok(document.querySelector('[data-operation-success]'), 'Completion must remain readable for the full display period')
    context.mock.timers.tick(1)
    assert.equal(document.querySelector('[data-operation-success]'), null, 'Success must hide after eight seconds')
    assert.ok(document.querySelector('[data-feature="firmware"] [data-result-status="succeeded"]'), 'Hiding the banner must preserve the completed update result')
    assert.equal(store.getState().lastOperation.status, 'succeeded')
    assert.equal(document.querySelector('[data-utility-mode]'), modeControl, 'Dismissing feedback must not replace controls the user is editing')
    assert.equal(modeControl.value, 'fixed')
    assert.equal(document.activeElement, modeControl)

    store.dispatch({ type: 'device/refreshed', device: { ...device, revision: device.revision + 2 } })
    assert.equal(document.querySelector('[data-operation-success]'), null, 'A later refresh must not bring the banner back')
}

test('firmware success hides after eight seconds without losing the result or restarting on refresh', firmwareSuccessSurvivesRefresh)

/**
 * A previous success deadline must not hide the next successful update early.
 * @param {import('node:test').TestContext} context - Owns clock and DOM cleanup.
 * @returns {void} Throws if operation replacement carries over a stale timer.
 */
function nextFirmwareSuccessGetsFreshTimeout(context) {
    context.mock.timers.enable({ apis: ['setTimeout', 'Date'] })
    const dom = new JSDOM('<!doctype html><div id="app"></div>', { pretendToBeVisual: true })
    context.mock.method(dom.window.document, 'hasFocus', () => true)
    const store = createStore(createFixtureState({ mode: 'one-device' }))
    const { document } = dom.window
    const controller = mountApplication(document.querySelector('#app'), { store })
    context.after(() => {
        controller.destroy()
        dom.window.close()
    })

    store.dispatch({ type: 'operation/started', operationId: 'op:first-update', kind: 'firmware-update' })
    store.dispatch({ type: 'operation/succeeded', operationId: 'op:first-update' })
    assert.ok(document.querySelector('[data-operation-success]'))
    context.mock.timers.tick(4_000)
    store.dispatch({ type: 'operation/started', operationId: 'op:second-update', kind: 'firmware-update' })
    assert.equal(document.querySelector('[data-operation-success]'), null, 'Starting another operation replaces the old banner')
    store.dispatch({ type: 'operation/succeeded', operationId: 'op:second-update' })
    context.mock.timers.tick(1_000)
    assert.ok(document.querySelector('[data-operation-success]'), 'The first update timeout must not dismiss the second success')
    context.mock.timers.tick(7_000)
    assert.equal(document.querySelector('[data-operation-success]'), null)
}

test('each successful firmware update gets a fresh timeout', nextFirmwareSuccessGetsFreshTimeout)

/**
 * A completion received in the background must still be visible on return.
 * @param {import('node:test').TestContext} context - Owns deterministic host focus and time.
 * @returns {void} Throws when time outside the app consumes the confirmation.
 */
function firmwareSuccessWaitsForForeground(context) {
    context.mock.timers.enable({ apis: ['setTimeout', 'Date'] })
    const dom = new JSDOM('<!doctype html><div id="app"></div>', { pretendToBeVisual: true })
    let focused = false
    context.mock.method(dom.window.document, 'hasFocus', () => focused)
    const store = createStore(createFixtureState({ mode: 'one-device' }))
    const { document } = dom.window
    const controller = mountApplication(document.querySelector('#app'), { store })
    context.after(() => {
        controller.destroy()
        dom.window.close()
    })

    store.dispatch({ type: 'operation/started', operationId: 'op:background-update', kind: 'firmware-update' })
    store.dispatch({ type: 'operation/succeeded', operationId: 'op:background-update' })
    context.mock.timers.tick(6_000)
    focused = true
    dom.window.dispatchEvent(new dom.window.Event('focus'))
    assert.ok(document.querySelector('[data-operation-success]'), 'Returning to the app must show the unseen success')

    context.mock.timers.tick(2_000)
    focused = false
    dom.window.dispatchEvent(new dom.window.Event('blur'))
    context.mock.timers.tick(10_000)
    focused = true
    dom.window.dispatchEvent(new dom.window.Event('focus'))
    context.mock.timers.tick(5_999)
    assert.ok(document.querySelector('[data-operation-success]'), 'Background time must not consume the remaining display period')
    context.mock.timers.tick(1)
    assert.equal(document.querySelector('[data-operation-success]'), null)
}

test('firmware success stays available until the app has displayed it for eight seconds', firmwareSuccessWaitsForForeground)

/**
 * Reconnect screens must not spend the display period before the dock returns.
 * @param {import('node:test').TestContext} context - Owns deterministic time and DOM cleanup.
 * @returns {void} Throws if the success expires before it can be rendered.
 */
function firmwareSuccessWaitsForDockView(context) {
    context.mock.timers.enable({ apis: ['setTimeout', 'Date'] })
    const dom = new JSDOM('<!doctype html><div id="app"></div>', { pretendToBeVisual: true })
    context.mock.method(dom.window.document, 'hasFocus', () => true)
    const fixture = createFixtureState({ mode: 'one-device' })
    const store = createStore(fixture)
    const { document } = dom.window
    const controller = mountApplication(document.querySelector('#app'), { store })
    context.after(() => {
        controller.destroy()
        dom.window.close()
    })
    store.dispatch({ type: 'operation/started', operationId: 'op:reconnect-update', kind: 'firmware-update' })
    store.dispatch({ type: 'service/status', status: 'reconciling' })
    store.dispatch({ type: 'operation/succeeded', operationId: 'op:reconnect-update' })
    context.mock.timers.tick(6_000)
    assert.equal(document.querySelector('[data-operation-success]'), null)

    store.dispatch({ type: 'service/ready', epoch: 1, listRevision: 0, mode: 'native', privileged: true, hardwareReady: true, hardwareVerified: true, platformCapability: { state: 'available' } })
    store.dispatch({ type: 'device/list-replaced', epoch: 1, listRevision: 0, devices: fixture.devices })
    assert.equal(store.getState().selectedDeviceId, fixture.devices[0].id)
    assert.ok(document.querySelector('[data-operation-success]'), 'The dock view must show the previously unseen completion')
    context.mock.timers.tick(7_999)
    assert.ok(document.querySelector('[data-operation-success]'))
    context.mock.timers.tick(1)
    assert.equal(document.querySelector('[data-operation-success]'), null)
}

test('firmware success starts its display period after the dock view returns', firmwareSuccessWaitsForDockView)

/**
 * Prevents cancelled, failed, other-device operations claiming firmware success.
 * @returns {void} Throws if non-success state renders a green confirmation.
 */
function firmwareSuccessRequiresMatchingCompletion() {
    const fixture = createFixtureState({ mode: 'operation-failed' })
    for (const overrides of [{ status: 'failed' }, { status: 'cancelled' }, { deviceId: 'rdx:other-device' }]) {
        const dom = new JSDOM('<!doctype html><div id="app"></div>')
        const store = createStore({ ...fixture, lastOperation: { ...fixture.lastOperation, kind: 'firmware-update', status: 'succeeded', ...overrides } })
        const controller = mountApplication(dom.window.document.querySelector('#app'), { store })
        try {
            assert.equal(dom.window.document.querySelector('[data-operation-success]'), null)
        } finally {
            controller.destroy()
            dom.window.close()
        }
    }
}

test('firmware success requires a successful operation for the selected dock', firmwareSuccessRequiresMatchingCompletion)

/**
 * Identifies the updated drive using its reported serial, preserving literal text.
 * @returns {void} Throws for a missing, hard-coded, cartridge, or interpreted serial.
 */
function firmwareSuccessShowsDriveSerial() {
    const fixture = createFixtureState({ mode: 'one-device' })
    for (const serial of ['0007360242', 'drive<&>"001']) {
        const dom = new JSDOM('<!doctype html><div id="app"></div>')
        const device = { ...fixture.devices[0], serial }
        const store = createStore({ ...fixture, devices: [device], lastOperation: { id: 'op:serial-feedback', kind: 'firmware-update', deviceId: device.id, deviceRevision: device.revision, status: 'succeeded' } })
        const controller = mountApplication(dom.window.document.querySelector('#app'), { store })
        try {
            const banner = dom.window.document.querySelector('[data-operation-success]')
            assert.ok(banner)
            assert.ok(banner.textContent.includes(`TANDBERG · Serial ${serial}`), 'Show the exact updated drive serial, including leading zeroes')
            assert.equal(banner.textContent.includes(device.media.serial), false, 'The cartridge serial does not identify the updated drive')
            assert.equal(banner.querySelector('drive'), null, 'Device text must not become markup')
        } finally {
            controller.destroy()
            dom.window.close()
        }
    }
}

test('firmware success identifies the Tandberg drive by its serial number', firmwareSuccessShowsDriveSerial)
