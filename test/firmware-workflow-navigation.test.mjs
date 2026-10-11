// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createOpenRdxIntentAdapter } from '../src/renderer/intent-adapter.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { createUtilityOperationController } from '../src/renderer/workflows/utility-operation-controller.mjs'

/**
 * Exercises the command-rail shortcut through the production renderer adapters.
 * Opening preflight must remain local; file selection requires a separate click.
 * @param {import('node:test').TestContext} context - Cleanup owner.
 * @returns {Promise<void>} Resolves after navigation and cancelled selection checks.
 */
async function testFirmwareWorkflowNavigation(context) {
    const dom = new JSDOM('<!doctype html><div id="app"></div>', { pretendToBeVisual: true })
    const { document } = dom.window
    const fixture = createFixtureState({ mode: 'one-device' })
    const store = createStore({ ...fixture, devices: [{ ...fixture.devices[0], media: null, mediaState: 'no-media' }] })
    const calls = []
    const api = {
        files: {
            /** @returns {Promise<object>} Records explicit selection and simulates cancellation. */
            async chooseFirmware() {
                calls.push('choose-firmware')
                return { ok: false, reason: 'firmware-selection-cancelled' }
            }
        },
        operations: {
            /** @param {object} request - Unexpected operation request. @returns {Promise<object>} Rejected admission. */
            async start(request) {
                calls.push(request)
                return { ok: false, reason: 'invalid-operation-request' }
            }
        }
    }
    const controller = mountApplication(document.querySelector('#app'), {
        store,
        intentAdapter: createOpenRdxIntentAdapter(api),
        utilityController: createUtilityOperationController(api)
    })
    context.after(() => {
        controller.destroy()
        dom.window.close()
    })

    const shortcut = document.querySelector('[data-operation="firmware-update"]')
    assert.equal(shortcut.disabled, false)
    shortcut.querySelector('span').click()

    assert.equal(document.querySelector('[role="tab"][aria-selected="true"]').dataset.area, 'utilities')
    const firmware = document.querySelector('[data-feature="firmware"]')
    assert.ok(firmware.querySelector('[data-prerequisite="media-ejected"]'))
    assert.equal(document.activeElement, firmware.querySelector('h3'))
    assert.deepEqual(calls, [], 'Opening the workflow must not choose a file or start an update')
    assert.equal(store.getState().activeOperation, null)

    const chooseFirmware = firmware.querySelector('[data-action="start-firmware"]')
    assert.equal(chooseFirmware.disabled, false)
    chooseFirmware.click()
    await new Promise((resolve) => setTimeout(resolve, 0))
    assert.deepEqual(calls, ['choose-firmware'])
    assert.match(document.querySelector('[data-utility-feedback]').textContent, /cancelled/i)
    assert.equal(document.querySelector('[data-utility-feedback]').closest('[data-feature]'), firmware, 'Chooser failures must stay beside the firmware action')
    assert.equal(chooseFirmware.disabled, false)
    store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
    store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
    assert.equal(document.querySelector('[data-utility-feedback]').closest('[data-feature]'), firmware)
    assert.match(document.querySelector('[data-utility-feedback]').textContent, /cancelled/i)
    assert.equal(store.getState().activeOperation, null)

    document.querySelector('[role="tab"][data-area="status"]').click()
    document.querySelector('[data-operation="firmware-update"]').click()
    assert.equal(document.activeElement, document.querySelector('[data-feature="firmware"] h3'))
    assert.deepEqual(calls, ['choose-firmware'], 'Reopening preflight must not repeat file selection')
}

test('firmware shortcut opens and focuses preflight before explicit file selection', testFirmwareWorkflowNavigation)

/**
 * Confirms unavailable firmware shortcuts cannot navigate around media or operation gates.
 * @returns {void} Throws if a disabled shortcut opens the firmware workflow.
 */
function testUnavailableFirmwareNavigation() {
    for (const mode of ['one-device', 'busy']) {
        const dom = new JSDOM('<!doctype html><div id="app"></div>')
        const { document } = dom.window
        const store = createStore(createFixtureState({ mode }))
        const controller = mountApplication(document.querySelector('#app'), {
            store,
            intentAdapter: createOpenRdxIntentAdapter({
                operations: {
                    /** @returns {never} Fails if a disabled shortcut reaches the bridge. */
                    start() {
                        assert.fail('Disabled firmware shortcut submitted an operation')
                    }
                }
            })
        })
        try {
            const shortcut = document.querySelector('[data-operation="firmware-update"]')
            assert.equal(shortcut.disabled, true)
            shortcut.click()
            assert.equal(document.querySelector('[data-utilities-view]'), null)
        } finally {
            controller.destroy()
            dom.window.close()
        }
    }
}

test('firmware shortcut preserves media and active-operation gates', testUnavailableFirmwareNavigation)

/** @returns {Promise<void>} Verifies discovery cannot release an outstanding firmware chooser. */
async function testPendingFirmwareSelection() {
    const dom = new JSDOM('<!doctype html><div id="app"></div>', { pretendToBeVisual: true })
    const { document } = dom.window
    const fixture = createFixtureState({ mode: 'one-device' })
    const store = createStore({ ...fixture, discovery: { ...fixture.discovery, epoch: 1, listRevision: 1 }, devices: [{ ...fixture.devices[0], media: null, mediaState: 'no-media' }] })
    let completeSelection
    let selections = 0
    const controller = mountApplication(document.querySelector('#app'), {
        store,
        utilityController: createUtilityOperationController({
            files: {
                /** @returns {Promise<object>} Held chooser response. */
                async chooseFirmware() {
                    selections += 1
                    return await new Promise((resolve) => {
                        completeSelection = resolve
                    })
                }
            },
            operations: { start: () => assert.fail('Cancelled selection must not dispatch firmware') }
        })
    })
    try {
        document.querySelector('[role="tab"][data-area="utilities"]').click()
        const action = document.querySelector('[data-action="start-firmware"]')
        action.click()
        for (let index = 0; index < 3; index += 1) {
            const state = store.getState()
            store.dispatch({ type: 'device/list-replaced', devices: [{ ...state.devices[0], revision: state.devices[0].revision + 1 }], epoch: 1, listRevision: state.discovery.listRevision + 1 })
            assert.equal(action.disabled, true)
            assert.equal(action.getAttribute('aria-busy'), 'true')
            action.click()
            assert.equal(selections, 1)
            assert.doesNotMatch(document.querySelector('[data-utility-feedback]').textContent, /\{operation\}/)
        }
        completeSelection({ ok: false, reason: 'firmware-selection-cancelled' })
        await new Promise(setImmediate)
        assert.equal(action.disabled, false)
        assert.equal(action.hasAttribute('aria-busy'), false)
    } finally {
        controller.destroy()
        dom.window.close()
    }
}

test('firmware chooser stays busy across newer discovery revisions and admits one selection', testPendingFirmwareSelection)
