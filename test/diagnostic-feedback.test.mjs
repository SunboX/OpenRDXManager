// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createOpenRdxIntentAdapter } from '../src/renderer/intent-adapter.mjs'
import { bindOpenRdxStore } from '../src/renderer/service-binding.mjs'
import { createStore } from '../src/renderer/store.mjs'

/** @returns {object} Promise whose completion is controlled by the test. */
function deferred() {
    let resolve
    let reject
    const promise = new Promise((accept, fail) => {
        resolve = accept
        reject = fail
    })
    return { promise, resolve, reject }
}

/** @returns {Promise<void>} Drains start acknowledgements and renderer updates. */
async function settle() {
    await new Promise((resolve) => setImmediate(resolve))
}

/**
 * Mounts the production intent adapter and native event binding without hardware.
 * @param {import('node:test').TestContext} context - Cleanup owner.
 * @param {Function} start - Controlled bridge implementation.
 * @returns {Promise<object>} Live renderer and strict operation event helpers.
 */
async function harness(context, start) {
    const dom = new JSDOM('<!doctype html><div id="app"></div>', { pretendToBeVisual: true })
    const source = createFixtureState({ mode: 'one-device' })
    const store = createStore({ ...source, activeArea: 'tests', discovery: { ...source.discovery, epoch: 1, listRevision: 1 } })
    let receive
    const calls = []
    const api = {
        devices: {
            /** @returns {Promise<object>} Initial validated discovery. */
            async list() {
                return { ok: true, status: 'ready', devices: source.devices, epoch: 1, listRevision: 1, mode: 'native', privileged: true, hardwareReady: true, hardwareVerified: true, platformCapability: { state: 'available' } }
            },
            /** @returns {Function} Unused device subscription cleanup. */
            subscribe() {
                return () => {}
            }
        },
        operations: {
            /** @param {object} request - Validated intent. @returns {unknown} Controlled response. */
            start(request) {
                calls.push(request)
                return start(request)
            },
            /** @param {Function} listener - Native event receiver. @returns {Function} Cleanup. */
            subscribe(listener) {
                receive = listener
                return () => {}
            }
        }
    }
    const binding = bindOpenRdxStore(api, store)
    await binding.ready
    const root = dom.window.document.querySelector('#app')
    const controller = mountApplication(root, { store, intentAdapter: createOpenRdxIntentAdapter(api) })
    context.after(() => {
        controller.destroy()
        binding.destroy()
        dom.window.close()
    })
    const device = store.getState().devices[0]
    /** @param {string} state - Native event state. @param {object} [extra={}] - State-specific payload. @returns {void} Publishes a strict native event. */
    function emit(state, extra = {}) {
        receive({ operationId: 'op:diagnostic', kind: 'self-test', deviceId: device.id, deviceRevision: device.revision, state, stage: state === 'queued' ? 'queued' : 'diagnostic-running', ...extra })
    }
    /** @returns {HTMLElement} Current self-test card after reconciliation. */
    function card() {
        return root.querySelector('[data-test-kind="self-test"]')
    }
    /** @returns {void} Invokes the actual delegated click path. */
    function click() {
        card().querySelector('[data-test-action]').click()
    }
    /** @returns {void} Advances the selected snapshot through Auto Scan. */
    function refresh() {
        store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
        store.dispatch({ type: 'device/list-replaced', epoch: 1, listRevision: store.getState().discovery.listRevision + 1, devices: store.getState().devices.map((item) => ({ ...item, revision: item.revision + 1 })) })
        store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
    }
    return { root, store, calls, card, click, emit, refresh, destroy: controller.destroy }
}

test('diagnostic submission is immediately visible and cannot be duplicated during Auto Scan', async (context) => {
    const response = deferred()
    const ui = await harness(context, () => response.promise)
    ui.click()
    assert.match(ui.card().textContent, /Submitting Self Test/)
    assert.equal(ui.card().querySelector('[data-test-action]').disabled, true)
    ui.refresh()
    ui.click()
    assert.equal(ui.calls.length, 1)
    assert.match(ui.card().textContent, /Submitting Self Test/)
    response.resolve({ ok: true, operationId: 'op:diagnostic' })
    await settle()
    assert.match(ui.card().textContent, /Self Test accepted/)
    assert.equal(ui.card().querySelector('[data-test-result]'), null, 'Admission is not a passed diagnostic')
})

test('start rejection is visible, survives refresh, and allows a deliberate retry', async (context) => {
    const ui = await harness(context, async () => ({ ok: false, reason: 'stale-device-revision' }))
    ui.click()
    await settle()
    assert.match(ui.card().textContent, /Self Test could not start/)
    assert.match(ui.card().textContent, /stale-device-revision/)
    assert.equal(ui.card().querySelector('[role="alert"]')?.dataset.resultStatus, 'failed')
    ui.refresh()
    assert.match(ui.card().textContent, /stale-device-revision/)
    assert.equal(ui.card().querySelector('[data-test-action]').disabled, false)
    ui.click()
    await settle()
    assert.equal(ui.calls.length, 2)
})

for (const mode of ['throw', 'reject', 'invalid']) {
    test(`diagnostic ${mode} bridge failure is visible without leaking exception details`, async (context) => {
        const ui = await harness(context, () => {
            if (mode === 'throw') throw new Error('/private/secret')
            if (mode === 'reject') return Promise.reject(new Error('/private/secret'))
            return Promise.resolve({ ok: true })
        })
        ui.click()
        await settle()
        assert.match(ui.card().textContent, /Self Test could not start/)
        assert.doesNotMatch(ui.root.textContent, /private\/secret/)
        assert.equal(ui.card().querySelector('[data-test-action]').disabled, false)
    })
}

test('native progress and success survive a late acknowledgement and newer device snapshots', async (context) => {
    const response = deferred()
    const ui = await harness(context, () => response.promise)
    ui.click()
    ui.emit('queued')
    ui.emit('started')
    ui.emit('progress', { progress: 0.5, cancellationState: 'cancellable' })
    assert.equal(ui.card().querySelector('[data-progress-timeline] progress').value, 0.5)
    ui.refresh()
    assert.ok(ui.card().querySelector('[data-progress-timeline]'))
    ui.emit('succeeded', { stage: 'complete' })
    response.resolve({ ok: true, operationId: 'op:diagnostic' })
    await settle()
    const result = ui.card().querySelector('[data-test-result="self-test"]')
    assert.equal(result?.dataset.resultStatus, 'succeeded')
    assert.match(result.textContent, /Self Test passed/)
    assert.ok(result.classList.contains('operation-result--success'))
    ui.refresh()
    assert.match(ui.card().textContent, /Self Test passed/)
    assert.doesNotMatch(ui.card().textContent, /Submitting|accepted/)
    ui.click()
    assert.equal(ui.card().querySelector('[data-test-result]'), null, 'A prior pass must not be shown as the result of a new request')
})

test('native diagnostic failure shows the failure and support reference', async (context) => {
    const ui = await harness(context, async () => ({ ok: true, operationId: 'op:diagnostic' }))
    ui.click()
    ui.emit('queued')
    ui.emit('started')
    ui.emit('failed', { error: { code: 'diagnostic-failed', messageKey: 'error.diagnosticFailed', category: 'transport', cleanupEvidence: [], attemptHistory: [], stage: 'diagnostic-running', retryable: false, supportCorrelationId: 'support:diagnostic' } })
    await settle()
    assert.match(ui.card().textContent, /Self Test failed/)
    assert.match(ui.card().textContent, /support:diagnostic/)
    ui.refresh()
    assert.match(ui.card().textContent, /Self Test failed/)
})

for (const kind of ['led-test', 'write-read-test']) {
    test(`${kind} uses the same visible admission failure path`, async (context) => {
        const ui = await harness(context, async () => ({ ok: false, reason: 'operation-in-progress' }))
        const card = () => ui.root.querySelector(`[data-test-kind="${kind}"]`)
        card().querySelector('[data-test-action]').click()
        await settle()
        assert.equal(ui.calls[0].kind, kind)
        assert.match(card().textContent, /could not start/)
        assert.match(card().textContent, /operation-in-progress/)
        assert.doesNotMatch(ui.card().textContent, /could not start/)
    })
}

test('destroyed diagnostic controller ignores a late start rejection', async (context) => {
    const response = deferred()
    const ui = await harness(context, () => response.promise)
    ui.click()
    ui.destroy()
    const html = ui.root.innerHTML
    response.resolve({ ok: false, reason: 'service-failure' })
    await settle()
    assert.equal(ui.root.innerHTML, html)
})

test('invalid start details never become diagnostic feedback', async (context) => {
    const ui = await harness(context, async () => ({ ok: false, reason: '/private/secret', stack: 'private-stack' }))
    ui.click()
    await settle()
    assert.match(ui.card().textContent, /invalid-service-response/)
    assert.doesNotMatch(ui.root.textContent, /private/)
})
