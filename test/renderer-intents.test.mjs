// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createDashboardDom, createRecordingIntentAdapter } from './helpers/renderer-dom.mjs'

/**
 * Verifies bound external controls emit only narrow renderer intents and that
 * every reviewed action type reaches the injected adapter.
 * @returns {Promise<void>} Throws when an action is inert or leaks transport data.
 */
async function testDispatchesNarrowInjectedRendererIntents() {
    const supported = ['scan', 'operation', 'retry-operation', 'retry-service', 'open-support', 'open-event-log']
    const recorder = createRecordingIntentAdapter(supported)
    const failed = createFixtureState({ mode: 'operation-failed' })
    const dashboard = createDashboardDom(failed, { intentAdapter: recorder.adapter })
    const document = dashboard.dom.window.document

    document.querySelector('[data-action="scan-devices"]').click()
    document.querySelector('[data-operation="status-refresh"]').click()
    document.querySelector('[data-action="retry-operation"]').click()
    document.querySelector('[data-action="open-event-log"]').click()
    document.querySelector('[data-action="open-support"]').click()

    const unavailable = createDashboardDom(createFixtureState({ mode: 'service-unavailable' }), { intentAdapter: recorder.adapter })
    unavailable.dom.window.document.querySelector('[data-action="retry-service"]').click()

    assert.deepEqual(recorder.calls, [{ type: 'scan' }, { type: 'operation', kind: 'status-refresh', deviceId: 'rdx:7810544062', deviceRevision: 4 }, { type: 'retry-operation', kind: 'self-test', deviceId: 'rdx:7810544062', deviceRevision: 4, operationId: 'op-fixture-self-test' }, { type: 'open-event-log' }, { type: 'open-support' }, { type: 'retry-service' }])
    assert.equal(await recorder.adapter.invoke({ type: 'scan', osPath: '/dev/disk9' }), false)
    assert.equal(recorder.calls.length, 6)
    assert.equal(JSON.stringify(recorder.calls).includes('osPath'), false)
    assert.equal(JSON.stringify(recorder.calls).includes('rawCdb'), false)

    dashboard.controller.destroy()
    dashboard.dom.window.close()
    unavailable.controller.destroy()
    unavailable.dom.window.close()
}

/**
 * Verifies a hardware action uses the already validated selected revision
 * without starting a disruptive discovery pass immediately before execution.
 * @returns {Promise<void>} Resolves after the operation intent is recorded.
 */
async function testUsesValidatedRevisionWithoutPreflightScan() {
    const recorder = createRecordingIntentAdapter(['operation'])
    const source = createFixtureState({ mode: 'one-device' })
    const fixture = { ...source, discovery: { ...source.discovery, epoch: 1 } }
    let preflightScans = 0
    const deviceController = {
        destroy() {},
        isAvailable: () => true,
        requestManualScan: async () => ({ ok: true }),
        startAutoScan() {},
        stopAutoScan() {},
        /** @returns {Promise<object>} Records an unwanted pre-operation scan. */
        async refreshForOperation() {
            preflightScans += 1
            return { ok: true }
        }
    }
    const dashboard = createDashboardDom(fixture, { deviceController, intentAdapter: recorder.adapter })

    dashboard.dom.window.document.querySelector('[data-operation="eject-safe"]').click()
    await Promise.resolve()

    assert.equal(preflightScans, 0)
    assert.deepEqual(recorder.calls, [{ type: 'operation', kind: 'eject-safe', deviceId: 'rdx:7810544062', deviceRevision: 4 }])
    dashboard.controller.destroy()
    dashboard.dom.window.close()
}

test('dispatches narrow injected renderer intents end to end', testDispatchesNarrowInjectedRendererIntents)
test('uses the validated selected revision without a disruptive preflight scan', testUsesValidatedRevisionWithoutPreflightScan)
