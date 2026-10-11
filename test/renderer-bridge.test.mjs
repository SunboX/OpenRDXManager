// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createOpenRdxIntentAdapter } from '../src/renderer/intent-adapter.mjs'
import { createStore } from '../src/renderer/store.mjs'

test('binds the named OpenRDX API end to end', () => {
    const calls = []
    const api = Object.freeze({
        devices: Object.freeze({
            /**
             * Records a named scan intent.
             * @param {object} request - Strict empty scan parameters.
             * @returns {Promise<number>} Updated call count.
             */
            async scan(request) {
                return calls.push({ method: 'devices.scan', request })
            }
        }),
        logs: Object.freeze({
            /**
             * Records a named event-log intent.
             * @param {object} request - Strict empty log parameters.
             * @returns {Promise<number>} Updated call count.
             */
            async list(request) {
                return calls.push({ method: 'logs.list', request })
            }
        }),
        operations: Object.freeze({
            /**
             * Records a named operation intent.
             * @param {object} request - Strict high-level operation request.
             * @returns {Promise<number>} Updated call count.
             */
            async start(request) {
                return calls.push({ method: 'operations.start', request })
            }
        }),
        service: Object.freeze({
            /**
             * Records a main-owned service recovery intent.
             * @param {object} request - Strict empty retry parameters.
             * @returns {Promise<number>} Updated call count.
             */
            async retry(request) {
                return calls.push({ method: 'service.retry', request })
            }
        }),
        support: Object.freeze({
            /**
             * Records a named application-owned support intent.
             * @param {object} request - Strict empty support parameters.
             * @returns {Promise<number>} Updated call count.
             */
            async generateSummary(request) {
                return calls.push({ method: 'support.generateSummary', request })
            }
        })
    })
    const intentAdapter = createOpenRdxIntentAdapter(api)
    const dom = new JSDOM('<!doctype html><html><body><div id="app"></div></body></html>', {
        url: 'file:///openrdxmanager/src/index.html',
        pretendToBeVisual: true
    })
    const controller = mountApplication(dom.window.document.querySelector('#app'), {
        intentAdapter,
        store: createStore(createFixtureState({ mode: 'one-device' }))
    })
    const document = dom.window.document

    document.querySelector('[data-action="scan-devices"]').click()
    document.querySelector('[data-operation="status-refresh"]').click()
    document.querySelector('[data-action="open-event-log"]').click()
    document.querySelector('[data-action="open-support"]').click()

    const recoveryDom = new JSDOM('<!doctype html><html><body><div id="app"></div></body></html>', {
        url: 'file:///openrdxmanager/src/index.html',
        pretendToBeVisual: true
    })
    const recoveryController = mountApplication(recoveryDom.window.document.querySelector('#app'), {
        intentAdapter,
        store: createStore(createFixtureState({ mode: 'service-unavailable' }))
    })
    recoveryDom.window.document.querySelector('[data-action="retry-service"]').click()

    assert.deepEqual(calls, [
        { method: 'devices.scan', request: {} },
        { method: 'operations.start', request: { kind: 'status-refresh', deviceId: 'rdx:7810544062', deviceRevision: 4 } },
        { method: 'logs.list', request: {} },
        { method: 'support.generateSummary', request: {} },
        { method: 'service.retry', request: {} }
    ])
    assert.equal(intentAdapter.isAvailable('retry-operation'), false)
    assert.equal(JSON.stringify(calls).includes('channel'), false)

    controller.destroy()
    dom.window.close()
    recoveryController.destroy()
    recoveryDom.window.close()
})

const diagnosticIntent = Object.freeze({ type: 'operation', kind: 'self-test', deviceId: 'rdx:7810544062', deviceRevision: 4 })

test('operation admission is awaitable and returns the validated result without a callback', async () => {
    const admission = Promise.withResolvers()
    const adapter = createOpenRdxIntentAdapter({ operations: { start: () => admission.promise } })
    const result = adapter.invoke(diagnosticIntent)
    admission.resolve({ ok: true, operationId: 'op:diagnostic' })
    assert.deepEqual(await result, { ok: true, operationId: 'op:diagnostic' })
})

for (const [description, response, expected] of [
    ['rejected admission', { ok: false, reason: 'operation-in-progress' }, { ok: false, reason: 'operation-in-progress' }],
    ['invalid admission', { ok: true, privateDetail: '/private/secret' }, { ok: false, reason: 'invalid-service-response' }]
]) {
    test(`awaited operation reports ${description}`, async () => {
        const adapter = createOpenRdxIntentAdapter({ operations: { start: async () => response } })
        assert.deepEqual(await adapter.invoke(diagnosticIntent), expected)
    })
}

for (const asynchronous of [false, true]) {
    test(`awaited operation contains ${asynchronous ? 'rejected' : 'thrown'} bridge errors`, async () => {
        const adapter = createOpenRdxIntentAdapter({
            operations: {
                /** @returns {Promise<never>} Simulates a failed IPC invocation without exposing private details. */
                start() {
                    const error = new Error('/private/secret')
                    if (asynchronous) return Promise.reject(error)
                    throw error
                }
            }
        })
        assert.deepEqual(await adapter.invoke(diagnosticIntent), { ok: false, reason: 'service-failure' })
    })
}

test('non-operation intents wait for their bridge completion and contain failures', async () => {
    const scan = Promise.withResolvers()
    const adapter = createOpenRdxIntentAdapter({ devices: { scan: () => scan.promise } })
    const result = adapter.invoke({ type: 'scan' })
    scan.reject(new Error('/private/secret'))
    assert.deepEqual(await result, { ok: false, reason: 'service-failure' })
    assert.equal(await adapter.invoke({ type: 'scan', path: '/dev/disk9' }), false)
    assert.equal(await adapter.invoke({ type: 'retry-service' }), false)
})
