// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { createRuntimeState, bindOpenRdxStore } from '../src/renderer/service-binding.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { renderShell } from '../src/renderer/views/shell-view.mjs'
import { createDeviceSnapshot } from '../src/shared/contracts.mjs'
import { englishCatalog } from '../src/locales/en.mjs'

/**
 * Creates a renderer-safe discovered-device snapshot without fixture provenance.
 * @returns {object} Strict device snapshot.
 */
function createDiscoveredDevice() {
    return createDeviceSnapshot({
        id: 'rdx:live-1',
        revision: 2,
        vendor: 'TANDBERG',
        product: 'RDX',
        serial: 'LIVE1',
        media: null,
        capabilities: { 'self-test': { state: 'available' } }
    })
}

/** @param {object[]} devices - Initial strict devices. @returns {object} Versioned native list response. */
function createListResponse(devices) {
    return { ok: true, status: 'ready', mode: 'native', privileged: true, hardwareReady: true, hardwareVerified: false, platformCapability: { state: 'available' }, epoch: 1, listRevision: 0, devices }
}

/**
 * Creates a controlled named preload API with observable subscriptions.
 * @param {object} listResponse - Initial devices.list response.
 * @returns {{api: object, deviceListeners: Set<Function>, operationListeners: Set<Function>}} Fake API and listeners.
 */
function createApi(listResponse) {
    const deviceListeners = new Set()
    const operationListeners = new Set()
    const settingsListeners = new Set()

    /**
     * Creates an idempotent listener remover.
     * @param {Set<Function>} listeners - Owning listener set.
     * @param {Function} listener - Registered callback.
     * @returns {() => void} Unsubscribe callback.
     */
    function createUnsubscribe(listeners, listener) {
        /** Removes the exact registered listener. */
        function unsubscribe() {
            listeners.delete(listener)
        }
        return unsubscribe
    }

    return {
        api: {
            service: {
                /** @returns {Promise<object>} Controlled setup state. */
                async getSetup() {
                    return { ok: true, state: 'enabled' }
                }
            },
            devices: {
                /** @returns {Promise<object>} Controlled initial device result. */
                async list() {
                    return listResponse
                },
                /**
                 * Registers one device/service event callback.
                 * @param {Function} listener - Renderer callback.
                 * @returns {() => void} Unsubscribe callback.
                 */
                subscribe(listener) {
                    deviceListeners.add(listener)
                    return createUnsubscribe(deviceListeners, listener)
                }
            },
            operations: {
                /**
                 * Registers one operation event callback.
                 * @param {Function} listener - Renderer callback.
                 * @returns {() => void} Unsubscribe callback.
                 */
                subscribe(listener) {
                    operationListeners.add(listener)
                    return createUnsubscribe(operationListeners, listener)
                }
            },
            settings: {
                /** @returns {Promise<object>} Controlled persisted settings. */
                async get() {
                    return { ok: true, settings: { autoScan: true, eventLogging: true, language: 'en', lastSafeView: 'status', updateChecks: true } }
                },
                /** @param {Function} listener - Renderer settings callback. @returns {() => void} Unsubscribe callback. */
                subscribe(listener) {
                    settingsListeners.add(listener)
                    return createUnsubscribe(settingsListeners, listener)
                }
            }
        },
        deviceListeners,
        operationListeners,
        settingsListeners
    }
}

test('hydrates persisted settings and follows later main or tray settings events', async () => {
    const store = createStore(createRuntimeState())
    const controlled = createApi(createListResponse([]))
    controlled.api.settings.get = async () => ({ ok: true, settings: { autoScan: false, eventLogging: false, language: 'de', lastSafeView: 'utilities', updateChecks: false } })
    const binding = bindOpenRdxStore(controlled.api, store)
    await binding.ready
    assert.deepEqual(store.getState().settings, { autoScan: false, eventLogging: false, language: 'de', lastSafeView: 'utilities', updateChecks: false })

    publish(controlled.settingsListeners, { autoScan: true, eventLogging: true, language: 'fr', lastSafeView: 'tests', updateChecks: true })
    assert.deepEqual(store.getState().settings, { autoScan: true, eventLogging: true, language: 'fr', lastSafeView: 'tests', updateChecks: true })
    binding.destroy()
    assert.equal(controlled.settingsListeners.size, 0)
})

/**
 * Delivers an event to every current listener.
 * @param {Set<Function>} listeners - Current subscription callbacks.
 * @param {object} event - Strict renderer-safe event.
 * @returns {void} Completes after synchronous delivery.
 */
function publish(listeners, event) {
    for (const listener of listeners) {
        listener(event)
    }
}

test('maps a ready zero-device service separately from service unavailability', async () => {
    const store = createStore(createRuntimeState())
    const { api, deviceListeners } = createApi(createListResponse([]))
    const binding = bindOpenRdxStore(api, store)

    assert.equal(store.getState().service.status, 'starting')
    await binding.ready
    assert.deepEqual(store.getState().service, { status: 'ready', mode: 'native', privileged: true, hardwareReady: true, hardwareVerified: false, platformCapability: { state: 'available' } })
    assert.deepEqual(store.getState().privilegedServiceSetup, { state: 'enabled' })
    assert.deepEqual(store.getState().devices, [])

    publish(deviceListeners, { type: 'service', status: 'unavailable', reason: 'service-malformed-data' })
    publish(deviceListeners, { type: 'snapshot', epoch: 1, listRevision: 1, device: createDiscoveredDevice() })
    assert.deepEqual(store.getState().service, { status: 'unavailable', reason: 'service-malformed-data' })
    assert.deepEqual(store.getState().devices, [])

    binding.destroy()
    assert.equal(deviceListeners.size, 0)
})

test('hydrates a closed hardware-service setup state without exposing native details', async () => {
    const store = createStore(createRuntimeState())
    const controlled = createApi(createListResponse([]))
    controlled.api.service.getSetup = async () => ({ ok: true, state: 'requires-approval' })
    const binding = bindOpenRdxStore(controlled.api, store)
    await binding.ready
    assert.deepEqual(store.getState().privilegedServiceSetup, { state: 'requires-approval' })
    binding.destroy()
})

test('the real runtime initial render is explicitly starting and never green-ready', () => {
    const state = createRuntimeState()
    const html = renderShell(state, { translator: createTranslator(englishCatalog, englishCatalog) })

    assert.match(html, /data-service-status="starting"/)
    assert.match(html, /service-pill--warning/)
    assert.match(html, /Service starting/)
    assert.doesNotMatch(html, /Service ready|ph-check-circle|Fixture preview|Fixture state loaded/)
})

test('fixture activity identifies deterministic preview data without an obsolete native roadmap claim', () => {
    const html = renderShell(createFixtureState({ mode: 'one-device' }), { translator: createTranslator(englishCatalog, englishCatalog) })

    assert.match(html, /Deterministic fixture preview/)
    assert.match(html, /bundled test data/)
    assert.match(html, /no live RDX hardware result is reported/)
    assert.doesNotMatch(html, /Hardware service pending|Native integration follows in a later phase/)
})

test('production service devices render a connected hardware badge without fixture claims', async () => {
    const store = createStore(createRuntimeState())
    const { api } = createApi(createListResponse([createDiscoveredDevice()]))
    const binding = bindOpenRdxStore(api, store)
    await binding.ready
    const html = renderShell(store.getState(), { translator: createTranslator(englishCatalog, englishCatalog) })

    assert.match(html, /Hardware connected/)
    assert.doesNotMatch(html, /Hardware unverified|service-pill--warning/)
    assert.match(html, /Detected|Live hardware|Updated from connected hardware|No service activity has been recorded/)
    assert.doesNotMatch(html, /Operational|Fixture preview|Fixture state loaded|Demonstration data|No live device was queried/)
    binding.destroy()
})

test('a ready native service with no validated devices never claims hardware is connected', async (context) => {
    for (const diagnostics of [
        { candidateCount: 0, acceptedCount: 0, rejections: [] },
        { candidateCount: 1, acceptedCount: 0, rejections: [{ reason: 'candidate-validation-failed', count: 1 }] }
    ]) {
        await context.test(`${diagnostics.candidateCount} candidates`, async () => {
            const store = createStore(createRuntimeState())
            const { api } = createApi({ ...createListResponse([]), hardwareVerified: true, diagnostics })
            const binding = bindOpenRdxStore(api, store)
            await binding.ready
            const html = renderShell(store.getState(), { intentAvailability: { scan: true }, translator: createTranslator(englishCatalog, englishCatalog) })

            assert.match(html, /data-service-status="ready"[^>]*><i[^>]*><\/i>No RDX devices connected<\/span>/)
            assert.doesNotMatch(html, /Hardware connected|Hardware unavailable/)
            assert.doesNotMatch(html, /data-action="scan-devices"[^>]*disabled/)
            assert.match(html, /No RDX drives detected/)
            binding.destroy()
        })
    }
})

test('the connected badge follows validated device additions and removals without a new handshake', async () => {
    const store = createStore(createRuntimeState())
    const { api, deviceListeners } = createApi(createListResponse([createDiscoveredDevice()]))
    const binding = bindOpenRdxStore(api, store)
    await binding.ready
    const translator = createTranslator(englishCatalog, englishCatalog)

    publish(deviceListeners, { type: 'removed', epoch: 1, listRevision: 1, deviceId: 'rdx:live-1', deviceRevision: 2 })
    assert.match(renderShell(store.getState(), { translator }), /No RDX devices connected/)
    assert.doesNotMatch(renderShell(store.getState(), { translator }), /Hardware connected/)

    const reconnected = { ...createDiscoveredDevice(), revision: 3 }
    publish(deviceListeners, { type: 'snapshot', epoch: 1, listRevision: 2, device: reconnected })
    assert.match(renderShell(store.getState(), { translator }), /Hardware connected/)

    publish(deviceListeners, { type: 'list', epoch: 1, listRevision: 3, devices: [] })
    assert.match(renderShell(store.getState(), { translator }), /No RDX devices connected/)
    assert.doesNotMatch(renderShell(store.getState(), { translator }), /Hardware connected/)
    binding.destroy()
})

test('disables Scan visibly when a ready no-device service reports hardware false', async () => {
    const store = createStore(createRuntimeState())
    const response = { ...createListResponse([]), mode: 'no-device', hardwareReady: false }
    const { api } = createApi(response)
    const binding = bindOpenRdxStore(api, store)
    await binding.ready
    const html = renderShell(store.getState(), { intentAvailability: { scan: true }, translator: createTranslator(englishCatalog, englishCatalog) })

    assert.match(html, /data-action="scan-devices"[^>]*disabled/)
    assert.match(html, /hardware-unavailable/)
    assert.doesNotMatch(html, /INTENT_SCAN_UNAVAILABLE/)
    binding.destroy()
})

test('maps strict device and operation events while preserving identity revisions', async () => {
    const device = createDiscoveredDevice()
    const store = createStore(createRuntimeState())
    const { api, deviceListeners, operationListeners } = createApi(createListResponse([device]))
    const binding = bindOpenRdxStore(api, store)
    await binding.ready

    assert.equal(store.getState().selectedDeviceId, 'rdx:live-1')
    publish(operationListeners, {
        state: 'queued',
        operationId: 'op:live-1',
        kind: 'self-test',
        deviceId: 'rdx:live-1',
        deviceRevision: 2,
        stage: 'queued'
    })
    publish(operationListeners, {
        state: 'progress',
        operationId: 'op:live-1',
        kind: 'self-test',
        deviceId: 'rdx:live-1',
        deviceRevision: 2,
        stage: 'diagnostic-running',
        progress: 0.4,
        cancellationState: 'cancellable'
    })

    assert.deepEqual(store.getState().activeOperation, {
        id: 'op:live-1',
        kind: 'self-test',
        deviceId: 'rdx:live-1',
        deviceRevision: 2,
        status: 'progress',
        stage: 'diagnostic-running',
        progress: 0.4,
        cancellationState: 'cancellable'
    })

    publish(operationListeners, {
        state: 'failed',
        operationId: 'op:live-1',
        kind: 'self-test',
        deviceId: 'rdx:live-1',
        deviceRevision: 2,
        stage: 'diagnostic-cleanup',
        error: {
            code: 'service-unavailable',
            messageKey: 'errors.service.unavailable',
            stage: 'diagnostic-running',
            category: 'transport',
            retryable: true,
            supportCorrelationId: 'support:live-1',
            cleanupEvidence: [],
            attemptHistory: []
        }
    })

    assert.equal(store.getState().activeOperation, null)
    assert.equal(store.getState().lastOperation.status, 'failed')
    assert.equal(store.getState().lastOperation.deviceRevision, 2)

    publish(deviceListeners, { type: 'removed', epoch: 1, listRevision: 1, deviceId: 'rdx:live-1', deviceRevision: 2 })
    assert.deepEqual(store.getState().devices, [])
    assert.equal(store.getState().selectedDeviceId, null)
    binding.destroy()
})

test('rejects delayed list rollback and tombstone resurrection in the renderer', async () => {
    const device = createDiscoveredDevice()
    const store = createStore(createRuntimeState())
    const { api, deviceListeners } = createApi(createListResponse([device]))
    const binding = bindOpenRdxStore(api, store)
    await binding.ready

    publish(deviceListeners, { type: 'removed', epoch: 1, listRevision: 2, deviceId: device.id, deviceRevision: 2 })
    publish(deviceListeners, { type: 'list', epoch: 1, listRevision: 1, devices: [device] })
    publish(deviceListeners, { type: 'snapshot', epoch: 1, listRevision: 3, device })

    assert.deepEqual(store.getState().devices, [])
    assert.equal(store.getState().discovery.listRevision, 2)
    assert.equal(store.getState().discovery.tombstones[device.id], 2)
    binding.destroy()
})

test('a failed device subscription cannot become ready from a later list', async () => {
    const store = createStore(createRuntimeState())
    const { api } = createApi(createListResponse([]))
    api.devices.subscribe = () => {
        throw new Error('controlled-subscription-failure')
    }
    const binding = bindOpenRdxStore(api, store)

    await binding.ready

    assert.deepEqual(store.getState().service, { status: 'unavailable', reason: 'service-unavailable' })
    binding.destroy()
})

test('maps an initial service failure without substituting fixture devices', async () => {
    const store = createStore(createRuntimeState())
    const { api } = createApi({ ok: false, reason: 'service-unavailable' })
    const binding = bindOpenRdxStore(api, store)

    await binding.ready

    assert.deepEqual(store.getState().service, { status: 'unavailable', reason: 'service-unavailable' })
    assert.deepEqual(store.getState().devices, [])
    assert.equal(JSON.stringify(store.getState()).includes('7810544062'), false)
    binding.destroy()
})
