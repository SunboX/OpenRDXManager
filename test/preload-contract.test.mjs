// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { wireEventSchema } from '../src/main/device-service-wire.mjs'
import { createPreloadApi } from '../src/preload-api.mjs'
import { completeDeviceSnapshot } from './helpers/device-snapshot.mjs'

/**
 * Creates a deterministic renderer transport that records IPC use.
 * @returns {{calls: object[], emit: (channel: string, payload: object) => void, transport: object}} Test transport and observations.
 */
function createTransport() {
    const calls = []
    const listeners = new Map()
    const responses = {
        'openrdx:app:get': { ok: true, app: { name: 'OpenRDXManager', version: '0.1.0', platform: 'darwin' } },
        'openrdx:app:set-tray-selection': { ok: true },
        'openrdx:devices:list': { ok: true, devices: [] },
        'openrdx:devices:scan': { ok: true },
        'openrdx:files:choose-firmware': { ok: false, reason: 'feature-unavailable' },
        'openrdx:files:choose-export': { ok: false, reason: 'feature-unavailable' },
        'openrdx:logs:list': { ok: true, entries: [] },
        'openrdx:logs:set-enabled': { ok: true },
        'openrdx:logs:export': { ok: false, reason: 'feature-unavailable' },
        'openrdx:operations:start': { ok: true, operationId: 'op:1' },
        'openrdx:operations:confirm': { ok: true, confirmationToken: 'confirm:service-owned' },
        'openrdx:operations:cancel': { ok: false, reason: 'operation-not-cancellable' },
        'openrdx:service:get-setup': { ok: true, state: 'requires-approval' },
        'openrdx:service:retry': { ok: true },
        'openrdx:service:register': { ok: false, reason: 'requires-approval' },
        'openrdx:service:open-approval-settings': { ok: true },
        'openrdx:settings:get': { ok: true, settings: { autoScan: true, eventLogging: true, language: 'en', lastSafeView: 'status', updateChecks: false } },
        'openrdx:settings:update': { ok: true, settings: { autoScan: false, eventLogging: true, language: 'en', lastSafeView: 'status', updateChecks: false } },
        'openrdx:support:generate-summary': { ok: false, reason: 'feature-unavailable' },
        'openrdx:updates:check': { ok: false, reason: 'feature-unavailable' }
    }

    return {
        calls,
        /**
         * Emits one simulated Electron event to registered preload listeners.
         * @param {string} channel - Internal test channel.
         * @param {object} payload - Candidate renderer event.
         * @returns {void} Completes after listeners receive the payload.
         */
        emit(channel, payload) {
            for (const listener of listeners.get(channel) ?? []) {
                listener({}, payload)
            }
        },
        transport: {
            /**
             * Records a validated invoke and returns its controlled response.
             * @param {string} channel - Internal channel selected by preload code.
             * @param {object} request - Validated request payload.
             * @returns {Promise<object>} Controlled main-process response.
             */
            async invoke(channel, request) {
                calls.push({ channel, request })
                return responses[channel]
            },
            /**
             * Registers one renderer-event wrapper.
             * @param {string} channel - Internal event channel.
             * @param {Function} listener - Preload-owned validation wrapper.
             * @returns {void} Completes after listener registration.
             */
            on(channel, listener) {
                const channelListeners = listeners.get(channel) ?? new Set()
                channelListeners.add(listener)
                listeners.set(channel, channelListeners)
            },
            /**
             * Removes exactly one renderer-event wrapper.
             * @param {string} channel - Internal event channel.
             * @param {Function} listener - Previously registered wrapper.
             * @returns {void} Completes after listener removal.
             */
            removeListener(channel, listener) {
                listeners.get(channel)?.delete(listener)
            }
        }
    }
}

test('exposes frozen named intents and no raw transport', () => {
    const { transport } = createTransport()
    const api = createPreloadApi(transport)

    assert.deepEqual(Object.keys(api).sort(), ['app', 'devices', 'files', 'logs', 'manufacturing', 'mcp', 'operations', 'recovery', 'service', 'settings', 'support', 'updates'])
    assert.deepEqual(Object.keys(api.manufacturing).sort(), ['backup', 'list', 'openFolder', 'restore'])
    assert.deepEqual(Object.keys(api.recovery).sort(), ['continue', 'list', 'start', 'status'])
    assert.equal('sendCdb' in api, false)
    assert.equal('invoke' in api, false)
    assert.equal(Object.isFrozen(api), true)
    for (const group of Object.values(api)) {
        assert.equal(Object.isFrozen(group), true)
    }
})

test('exposes only fixed zero-argument hardware service setup intents', async () => {
    const { calls, transport } = createTransport()
    const api = createPreloadApi(transport)

    assert.deepEqual(await api.service.getSetup({}), { ok: true, state: 'requires-approval' })
    assert.deepEqual(await api.service.retry({}), { ok: true })
    assert.deepEqual(await api.service.register({}), { ok: false, reason: 'requires-approval' })
    assert.deepEqual(await api.service.openApprovalSettings({}), { ok: true })
    await assert.rejects(api.service.register({ path: '/Library/LaunchDaemons/other.plist' }), /Invalid OpenRDX request/)
    assert.deepEqual(calls, [
        { channel: 'openrdx:service:get-setup', request: {} },
        { channel: 'openrdx:service:retry', request: {} },
        { channel: 'openrdx:service:register', request: {} },
        { channel: 'openrdx:service:open-approval-settings', request: {} }
    ])
})

test('validates operation requests before using the renderer transport', async () => {
    const { calls, transport } = createTransport()
    const api = createPreloadApi(transport)

    await assert.rejects(api.operations.start({ kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 3, osPath: '/dev/sg4' }), /Invalid OpenRDX request/)
    assert.deepEqual(calls, [])

    const response = await api.operations.start({ kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 3 })
    assert.deepEqual(response, { ok: true, operationId: 'op:1' })
    assert.deepEqual(calls, [
        {
            channel: 'openrdx:operations:start',
            request: { kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 3 }
        }
    ])
})

test('publishes only a bounded selected device identity for tray actions', async () => {
    const { calls, transport } = createTransport()
    const api = createPreloadApi(transport)

    assert.deepEqual(await api.app.setTraySelection({ deviceId: 'rdx:dock-2' }), { ok: true })
    assert.deepEqual(await api.app.setTraySelection({ deviceId: null }), { ok: true })
    await assert.rejects(api.app.setTraySelection({ deviceId: 'rdx:dock-2', osPath: '/dev/disk4' }), /Invalid OpenRDX request/)
    assert.deepEqual(calls, [
        { channel: 'openrdx:app:set-tray-selection', request: { deviceId: 'rdx:dock-2' } },
        { channel: 'openrdx:app:set-tray-selection', request: { deviceId: null } }
    ])
})

test('settings subscription accepts only complete safe snapshots', () => {
    const { emit, transport } = createTransport()
    const api = createPreloadApi(transport)
    const settings = []
    const unsubscribe = api.settings.subscribe((snapshot) => settings.push(snapshot))
    emit('openrdx:settings:event', { autoScan: false, eventLogging: false, language: 'de', lastSafeView: 'utilities', updateChecks: false })
    emit('openrdx:settings:event', { autoScan: false, eventLogging: false, language: 'de', updateChecks: false })
    assert.deepEqual(settings, [{ autoScan: false, eventLogging: false, language: 'de', lastSafeView: 'utilities', updateChecks: false }])
    unsubscribe()
})

test('service and preload preserve only strict available drive-letter snapshots', () => {
    const { emit, transport } = createTransport()
    const api = createPreloadApi(transport)
    const device = completeDeviceSnapshot({
        id: 'rdx:windows-usb3',
        revision: 7,
        vendor: 'TANDBERG',
        product: 'RDX QuikStor USB3',
        serial: 'USB3DOCK01',
        drive: { availableDriveLetters: ['D', 'R', 'Z'], connectionType: 'USB 3' },
        media: null,
        capabilities: { 'drive-letter-reset': { state: 'available' }, 'drive-letter-set': { state: 'available' } }
    })
    const wire = { type: 'event', channel: 'device', event: { type: 'snapshot', listRevision: 4, device } }
    assert.equal(wireEventSchema.safeParse(wire).success, true)

    const events = []
    api.devices.subscribe((event) => events.push(event))
    emit('openrdx:devices:event', { ...wire.event, epoch: 2 })
    assert.deepEqual(events[0].device.drive.availableDriveLetters, ['D', 'R', 'Z'])
    assert.equal(Object.isFrozen(events[0].device.drive.availableDriveLetters), true)

    const unsafeDevice = structuredClone(device)
    unsafeDevice.drive.availableDriveLetters = ['C', 'R:\\']
    emit('openrdx:devices:event', { ...wire.event, epoch: 2, listRevision: 5, device: unsafeDevice })
    assert.equal(events.length, 1)
})

test('exposes only token-free destructive confirmation requests', async () => {
    const { calls, transport } = createTransport()
    const api = createPreloadApi(transport)

    const request = { kind: 'format', deviceId: 'rdx:1', deviceRevision: 3, filesystem: 'exfat' }
    assert.deepEqual(await api.operations.confirm(request), { ok: true, confirmationToken: 'confirm:service-owned' })
    await assert.rejects(api.operations.confirm({ ...request, confirmationToken: 'confirm:renderer-invented' }), /Invalid OpenRDX request/)
    await assert.rejects(api.operations.confirm({ ...request, osPath: '/dev/rdx' }), /Invalid OpenRDX request/)
    assert.deepEqual(calls, [{ channel: 'openrdx:operations:confirm', request }])
})

test('rejects unknown keys on no-argument and settings requests', async () => {
    const { calls, transport } = createTransport()
    const api = createPreloadApi(transport)

    await assert.rejects(api.devices.list({ path: '/tmp' }), /Invalid OpenRDX request/)
    await assert.rejects(api.settings.update({ autoScan: false, unknown: true }), /Invalid OpenRDX request/)
    assert.deepEqual(calls, [])
})

test('rejects own prototype-control keys recursively before using the renderer transport', async () => {
    const { calls, transport } = createTransport()
    const api = createPreloadApi(transport)
    const nullPrototypeRequest = Object.assign(Object.create(null), {
        autoScan: false,
        constructor: 'controlled-constructor'
    })
    const requests = [JSON.parse('{"autoScan":false,"__proto__":{"polluted":true}}'), nullPrototypeRequest, { autoScan: false, nested: { prototype: 'controlled-prototype' } }]

    for (const request of requests) {
        await assert.rejects(api.settings.update(request), /prohibited prototype-control key/)
    }

    assert.deepEqual(calls, [])
})

test('accepts normal inherited constructor and safe null-prototype requests', async () => {
    const { calls, transport } = createTransport()
    const api = createPreloadApi(transport)
    const nullPrototypeRequest = Object.assign(Object.create(null), { autoScan: false })

    await api.settings.update({ autoScan: false })
    await api.settings.update(nullPrototypeRequest)

    assert.equal(calls.length, 2)
    assert.deepEqual(
        calls.map(({ request }) => request),
        [{ autoScan: false }, { autoScan: false }]
    )
})

test('creates only the literal scan request for the named device intent', async () => {
    const { calls, transport } = createTransport()
    const api = createPreloadApi(transport)

    await assert.rejects(api.devices.scan({ kind: 'self-test' }), /Invalid OpenRDX request/)
    assert.deepEqual(await api.devices.scan(), { ok: true })
    assert.deepEqual(calls, [{ channel: 'openrdx:devices:scan', request: { kind: 'scan' } }])
})

test('validates subscription callbacks and drops malformed events', () => {
    const { emit, transport } = createTransport()
    const api = createPreloadApi(transport)
    const events = []

    /**
     * Records one validated renderer event.
     * @param {object} event - Frozen renderer-safe event.
     * @returns {void} Completes after recording.
     */
    function recordEvent(event) {
        events.push(event)
    }

    assert.throws(() => api.operations.subscribe('not-a-function'), /listener must be a function/)
    const unsubscribe = api.operations.subscribe(recordEvent)
    assert.equal(Object.isFrozen(unsubscribe), true)

    emit('openrdx:operations:event', {
        state: 'progress',
        operationId: 'op:1',
        kind: 'self-test',
        deviceId: 'rdx:1',
        deviceRevision: 3,
        stage: 'diagnostic-running',
        progress: 0.5,
        cancellationState: 'cancellable'
    })
    emit('openrdx:operations:event', {
        state: 'progress',
        operationId: 'op:1',
        kind: 'self-test',
        deviceId: 'rdx:1',
        deviceRevision: 3,
        stage: 'diagnostic-running',
        progress: 0.6,
        cancellationState: 'cancellable',
        osPath: '/dev/sg4'
    })
    unsubscribe()
    emit('openrdx:operations:event', {
        state: 'succeeded',
        operationId: 'op:1',
        kind: 'self-test',
        deviceId: 'rdx:1',
        deviceRevision: 3,
        stage: 'complete'
    })

    assert.equal(events.length, 1)
    assert.equal(events[0].progress, 0.5)
    assert.equal(Object.isFrozen(events[0]), true)
})
