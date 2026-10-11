// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'

import { isTrustedApplicationSender, registerIpcHandlers, trustApplicationWindow } from '../src/main/ipc-controller.mjs'

test('closing a window revokes its sender without reading the destroyed window', () => {
    const contents = new EventEmitter()
    const otherContents = new EventEmitter()
    let destroyed = false
    const window = {
        /** @returns {EventEmitter} Contents only while the native window is alive. */
        get webContents() {
            if (destroyed) throw new TypeError('Object has been destroyed')
            return contents
        }
    }
    const trusted = new Set([otherContents])
    trustApplicationWindow(window, trusted)
    assert.equal(trusted.has(contents), true)
    destroyed = true
    assert.doesNotThrow(() => contents.emit('destroyed'))
    assert.equal(trusted.has(contents), false)
    assert.equal(trusted.has(otherContents), true)
    assert.equal(contents.listenerCount('destroyed'), 0)
})

/**
 * Creates an ipcMain-compatible handler registry for direct boundary tests.
 * @returns {{handlers: Map<string, Function>, ipcMain: object}} Fake registry and registered handlers.
 */
function createIpcMain() {
    const handlers = new Map()
    return {
        handlers,
        ipcMain: {
            /**
             * Registers a handler under one exact channel.
             * @param {string} channel - Internal IPC channel.
             * @param {Function} handler - Main boundary handler.
             * @returns {void} Completes after registration.
             */
            handle(channel, handler) {
                handlers.set(channel, handler)
            },
            /**
             * Removes a registered handler.
             * @param {string} channel - Internal IPC channel.
             * @returns {void} Completes after removal.
             */
            removeHandler(channel) {
                handlers.delete(channel)
            }
        }
    }
}

/**
 * Creates injectable services with one real allow path and call recording.
 * @returns {{calls: object[], services: object}} Main services and dispatch observations.
 */
function createServices() {
    const calls = []
    return {
        calls,
        services: {
            /**
             * Accepts only the controlled test sender.
             * @param {object} event - Candidate fake Electron event.
             * @returns {boolean} True for the controlled sender fixture.
             */
            isTrustedSender(event) {
                return event.sender?.id === 7 && event.senderFrame?.url === 'file:///trusted/index.html'
            },
            operations: {
                /**
                 * Records one exact token-free confirmation request.
                 * @param {object} request - Strict destructive action binding.
                 * @returns {Promise<object>} Controlled service-issued token.
                 */
                async confirm(request) {
                    calls.push({ confirm: request })
                    return { ok: true, confirmationToken: 'confirm:service-owned' }
                },
                /**
                 * Returns the controlled current-device safety context.
                 * @returns {Promise<object>} Current main-owned policy context.
                 */
                async getContext() {
                    return {
                        device: {
                            id: 'rdx:1',
                            revision: 3,
                            mediaState: 'present',
                            capabilities: {
                                'self-test': { state: 'available' },
                                'eject-force': { state: 'available' }
                            }
                        },
                        activeOperation: null,
                        hardwareReady: true,
                        hasPrivilege: true,
                        confirmationTokenValid: true,
                        platformCapability: { state: 'available' },
                        serviceMode: 'native'
                    }
                },
                /**
                 * Records one permitted operation dispatch.
                 * @param {object} request - Strict operation request.
                 * @returns {Promise<object>} Safe accepted response.
                 */
                async start(request) {
                    calls.push(request)
                    return { ok: true, operationId: 'op:1' }
                }
            }
        }
    }
}

const trustedEvent = Object.freeze({ sender: Object.freeze({ id: 7 }), senderFrame: Object.freeze({ url: 'file:///trusted/index.html' }) })
const validOperationEvent = Object.freeze({
    state: 'succeeded',
    operationId: 'op:1',
    kind: 'self-test',
    deviceId: 'rdx:1',
    deviceRevision: 3,
    stage: 'complete'
})

test('accepts only the exact application main frame as a trusted sender', () => {
    const mainFrame = { url: 'file:///trusted/index.html' }
    const sender = { mainFrame }
    const trustedWebContents = new Set([sender])

    assert.equal(isTrustedApplicationSender({ event: { sender, senderFrame: mainFrame }, rendererUrl: mainFrame.url, trustedWebContents }), true)
    assert.equal(isTrustedApplicationSender({ event: { sender, senderFrame: { url: mainFrame.url } }, rendererUrl: mainFrame.url, trustedWebContents }), false)
    assert.equal(isTrustedApplicationSender({ event: { sender, senderFrame: mainFrame }, rendererUrl: 'file:///other/index.html', trustedWebContents }), false)
})

test('dispatches only a strict current-device operation from the trusted renderer', async () => {
    const { handlers, ipcMain } = createIpcMain()
    const { calls, services } = createServices()
    registerIpcHandlers({ ipcMain, services })

    const response = await handlers.get('openrdx:operations:start')(trustedEvent, {
        kind: 'self-test',
        deviceId: 'rdx:1',
        deviceRevision: 3
    })

    assert.deepEqual(response, { ok: true, operationId: 'op:1' })
    assert.deepEqual(calls, [{ kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 3 }])
})

test('issues destructive confirmation only through the trusted token-free route', async () => {
    const { handlers, ipcMain } = createIpcMain()
    const { calls, services } = createServices()
    registerIpcHandlers({ ipcMain, services })
    const request = { kind: 'eject-force', deviceId: 'rdx:1', deviceRevision: 3 }

    assert.deepEqual(await handlers.get('openrdx:operations:confirm')(trustedEvent, request), {
        ok: true,
        confirmationToken: 'confirm:service-owned'
    })
    assert.deepEqual(await handlers.get('openrdx:operations:confirm')(trustedEvent, { ...request, confirmationToken: 'confirm:invented' }), {
        ok: false,
        reason: 'invalid-request'
    })
    assert.deepEqual(await handlers.get('openrdx:operations:confirm')({ sender: { id: 99 } }, request), {
        ok: false,
        reason: 'untrusted-sender'
    })
    assert.deepEqual(calls, [{ confirm: request }])
})

test('rejects unknown request keys before an injectable service is called', async () => {
    const { handlers, ipcMain } = createIpcMain()
    const { calls, services } = createServices()
    registerIpcHandlers({ ipcMain, services })

    const response = await handlers.get('openrdx:operations:start')(trustedEvent, {
        kind: 'self-test',
        deviceId: 'rdx:1',
        deviceRevision: 3,
        rawCdb: [0x1d]
    })

    assert.deepEqual(response, { ok: false, reason: 'invalid-request' })
    assert.deepEqual(calls, [])
})

test('keeps privileged service setup behind fixed trusted zero-argument routes', async () => {
    const { handlers, ipcMain } = createIpcMain()
    const calls = []
    registerIpcHandlers({
        ipcMain,
        services: {
            ...createServices().services,
            service: {
                getSetup() {
                    calls.push('status')
                    return { ok: true, state: 'requires-approval' }
                },
                retry() {
                    calls.push('retry')
                    return { ok: true }
                },
                register() {
                    calls.push('register')
                    return { ok: false, reason: 'requires-approval' }
                },
                openApprovalSettings() {
                    calls.push('settings')
                    return { ok: true }
                }
            }
        }
    })

    assert.deepEqual(await handlers.get('openrdx:service:get-setup')(trustedEvent, {}), { ok: true, state: 'requires-approval' })
    assert.deepEqual(await handlers.get('openrdx:service:retry')(trustedEvent, {}), { ok: true })
    assert.deepEqual(await handlers.get('openrdx:service:register')(trustedEvent, {}), { ok: false, reason: 'requires-approval' })
    assert.deepEqual(await handlers.get('openrdx:service:open-approval-settings')(trustedEvent, {}), { ok: true })
    assert.deepEqual(await handlers.get('openrdx:service:register')(trustedEvent, { label: 'other' }), { ok: false, reason: 'invalid-request' })
    assert.deepEqual(await handlers.get('openrdx:service:get-setup')({ sender: { id: 9 } }, {}), { ok: false, reason: 'untrusted-sender' })
    assert.deepEqual(calls, ['status', 'retry', 'register', 'settings'])
})

test('rejects own prototype-control keys recursively at the registered main boundary', async () => {
    const { handlers, ipcMain } = createIpcMain()
    const { calls, services } = createServices()
    registerIpcHandlers({ ipcMain, services })
    const nullPrototypeRequest = Object.assign(Object.create(null), {
        kind: 'self-test',
        deviceId: 'rdx:1',
        deviceRevision: 3,
        constructor: 'controlled-constructor'
    })
    const requests = [
        JSON.parse('{"kind":"self-test","deviceId":"rdx:1","deviceRevision":3,"__proto__":{"polluted":true}}'),
        nullPrototypeRequest,
        {
            kind: 'self-test',
            deviceId: 'rdx:1',
            deviceRevision: 3,
            nested: { prototype: 'controlled-prototype' }
        }
    ]

    for (const request of requests) {
        const response = await handlers.get('openrdx:operations:start')(trustedEvent, request)
        assert.deepEqual(response, { ok: false, reason: 'prototype-control-key' })
    }

    assert.deepEqual(calls, [])
})

test('accepts a safe null-prototype request without treating inherited constructor as own', async () => {
    const { handlers, ipcMain } = createIpcMain()
    const { calls, services } = createServices()
    registerIpcHandlers({ ipcMain, services })
    const request = Object.assign(Object.create(null), {
        kind: 'self-test',
        deviceId: 'rdx:1',
        deviceRevision: 3
    })

    const response = await handlers.get('openrdx:operations:start')(trustedEvent, request)

    assert.deepEqual(response, { ok: true, operationId: 'op:1' })
    assert.deepEqual(calls, [{ kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 3 }])
})

test('rejects a stale revision before operation dispatch', async () => {
    const { handlers, ipcMain } = createIpcMain()
    const { calls, services } = createServices()
    registerIpcHandlers({ ipcMain, services })

    const response = await handlers.get('openrdx:operations:start')(trustedEvent, {
        kind: 'self-test',
        deviceId: 'rdx:1',
        deviceRevision: 2
    })

    assert.deepEqual(response, { ok: false, reason: 'stale-device-revision' })
    assert.deepEqual(calls, [])
})

test('rejects missing or invalid force-eject confirmation before dispatch', async () => {
    const { handlers, ipcMain } = createIpcMain()
    const { calls, services } = createServices()
    const getValidContext = services.operations.getContext

    /**
     * Simulates main-owned confirmation-token resolution failure.
     * @param {object} request - Strict force-eject request.
     * @returns {Promise<object>} Otherwise valid safety context with invalid confirmation.
     */
    async function getInvalidConfirmationContext(request) {
        return { ...(await getValidContext(request)), confirmationTokenValid: false }
    }

    services.operations.getContext = getInvalidConfirmationContext
    registerIpcHandlers({ ipcMain, services })

    const missing = await handlers.get('openrdx:operations:start')(trustedEvent, {
        kind: 'eject-force',
        deviceId: 'rdx:1',
        deviceRevision: 3
    })
    const invalid = await handlers.get('openrdx:operations:start')(trustedEvent, {
        kind: 'eject-force',
        deviceId: 'rdx:1',
        deviceRevision: 3,
        confirmationToken: 'confirm:invalid'
    })

    assert.deepEqual(missing, { ok: false, reason: 'invalid-request' })
    assert.deepEqual(invalid, { ok: false, reason: 'confirmation-required' })
    assert.deepEqual(calls, [])
})

test('dispatches force eject only after valid main-owned confirmation', async () => {
    const { handlers, ipcMain } = createIpcMain()
    const { calls, services } = createServices()
    registerIpcHandlers({ ipcMain, services })
    const request = {
        kind: 'eject-force',
        deviceId: 'rdx:1',
        deviceRevision: 3,
        confirmationToken: 'confirm:force-eject'
    }

    const response = await handlers.get('openrdx:operations:start')(trustedEvent, request)

    assert.deepEqual(response, { ok: true, operationId: 'op:1' })
    assert.deepEqual(calls, [request])
})

test('rejects manual scan while another operation owns the application lock', async () => {
    const { handlers, ipcMain } = createIpcMain()
    const { calls, services } = createServices()
    services.devices = {
        /**
         * Records a scan only if the IPC safety boundary permits dispatch.
         * @param {object} request - Strict scan request.
         * @returns {Promise<object>} Safe scan acceptance result.
         */
        async scan(request) {
            calls.push(request)
            return { ok: true }
        }
    }
    /**
     * Returns the controlled busy operation context.
     * @returns {Promise<object>} Current application lock.
     */
    async function getBusyContext() {
        return { activeOperation: { id: 'op:active' } }
    }
    services.operations.getContext = getBusyContext
    registerIpcHandlers({ ipcMain, services })

    const response = await handlers.get('openrdx:devices:scan')(trustedEvent, { kind: 'scan' })

    assert.deepEqual(response, { ok: false, reason: 'operation-in-progress' })
    assert.deepEqual(calls, [])
})

test('rejects an unknown sender and registers no arbitrary channel', async () => {
    const { handlers, ipcMain } = createIpcMain()
    const { calls, services } = createServices()
    registerIpcHandlers({ ipcMain, services })

    const response = await handlers.get('openrdx:operations:start')({ sender: { id: 99 }, senderFrame: { url: 'file:///untrusted/index.html' } }, { kind: 'self-test', deviceId: 'rdx:1', deviceRevision: 3 })

    assert.deepEqual(response, { ok: false, reason: 'untrusted-sender' })
    assert.equal(handlers.has('openrdx:raw-command'), false)
    assert.deepEqual(calls, [])
})

test('rejects unsafe service responses instead of serializing them', async () => {
    const { handlers, ipcMain } = createIpcMain()
    const { services } = createServices()
    /**
     * Simulates a compromised service attempting to expose an operating-system path.
     * @returns {Promise<object>} Deliberately invalid service response.
     */
    async function returnUnsafeResponse() {
        return { ok: true, operationId: 'op:1', osPath: '/dev/sg4' }
    }
    services.operations.start = returnUnsafeResponse
    registerIpcHandlers({ ipcMain, services })

    const response = await handlers.get('openrdx:operations:start')(trustedEvent, {
        kind: 'self-test',
        deviceId: 'rdx:1',
        deviceRevision: 3
    })

    assert.deepEqual(response, { ok: false, reason: 'invalid-service-response' })
})

test('publishes only strict renderer-safe operation events to trusted targets', () => {
    const { ipcMain } = createIpcMain()
    const { services } = createServices()
    const events = []
    const target = {
        /**
         * Reports that the controlled renderer target remains live.
         * @returns {boolean} Always false for the live fixture.
         */
        isDestroyed() {
            return false
        },
        /**
         * Records one validated main-to-renderer event.
         * @param {string} channel - Exact internal event channel.
         * @param {object} event - Renderer-safe operation event.
         * @returns {void} Completes after recording.
         */
        send(channel, event) {
            events.push({ channel, event })
        }
    }
    /**
     * Returns the single controlled trusted renderer target.
     * @returns {object[]} Fake trusted web contents.
     */
    function getTrustedWebContents() {
        return [target]
    }
    services.getTrustedWebContents = getTrustedWebContents
    const controller = registerIpcHandlers({ ipcMain, services })
    assert.equal(controller.publishOperationEvent({ ...validOperationEvent, osPath: '/dev/sg4' }), false)
    assert.equal(controller.publishOperationEvent(validOperationEvent), true)
    assert.deepEqual(events, [{ channel: 'openrdx:operations:event', event: validOperationEvent }])
})

test('contains trusted-target provider failure and reports no delivery', () => {
    const { ipcMain } = createIpcMain()
    const { services } = createServices()

    /**
     * Simulates failure while resolving application-owned renderer targets.
     * @throws {Error} Always throws the controlled provider failure.
     */
    function failTargetProvider() {
        throw new Error('controlled target provider failure')
    }

    services.getTrustedWebContents = failTargetProvider
    const controller = registerIpcHandlers({ ipcMain, services })

    assert.equal(controller.publishOperationEvent(validOperationEvent), false)
})

test('contains a throwing trusted-target provider property getter', () => {
    const { ipcMain } = createIpcMain()
    const { services } = createServices()
    Object.defineProperty(services, 'getTrustedWebContents', {
        /**
         * Simulates failure while retrieving the trusted-target provider itself.
         * @throws {Error} Always throws the controlled property-access failure.
         */
        get() {
            throw new Error('controlled provider property failure')
        }
    })
    const controller = registerIpcHandlers({ ipcMain, services })

    assert.equal(controller.publishOperationEvent(validOperationEvent), false)
})

test('reports no delivery for zero or destroyed renderer targets', () => {
    const { ipcMain } = createIpcMain()
    const { services } = createServices()
    let sendCount = 0
    const destroyedTarget = {
        /**
         * Reports the controlled target as destroyed.
         * @returns {boolean} Always true.
         */
        isDestroyed() {
            return true
        },
        /**
         * Records any invalid attempt to send to the destroyed target.
         * @returns {void} Completes after incrementing the attempt count.
         */
        send() {
            sendCount += 1
        }
    }

    /**
     * Returns no renderer targets.
     * @returns {object[]} Empty target list.
     */
    function getNoTargets() {
        return []
    }

    services.getTrustedWebContents = getNoTargets
    const emptyController = registerIpcHandlers({ ipcMain, services })
    assert.equal(emptyController.publishOperationEvent(validOperationEvent), false)
    emptyController.dispose()

    /**
     * Returns one destroyed renderer target.
     * @returns {object[]} Destroyed target fixture.
     */
    function getDestroyedTarget() {
        return [destroyedTarget]
    }

    services.getTrustedWebContents = getDestroyedTarget
    const destroyedController = registerIpcHandlers({ ipcMain, services })
    assert.equal(destroyedController.publishOperationEvent(validOperationEvent), false)
    assert.equal(sendCount, 0)
})

test('continues after target lifecycle and send failures and reports partial success', () => {
    const { ipcMain } = createIpcMain()
    const { services } = createServices()
    const deliveries = []
    const lifecycleFailure = {
        /**
         * Simulates a target lifecycle query failure.
         * @throws {Error} Always throws the controlled lifecycle failure.
         */
        isDestroyed() {
            throw new Error('controlled lifecycle failure')
        },
        /**
         * Represents the unreachable send method after lifecycle failure.
         * @returns {void} Completes without side effects if unexpectedly called.
         */
        send() {}
    }
    const sendFailure = {
        /**
         * Reports that the controlled send-failure target remains live.
         * @returns {boolean} Always false for the live fixture.
         */
        isDestroyed() {
            return false
        },
        /**
         * Simulates a renderer send failure.
         * @throws {Error} Always throws the controlled send failure.
         */
        send() {
            throw new Error('controlled send failure')
        }
    }
    const successfulTarget = {
        /**
         * Reports that the successful controlled target remains live.
         * @returns {boolean} Always false for the live fixture.
         */
        isDestroyed() {
            return false
        },
        /**
         * Records a successful safe event delivery.
         * @param {string} channel - Exact event channel.
         * @param {object} event - Strict operation event.
         * @returns {void} Completes after recording.
         */
        send(channel, event) {
            deliveries.push({ channel, event })
        }
    }

    /**
     * Returns failing targets before one deliverable renderer.
     * @returns {object[]} Mixed target fixtures.
     */
    function getMixedTargets() {
        return [lifecycleFailure, sendFailure, successfulTarget]
    }

    services.getTrustedWebContents = getMixedTargets
    const controller = registerIpcHandlers({ ipcMain, services })

    assert.equal(controller.publishOperationEvent(validOperationEvent), true)
    assert.deepEqual(deliveries, [{ channel: 'openrdx:operations:event', event: validOperationEvent }])
})

test('reports no delivery when every live target send fails', () => {
    const { ipcMain } = createIpcMain()
    const { services } = createServices()
    const target = {
        /**
         * Reports that the controlled send-failure target remains live.
         * @returns {boolean} Always false for the live fixture.
         */
        isDestroyed() {
            return false
        },
        /**
         * Simulates failure for every attempted renderer delivery.
         * @throws {Error} Always throws the controlled send failure.
         */
        send() {
            throw new Error('controlled send failure')
        }
    }

    /**
     * Returns one live target whose send fails.
     * @returns {object[]} Failing target fixture.
     */
    function getFailingTarget() {
        return [target]
    }

    services.getTrustedWebContents = getFailingTarget
    const controller = registerIpcHandlers({ ipcMain, services })

    assert.equal(controller.publishOperationEvent(validOperationEvent), false)
})
