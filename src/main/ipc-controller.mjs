// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { IpcChannel } from '../shared/ipc-contract.mjs'
import { deviceEventSchema, operationEventSchema, settingsSchema } from '../shared/schemas.mjs'
import { APPLICATION_ROUTES, dispatchApplicationRequest } from './application-dispatcher.mjs'

/**
 * Trusts a live window and revokes its captured contents when they are destroyed.
 * @param {object} window - Live Electron window; its getter is unusable after destruction.
 * @param {Set<object>} trustedWebContents - Main-owned sender allowlist.
 * @returns {void} Registers cleanup without retaining access to a destroyed window.
 */
export function trustApplicationWindow(window, trustedWebContents) {
    const contents = window.webContents
    trustedWebContents.add(contents)
    /** @returns {void} Revokes the exact sender without dereferencing its closed window. */
    function revokeRendererTrust() {
        trustedWebContents.delete(contents)
    }
    contents.once('destroyed', revokeRendererTrust)
}

/**
 * Accepts only the exact main frame of a currently application-owned web
 * contents at the expected local renderer URL.
 * @param {{event: object, rendererUrl: string, trustedWebContents: {has: (value: object) => boolean}}} options - Sender policy inputs.
 * @returns {boolean} True only for the trusted local application main frame.
 */
export function isTrustedApplicationSender({ event, rendererUrl, trustedWebContents }) {
    return typeof trustedWebContents?.has === 'function' && trustedWebContents.has(event?.sender) && event?.senderFrame === event?.sender?.mainFrame && event.senderFrame?.url === rendererUrl
}

/**
 * Builds a stable renderer-safe failure without including exception details.
 * @param {string} reason - Internal fixed failure reason.
 * @returns {{ok: false, reason: string}} Safe failure response.
 */
function failure(reason) {
    return { ok: false, reason }
}

/**
 * Checks an inbound Electron event against the application-owned sender policy.
 * Policy exceptions fail closed.
 * @param {object} services - Injected main-process services.
 * @param {unknown} event - Candidate Electron invoke event.
 * @returns {boolean} True only for the currently trusted application renderer.
 */
function isTrustedSender(services, event) {
    try {
        return typeof services.isTrustedSender === 'function' && services.isTrustedSender(event) === true
    } catch (_error) {
        return false
    }
}

/**
 * Creates a fail-closed handler for one exact registered channel.
 * @param {object} route - Exact route descriptor.
 * @param {object} services - Injected main services.
 * @returns {(event: object, request: unknown) => Promise<object>} Electron invoke handler.
 */
function createRouteHandler(route, services) {
    /**
     * Validates sender and payload before dispatching to a main-owned service.
     * @param {object} event - Electron invoke event.
     * @param {unknown} request - Candidate renderer payload.
     * @returns {Promise<object>} Safe renderer response.
     */
    async function handleRequest(event, request) {
        if (!isTrustedSender(services, event)) {
            return failure('untrusted-sender')
        }
        return dispatchApplicationRequest(services, route.channel, request)
    }

    return handleRequest
}

/**
 * Publishes one validated event only to application-owned web contents.
 * @param {object} services - Injected trusted-target provider.
 * @param {string} channel - Exact internal event channel.
 * @param {import('zod').ZodType} schema - Exact renderer event schema.
 * @param {unknown} event - Candidate main/service event.
 * @returns {boolean} True only when at least one trusted target received the event.
 */
function publishEvent(services, channel, schema, event) {
    const parsedEvent = schema.safeParse(event)
    if (!parsedEvent.success) {
        return false
    }

    let targets
    try {
        const getTrustedWebContents = services.getTrustedWebContents
        if (typeof getTrustedWebContents !== 'function') {
            return false
        }
        targets = getTrustedWebContents.call(services)
    } catch {
        return false
    }
    if (!Array.isArray(targets)) {
        return false
    }

    let delivered = false
    for (const target of targets) {
        try {
            if (typeof target?.send === 'function' && target.isDestroyed?.() === false) {
                target.send(channel, parsedEvent.data)
                delivered = true
            }
        } catch {
            // A closing or faulty renderer must not prevent delivery to other targets.
        }
    }
    return delivered
}

/**
 * Registers the complete exact Electron IPC allowlist around injectable
 * main-owned services. Missing services fail safely and expose no fallback.
 * @param {{ipcMain: {handle: Function, removeHandler: Function}, services: object}} options - Electron registry and main services.
 * @returns {{dispose: () => void, publishDeviceEvent: (event: object) => boolean, publishOperationEvent: (event: object) => boolean, publishSettingsEvent: (event: object) => boolean}} Frozen controller API.
 * @throws {TypeError} When registration dependencies are invalid.
 */
export function registerIpcHandlers({ ipcMain, services }) {
    if (typeof ipcMain?.handle !== 'function' || typeof ipcMain?.removeHandler !== 'function' || services === null || typeof services !== 'object') {
        throw new TypeError('IPC registration requires ipcMain and services')
    }

    for (const route of APPLICATION_ROUTES) {
        ipcMain.handle(route.channel, createRouteHandler(route, services))
    }
    let registered = true

    /**
     * Removes only the exact OpenRDX invoke handlers registered here.
     * @returns {void} Completes after idempotent handler removal.
     */
    function dispose() {
        if (!registered) {
            return
        }
        for (const route of APPLICATION_ROUTES) {
            ipcMain.removeHandler(route.channel)
        }
        registered = false
    }

    /**
     * Validates and publishes one safe discovered-device event.
     * @param {object} event - Candidate device event.
     * @returns {boolean} True when accepted for trusted targets.
     */
    function publishDeviceEvent(event) {
        return publishEvent(services, IpcChannel.DEVICES_EVENT, deviceEventSchema, event)
    }

    /**
     * Validates and publishes one safe operation event.
     * @param {object} event - Candidate operation event.
     * @returns {boolean} True when accepted for trusted targets.
     */
    function publishOperationEvent(event) {
        return publishEvent(services, IpcChannel.OPERATIONS_EVENT, operationEventSchema, event)
    }

    /** @param {object} event - Complete renderer-safe settings. @returns {boolean} True when accepted for trusted targets. */
    function publishSettingsEvent(event) {
        return publishEvent(services, IpcChannel.SETTINGS_EVENT, settingsSchema, event)
    }

    return Object.freeze({ dispose, publishDeviceEvent, publishOperationEvent, publishSettingsEvent })
}
