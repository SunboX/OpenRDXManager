// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { IpcChannel } from './shared/ipc-contract.mjs'
import { actionResponseSchema, appInfoResponseSchema, deviceEventSchema, deviceListResponseSchema, emptyRequestSchema, exportDestinationRequestSchema, fileTokenResponseSchema, localExportResponseSchema, logListResponseSchema, logSettingRequestSchema, operationCancelRequestSchema, operationContinueRequestSchema, operationConfirmationRequestSchema, operationConfirmationResponseSchema, operationEventSchema, operationRequestSchema, operationStartResponseSchema, privilegedServiceSetupResponseSchema, scanRequestSchema, settingsResponseSchema, settingsSchema, settingsUpdateRequestSchema, supportSummaryResponseSchema, traySelectionRequestSchema, updateCheckRequestSchema, updateCheckResponseSchema } from './shared/schemas.mjs'
import { hasOwnPrototypeControlKey } from './shared/boundary-validation.mjs'
import { mcpSettingsUpdateSchema, mcpStatusResponseSchema } from './shared/mcp-schemas.mjs'
import { recoveryListResponseSchema, recoveryStatusResponseSchema, recoveryStartRequestSchema, recoveryContinueRequestSchema } from './shared/recovery-schemas.mjs'
import { manufacturingRequestSchema, manufacturingRestoreRequestSchema, manufacturingResponseSchema } from './shared/manufacturing-schemas.mjs'

/**
 * Recursively freezes a validated data-only result before renderer delivery.
 * @template T
 * @param {T} value - Parsed response or event data.
 * @returns {T} The same deeply frozen value.
 */
function deepFreeze(value) {
    if (value === null || typeof value !== 'object' || Object.isFrozen(value)) {
        return value
    }
    for (const nestedValue of Object.values(value)) {
        deepFreeze(nestedValue)
    }
    return Object.freeze(value)
}

/**
 * Parses one renderer request without leaking validator internals.
 * @param {import('zod').ZodType} schema - Exact shared request schema.
 * @param {unknown} request - Candidate renderer payload.
 * @returns {object} Strict parsed request.
 * @throws {TypeError} When the request is malformed or contains unknown keys.
 */
function parseRequest(schema, request) {
    if (hasOwnPrototypeControlKey(request)) {
        throw new TypeError('OpenRDX request contains a prohibited prototype-control key')
    }
    const parsed = schema.safeParse(request)
    if (!parsed.success) {
        throw new TypeError('Invalid OpenRDX request')
    }
    return parsed.data
}

/**
 * Parses and freezes one main-process result without exposing invalid data.
 * @param {import('zod').ZodType} schema - Exact shared response schema.
 * @param {unknown} response - Candidate IPC response.
 * @returns {object} Validated frozen response.
 * @throws {TypeError} When main returned data outside the renderer contract.
 */
function parseResponse(schema, response) {
    const parsed = schema.safeParse(response)
    if (!parsed.success) {
        throw new TypeError('Invalid OpenRDX response')
    }
    return deepFreeze(parsed.data)
}

/**
 * Creates one named request method around a private internal channel.
 * @param {object} transport - Minimal ipcRenderer-compatible transport.
 * @param {string} channel - Private allowlisted IPC channel.
 * @param {import('zod').ZodType} requestSchema - Strict request schema.
 * @param {import('zod').ZodType} responseSchema - Strict response schema.
 * @returns {(request?: object) => Promise<object>} Frozen public intent method.
 */
function createInvokeMethod(transport, channel, requestSchema, responseSchema) {
    /**
     * Validates, invokes, validates again, and freezes one named intent result.
     * @param {object} [request={}] - Candidate renderer request.
     * @returns {Promise<object>} Validated renderer-safe result.
     */
    async function invoke(request = {}) {
        const parsedRequest = parseRequest(requestSchema, request)
        const response = await transport.invoke(channel, parsedRequest)
        return parseResponse(responseSchema, response)
    }

    return Object.freeze(invoke)
}

/**
 * Creates the parameterless discovery intent while still parsing the exact
 * Task 2 scan variant before IPC invocation.
 * @param {object} transport - Minimal ipcRenderer-compatible transport.
 * @returns {(request?: object) => Promise<object>} Frozen scan method.
 */
function createScanMethod(transport) {
    /**
     * Rejects renderer parameters and invokes only the literal scan variant.
     * @param {object} [request={}] - Must be an exact empty object.
     * @returns {Promise<object>} Validated renderer-safe scan result.
     */
    async function scan(request = {}) {
        parseRequest(emptyRequestSchema, request)
        const scanRequest = parseRequest(scanRequestSchema, { kind: 'scan' })
        const response = await transport.invoke(IpcChannel.DEVICES_SCAN, scanRequest)
        return parseResponse(actionResponseSchema, response)
    }

    return Object.freeze(scan)
}

/**
 * Creates one event subscription with callback validation and exact event
 * parsing. Malformed main-process events are discarded at the preload edge.
 * @param {object} transport - Minimal ipcRenderer-compatible transport.
 * @param {string} channel - Private allowlisted event channel.
 * @param {import('zod').ZodType} eventSchema - Exact shared event schema.
 * @param {(event: object) => void} listener - Trusted renderer callback.
 * @returns {() => void} Frozen idempotent unsubscribe callback.
 * @throws {TypeError} When listener is not callable.
 */
function subscribe(transport, channel, eventSchema, listener) {
    if (typeof listener !== 'function') {
        throw new TypeError('OpenRDX listener must be a function')
    }

    /**
     * Validates an IPC event before invoking renderer-owned code.
     * @param {unknown} _event - Electron event intentionally not exposed.
     * @param {unknown} payload - Candidate main-process event payload.
     * @returns {void} Completes after a valid event is delivered.
     */
    function handleEvent(_event, payload) {
        const parsed = eventSchema.safeParse(payload)
        if (parsed.success) {
            listener(deepFreeze(parsed.data))
        }
    }

    transport.on(channel, handleEvent)
    let subscribed = true

    /**
     * Removes only the wrapper registered for this callback. Repeated calls are safe.
     * @returns {void} Completes after the listener is detached.
     */
    function unsubscribe() {
        if (subscribed) {
            transport.removeListener(channel, handleEvent)
            subscribed = false
        }
    }

    return Object.freeze(unsubscribe)
}

/**
 * Creates the complete narrow API exposed as `window.openRdx`. The renderer
 * receives no channel selector, raw send primitive, path, or command method.
 * @param {{invoke: Function, on: Function, removeListener: Function}} transport - Minimal private Electron renderer transport.
 * @returns {object} Deeply frozen grouped renderer API.
 * @throws {TypeError} When the private transport contract is incomplete.
 */
export function createPreloadApi(transport) {
    if (typeof transport?.invoke !== 'function' || typeof transport?.on !== 'function' || typeof transport?.removeListener !== 'function') {
        throw new TypeError('OpenRDX preload transport is unavailable')
    }

    const api = {
        mcp: {
            getStatus: createInvokeMethod(transport, IpcChannel.MCP_GET_STATUS, emptyRequestSchema, mcpStatusResponseSchema),
            update: createInvokeMethod(transport, IpcChannel.MCP_UPDATE, mcpSettingsUpdateSchema, mcpStatusResponseSchema),
            copyConfiguration: createInvokeMethod(transport, IpcChannel.MCP_COPY_CONFIGURATION, emptyRequestSchema, actionResponseSchema)
        },
        app: {
            getInfo: createInvokeMethod(transport, IpcChannel.APP_GET, emptyRequestSchema, appInfoResponseSchema),
            setTraySelection: createInvokeMethod(transport, IpcChannel.APP_SET_TRAY_SELECTION, traySelectionRequestSchema, actionResponseSchema)
        },
        devices: {
            list: createInvokeMethod(transport, IpcChannel.DEVICES_LIST, emptyRequestSchema, deviceListResponseSchema),
            scan: createScanMethod(transport),
            /**
             * Subscribes to renderer-safe discovered-device events.
             * @param {(event: object) => void} listener - Renderer event callback.
             * @returns {() => void} Frozen idempotent unsubscribe callback.
             */
            subscribe(listener) {
                return subscribe(transport, IpcChannel.DEVICES_EVENT, deviceEventSchema, listener)
            }
        },
        files: {
            chooseFirmware: createInvokeMethod(transport, IpcChannel.FILES_CHOOSE_FIRMWARE, emptyRequestSchema, fileTokenResponseSchema),
            chooseExportDestination: createInvokeMethod(transport, IpcChannel.FILES_CHOOSE_EXPORT, exportDestinationRequestSchema, fileTokenResponseSchema)
        },
        logs: {
            list: createInvokeMethod(transport, IpcChannel.LOGS_LIST, emptyRequestSchema, logListResponseSchema),
            setEnabled: createInvokeMethod(transport, IpcChannel.LOGS_SET_ENABLED, logSettingRequestSchema, actionResponseSchema),
            export: createInvokeMethod(transport, IpcChannel.LOGS_EXPORT, emptyRequestSchema, localExportResponseSchema)
        },
        recovery: {
            list: createInvokeMethod(transport, IpcChannel.RECOVERY_LIST, emptyRequestSchema, recoveryListResponseSchema),
            status: createInvokeMethod(transport, IpcChannel.RECOVERY_STATUS, emptyRequestSchema, recoveryStatusResponseSchema),
            start: createInvokeMethod(transport, IpcChannel.RECOVERY_START, recoveryStartRequestSchema, recoveryStatusResponseSchema),
            continue: createInvokeMethod(transport, IpcChannel.RECOVERY_CONTINUE, recoveryContinueRequestSchema, recoveryStatusResponseSchema)
        },
        manufacturing: {
            openFolder: createInvokeMethod(transport, IpcChannel.MANUFACTURING_OPEN_FOLDER, emptyRequestSchema, actionResponseSchema),
            list: createInvokeMethod(transport, IpcChannel.MANUFACTURING_LIST, manufacturingRequestSchema, manufacturingResponseSchema),
            backup: createInvokeMethod(transport, IpcChannel.MANUFACTURING_BACKUP, manufacturingRequestSchema, manufacturingResponseSchema),
            restore: createInvokeMethod(transport, IpcChannel.MANUFACTURING_RESTORE, manufacturingRestoreRequestSchema, manufacturingResponseSchema)
        },
        operations: {
            continue: createInvokeMethod(transport, IpcChannel.OPERATIONS_CONTINUE, operationContinueRequestSchema, operationStartResponseSchema),
            confirm: createInvokeMethod(transport, IpcChannel.OPERATIONS_CONFIRM, operationConfirmationRequestSchema, operationConfirmationResponseSchema),
            start: createInvokeMethod(transport, IpcChannel.OPERATIONS_START, operationRequestSchema, operationStartResponseSchema),
            cancel: createInvokeMethod(transport, IpcChannel.OPERATIONS_CANCEL, operationCancelRequestSchema, actionResponseSchema),
            /**
             * Subscribes to renderer-safe operation lifecycle events.
             * @param {(event: object) => void} listener - Renderer event callback.
             * @returns {() => void} Frozen idempotent unsubscribe callback.
             */
            subscribe(listener) {
                return subscribe(transport, IpcChannel.OPERATIONS_EVENT, operationEventSchema, listener)
            }
        },
        service: {
            getSetup: createInvokeMethod(transport, IpcChannel.SERVICE_GET_SETUP, emptyRequestSchema, privilegedServiceSetupResponseSchema),
            retry: createInvokeMethod(transport, IpcChannel.SERVICE_RETRY, emptyRequestSchema, actionResponseSchema),
            register: createInvokeMethod(transport, IpcChannel.SERVICE_REGISTER, emptyRequestSchema, actionResponseSchema),
            openApprovalSettings: createInvokeMethod(transport, IpcChannel.SERVICE_OPEN_APPROVAL_SETTINGS, emptyRequestSchema, actionResponseSchema)
        },
        settings: {
            get: createInvokeMethod(transport, IpcChannel.SETTINGS_GET, emptyRequestSchema, settingsResponseSchema),
            update: createInvokeMethod(transport, IpcChannel.SETTINGS_UPDATE, settingsUpdateRequestSchema, settingsResponseSchema),
            /** @param {(settings: object) => void} listener - Strict settings listener. @returns {() => void} Listener cleanup. */
            subscribe(listener) {
                return subscribe(transport, IpcChannel.SETTINGS_EVENT, settingsSchema, listener)
            }
        },
        support: {
            generateSummary: createInvokeMethod(transport, IpcChannel.SUPPORT_GENERATE_SUMMARY, emptyRequestSchema, supportSummaryResponseSchema)
        },
        updates: {
            check: createInvokeMethod(transport, IpcChannel.UPDATES_CHECK, updateCheckRequestSchema, updateCheckResponseSchema)
        }
    }

    for (const group of Object.values(api)) {
        Object.freeze(group)
    }
    return Object.freeze(api)
}
