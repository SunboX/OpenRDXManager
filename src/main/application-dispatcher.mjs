// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { IpcChannel } from '../shared/ipc-contract.mjs'
import { manufacturingRequestSchema, manufacturingRestoreRequestSchema, manufacturingResponseSchema } from '../shared/manufacturing-schemas.mjs'
import { actionResponseSchema, appInfoResponseSchema, deviceEventSchema, deviceListResponseSchema, emptyRequestSchema, exportDestinationRequestSchema, fileTokenResponseSchema, localExportResponseSchema, logListResponseSchema, logSettingRequestSchema, operationCancelRequestSchema, operationContinueRequestSchema, operationConfirmationRequestSchema, operationConfirmationResponseSchema, operationEventSchema, operationRequestSchema, operationStartResponseSchema, privilegedServiceSetupResponseSchema, scanRequestSchema, settingsResponseSchema, settingsSchema, settingsUpdateRequestSchema, supportSummaryResponseSchema, traySelectionRequestSchema, updateCheckRequestSchema, updateCheckResponseSchema } from '../shared/schemas.mjs'
import { hasOwnPrototypeControlKey } from '../shared/boundary-validation.mjs'
import { evaluateOperation } from './safety-policy.mjs'
import { captureFirmwareScanBinding, refreshFirmwareScanRevision } from './firmware-scan-admission.mjs'
import { mcpSettingsUpdateSchema, mcpStatusResponseSchema } from '../shared/mcp-schemas.mjs'
import { recoveryContinueRequestSchema, recoveryListResponseSchema, recoveryStartRequestSchema, recoveryStatusResponseSchema } from '../shared/recovery-schemas.mjs'

export const APPLICATION_ROUTES = Object.freeze([
    Object.freeze({ channel: IpcChannel.MANUFACTURING_OPEN_FOLDER, requestSchema: emptyRequestSchema, responseSchema: actionResponseSchema, serviceGroup: 'manufacturing', serviceMethod: 'openFolder' }),
    Object.freeze({ channel: IpcChannel.MANUFACTURING_LIST, requestSchema: manufacturingRequestSchema, responseSchema: manufacturingResponseSchema, serviceGroup: 'manufacturing', serviceMethod: 'list' }),
    Object.freeze({ channel: IpcChannel.MANUFACTURING_BACKUP, requestSchema: manufacturingRequestSchema, responseSchema: manufacturingResponseSchema, serviceGroup: 'manufacturing', serviceMethod: 'backup' }),
    Object.freeze({ channel: IpcChannel.MANUFACTURING_RESTORE, requestSchema: manufacturingRestoreRequestSchema, responseSchema: manufacturingResponseSchema, serviceGroup: 'manufacturing', serviceMethod: 'restore' }),
    Object.freeze({ channel: IpcChannel.RECOVERY_LIST, requestSchema: emptyRequestSchema, responseSchema: recoveryListResponseSchema, serviceGroup: 'recovery', serviceMethod: 'list' }),
    Object.freeze({ channel: IpcChannel.RECOVERY_STATUS, requestSchema: emptyRequestSchema, responseSchema: recoveryStatusResponseSchema, serviceGroup: 'recovery', serviceMethod: 'status' }),
    Object.freeze({ channel: IpcChannel.RECOVERY_START, requestSchema: recoveryStartRequestSchema, responseSchema: recoveryStatusResponseSchema, serviceGroup: 'recovery', serviceMethod: 'start' }),
    Object.freeze({ channel: IpcChannel.RECOVERY_CONTINUE, requestSchema: recoveryContinueRequestSchema, responseSchema: recoveryStatusResponseSchema, serviceGroup: 'recovery', serviceMethod: 'continue' }),
    Object.freeze({ channel: IpcChannel.OPERATIONS_CONTINUE, requestSchema: operationContinueRequestSchema, responseSchema: operationStartResponseSchema, serviceGroup: 'operations', serviceMethod: 'continue' }),
    Object.freeze({ channel: IpcChannel.MCP_GET_STATUS, requestSchema: emptyRequestSchema, responseSchema: mcpStatusResponseSchema, serviceGroup: 'mcp', serviceMethod: 'getStatus' }),
    Object.freeze({ channel: IpcChannel.MCP_UPDATE, requestSchema: mcpSettingsUpdateSchema, responseSchema: mcpStatusResponseSchema, serviceGroup: 'mcp', serviceMethod: 'update' }),
    Object.freeze({ channel: IpcChannel.MCP_COPY_CONFIGURATION, requestSchema: emptyRequestSchema, responseSchema: actionResponseSchema, serviceGroup: 'mcp', serviceMethod: 'copyConfiguration' }),
    Object.freeze({ channel: IpcChannel.APP_GET, requestSchema: emptyRequestSchema, responseSchema: appInfoResponseSchema, serviceGroup: 'app', serviceMethod: 'getInfo' }),
    Object.freeze({ channel: IpcChannel.APP_SET_TRAY_SELECTION, requestSchema: traySelectionRequestSchema, responseSchema: actionResponseSchema, serviceGroup: 'app', serviceMethod: 'setTraySelection' }),
    Object.freeze({ channel: IpcChannel.DEVICES_LIST, requestSchema: emptyRequestSchema, responseSchema: deviceListResponseSchema, serviceGroup: 'devices', serviceMethod: 'list' }),
    Object.freeze({ channel: IpcChannel.DEVICES_SCAN, requestSchema: scanRequestSchema, responseSchema: actionResponseSchema, serviceGroup: 'devices', serviceMethod: 'scan', safetyContextGroup: 'operations' }),
    Object.freeze({ channel: IpcChannel.FILES_CHOOSE_FIRMWARE, requestSchema: emptyRequestSchema, responseSchema: fileTokenResponseSchema, serviceGroup: 'files', serviceMethod: 'chooseFirmware' }),
    Object.freeze({ channel: IpcChannel.FILES_CHOOSE_EXPORT, requestSchema: exportDestinationRequestSchema, responseSchema: fileTokenResponseSchema, serviceGroup: 'files', serviceMethod: 'chooseExportDestination' }),
    Object.freeze({ channel: IpcChannel.LOGS_LIST, requestSchema: emptyRequestSchema, responseSchema: logListResponseSchema, serviceGroup: 'logs', serviceMethod: 'list' }),
    Object.freeze({ channel: IpcChannel.LOGS_SET_ENABLED, requestSchema: logSettingRequestSchema, responseSchema: actionResponseSchema, serviceGroup: 'logs', serviceMethod: 'setEnabled' }),
    Object.freeze({ channel: IpcChannel.LOGS_EXPORT, requestSchema: emptyRequestSchema, responseSchema: localExportResponseSchema, serviceGroup: 'logs', serviceMethod: 'export' }),
    Object.freeze({ channel: IpcChannel.OPERATIONS_START, requestSchema: operationRequestSchema, responseSchema: operationStartResponseSchema, serviceGroup: 'operations', serviceMethod: 'start', safetyPolicy: true }),
    Object.freeze({ channel: IpcChannel.OPERATIONS_CONFIRM, requestSchema: operationConfirmationRequestSchema, responseSchema: operationConfirmationResponseSchema, serviceGroup: 'operations', serviceMethod: 'confirm' }),
    Object.freeze({ channel: IpcChannel.OPERATIONS_CANCEL, requestSchema: operationCancelRequestSchema, responseSchema: actionResponseSchema, serviceGroup: 'operations', serviceMethod: 'cancel' }),
    Object.freeze({ channel: IpcChannel.SERVICE_GET_SETUP, requestSchema: emptyRequestSchema, responseSchema: privilegedServiceSetupResponseSchema, serviceGroup: 'service', serviceMethod: 'getSetup' }),
    Object.freeze({ channel: IpcChannel.SERVICE_RETRY, requestSchema: emptyRequestSchema, responseSchema: actionResponseSchema, serviceGroup: 'service', serviceMethod: 'retry' }),
    Object.freeze({ channel: IpcChannel.SERVICE_REGISTER, requestSchema: emptyRequestSchema, responseSchema: actionResponseSchema, serviceGroup: 'service', serviceMethod: 'register' }),
    Object.freeze({ channel: IpcChannel.SERVICE_OPEN_APPROVAL_SETTINGS, requestSchema: emptyRequestSchema, responseSchema: actionResponseSchema, serviceGroup: 'service', serviceMethod: 'openApprovalSettings' }),
    Object.freeze({ channel: IpcChannel.SETTINGS_GET, requestSchema: emptyRequestSchema, responseSchema: settingsResponseSchema, serviceGroup: 'settings', serviceMethod: 'get' }),
    Object.freeze({ channel: IpcChannel.SETTINGS_UPDATE, requestSchema: settingsUpdateRequestSchema, responseSchema: settingsResponseSchema, serviceGroup: 'settings', serviceMethod: 'update' }),
    Object.freeze({ channel: IpcChannel.SUPPORT_GENERATE_SUMMARY, requestSchema: emptyRequestSchema, responseSchema: supportSummaryResponseSchema, serviceGroup: 'support', serviceMethod: 'generateSummary' }),
    Object.freeze({ channel: IpcChannel.UPDATES_CHECK, requestSchema: updateCheckRequestSchema, responseSchema: updateCheckResponseSchema, serviceGroup: 'updates', serviceMethod: 'check' })
])

/**
 * Builds a stable renderer-safe failure without including exception details.
 * @param {string} reason - Internal fixed failure reason.
 * @returns {{ok: false, reason: string}} Safe failure response.
 */
function failure(reason) {
    return { ok: false, reason }
}

/**
 * Invokes one injected main service after strict request parsing and optional
 * safety evaluation, then validates its renderer-safe response.
 * @param {object} route - Exact route descriptor.
 * @param {object} services - Injected main services.
 * @param {object} request - Strict parsed request.
 * @returns {Promise<object>} Validated response or stable safe failure.
 */
async function dispatchRoute(route, services, request) {
    const service = services[route.serviceGroup]
    const method = service?.[route.serviceMethod]
    if (typeof method !== 'function') {
        return failure('service-unavailable')
    }

    try {
        if (route.safetyPolicy === true || typeof route.safetyContextGroup === 'string') {
            const safetyService = services[route.safetyContextGroup ?? route.serviceGroup]
            if (typeof safetyService?.getContext !== 'function') {
                return failure('service-unavailable')
            }
            // Discovery is temporary contention, not an operation rejection.
            // Fetch fresh safety context only after its reservation settles.
            let firmwareBinding = null
            if (route.safetyPolicy === true && typeof safetyService.waitForScan === 'function') {
                if (request.kind === 'firmware-update') firmwareBinding = captureFirmwareScanBinding(request, await safetyService.getContext(request))
                await safetyService.waitForScan()
            }
            const context = await safetyService.getContext(request)
            request = refreshFirmwareScanRevision(request, firmwareBinding, context)
            const decision = evaluateOperation(request, context)
            if (!decision.allowed) {
                return failure(decision.reason)
            }
            request = decision.request
        }

        const response = await method.call(service, request)
        const parsedResponse = route.responseSchema.safeParse(response)
        return parsedResponse.success ? parsedResponse.data : failure('invalid-service-response')
    } catch (_error) {
        return failure('service-failure')
    }
}

/**
 * Validates one allowlisted service request for an already authenticated adapter.
 * Transport authentication remains the caller's responsibility.
 * @param {object} services - Main-owned application service groups.
 * @param {string} channel - Exact registered service route.
 * @param {unknown} request - Untrusted candidate payload.
 * @returns {Promise<object>} Strict public result or stable failure.
 */
export async function dispatchApplicationRequest(services, channel, request) {
    const route = APPLICATION_ROUTES.find((candidate) => candidate.channel === channel)
    if (route === undefined) return failure('unknown-route')
    if (hasOwnPrototypeControlKey(request)) return failure('prototype-control-key')
    const parsed = route.requestSchema.safeParse(request)
    if (!parsed.success) return failure('invalid-request')
    return dispatchRoute(route, services, parsed.data)
}
