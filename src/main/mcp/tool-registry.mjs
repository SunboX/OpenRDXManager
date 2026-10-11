// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { z } from 'zod'
import { APPLICATION_ROUTES, dispatchApplicationRequest } from '../application-dispatcher.mjs'
import { getOperationRiskClass } from '../safety-policy.mjs'
import { hasOwnPrototypeControlKey } from '../../shared/boundary-validation.mjs'
import { IpcChannel } from '../../shared/ipc-contract.mjs'
import { actionResponseSchema, emptyRequestSchema, fileTokenResponseSchema, localExportResponseSchema, operationIdSchema, operationRequestSchema, operationConfirmationRequestSchema, platformCapabilitySchema } from '../../shared/schemas.mjs'
import { FEATURE_MANIFEST } from '../../renderer/feature-manifest.mjs'
import { HELP_TOPICS } from '../../help/help-index.mjs'
import { englishCatalog } from '../../locales/en.mjs'

/** Explicit inventory makes newly added native operations require an MCP decision. */
export const MCP_OPERATION_TOOLS = Object.freeze({
    scan: 'rdx_scan',
    'status-refresh': 'rdx_status_refresh',
    'access-enable': 'rdx_access_enable',
    'access-disable': 'rdx_access_disable',
    'credential-create': 'rdx_credential_create',
    'credential-change': 'rdx_credential_change',
    'credential-delete': 'rdx_credential_delete',
    'credential-reset': 'rdx_credential_reset',
    'credential-configure': 'rdx_credential_configure',
    'self-test': 'rdx_self_test',
    'led-test': 'rdx_led_test',
    'write-read-test': 'rdx_write_read_test',
    'firmware-update': 'rdx_firmware_update',
    'volume-label-set': 'rdx_volume_label_set',
    'drive-letter-set': 'rdx_drive_letter_set',
    'drive-letter-reset': 'rdx_drive_letter_reset',
    format: 'rdx_format',
    'drive-mode-set': 'rdx_drive_mode_set',
    'sata-mode-set': 'rdx_sata_mode_set',
    'eject-safe': 'rdx_eject_safe',
    'eject-force': 'rdx_eject_force'
})

const OPERATION_DESCRIPTIONS = Object.freeze({
    scan: 'Scan for connected RDX devices and refresh discovery.',
    'status-refresh': 'Refresh all reported values for the selected drive and cartridge.',
    'self-test': 'Start the device self-test; inspect its operation ID for progress and results.',
    'led-test': 'Start the physical drive LED test.',
    'write-read-test': 'Start the bounded cartridge write/read diagnostic test.',
    'firmware-update': 'Update drive firmware using a token from rdx_firmware_register. The device may reboot. Do not disconnect power.',
    format: 'Erase and format the selected cartridge. Requires a one-use token from rdx_confirm_format bound to this exact device revision and filesystem.',
    'eject-safe': 'Safely unmount and eject the selected cartridge.',
    'eject-force': 'Force eject the cartridge, potentially losing unsaved data. Requires a token from rdx_confirm_eject_force.',
    'volume-label-set': 'Rename the selected mounted Windows cartridge volume without formatting it. An empty label removes the name. Requires the exact current device revision.',
    'drive-letter-set': 'Set the Windows drive letter, subject to platform and availability checks.',
    'drive-letter-reset': 'Reset the Windows drive letter through the native service.',
    'drive-mode-set': 'Change the drive fixed/removable operating mode.',
    'sata-mode-set': 'Change the drive SATA speed mode.'
})

const ROUTE_TOOLS = Object.freeze([
    ['rdx_manufacturing_list', IpcChannel.MANUFACTURING_LIST, 'Read verified manufacturing backup history and current backup/restore capability for the selected dock. Use page to access earlier records. Raw data and paths remain private.', true],
    ['rdx_manufacturing_backup', IpcChannel.MANUFACTURING_BACKUP, 'Save and verify a private manufacturing-sector backup of the explicitly selected dock. The cartridge must be removed.', false],
    ['rdx_manufacturing_restore', IpcChannel.MANUFACTURING_RESTORE, 'Restore the selected original manufacturing record only after the operator associates the physical dock with its saved original serial and explicitly authorizes this action. Requires confirmationSerial and acknowledged=true. Replacing a checksum-valid identity also requires separate explicit operator consent and allowIdentityChange=true; never infer this consent from a serial mismatch. Saves current data first, writes once, verifies the whole sector, and never automatically resets or retries. Tell the operator to power-cycle only after verified success.', false],
    ['rdx_mcp_status', IpcChannel.MCP_GET_STATUS, 'Read local MCP endpoint status and non-secret configuration.', true],
    ['rdx_app_info', IpcChannel.APP_GET, 'Read application name, version, and platform.', true],
    ['rdx_devices_list', IpcChannel.DEVICES_LIST, 'Read the full current device inventory, reported/unavailable drive and cartridge values, revisions, discovery diagnostics, and per-device capabilities. Use scan/refresh for new hardware reads.', true],
    ['rdx_logs_list', IpcChannel.LOGS_LIST, 'Read bounded, redacted activity records.', true],
    ['rdx_logging_set', IpcChannel.LOGS_SET_ENABLED, 'Enable or disable persistent event logging.', false],
    ['rdx_operation_cancel', IpcChannel.OPERATIONS_CANCEL, 'Request cancellation at the current safe boundary; irreversible stages may refuse.', false],
    ['rdx_operation_continue', IpcChannel.OPERATIONS_CONTINUE, 'Acknowledge the requested USB power cycle only after the operator has reconnected the dock; exact operation and awaiting stage required.', false],
    ['rdx_recovery_list', IpcChannel.RECOVERY_LIST, 'Read saved recovery profiles and currently connected ROM-loader targets. Targets may use any USB port. The generic bootloader serial cannot identify a unit; the operator must associate the physical dock with its saved profile.', true],
    ['rdx_recovery_status', IpcChannel.RECOVERY_STATUS, 'Read the current recovery attempt, progress, power-cycle gate, and verified outcome.', true],
    ['rdx_recovery_start', IpcChannel.RECOVERY_START, 'Start firmware recovery only after the operator has identified the physical ROM-loader dock as the unit belonging to the selected saved profile. Use a fresh target token from rdx_recovery_list and acknowledged=true. Recovery writes firmware; never retry an uncertain outcome automatically.', false],
    ['rdx_recovery_continue', IpcChannel.RECOVERY_CONTINUE, 'Continue recovery only after the operator physically power-cycled the selected dock. Requires the exact current attempt and awaiting stage with acknowledged=true. May release further firmware writes; never retry an uncertain outcome automatically.', false],
    ['rdx_service_setup', IpcChannel.SERVICE_GET_SETUP, 'Inspect native service setup and any required OS approval.', true],
    ['rdx_service_retry', IpcChannel.SERVICE_RETRY, 'Retry the configured native hardware service.', false],
    ['rdx_service_register', IpcChannel.SERVICE_REGISTER, 'Request registration of the bundled native helper; OS approval may be required.', false],
    ['rdx_service_open_approval', IpcChannel.SERVICE_OPEN_APPROVAL_SETTINGS, 'Open the operating system approval settings for the bundled helper.', false],
    ['rdx_settings_get', IpcChannel.SETTINGS_GET, 'Read all public desktop application settings.', true],
    ['rdx_settings_update', IpcChannel.SETTINGS_UPDATE, 'Persist public settings and update the GUI.', false],
    ['rdx_updates_check', IpcChannel.UPDATES_CHECK, 'Check configured signed update metadata for the manager and firmware; does not install updates.', true],
    ['rdx_device_select', IpcChannel.APP_SET_TRAY_SELECTION, 'Select the device used by the application tray.', false]
])

/** Explicit parity mapping, including desktop-only endpoint administration and dialog replacements. */
export const MCP_ROUTE_COVERAGE = Object.freeze({
    [IpcChannel.MANUFACTURING_OPEN_FOLDER]: 'local desktop file manager control',
    ...Object.fromEntries(ROUTE_TOOLS.map(([name, channel]) => [channel, name])),
    [IpcChannel.DEVICES_SCAN]: 'rdx_scan',
    [IpcChannel.OPERATIONS_START]: 'named operation tools',
    [IpcChannel.OPERATIONS_CONFIRM]: 'rdx_confirm_format / rdx_confirm_eject_force',
    [IpcChannel.FILES_CHOOSE_FIRMWARE]: 'rdx_firmware_register',
    [IpcChannel.FILES_CHOOSE_EXPORT]: 'rdx_activity_export / rdx_summary_export',
    [IpcChannel.LOGS_EXPORT]: 'rdx_activity_export',
    [IpcChannel.SUPPORT_GENERATE_SUMMARY]: 'rdx_summary_export',
    [IpcChannel.MCP_UPDATE]: 'local desktop endpoint lifecycle control',
    [IpcChannel.MCP_COPY_CONFIGURATION]: 'local desktop clipboard control'
})

const safeReasonSchema = z.string().regex(/^[a-z][a-z0-9-]{0,127}$/)
const activeOperationSchema = z
    .object({
        operationId: operationIdSchema,
        kind: z.enum(Object.keys(MCP_OPERATION_TOOLS)),
        deviceId: z
            .string()
            .regex(/^rdx:[a-z0-9:-]+$/i)
            .optional(),
        deviceRevision: z.number().int().nonnegative().optional(),
        stage: safeReasonSchema,
        cancellationRequested: z.boolean(),
        cancellationState: z.enum(['cancellable', 'requested', 'closed']).optional(),
        irreversible: z.boolean()
    })
    .strip()

const textResponseSchema = z.union([z.object({ ok: z.literal(true), text: z.string().max(2_000_000) }).strict(), z.object({ ok: z.literal(false), reason: z.string().regex(/^[a-z][a-z0-9-]{0,127}$/) }).strict()])
const deviceQuerySchema = operationRequestSchema.options.find((schema) => schema.shape.kind.value === 'status-refresh').pick({ deviceId: true })

/** @param {boolean} readOnly - Whether the action mutates state. @param {boolean} destructive - Potential for irreversible changes. @param {boolean} openWorld - Whether external network entities are contacted. @returns {object} Advisory MCP annotations; enforcement is in services. */
function annotations(readOnly, destructive = false, openWorld = false) {
    return { readOnlyHint: readOnly, destructiveHint: destructive, idempotentHint: readOnly, openWorldHint: openWorld }
}

/** @param {string} name - Stable tool name. @param {string} description - User-facing contract. @param {object} inputSchema - Strict Zod schema. @param {Function} handler - Main-owned implementation. @param {object} hints - MCP annotations. @returns {object} Tool whose direct and SDK invocations share validation. */
function tool(name, description, inputSchema, handler, hints = annotations(true)) {
    return Object.freeze({
        name,
        description,
        inputSchema,
        annotations: hints,
        /** @param {unknown} request - Untrusted caller arguments. @returns {Promise<object>} Safe result with no exception internals. */
        async execute(request) {
            if (hasOwnPrototypeControlKey(request)) return { ok: false, reason: 'prototype-control-key' }
            const parsed = inputSchema.safeParse(request)
            if (!parsed.success) return { ok: false, reason: 'invalid-request' }
            try {
                return await handler(parsed.data)
            } catch {
                return { ok: false, reason: 'service-failure' }
            }
        }
    })
}

/** @param {object|undefined} service - Main-only dependency. @param {string} method - Fixed method name. @param {object} schema - Public response validator. @param {unknown[]} args - Validated arguments. @returns {Promise<object>} Strict public response, or contained failure. */
async function callPublic(service, method, schema, ...args) {
    if (typeof service?.[method] !== 'function') return { ok: false, reason: 'service-unavailable' }
    const parsed = schema.safeParse(await service[method](...args))
    return parsed.success ? parsed.data : { ok: false, reason: 'invalid-service-response' }
}

/** @param {object} options - Shared main services, accepted operation history, firmware/report boundaries, and desktop actions. @returns {object[]} Complete named MCP tools; no renderer sender impersonation. */
export function createMcpToolRegistry({ services, operationStore, firmwareFiles, support, desktop, getReadiness, getActiveOperation }) {
    const tools = ROUTE_TOOLS.map(([name, channel, description, readOnly]) => {
        const route = APPLICATION_ROUTES.find((entry) => entry.channel === channel)
        return tool(name, description, route.requestSchema, (request) => dispatchApplicationRequest(services, channel, request), annotations(readOnly, [IpcChannel.MANUFACTURING_RESTORE, IpcChannel.OPERATIONS_CONTINUE, IpcChannel.RECOVERY_START, IpcChannel.RECOVERY_CONTINUE].includes(channel), channel === IpcChannel.UPDATES_CHECK))
    })
    for (const [kind, name] of Object.entries(MCP_OPERATION_TOOLS)) {
        const variant = operationRequestSchema.options.find((schema) => schema.shape.kind.value === kind)
        const risk = getOperationRiskClass(kind)
        const description = OPERATION_DESCRIPTIONS[kind] ?? `Request ${kind}. Consult device capabilities first; current security writes may report evidence-incomplete.`
        tools.push(tool(name, description, variant.omit({ kind: true }), (request) => dispatchApplicationRequest(services, kind === 'scan' ? IpcChannel.DEVICES_SCAN : IpcChannel.OPERATIONS_START, { ...request, kind }), annotations(risk === 'read-only', ['critical', 'destructive'].includes(risk))))
    }
    for (const variant of operationConfirmationRequestSchema.options) {
        const kind = variant.shape.kind.value
        tools.push(tool(`rdx_confirm_${kind.replaceAll('-', '_')}`, `Explicitly request a one-use confirmation for ${kind} after obtaining the user's authorization. Bound to the exact device revision and action; expires after 60 seconds. This call itself does not perform the action.`, variant.omit({ kind: true }), (request) => dispatchApplicationRequest(services, IpcChannel.OPERATIONS_CONFIRM, { ...request, kind }), annotations(false)))
    }
    tools.push(
        tool('rdx_device_get', 'Read every public value and unavailable reason for one current device.', deviceQuerySchema, async ({ deviceId }) => {
            const listed = await dispatchApplicationRequest(services, IpcChannel.DEVICES_LIST, {})
            if (!listed.ok) return listed
            const device = listed.devices.find((entry) => entry.id === deviceId)
            return device === undefined ? { ok: false, reason: 'device-not-found' } : { ok: true, device, epoch: listed.epoch, listRevision: listed.listRevision }
        }),
        tool('rdx_operations_list', 'Read the active operation/scan reservation and up to 128 recent operation states.', emptyRequestSchema, () => {
            const active = activeOperationSchema.safeParse(getActiveOperation?.())
            return { ...operationStore.list(), activeOperation: active.success ? active.data : null }
        }),
        tool('rdx_operation_get', 'Read progress, cancellation state, terminal result, or structured failure by operation ID.', z.object({ operationId: operationIdSchema }).strict(), ({ operationId }) => operationStore.get(operationId)),
        tool('rdx_capabilities', 'Read operation/tool mappings, feature coverage including unsupported features, and per-device availability.', emptyRequestSchema, async () => ({ ok: true, operations: Object.entries(MCP_OPERATION_TOOLS).map(([kind, name]) => ({ kind, tool: name, riskClass: getOperationRiskClass(kind) })), features: structuredClone(FEATURE_MANIFEST), inventory: await dispatchApplicationRequest(services, IpcChannel.DEVICES_LIST, {}) })),
        tool('rdx_service_status', 'Read current native runtime readiness without internal endpoints or credentials.', emptyRequestSchema, () => {
            const readiness = getReadiness?.() ?? { status: 'unavailable' }
            const status = safeReasonSchema.safeParse(readiness.status)
            const reason = safeReasonSchema.safeParse(readiness.reason)
            const capability = platformCapabilitySchema.safeParse(readiness.platformCapability)
            return { ok: true, status: status.success ? status.data : 'unavailable', hardwareReady: readiness.hardwareReady === true, hardwareVerified: readiness.hardwareVerified === true, mode: ['native', 'no-device'].includes(readiness.mode) ? readiness.mode : null, privileged: readiness.privileged === true, ...(reason.success ? { reason: reason.data } : {}), ...(capability.success ? { platformCapability: capability.data } : {}) }
        }),
        tool(
            'rdx_firmware_register',
            'Validate one explicit local .BIN/.BIP firmware file and obtain a one-use file token for rdx_firmware_update. Does not write the device.',
            z
                .object({
                    path: z
                        .string()
                        .min(1)
                        .max(4096)
                        .regex(/^[^\x00-\x1f\x7f]+$/)
                })
                .strict(),
            ({ path }) => callPublic(firmwareFiles, 'registerFirmwarePath', fileTokenResponseSchema, path),
            annotations(false)
        ),
        tool('rdx_summary_read', 'Read the sanitized system summary as text without a file dialog.', emptyRequestSchema, () => callPublic(support, 'readSummary', textResponseSchema)),
        tool('rdx_activity_read', 'Read a redacted activity report as text without a file dialog.', emptyRequestSchema, () => callPublic(support, 'readActivity', textResponseSchema)),
        tool('rdx_summary_export', 'Save a new sanitized summary in the application exports directory; existing files are never overwritten.', emptyRequestSchema, () => callPublic(support, 'exportSummary', localExportResponseSchema), annotations(false)),
        tool('rdx_activity_export', 'Save a new redacted activity report in the application exports directory.', emptyRequestSchema, () => callPublic(support, 'exportActivity', localExportResponseSchema), annotations(false)),
        tool('rdx_help', 'Read bundled help and compatibility/feature coverage in English.', emptyRequestSchema, () => ({ ok: true, topics: HELP_TOPICS.map((topic) => ({ id: topic.id, title: englishCatalog[topic.titleKey], summary: englishCatalog[topic.summaryKey], paragraphs: topic.paragraphKeys.map((key) => englishCatalog[key]) })), features: structuredClone(FEATURE_MANIFEST) })),
        tool('rdx_app_show', 'Show or focus the manager window.', emptyRequestSchema, () => callPublic(desktop, 'show', actionResponseSchema), annotations(false)),
        tool('rdx_app_exit', 'Request normal application exit. Refused while any device operation is active.', emptyRequestSchema, () => callPublic(desktop, 'exit', actionResponseSchema), annotations(false))
    )
    return tools
}
