// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { firmwareTargetBinding } from '../../shared/firmware-target-binding.mjs'
import { operationConfirmationRequestSchema, operationRequestSchema } from '../../shared/schemas.mjs'

/**
 * Returns a stable path-free bridge failure.
 * @param {unknown} reason - Candidate renderer-safe reason.
 * @returns {{ok: false, reason: string}} Bounded failure.
 */
function failure(reason) {
    return { ok: false, reason: typeof reason === 'string' && /^[a-z][a-z0-9-]{0,127}$/.test(reason) ? reason : 'service-failure' }
}

/**
 * Creates the dedicated utility operation bridge around named preload methods.
 * Firmware paths remain behind an opaque file token, and destructive tokens are
 * issued by the service for the exact already-selected action.
 * @param {unknown} api - Candidate frozen preload API.
 * @returns {{isAvailable: (kind?: string) => boolean, start: (request: object, options?: object) => Promise<object>}} Frozen utility controller.
 */
export function createUtilityOperationController(api) {
    const canStart = typeof api?.operations?.start === 'function'
    const canConfirm = typeof api?.operations?.confirm === 'function'
    const canChooseFirmware = typeof api?.files?.chooseFirmware === 'function'

    /**
     * Reports whether the named methods required by a utility kind exist.
     * @param {string} [kind] - Optional operation kind.
     * @returns {boolean} True only when every required named method is bound.
     */
    function isAvailable(kind) {
        if (!canStart) return false
        if (kind === 'firmware-update') return canChooseFirmware
        if (kind === 'format' || kind === 'eject-force') return canConfirm
        return true
    }

    /**
     * Starts one exact utility request after obtaining any main-owned token.
     * @param {object} request - Token-free structured request from the utility view.
     * @param {{getSelectedDevice?: () => object|null}} [options={}] - Live renderer selection accessor, read after choosing.
     * @returns {Promise<object>} Strict start response or bounded failure.
     */
    async function start(request, options = {}) {
        if (!isAvailable(request?.kind)) return failure('service-unavailable')
        let operation = { ...request }
        try {
            if (request.kind === 'firmware-update') {
                const initial = options.getSelectedDevice?.()
                const binding = firmwareTargetBinding(initial)
                if (options.getSelectedDevice && (binding === null || initial.id !== request.deviceId || initial.revision !== request.deviceRevision)) return failure('stale-device-revision')
                const selected = await api.files.chooseFirmware({})
                if (selected?.ok !== true) return failure(selected?.reason ?? 'firmware-selection-cancelled')
                if (options.getSelectedDevice) {
                    const current = options.getSelectedDevice()
                    // Selecting a file is not admission: refresh only the revision of
                    // the same unchanged empty dock, then let main/native validate it.
                    if (!current || firmwareTargetBinding(current) !== binding) return failure('stale-device-revision')
                    operation.deviceRevision = current.revision
                    if (typeof api.devices?.list === 'function') {
                        // IPC publications can trail the service's cached inventory.
                        // Read that current inventory without starting another scan.
                        const listed = await api.devices.list({})
                        if (listed?.ok !== true) return failure(listed?.reason ?? 'service-failure')
                        const latest = listed.devices?.find((device) => device.id === request.deviceId)
                        if (firmwareTargetBinding(latest) !== binding || firmwareTargetBinding(options.getSelectedDevice()) !== binding) return failure('stale-device-revision')
                        operation.deviceRevision = latest.revision
                    }
                }
                operation.firmwareFileToken = selected.fileToken
            } else if (request.kind === 'format' || request.kind === 'eject-force') {
                const { passphrase: _passphrase, ...confirmationRequest } = request
                const confirmation = operationConfirmationRequestSchema.safeParse(confirmationRequest)
                if (!confirmation.success) return failure('invalid-operation-request')
                const issued = await api.operations.confirm(confirmation.data)
                if (issued?.ok !== true) return failure(issued?.reason ?? 'confirmation-unavailable')
                operation.confirmationToken = issued.confirmationToken
            }
            const parsed = operationRequestSchema.safeParse(operation)
            if (!parsed.success) return failure('invalid-operation-request')
            const result = await api.operations.start(parsed.data)
            return result?.ok === true ? result : failure(result?.reason)
        } catch {
            return failure('service-failure')
        }
    }

    return Object.freeze({ isAvailable, start })
}
