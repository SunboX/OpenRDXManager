// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { deviceEventSchema, operationEventSchema, settingsSchema } from '../../shared/schemas.mjs'

/** @param {object} options - Existing IPC controller, public operation store, and current MCP controller getter. @returns {object} Shared validated publication edge, preserving native/GUI delivery behavior. */
export function createMcpEventPublisher({ ipcController, operationStore, getController }) {
    /** @param {string[]} uris - Fixed public resource identities. @returns {void} Contains disconnected observer failures. */
    function notify(uris) {
        for (const uri of uris) {
            try {
                getController()?.notifyResource(uri)
            } catch {
                /* MCP observers never interrupt application work. */
            }
        }
    }
    return Object.freeze({
        /** @param {unknown} event - Accepted coordinator event. @returns {boolean} Existing IPC delivery result. */
        publishOperationEvent(event) {
            const parsed = operationEventSchema.safeParse(event)
            if (!parsed.success) return false
            operationStore.publish(parsed.data)
            notify(['openrdx://operations', `openrdx://operations/${encodeURIComponent(parsed.data.operationId)}`, 'openrdx://activity', 'openrdx://support-summary'])
            return ipcController.publishOperationEvent(parsed.data)
        },
        /** @param {unknown} event - Validated runtime discovery/lifecycle publication. @returns {boolean} Existing IPC delivery result. */
        publishDeviceEvent(event) {
            const parsed = deviceEventSchema.safeParse(event)
            if (!parsed.success) return false
            const value = parsed.data
            const ids = value.type === 'list' ? value.devices.map((device) => device.id) : value.type === 'snapshot' ? [value.device.id] : value.type === 'removed' ? [value.deviceId] : []
            notify(['openrdx://devices', 'openrdx://capabilities', 'openrdx://service', 'openrdx://support-summary', ...ids.map((id) => `openrdx://devices/${encodeURIComponent(id)}`)])
            return ipcController.publishDeviceEvent(value)
        },
        /** @param {unknown} event - Complete public settings. @returns {boolean} Existing IPC delivery result. */
        publishSettingsEvent(event) {
            const parsed = settingsSchema.safeParse(event)
            if (!parsed.success) return false
            notify(['openrdx://settings', 'openrdx://activity'])
            return ipcController.publishSettingsEvent(parsed.data)
        }
    })
}
