// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Binds a firmware choice to one available empty dock and its reported identity.
 * Telemetry revisions may advance during discovery; identity and firmware may not.
 * @param {object|null} device - Current public device snapshot.
 * @returns {string|null} Stable binding, or null when firmware admission is unavailable.
 */
export function firmwareTargetBinding(device) {
    if (!device || device.media !== null || device.mediaState !== 'no-media' || device.capabilities?.['firmware-update']?.state !== 'available') return null
    const details = device.drive?.details
    return JSON.stringify([device.id, device.vendor, device.product, device.serial, details?.connectionType, details?.productType, details?.product, device.drive?.connectionType, device.drive?.productType, details?.firmwareRevision, device.drive?.firmwareRevision])
}
