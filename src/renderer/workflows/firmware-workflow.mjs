// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { firmwareInstallationStageKeys } from '../firmware-installation-stages.mjs'
import { OperationKind } from '../../shared/contracts.mjs'
import { reportedUtilityProductIdentity, resolveUtilityCapability, utilityPrerequisite, utilityStages } from './utility-workflow-helpers.mjs'

const FIRMWARE_STAGE_DEFINITIONS = [
    ['firmware-validating', 'utilities.stage.firmwareValidating'],
    ['firmware-writing', 'utilities.stage.firmwareWriting'],
    ['firmware-finalizing', 'utilities.stage.firmwareFinalizing'],
    ['device-reconnecting', 'utilities.stage.deviceReconnecting'],
    ['firmware-readback', 'utilities.stage.firmwareReadback']
]
const FIRMWARE_STAGES = utilityStages(FIRMWARE_STAGE_DEFINITIONS)
const INSTALLATION_STAGES = utilityStages([FIRMWARE_STAGE_DEFINITIONS[0], ...Object.entries(firmwareInstallationStageKeys), ...FIRMWARE_STAGE_DEFINITIONS.slice(1)])

/**
 * Maps a reported interface to the one documented firmware image family.
 * @param {unknown} connectionType - Reported renderer-safe connection type.
 * @returns {{extension: '.BIP'|'.BIN'|null, family: string|null, familyKey: string}} Exact documented image family or an unknown result.
 */
function firmwareImageFamily(connectionType) {
    if (typeof connectionType !== 'string') return Object.freeze({ extension: null, family: null, familyKey: 'utilities.firmware.family.unreported' })
    const normalized = connectionType.toUpperCase()
    if (/USB\s*3/.test(normalized) || /SATA\s*(?:III|3)/.test(normalized)) {
        return Object.freeze({ extension: '.BIN', family: 'USB 3 / SATA III', familyKey: 'utilities.firmware.family.modern' })
    }
    if (normalized.includes('LEGACY') || /USB\s*2/.test(normalized) || /SATA\s*(?:I|1)(?:\s|$|\/)/.test(normalized)) {
        return Object.freeze({ extension: '.BIP', family: 'USB 2 / SATA I', familyKey: 'utilities.firmware.family.legacy' })
    }
    return Object.freeze({ extension: null, family: null, familyKey: 'utilities.firmware.family.unrecognized' })
}

/**
 * Builds the complete firmware preflight and progress presentation.
 * The chosen path and bytes remain main/native owned and are never returned here.
 * @param {object} device - Selected renderer-safe RDX device.
 * @param {{locked?: boolean, operationIntentAvailable?: boolean, activeOperation?: object}} [options={}] - Shell gates.
 * @returns {object} Frozen critical firmware workflow.
 */
export function createFirmwareWorkflow(device, options = {}) {
    const image = firmwareImageFamily(reportedUtilityProductIdentity(device))
    const mediaEjected = device?.media === null
    const prerequisites = Object.freeze([utilityPrerequisite('media-ejected', 'utilities.prerequisite.mediaEjected.label', mediaEjected, mediaEjected ? 'utilities.prerequisite.mediaEjected.met' : 'utilities.prerequisite.mediaEjected.firmware'), utilityPrerequisite('product-family', 'utilities.prerequisite.productFamily.label', image.extension !== null, image.extension === null ? 'utilities.prerequisite.productFamily.unmatched' : 'utilities.prerequisite.productFamily.matched', image.extension === null ? {} : { extension: image.extension, family: image.family }), utilityPrerequisite('stable-power', 'utilities.prerequisite.stablePower.label', true, 'utilities.prerequisite.stablePower.detail')])
    let capability = resolveUtilityCapability(device, OperationKind.FIRMWARE_UPDATE, prerequisites, options)
    if (device?.capabilities?.[OperationKind.FIRMWARE_UPDATE]?.state === 'available' && !mediaEjected) {
        capability = Object.freeze({ reason: 'media-must-be-ejected', state: 'wrong-media-state' })
    }
    return Object.freeze({
        capability,
        image,
        kind: OperationKind.FIRMWARE_UPDATE,
        prerequisites,
        risk: 'critical',
        stages: Object.hasOwn(firmwareInstallationStageKeys, options.activeOperation?.stage ?? '') ? INSTALLATION_STAGES : FIRMWARE_STAGES,
        warnings: Object.freeze(['utilities.firmware.warning.power', 'utilities.firmware.warning.imageMatch', 'utilities.firmware.warning.signature', 'utilities.firmware.warning.retry'])
    })
}
