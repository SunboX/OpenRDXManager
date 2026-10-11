// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { OperationKind } from '../../shared/contracts.mjs'
import { getFormatFilesystemPolicy, normalizeFormatFilesystem } from './format-filesystem-policy.mjs'
import { reportedUtilityValue, resolveUtilityCapability, utilityPrerequisite, utilityStages } from './utility-workflow-helpers.mjs'

const FORMAT_STAGES = utilityStages([
    ['format-validating', 'utilities.stage.formatValidating'],
    ['format-writing', 'utilities.stage.formatWriting'],
    ['format-finalizing', 'utilities.stage.formatFinalizing'],
    ['format-readback', 'utilities.stage.formatReadback']
])

/**
 * Creates the exact visible destructive identity for one dock and cartridge.
 * @param {object} device - Selected renderer-safe device.
 * @returns {string|null} Dock/cartridge identity the user must enter, or null without exact identity.
 */
function formatIdentity(device) {
    const dockIdentity = device?.serial ?? device?.id
    const mediaIdentity = reportedUtilityValue(device?.media?.details?.serialNumber) ?? device?.media?.serial ?? device?.media?.id
    if (typeof dockIdentity !== 'string' || dockIdentity === '' || typeof mediaIdentity !== 'string' || mediaIdentity === '') return null
    return `${dockIdentity} / ${mediaIdentity}`
}

/**
 * Builds the destructive partition-and-format workflow.
 * @param {object} device - Selected renderer-safe RDX device.
 * @param {{confirmationValue?: string, filesystem?: string, locked?: boolean, operationIntentAvailable?: boolean, platform?: string}} [options={}] - User selection, host platform, and shell gates.
 * @returns {object} Frozen format workflow.
 */
export function createFormatWorkflow(device, options = {}) {
    const policy = getFormatFilesystemPolicy(options.platform)
    const filesystem = normalizeFormatFilesystem(options.platform, options.filesystem)
    const inserted = device?.media !== null && device?.media !== undefined
    const writable = inserted && device.media.writable === true
    const expectedIdentity = formatIdentity(device)
    const confirmed = expectedIdentity !== null && options.confirmationValue === expectedIdentity
    const identityReported = expectedIdentity !== null
    const prerequisites = Object.freeze([utilityPrerequisite('media-inserted', 'utilities.prerequisite.mediaInserted.label', inserted, inserted ? 'utilities.prerequisite.mediaInserted.present' : 'utilities.prerequisite.mediaInserted.disposableRequired'), utilityPrerequisite('write-access', 'utilities.prerequisite.writeAccess.label', writable, writable ? 'utilities.prerequisite.writeAccess.met' : 'utilities.prerequisite.writeAccess.unmet'), utilityPrerequisite('exact-identity', 'utilities.prerequisite.exactIdentity.label', confirmed, confirmed ? 'utilities.prerequisite.exactIdentity.match' : identityReported ? 'utilities.prerequisite.exactIdentity.required' : 'utilities.prerequisite.exactIdentity.unavailable', identityReported ? { identity: expectedIdentity } : {})])
    const resolvedCapability = resolveUtilityCapability(device, OperationKind.FORMAT, prerequisites, options)
    const capability = resolvedCapability.state === 'available' && policy.filesystemChoices.length === 0 ? Object.freeze({ reason: 'format-host-filesystem-unavailable', state: 'host-dependency-missing' }) : resolvedCapability
    return Object.freeze({
        capability,
        confirmed,
        consequenceKey: 'utilities.format.consequence',
        defaultFilesystem: policy.defaultFilesystem,
        expectedIdentity,
        filesystem,
        filesystemChoices: policy.filesystemChoices,
        kind: OperationKind.FORMAT,
        prerequisites,
        risk: 'destructive',
        stages: FORMAT_STAGES,
        toolingKey: policy.toolingKey
    })
}
