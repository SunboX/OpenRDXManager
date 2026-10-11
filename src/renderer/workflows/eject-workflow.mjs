// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { OperationKind } from '../../shared/contracts.mjs'
import { resolveUtilityCapability, utilityPrerequisite, utilityStages } from './utility-workflow-helpers.mjs'

const SAFE_EJECT_STAGES = utilityStages([
    ['host-unmounting', 'utilities.stage.hostUnmounting'],
    ['host-ejecting', 'utilities.stage.hostEjecting'],
    ['eject-readback', 'utilities.stage.ejectReadback']
])
const FORCE_EJECT_STAGES = utilityStages([
    ['host-ejecting', 'utilities.stage.hostForceEjecting'],
    ['eject-readback', 'utilities.stage.ejectReadback']
])

/**
 * Builds safe or forced eject presentation without conflating their host policies.
 * @param {object} device - Selected renderer-safe RDX device.
 * @param {'safe'|'force'} policy - Requested host eject policy.
 * @param {{riskAccepted?: boolean, locked?: boolean, operationIntentAvailable?: boolean}} [options={}] - Force acknowledgement and shell gates.
 * @returns {object} Frozen eject workflow.
 * @throws {RangeError} When policy is unknown.
 */
export function createEjectWorkflow(device, policy, options = {}) {
    if (!['safe', 'force'].includes(policy)) throw new RangeError('Unknown eject policy')
    const kind = policy === 'safe' ? OperationKind.EJECT_SAFE : OperationKind.EJECT_FORCE
    const mediaPresent = device?.media !== null && device?.media !== undefined
    const riskAccepted = policy === 'safe' || options.riskAccepted === true
    const prerequisites = Object.freeze([utilityPrerequisite('media-inserted', 'utilities.prerequisite.mediaInserted.label', mediaPresent, mediaPresent ? 'utilities.prerequisite.mediaInserted.present' : 'utilities.prerequisite.mediaInserted.noEjectableMedia'), utilityPrerequisite('force-risk', 'utilities.prerequisite.forceRisk.label', riskAccepted, policy === 'safe' ? 'utilities.prerequisite.forceRisk.safe' : riskAccepted ? 'utilities.prerequisite.forceRisk.acknowledged' : 'utilities.prerequisite.forceRisk.required')])
    return Object.freeze({
        capability: resolveUtilityCapability(device, kind, prerequisites, options),
        guidanceKey: policy === 'safe' ? 'utilities.eject.safeGuidance' : 'utilities.eject.forceGuidance',
        kind,
        policy,
        prerequisites,
        risk: policy === 'safe' ? 'routine' : 'critical',
        stages: policy === 'safe' ? SAFE_EJECT_STAGES : FORCE_EJECT_STAGES
    })
}
