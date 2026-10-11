// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Closed first-install phase labels and operator instructions. */
export const firmwareInstallationStageKeys = Object.freeze({
    'firmware-capturing': 'utilities.stage.firmwareCapturing',
    'firmware-compatibility-setup': 'utilities.stage.firmwareCompatibilitySetup',
    'firmware-staging': 'utilities.stage.firmwareStaging',
    'firmware-awaiting-bootloader': 'utilities.stage.firmwareAwaitingBootloader',
    'firmware-programming-bootstrap': 'utilities.stage.firmwareProgrammingBootstrap',
    'firmware-awaiting-bootstrap': 'utilities.stage.firmwareAwaitingBootstrap',
    'firmware-restoring-identity': 'utilities.stage.firmwareRestoringIdentity'
})

const GUIDANCE_KEYS = Object.freeze({
    'firmware-capturing': 'utilities.firmware.installation.capturing',
    'firmware-compatibility-setup': 'utilities.firmware.installation.compatibilitySetup',
    'firmware-staging': 'utilities.firmware.installation.staging',
    'firmware-awaiting-bootloader': 'utilities.firmware.installation.awaitingBootloader',
    'firmware-programming-bootstrap': 'utilities.firmware.installation.programmingBootstrap',
    'firmware-awaiting-bootstrap': 'utilities.firmware.installation.awaitingBootstrap',
    'firmware-restoring-identity': 'utilities.firmware.installation.restoringIdentity'
})

/**
 * Returns bundled guidance only for an active firmware installation phase.
 * Native messages cannot introduce arbitrary copy or premature power-cycle prompts.
 * @param {object|null} operation - Current renderer-safe operation.
 * @returns {string|undefined} Fixed localized guidance key for this exact phase.
 */
export function getFirmwareInstallationGuidanceKey(operation) {
    return operation?.kind === 'firmware-update' && typeof operation.stage === 'string' && Object.hasOwn(GUIDANCE_KEYS, operation.stage) ? GUIDANCE_KEYS[operation.stage] : undefined
}
