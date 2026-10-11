// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Closed mapping shared by firmware admission, utility results, and terminal recovery. */
export const firmwareFailureReasonKeys = Object.freeze({
    'firmware-reconnect-failed': 'reason.firmwareReconnectFailed',
    'firmware-transfer-incomplete': 'reason.firmwareTransferIncomplete',
    'firmware-device-rejected': 'reason.firmwareDeviceRejected',
    'firmware-command-unsupported': 'reason.firmwareCommandUnsupported',
    'firmware-command-invalid': 'reason.firmwareCommandInvalid',
    'firmware-power-cycle-required': 'reason.firmwarePowerCycleRequired',
    'firmware-receiver-readiness-unknown': 'reason.firmwareReceiverReadinessUnknown',
    'firmware-device-not-ready': 'reason.firmwareDeviceNotReady',
    'firmware-hardware-failure': 'reason.firmwareHardwareFailure',
    'firmware-write-protected': 'reason.firmwareWriteProtected',
    'firmware-unit-attention': 'reason.firmwareUnitAttention',
    'firmware-transport-unavailable': 'reason.firmwareTransportUnavailable',
    'firmware-transport-invalid': 'reason.firmwareTransportInvalid',
    'firmware-signature-error': 'reason.firmwareSignatureError',
    'firmware-manufacturing-restore-unsupported': 'reason.firmwareManufacturingRestoreUnsupported',
    'firmware-manufacturing-unreadable': 'reason.firmwareManufacturingUnreadable',
    'firmware-manufacturing-invalid': 'reason.firmwareManufacturingInvalid',
    'firmware-manufacturing-changed': 'reason.firmwareManufacturingChanged',
    'firmware-manufacturing-backup-unavailable': 'reason.firmwareManufacturingBackupUnavailable',
    'firmware-migration-capture-invalid': 'reason.firmwareMigrationCaptureInvalid',
    'firmware-migration-recovery-unavailable': 'reason.firmwareMigrationRecoveryUnavailable',
    'firmware-migration-staging-failed': 'reason.firmwareMigrationStagingFailed',
    'firmware-migration-bootloader-unavailable': 'reason.firmwareMigrationBootloaderUnavailable',
    'firmware-migration-programming-failed': 'reason.firmwareMigrationProgrammingFailed',
    'firmware-migration-readback-mismatch': 'reason.firmwareMigrationReadbackMismatch',
    'firmware-openrdx-installation-unsupported': 'reason.firmwareOpenRdxInstallationUnsupported',
    'firmware-openrdx-manifest-missing': 'reason.firmwareOpenRdxManifestMissing',
    'firmware-openrdx-manifest-malformed': 'reason.firmwareOpenRdxManifestMalformed',
    'firmware-openrdx-manifest-filename-mismatch': 'reason.firmwareOpenRdxManifestFilenameMismatch',
    'firmware-openrdx-manifest-hash-mismatch': 'reason.firmwareOpenRdxManifestHashMismatch',
    'firmware-openrdx-manifest-invalid': 'reason.firmwareOpenRdxManifestInvalid'
})

/**
 * Resolves a known firmware cause independently from any no-write assurance.
 * @param {object} operation - Structured terminal operation.
 * @returns {string|undefined} Fixed cause key, never a service-supplied message.
 */
export function getFirmwareFailureReasonKey(operation) {
    const code = operation?.error?.code
    if (code === 'firmware-power-cycle-required' && operation?.error?.stage !== 'firmware-validating') return undefined
    return operation?.kind === 'firmware-update' && typeof code === 'string' && Object.hasOwn(firmwareFailureReasonKeys, code) ? firmwareFailureReasonKeys[code] : undefined
}

/**
 * Resolves failures whose exact cause and stage prove rejection before transfer.
 * Unknown failures must retain the existing stage-specific recovery guidance.
 * @param {object} operation - Terminal operation with a structured primary error.
 * @returns {string|undefined} Allowlisted localized cause key for a known pre-transfer rejection.
 */
export function getFirmwarePreflightFailureReasonKey(operation) {
    const { code, stage } = operation?.error ?? {}
    const reasonKey = getFirmwareFailureReasonKey(operation)
    if (reasonKey === undefined) return undefined
    if (code === 'firmware-reconnect-failed') return undefined
    if (['firmware-power-cycle-required', 'firmware-receiver-readiness-unknown'].includes(code)) return stage === 'firmware-validating' ? reasonKey : undefined
    if (code.startsWith('firmware-manufacturing-')) return stage === 'firmware-validating' ? reasonKey : undefined
    if (code === 'firmware-migration-capture-invalid') return stage === 'firmware-capturing' ? reasonKey : undefined
    if (code === 'firmware-migration-recovery-unavailable') return ['firmware-validating', 'firmware-capturing'].includes(stage) ? reasonKey : undefined
    if (code.startsWith('firmware-migration-')) return undefined
    const requiredStage = code === 'firmware-openrdx-installation-unsupported' ? 'firmware-validating' : 'queued'
    return stage === requiredStage ? firmwareFailureReasonKeys[code] : undefined
}
