// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

const REASONS = Object.freeze({
    'recovery-selected-rom-unavailable': 'target',
    'recovery-selected-target-unavailable': 'target',
    'recovery-original-port-rom-unavailable': 'target',
    'recovery-original-port-target-unavailable': 'target',
    'recovery-artifacts-unavailable': 'artifacts',
    'migration-private-recovery-unavailable': 'artifacts',
    'recovery-record-readback-mismatch': 'readback',
    'recovery-privilege-required': 'privilege',
    'privilege-required': 'privilege',
    'recovery-platform-unsupported': 'platform',
    'recovery-selection-stale': 'selection',
    'recovery-target-token-invalid': 'selection',
    'recovery-invalid-arguments': 'selection',
    'recovery-hardware-owner-unavailable': 'busy',
    'operation-in-progress': 'busy',
    'recovery-outcome-unknown': 'unknown',
    'operation-outcome-unknown': 'unknown',
    'recovery-rom-operation-unknown': 'unknown',
    'recovery-final-update-unknown': 'unknown',
    'recovery-observer-unavailable': 'unknown',
    'recovery-operator-acknowledgment-required': 'acknowledgment'
})

/** @param {unknown} reason - Untrusted bounded failure code. @returns {string} App-owned localized explanation key. */
export function recoveryReasonKey(reason) {
    return Object.hasOwn(REASONS, reason) ? `recovery.error.${REASONS[reason]}` : 'recovery.unavailable'
}
