// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Checks one lifecycle timeout against the fixed safety bound.
 * @param {unknown} timeout - Candidate timeout milliseconds.
 * @returns {boolean} True for an integer from 1 ms through 60 seconds.
 */
export function isBoundedTimeout(timeout) {
    return Number.isInteger(timeout) && timeout >= 1 && timeout <= 60_000
}

/**
 * Checks one restart delay against the fixed safety bound.
 * @param {unknown} delay - Candidate delay milliseconds.
 * @returns {boolean} True for an integer from zero through 60 seconds.
 */
export function isBoundedRestartDelay(delay) {
    return Number.isInteger(delay) && delay >= 0 && delay <= 60_000
}
/** Methods whose lost replies cannot prove whether the service changed state. */
export const AMBIGUOUS_METHODS = new Set(['devices-scan', 'operation-start', 'operation-cancel', 'operation-continue', 'recovery-start', 'recovery-continue', 'manufacturing-backup', 'manufacturing-restore'])
/** Closed operation lifecycle outcomes. */
export const TERMINAL_STATES = new Set(['succeeded', 'failed', 'cancelled'])
// macOS discovery can spend two bounded three-second windows waiting for the
// USB storage service and its mounted media to rematch after an exclusive probe.
export const SCAN_REQUEST_TIMEOUT_MS = 15_000
/** Maximum graceful shutdown acknowledgment wait. */
export const SHUTDOWN_REQUEST_TIMEOUT_MS = 500
