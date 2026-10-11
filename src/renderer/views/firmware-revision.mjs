// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Formats the four decimal revision digits for display, preserving raw device
 * data elsewhere. Legacy OpenRDX 0001 is a family marker, not release 0.01.
 * @param {string} revision - Reported revision or an unavailable-field token.
 * @returns {string} Major.minor display text, or the unchanged legacy/opaque value.
 */
export function formatFirmwareRevision(revision) {
    if (!/^[0-9]{4}$/.test(revision) || revision === '0001') return revision
    return `${Number(revision.slice(0, 2))}.${revision.slice(2)}`
}
