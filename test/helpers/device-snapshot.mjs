// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createDeviceSnapshot } from '../../src/shared/contracts.mjs'

/**
 * Expands a concise legacy test fixture into the complete strict production
 * snapshot shape. Production wire parsing never calls this helper.
 * @param {object} input - Concise trusted fixture input.
 * @returns {object} Complete immutable device snapshot.
 */
export function completeDeviceSnapshot(input) {
    const { mediaState: _derivedMediaState, ...fixtureInput } = input
    return createDeviceSnapshot(fixtureInput)
}
