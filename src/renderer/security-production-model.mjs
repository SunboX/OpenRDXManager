// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { SECURITY_MUTATOR_EVIDENCE } from './security-evidence-registry.mjs'
import { englishCatalog } from '../locales/en.mjs'
import { createTranslator } from './i18n.mjs'

const defaultTranslator = createTranslator(englishCatalog, englishCatalog)

/**
 * Projects the currently reported production snapshot into a fail-closed
 * Encryption model. Missing security status remains unknown instead of being
 * treated as disabled, unprotected, or an empty credential table.
 * @param {object} state - Complete renderer store snapshot.
 * @param {object} device - Selected strict renderer-safe device.
 * @param {object|null} [workflow=null] - Controller-owned local guided state.
 * @param {(key: string, params?: object) => string} [translator=defaultTranslator] - Active presentation translator.
 * @returns {object} Path-free security presentation model.
 */
export function createProductionSecurityModel(state, device, workflow = null, translator = defaultTranslator) {
    const session = state.authenticationSessions?.[device.id]
    const access = session?.deviceRevision === device.revision ? 'enabled' : 'unknown'
    const encrypted = device.media?.details?.encrypted
    const mode = encrypted?.availability === 'reported' && encrypted.value === true ? 'aes' : 'unknown'
    const mediaIdentity = typeof device.media?.serial === 'string' && device.media.serial.length > 0 ? device.media.serial : device.media?.id
    return Object.freeze({
        access,
        automaticAuthentication: Object.freeze({}),
        credentials: undefined,
        device: Object.freeze({
            drive: device.drive,
            id: device.id,
            label: `${device.product} · ${mediaIdentity ?? translator('encryption.noCartridge')}`,
            media: device.media,
            revision: device.revision
        }),
        evidence: SECURITY_MUTATOR_EVIDENCE,
        mode,
        resetWithoutPassword: undefined,
        workflow
    })
}
