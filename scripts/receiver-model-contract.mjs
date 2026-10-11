// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Copies the endpoint counter declarations from the production structure.
 * The replay models values, not target layout; signedness must still be exact.
 * @param {string} source - Complete production usb_hal.h text.
 * @returns {string} Validated C declarations, without modifying the source.
 * @throws {Error} If a structure, field, or its reviewed type changes.
 */
export function endpointCounterDeclarations(source) {
    const structures = [...source.matchAll(/typedef\s+struct\s+_EP_INFO_T\s*\{([^}]+)\}\s*EP_INFO_T\s*;/gu)]
    if (structures.length !== 1) throw new Error('Expected one production EP_INFO_T')
    const body = structures[0][1].replace(/\/\*[\s\S]*?\*\//gu, '')
    return [
        ['dBytesRemaining', 'INT32_T'],
        ['dByteCount', 'UINT32_T'],
        ['dXferLength', 'UINT32_T']
    ]
        .map(([field, expectedType]) => {
            const declarations = [...body.matchAll(new RegExp(`\\b(\\w+)\\s+${field}\\s*;`, 'gu'))]
            if (declarations.length !== 1 || declarations[0][1] !== expectedType) {
                throw new Error(`Unreviewed endpoint counter: ${field}`)
            }
            return declarations[0][0]
        })
        .join('\n    ')
}
