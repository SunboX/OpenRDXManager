// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Escapes renderer-supplied text before interpolation into trusted view markup.
 * @param {unknown} value - Value to present as inert text.
 * @returns {string} HTML-safe text representation.
 */
export function escapeHtml(value) {
    return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;')
}

/**
 * Converts a controlled machine token into a readable English label.
 * @param {unknown} value - Stable renderer-safe state token.
 * @returns {string} Human-readable token with title casing.
 */
export function formatToken(value) {
    const words = String(value ?? '')
        .split('-')
        .filter(Boolean)
    const formatted = []

    for (const word of words) {
        formatted.push(`${word.charAt(0).toUpperCase()}${word.slice(1)}`)
    }

    return formatted.join(' ')
}

/**
 * Converts a controlled machine token into sentence case while preserving the
 * familiar hyphenated self-test label.
 * @param {unknown} value - Stable renderer-safe state token.
 * @returns {string} Human-readable sentence-case token.
 */
export function formatSentenceToken(value) {
    const token = String(value ?? '')
    if (token === 'self-test') {
        return 'Self-test'
    }

    const words = token.replaceAll('-', ' ')
    return `${words.charAt(0).toUpperCase()}${words.slice(1)}`
}

/**
 * Localizes a controlled presentation token while preserving an unknown raw
 * token's readable fallback for future service states.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @param {unknown} value - Stable renderer-safe state or operation token.
 * @returns {string} Localized known token or readable unknown fallback.
 */
export function formatLocalizedToken(t, value) {
    const token = String(value ?? '')
    const key = `token.${token.replaceAll(/-([a-z])/g, toCamelCaseTokenSegment)}`
    const translated = t(key)
    return translated === `[${key}]` ? formatToken(token) : translated
}

/**
 * Converts one hyphenated token segment into the camel-case catalog suffix.
 * @param {string} match - Matched hyphen-and-letter source segment.
 * @param {string} letter - Captured lowercase letter after the hyphen.
 * @returns {string} Uppercase letter without its source hyphen.
 */
function toCamelCaseTokenSegment(match, letter) {
    return letter.toUpperCase()
}

/**
 * Localizes a controlled operation token in sentence case.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @param {unknown} value - Stable renderer-safe operation token.
 * @returns {string} Localized operation label.
 */
export function formatLocalizedSentenceToken(t, value) {
    return formatLocalizedToken(t, value)
}

/**
 * Restricts a controlled renderer token to characters safe for DOM identifiers.
 * @param {unknown} value - Candidate token from renderer state.
 * @returns {string} Identifier-safe token.
 */
export function toDomToken(value) {
    return String(value ?? 'unknown').replaceAll(/[^a-z0-9_-]/gi, '-')
}
