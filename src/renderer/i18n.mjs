// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

const PROTOTYPE_PATH_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype'])

/** The language codes documented by the bundled RDX Manager resources. */
export const supportedLanguageCodes = Object.freeze(['en', 'zh', 'de', 'fr', 'it', 'pt', 'es', 'ja'])

/**
 * Escapes a catalog message or supported interpolation parameter for insertion
 * into trusted renderer markup.
 * @param {string} value - Catalog or parameter text to render inertly.
 * @returns {string} HTML-safe text.
 */
function escapeMessageHtml(value) {
    return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#039;')
}

/**
 * Rejects property paths that could observe or mutate JavaScript prototypes.
 * @param {string} key - Candidate dot-separated catalog key.
 * @returns {boolean} True when every path segment is safe for own-key lookup.
 */
function isSafeMessageKey(key) {
    if (key.length === 0) {
        return false
    }
    for (const segment of key.split('.')) {
        if (PROTOTYPE_PATH_SEGMENTS.has(segment)) {
            return false
        }
    }
    return true
}

/**
 * Reads one string message through an own-property lookup only.
 * @param {object} catalog - Candidate flat bundled message catalog.
 * @param {string} key - Safe catalog message key.
 * @returns {string|null} Message string when present, otherwise null.
 */
function getOwnMessage(catalog, key) {
    if (catalog === null || typeof catalog !== 'object' || !Object.hasOwn(catalog, key) || typeof catalog[key] !== 'string') {
        return null
    }
    return catalog[key]
}

/**
 * Returns a safe primitive interpolation representation without coercing
 * objects, functions, booleans, symbols, or non-finite numbers.
 * @param {object} params - Optional interpolation parameter record.
 * @param {string} name - Placeholder name from the catalog message.
 * @returns {string|null} HTML-safe parameter text, or null when unsupported.
 */
function getBoundedParameter(params, name) {
    if (params === null || typeof params !== 'object' || !Object.hasOwn(params, name)) {
        return null
    }
    const value = params[name]
    if (typeof value === 'string') {
        return escapeMessageHtml(value)
    }
    if (typeof value === 'number' && Number.isFinite(value)) {
        return escapeMessageHtml(String(value))
    }
    return null
}

/**
 * Replaces named placeholders in trusted bundled catalog text with bounded
 * HTML-safe primitive parameters. Catalog strings are inserted once by views;
 * escaping them here would double-escape composed translated fragments.
 * Unsupported parameter values leave their placeholder visible rather than
 * invoking user-controlled coercion behavior.
 * @param {string} message - Trusted local catalog message.
 * @param {object} params - Optional interpolation parameter record.
 * @returns {string} HTML-safe rendered message.
 */
function interpolateMessage(message, params) {
    return message.replaceAll(/\{([A-Za-z][A-Za-z0-9_]*)\}/g, interpolatePlaceholder.bind(null, params))
}

/**
 * Resolves one catalog placeholder through the bounded interpolation policy.
 * @param {object} params - Optional interpolation parameter record.
 * @param {string} placeholder - Complete source placeholder text.
 * @param {string} name - Captured placeholder name.
 * @returns {string} HTML-safe bounded value or its visible placeholder.
 */
function interpolatePlaceholder(params, placeholder, name) {
    return getBoundedParameter(params, name) ?? placeholder
}

/**
 * Creates a deterministic translator for one bundled catalog with an English
 * fallback. Catalogs are flat own-key records; this prevents prototype-path
 * traversal and keeps each future locale independently loadable.
 * @param {object} catalog - Selected bundled language catalog.
 * @param {object} fallbackCatalog - English bundled fallback catalog.
 * @returns {(key: string, params?: object) => string} Trusted catalog message with HTML-safe interpolated values.
 */
export function createTranslator(catalog, fallbackCatalog) {
    /**
     * Resolves one user-facing message and safely interpolates bounded values.
     * @param {string} key - Flat dot-separated bundled message key.
     * @param {object} [params={}] - Named primitive interpolation parameters.
     * @returns {string} Trusted translated message or visible missing key.
     */
    function t(key, params = {}) {
        if (typeof key !== 'string' || !isSafeMessageKey(key)) {
            return `[${String(key)}]`
        }
        const message = getOwnMessage(catalog, key) ?? getOwnMessage(fallbackCatalog, key)
        return message === null ? `[${key}]` : interpolateMessage(message, params)
    }

    return Object.freeze(t)
}
