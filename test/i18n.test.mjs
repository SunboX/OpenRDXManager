// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { englishCatalog } from '../src/locales/en.mjs'
import { createTranslator, supportedLanguageCodes } from '../src/renderer/i18n.mjs'
import { CapabilityState, OperationKind, RiskClass } from '../src/shared/contracts.mjs'

/**
 * Verifies a sparse language catalog delegates missing copy to English and
 * interpolates only supported primitive values into a trusted message.
 * @returns {void} Throws when fallback or interpolation is incorrect.
 */
function testFallsBackToEnglishAndInterpolatesBoundedValues() {
    const t = createTranslator({}, englishCatalog)

    assert.equal(t('devices.count', { count: 2 }), '2 RDX devices')
    assert.equal(t('missing.key'), '[missing.key]')
    assert.equal(t('devices.count', { count: '<img src=x onerror=alert(1)>' }), '&lt;img src=x onerror=alert(1)&gt; RDX devices')
    assert.equal(t('devices.count', { count: { toString: () => 'unsafe' } }), '{count} RDX devices')
}

/**
 * Verifies an explicitly supplied catalog overrides English without changing
 * the fallback contract for keys it does not own.
 * @returns {void} Throws when catalogs are not resolved by own message keys.
 */
function testUsesOwnCatalogMessagesBeforeEnglishFallback() {
    const t = createTranslator({ 'devices.count': '{count} Geräte' }, englishCatalog)

    assert.equal(t('devices.count', { count: 3 }), '3 Geräte')
    assert.equal(t('status.drive'), 'Drive status')
}

/**
 * Verifies dangerous prototype paths cannot be resolved from a catalog or
 * parameter object, while the documented bundled language codes stay stable.
 * @returns {void} Throws when a prototype path is accepted or codes drift.
 */
function testRejectsPrototypePathsAndPublishesBundledLanguageCodes() {
    const t = createTranslator({ '__proto__.polluted': 'unsafe' }, englishCatalog)

    assert.equal(t('__proto__.polluted'), '[__proto__.polluted]')
    assert.equal(t('devices.constructor.name'), '[devices.constructor.name]')
    assert.deepEqual(supportedLanguageCodes, ['en', 'zh', 'de', 'fr', 'it', 'pt', 'es', 'ja'])
}

/**
 * Verifies every published operation and capability token has an English
 * catalog entry, plus the controlled renderer-only state tokens.
 * @returns {void} Throws when a new enum value can fall back to English text.
 */
function testEnglishCatalogCoversPublishedAndControlledTokens() {
    const controlledTokens = ['ready', 'present', 'no-media', 'starting', 'firmware-writing', 'diagnostic-running']
    const publishedTokens = [...Object.values(OperationKind), ...Object.values(CapabilityState), ...Object.values(RiskClass), ...controlledTokens]

    for (const token of publishedTokens) {
        assert.equal(typeof englishCatalog[tokenCatalogKey(token)], 'string', `Missing English token catalog entry for ${token}`)
    }
}

/**
 * Verifies the real supervised-service state never claims fixture provenance.
 * @returns {void} Throws when ready-state copy becomes fixture-specific.
 */
function testReadyServiceCopyIsRuntimeTruthful() {
    assert.equal(englishCatalog['service.ready'], 'Service ready')
}

/**
 * Derives the documented camel-case catalog key for a published machine token
 * without relying on the renderer formatting helper under test.
 * @param {string} token - Published hyphen-separated machine token.
 * @returns {string} Required English catalog key.
 */
function tokenCatalogKey(token) {
    const parts = token.split('-')
    let suffix = parts[0]
    for (let index = 1; index < parts.length; index += 1) {
        const part = parts[index]
        suffix += `${part.charAt(0).toUpperCase()}${part.slice(1)}`
    }
    return `token.${suffix}`
}

test('falls back to English and interpolates bounded values', testFallsBackToEnglishAndInterpolatesBoundedValues)
test('uses own catalog messages before English fallback', testUsesOwnCatalogMessagesBeforeEnglishFallback)
test('rejects prototype paths and publishes bundled language codes', testRejectsPrototypePathsAndPublishesBundledLanguageCodes)
test('English catalog covers published and controlled presentation tokens', testEnglishCatalogCoversPublishedAndControlledTokens)
test('ready service copy does not claim fixture provenance', testReadyServiceCopyIsRuntimeTruthful)
