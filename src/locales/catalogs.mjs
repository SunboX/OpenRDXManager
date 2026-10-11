// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { germanCatalog } from './de.mjs'
import { englishCatalog } from './en.mjs'
import { spanishCatalog } from './es.mjs'
import { frenchCatalog } from './fr.mjs'
import { italianCatalog } from './it.mjs'
import { japaneseCatalog } from './ja.mjs'
import { portugueseCatalog } from './pt.mjs'
import { chineseCatalog } from './zh.mjs'

/** Complete bundled locale catalogs selected only by the strict settings code. */
export const catalogsByLanguage = Object.freeze({ de: germanCatalog, en: englishCatalog, es: spanishCatalog, fr: frenchCatalog, it: italianCatalog, ja: japaneseCatalog, pt: portugueseCatalog, zh: chineseCatalog })

/** @param {unknown} language - Candidate supported language. @returns {object} Matching catalog or English fallback. */
export function getCatalog(language) {
    return typeof language === 'string' && Object.hasOwn(catalogsByLanguage, language) ? catalogsByLanguage[language] : englishCatalog
}
