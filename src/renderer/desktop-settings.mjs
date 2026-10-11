// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { englishCatalog } from '../locales/en.mjs'
import { catalogsByLanguage, getCatalog } from '../locales/catalogs.mjs'
import { settingsSchema } from '../shared/schemas.mjs'
import { createTranslator } from './i18n.mjs'

/** @param {object} state - Initial renderer state. @param {unknown} settings - Candidate validated desktop settings. @returns {object} State hydrated before first render. */
export function applyDesktopSettings(state, settings) {
    const parsed = settingsSchema.safeParse(settings)
    if (!parsed.success) return state
    return Object.freeze({ ...state, activeArea: parsed.data.lastSafeView, settings: Object.freeze({ ...parsed.data }) })
}

/** @param {object} api - Narrow renderer bridge. @param {object} state - Safe initial runtime state. @returns {Promise<object>} Hydrated state or unchanged fallback. */
export async function loadDesktopSettings(api, state) {
    if (typeof api?.settings?.get !== 'function') return state
    try {
        const response = await api.settings.get({})
        return response?.ok === true ? applyDesktopSettings(state, response.settings) : state
    } catch {
        return state
    }
}

/** @param {unknown} language - Initial supported language. @returns {{translate: Function, setLanguage: Function}} Stable translation callback and bounded switch. */
export function createLiveTranslator(language) {
    let currentLanguage = typeof language === 'string' && Object.hasOwn(catalogsByLanguage, language) ? language : 'en'
    let current = createTranslator(getCatalog(currentLanguage), englishCatalog)
    return Object.freeze({
        /** @param {string} key - Catalog key. @param {object} [params] - Placeholder values. @returns {string} Current localized message. */
        translate(key, params) {
            return current(key, params)
        },
        /** @param {unknown} nextLanguage - Candidate language code. @returns {boolean} Whether the catalog switched. */
        setLanguage(nextLanguage) {
            if (typeof nextLanguage !== 'string' || !Object.hasOwn(catalogsByLanguage, nextLanguage)) return false
            currentLanguage = nextLanguage
            current = createTranslator(getCatalog(currentLanguage), englishCatalog)
            return true
        }
    })
}

/** @param {object} api - Narrow preload API. @param {object} store - Renderer store. @returns {() => void} Selection bridge cleanup. */
export function bindTraySelection(api, store) {
    if (typeof api?.app?.setTraySelection !== 'function' || typeof store?.subscribe !== 'function' || typeof store?.getState !== 'function') return () => {}
    let lastDeviceId
    /** @param {object} state - Current store state. @returns {Promise<void>} Publishes a changed selection, containing bridge failures. */
    async function publish(state) {
        const deviceId = typeof state?.selectedDeviceId === 'string' ? state.selectedDeviceId : null
        if (deviceId === lastDeviceId) return
        lastDeviceId = deviceId
        try {
            await api.app.setTraySelection({ deviceId })
        } catch {
            // Tray publication is best effort; selection remains owned by the store.
        }
    }
    const unsubscribe = store.subscribe(publish)
    void publish(store.getState())
    return unsubscribe
}
