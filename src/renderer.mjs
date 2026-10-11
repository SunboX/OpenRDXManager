// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createDeviceController, mountApplication } from './renderer/app-controller.mjs'
import { bindTraySelection, createLiveTranslator, loadDesktopSettings } from './renderer/desktop-settings.mjs'
import { createFixtureState } from './renderer/fixture-state.mjs'
import { createOpenRdxIntentAdapter } from './renderer/intent-adapter.mjs'
import { createUtilityOperationController } from './renderer/workflows/utility-operation-controller.mjs'
import { bindOpenRdxStore, createRuntimeState } from './renderer/service-binding.mjs'
import { createStore } from './renderer/store.mjs'
import { mountMcpSettings } from './renderer/mcp-settings.mjs'
const root = document.querySelector('#app')
const userAgent = globalThis.navigator?.userAgent ?? ''
const platform = /Windows/i.test(userAgent) ? 'win32' : /Linux/i.test(userAgent) ? 'linux' : /Macintosh|Mac OS/i.test(userAgent) ? 'darwin' : 'unknown'

/** @returns {Promise<void>} Hydrates main-owned settings before mounting the localized renderer. */
async function bootstrapRenderer() {
    const initialState = globalThis.openRdx === undefined ? createFixtureState({ mode: 'service-unavailable' }) : await loadDesktopSettings(globalThis.openRdx, createRuntimeState())
    const store = createStore(initialState)
    const liveTranslator = createLiveTranslator(initialState.settings.language)
    const intentAdapter = createOpenRdxIntentAdapter(globalThis.openRdx)
    const utilityController = createUtilityOperationController(globalThis.openRdx)
    const deviceController = typeof globalThis.openRdx?.devices?.scan === 'function' ? createDeviceController({ service: globalThis.openRdx.devices, store }) : undefined
    bindOpenRdxStore(globalThis.openRdx, store)
    bindTraySelection(globalThis.openRdx, store)
    const mcpSettings = mountMcpSettings({ document, api: globalThis.openRdx?.mcp, translator: liveTranslator.translate })
    /** @param {string} language - Accepted desktop language. @returns {boolean} Whether the live catalog changed. */
    function changeLanguage(language) {
        const changed = liveTranslator.setLanguage(language)
        mcpSettings.refreshLanguage()
        return changed
    }
    mountApplication(root, { store, translator: liveTranslator.translate, onLanguageChanged: changeLanguage, intentAdapter, deviceController, platform, supportApi: globalThis.openRdx, utilityController })
}

try {
    await bootstrapRenderer()
} catch {
    const fallback = createFixtureState({ mode: 'service-unavailable' })
    const translator = createLiveTranslator('en')
    mountApplication(root, { store: createStore(fallback), translator: translator.translate, platform })
    mountMcpSettings({ document, api: globalThis.openRdx?.mcp, translator: translator.translate })
}
