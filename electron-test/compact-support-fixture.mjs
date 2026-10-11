// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createRendererIntentAdapter } from '../src/renderer/intent-adapter.mjs'
import { createStore } from '../src/renderer/store.mjs'

/**
 * Replaces the default renderer mount with a selected-device fixture whose
 * support intent is bound and observable by the real-Electron runtime check.
 * @returns {void} Completes after the compact runtime fixture is mounted.
 */
export function mountCompactSupportFixture() {
    const currentRoot = document.querySelector('#app')
    const root = currentRoot.cloneNode(false)
    const calls = []

    /**
     * Records only the validated support intent accepted by this fixture.
     * @param {object} intent - Validated renderer-safe intent payload.
     * @returns {boolean} True after recording the accepted intent.
     */
    function invoke(intent) {
        calls.push(intent)
        return true
    }

    currentRoot.replaceWith(root)
    globalThis.__openRdxCompactSupportFixture = {
        calls,
        controller: mountApplication(root, {
            store: createStore(createFixtureState({ mode: 'one-device' })),
            intentAdapter: createRendererIntentAdapter({ supportedIntents: ['open-support'], invoke })
        })
    }
}
