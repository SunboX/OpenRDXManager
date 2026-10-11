// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'

import { mountApplication } from '../src/renderer/app-controller.mjs'
import { applyDesktopSettings, bindTraySelection, createLiveTranslator, loadDesktopSettings } from '../src/renderer/desktop-settings.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'
import { createRuntimeState } from '../src/renderer/service-binding.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { renderShell } from '../src/renderer/views/shell-view.mjs'
import { englishCatalog } from '../src/locales/en.mjs'

test('applies persisted desktop settings before the first real renderer view', () => {
    const state = applyDesktopSettings(createRuntimeState(), {
        autoScan: false,
        eventLogging: false,
        language: 'de',
        lastSafeView: 'utilities',
        updateChecks: false
    })

    assert.equal(state.activeArea, 'utilities')
    assert.deepEqual(state.settings, {
        autoScan: false,
        eventLogging: false,
        language: 'de',
        lastSafeView: 'utilities',
        updateChecks: false
    })
})

test('rejects unrestorable overlay names before rendering a labelled management panel', () => {
    const fixture = createFixtureState({ mode: 'one-device' })
    const state = applyDesktopSettings(fixture, {
        autoScan: true,
        eventLogging: true,
        language: 'en',
        lastSafeView: 'help',
        updateChecks: true
    })
    const dom = new JSDOM(`<main>${renderShell(state, { translator: createTranslator(englishCatalog) })}</main>`)
    const panel = dom.window.document.querySelector('[role="tabpanel"]')

    assert.equal(state.activeArea, 'status')
    assert.equal(panel.getAttribute('aria-labelledby'), 'tab-status')
    assert.ok(dom.window.document.getElementById(panel.getAttribute('aria-labelledby')))
    dom.window.close()
})

test('accepted persisted settings replace stale renderer values as one transition', () => {
    const store = createStore(createRuntimeState())
    store.dispatch({
        type: 'settings/changed',
        settings: { autoScan: false, eventLogging: false, language: 'fr', lastSafeView: 'tests', updateChecks: false }
    })

    assert.deepEqual(store.getState().settings, { autoScan: false, eventLogging: false, language: 'fr', lastSafeView: 'tests', updateChecks: false })
})

test('loads settings before renderer bootstrap and contains bridge failure', async () => {
    const state = createRuntimeState()
    const loaded = await loadDesktopSettings({ settings: { get: async () => ({ ok: true, settings: { autoScan: false, eventLogging: false, language: 'es', lastSafeView: 'encryption', updateChecks: false } }) } }, state)
    assert.equal(loaded.activeArea, 'encryption')
    assert.equal(loaded.settings.language, 'es')
    assert.equal(await loadDesktopSettings({ settings: { get: async () => ({ ok: false, reason: 'service-failure' }) } }, state), state)
})

test('live translator switches the visible catalog without recreating its callback', () => {
    const live = createLiveTranslator('de')
    const translator = live.translate
    assert.equal(translator('devices.scan'), 'Nach Geräten suchen')

    assert.equal(live.setLanguage('ja'), true)
    assert.equal(translator('devices.scan'), 'デバイスをスキャン')
    assert.equal(live.setLanguage('xx'), false)
    assert.equal(translator('devices.scan'), 'デバイスをスキャン')
})

test('selected device bridge publishes exact selection changes and clears on departure', async () => {
    const calls = []
    const fixture = createFixtureState({ mode: 'one-device' })
    const second = { ...fixture.devices[0], id: 'rdx:dock-2', serial: 'DOCK-2', media: { ...fixture.devices[0].media, id: 'media:dock-2', serial: 'MEDIA-2' } }
    const store = createStore({ ...fixture, devices: [fixture.devices[0], second], selectedDeviceId: second.id })
    const unbind = bindTraySelection(
        {
            app: {
                async setTraySelection(request) {
                    calls.push(request)
                    return { ok: true }
                }
            }
        },
        store
    )

    store.dispatch({ type: 'service/unavailable', reason: 'service-failure' })
    await new Promise((resolve) => setImmediate(resolve))
    assert.deepEqual(calls, [{ deviceId: 'rdx:dock-2' }, { deviceId: null }])
    unbind()
})

test('persists desktop settings without a renderer Auto Scan scheduler', async () => {
    const calls = []
    const languages = []
    let settings = { ...createFixtureState({ mode: 'one-device' }).settings }
    const dom = new JSDOM('<div id="app"></div>', { url: 'file:///openrdxmanager/src/index.html', pretendToBeVisual: true })
    const store = createStore(createFixtureState({ mode: 'one-device' }))
    const deviceController = {
        destroy() {},
        isAvailable: () => true,
        requestManualScan: async () => ({ ok: true }),
        startAutoScan: () => calls.push({ rendererScheduler: 'start' }),
        stopAutoScan: () => calls.push({ rendererScheduler: 'stop' })
    }
    const supportApi = {
        settings: {
            async update(request) {
                calls.push(request)
                settings = { ...settings, ...request }
                return { ok: true, settings }
            }
        }
    }
    const controller = mountApplication(dom.window.document.querySelector('#app'), { deviceController, onLanguageChanged: (language) => languages.push(language), store, supportApi })
    const document = dom.window.document
    document.querySelector('[data-setting="auto-scan"]').click()
    await new Promise((resolve) => setImmediate(resolve))
    const language = document.querySelector('[data-setting="language"]')
    language.value = 'de'
    language.dispatchEvent(new dom.window.Event('change', { bubbles: true }))
    await new Promise((resolve) => setImmediate(resolve))
    document.querySelector('[data-setting="update-checks"]').click()
    await new Promise((resolve) => setImmediate(resolve))
    document.querySelector('[data-area="utilities"]').click()
    await new Promise((resolve) => setImmediate(resolve))
    assert.deepEqual(calls, [{ autoScan: false }, { language: 'de' }, { updateChecks: false }, { lastSafeView: 'utilities' }])
    assert.deepEqual(languages, ['de'])
    assert.equal(
        calls.some((call) => Object.hasOwn(call, 'rendererScheduler')),
        false
    )
    controller.destroy()
    dom.window.close()
})
