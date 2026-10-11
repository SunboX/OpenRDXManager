// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { getCatalog } from '../src/locales/catalogs.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'

const idle = { state: 'idle', revision: 0 }
const waiting = { state: 'running', revision: 2, attemptId: 'recovery:fixture', stage: 'recovery-awaiting-power-cycle', awaitingAcknowledgment: true }
const bundle = { bundleId: 'migration-1-0', serial: '001234567890', sourceVersion: '2.83', targetVersion: '1.07', recoveryNeeded: true }

/** @returns {Promise<void>} Drains renderer promises without advancing polling timers. */
async function settled() {
    await new Promise(setImmediate)
}

/** @param {object} api - Controlled recovery methods. @param {string} language - Catalog. @returns {object} An empty-device renderer and its cleanup. */
function mount(api, language = 'en') {
    const fixture = createFixtureState({ mode: 'no-device' })
    const store = createStore({ ...fixture, devices: [], selectedDeviceId: null })
    const dom = new JSDOM('<!doctype html><div id="app"></div>')
    const root = dom.window.document.querySelector('#app')
    const controller = mountApplication(root, { store, recoveryApi: api, translator: createTranslator(getCatalog(language), getCatalog('en')) })
    return {
        root,
        store,
        dom,
        close: () => {
            controller.destroy()
            dom.window.close()
        }
    }
}

/** @param {object} status - Initial native snapshot. @returns {object} A read-only fixture until an explicit button invokes a mutation. */
function apiFixture(status = idle) {
    return { list: async () => ({ ok: true, targets: [{ token: 'rom:fixture', label: 'USB port 0x00200000' }], bundles: [bundle], status }), status: async () => ({ ok: true, status }), start: async () => ({ ok: true, status: waiting }), continue: async () => ({ ok: true, status: { ...waiting, revision: 3, awaitingAcknowledgment: false } }) }
}

test('ROM recovery appears without a normal device and requires both selections plus physical association acknowledgement', async () => {
    const calls = []
    const api = apiFixture()
    api.start = async (request) => {
        calls.push(request)
        return { ok: true, status: waiting }
    }
    const ui = mount(api)
    try {
        await settled()
        assert.notEqual(ui.root.querySelector('[data-recovery-panel]'), null)
        const start = () => ui.root.querySelector('[data-recovery-action="start"]')
        assert.equal(start().disabled, true)
        for (const [field, value] of [
            ['bundle', bundle.bundleId],
            ['target', 'rom:fixture']
        ]) {
            const select = ui.root.querySelector(`[data-recovery-field="${field}"]`)
            select.value = value
            select.dispatchEvent(new ui.dom.window.Event('change', { bubbles: true }))
        }
        assert.equal(start().disabled, true)
        const acknowledge = ui.root.querySelector('[data-recovery-field="acknowledged"]')
        acknowledge.checked = true
        acknowledge.dispatchEvent(new ui.dom.window.Event('change', { bubbles: true }))
        assert.equal(start().disabled, false)
        start().click()
        await settled()
        assert.deepEqual(calls, [{ bundleId: bundle.bundleId, targetToken: 'rom:fixture', acknowledged: true }])
        assert.equal(ui.store.getState().recoveryLocked, true)
        assert.equal(ui.root.textContent.includes('rom:fixture'), false)
    } finally {
        ui.close()
    }
})

test('renderer reload restores the exact waiting gate and disables it after accepted continuation', async () => {
    const calls = []
    const api = apiFixture(waiting)
    api.continue = async (request) => {
        calls.push(request)
        return { ok: true, status: { ...waiting, revision: 3, awaitingAcknowledgment: false } }
    }
    const ui = mount(api)
    try {
        await settled()
        const button = () => ui.root.querySelector('[data-recovery-action="continue"]')
        assert.equal(ui.store.getState().recoveryLocked, true)
        assert.equal(button().disabled, false)
        assert.equal(calls.length, 0)
        button().click()
        button().click()
        await settled()
        assert.deepEqual(calls, [{ attemptId: waiting.attemptId, stage: waiting.stage, acknowledged: true }])
        assert.equal(button().disabled, true)
        assert.equal(ui.root.querySelector('[data-recovery-success]'), null)
    } finally {
        ui.close()
    }
    const reloaded = mount(apiFixture({ ...waiting, revision: 3, awaitingAcknowledgment: false }))
    try {
        await settled()
        assert.equal(reloaded.root.querySelector('[data-recovery-action="continue"]').disabled, true)
    } finally {
        reloaded.close()
    }
})

test('every locale explains missing saved recovery data and failed recovery never claims success', async () => {
    for (const language of ['en', 'de', 'es', 'fr', 'it', 'pt', 'ja', 'zh']) {
        const api = apiFixture()
        api.list = async () => ({ ok: true, targets: [{ token: 'rom:fixture', label: 'USB port 0x00200000' }], bundles: [], status: idle })
        const ui = mount(api, language)
        try {
            await settled()
            assert.ok(ui.root.textContent.includes(getCatalog(language)['recovery.noBundles']))
            assert.equal(ui.root.querySelector('[data-recovery-action="start"]').disabled, true)
        } finally {
            ui.close()
        }
        const failed = mount(apiFixture({ ...waiting, state: 'failed', awaitingAcknowledgment: false, reason: 'recovery-record-readback-mismatch' }), language)
        try {
            await settled()
            assert.ok(failed.root.textContent.includes(getCatalog(language)['recovery.failed']))
            assert.ok(failed.root.textContent.includes(getCatalog(language)['recovery.error.readback']))
            assert.ok(failed.root.textContent.includes('recovery-record-readback-mismatch'))
            assert.equal(failed.root.querySelector('[data-recovery-success]'), null)
            assert.equal(failed.root.querySelector('[data-recovery-action="continue"]'), null)
        } finally {
            failed.close()
        }
    }
})

test('zero-ROM startup preserves normal empty-device guidance and later Scan reveals a connected ROM dock', async () => {
    const api = apiFixture()
    let targets = []
    let lists = 0
    api.list = async () => {
        lists += 1
        return { ok: true, targets, bundles: [bundle], status: idle }
    }
    const ui = mount(api)
    try {
        await settled()
        assert.equal(ui.root.querySelector('[data-recovery-panel]'), null)
        assert.notEqual(ui.root.querySelector('[data-focus-fallback="primary-state"]'), null)
        assert.equal(ui.store.getState().recoveryLocked, false)
        targets = [{ token: 'rom:later', label: 'USB port 0x00300000' }]
        ui.store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
        ui.store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
        await settled()
        assert.notEqual(ui.root.querySelector('[data-recovery-panel]'), null)
        assert.equal(lists, 2)
        const select = ui.root.querySelector('[data-recovery-field="bundle"]')
        select.value = bundle.bundleId
        select.dispatchEvent(new ui.dom.window.Event('change', { bubbles: true }))
        ui.store.dispatch({ type: 'discovery/scan-started', trigger: 'manual' })
        ui.store.dispatch({ type: 'discovery/scan-completed', trigger: 'manual' })
        await settled()
        assert.equal(lists, 2, 'background scan cannot replace tokens while choosing a profile')
    } finally {
        ui.close()
    }
})
