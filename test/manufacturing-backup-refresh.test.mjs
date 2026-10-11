// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { JSDOM } from 'jsdom'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createStore } from '../src/renderer/store.mjs'

const response = { ok: true, backups: [], backupSupported: true, restoreSupported: false }

/** @param {object} api - Controlled factory-record methods. @returns {object} Mounted real renderer without hardware. */
function mount(api) {
    const fixture = createFixtureState({ mode: 'one-device' })
    const device = { ...fixture.devices[0], media: null, mediaState: 'no-media' }
    const store = createStore({ ...fixture, devices: [device], activeArea: 'utilities', discovery: { ...fixture.discovery, epoch: 1, listRevision: 1 } })
    const dom = new JSDOM('<!doctype html><div id="app"></div>')
    const controller = mountApplication(dom.window.document.querySelector('#app'), { store, manufacturingApi: { restore: async () => ({ ok: false, reason: 'manufacturing-restore-unsupported' }), ...api } })
    return {
        device,
        store,
        document: dom.window.document,
        close() {
            controller.destroy()
            dom.window.close()
        }
    }
}

/** @param {object} ui - Mounted real renderer. @returns {HTMLButtonElement} Current reconciled action. */
function backup(ui) {
    return ui.document.querySelector('[data-manufacturing-action="backup"]')
}

test('backup stays stable through scans and queues exactly one request on the freshly validated revision', async () => {
    const inventory = Promise.withResolvers()
    const calls = []
    let reads = 0
    const ui = mount({
        list: async () => (++reads === 2 ? inventory.promise : response),
        backup: async (request) => {
            calls.push(request)
            return response
        }
    })
    try {
        await delay(0)
        const original = backup(ui)
        assert.equal(original.disabled, false)
        ui.store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
        assert.equal(backup(ui), original)
        assert.equal(original.disabled, false)
        const fresh = { ...ui.device, revision: ui.device.revision + 1 }
        ui.store.dispatch({ type: 'device/list-replaced', devices: [fresh], epoch: 1, listRevision: 2 })
        assert.equal(backup(ui).disabled, false)
        ui.store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
        assert.equal(reads, 2)
        assert.equal(backup(ui).disabled, false)
        backup(ui).click()
        backup(ui).dispatchEvent(new ui.document.defaultView.MouseEvent('click', { bubbles: true }))
        assert.equal(backup(ui).disabled, true)
        assert.equal(ui.store.getState().manufacturingLocked, true)
        assert.deepEqual(calls, [])
        inventory.resolve(response)
        await delay(0)
        assert.deepEqual(calls, [{ deviceId: fresh.id, deviceRevision: fresh.revision }])
        assert.equal(ui.store.getState().manufacturingLocked, false)
        const success = ui.document.querySelector('[data-manufacturing-success]')?.textContent
        assert.ok(success)
        ui.store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
        ui.store.dispatch({ type: 'device/list-replaced', devices: [{ ...fresh, revision: fresh.revision + 1 }], epoch: 1, listRevision: 3 })
        assert.equal(backup(ui).disabled, false)
        assert.equal(ui.document.querySelector('[data-manufacturing-success]')?.textContent, success)
        ui.store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
        await delay(0)
        assert.equal(calls.length, 1)
        assert.equal(ui.document.querySelector('[data-manufacturing-success]')?.textContent, success)
    } finally {
        inventory.resolve(response)
        ui.close()
    }
})

test('backup clicked during discovery waits for scan completion before dispatch', async () => {
    const calls = []
    const ui = mount({
        list: async () => response,
        backup: async (request) => {
            calls.push(request)
            return response
        }
    })
    try {
        await delay(0)
        ui.store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
        backup(ui).click()
        assert.equal(calls.length, 0)
        assert.equal(ui.store.getState().manufacturingLocked, true)
        ui.store.dispatch({ type: 'device/list-replaced', devices: [{ ...ui.device, revision: ui.device.revision + 1 }], epoch: 1, listRevision: 2 })
        ui.store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
        await delay(0)
        assert.equal(calls.length, 1)
        assert.equal(calls[0].deviceRevision, ui.device.revision + 1)
    } finally {
        ui.close()
    }
})

test('queued backups cannot survive changed identity, firmware, media, service epoch or revoked support', async () => {
    for (const change of ['removed', 'serial', 'firmware', 'media', 'epoch', 'service', 'unsupported']) {
        let reads = 0
        const calls = []
        const ui = mount({
            list: async () => ({ ...response, backupSupported: !(++reads > 1 && change === 'unsupported') }),
            backup: async (request) => {
                calls.push(request)
                return response
            }
        })
        try {
            await delay(0)
            ui.store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
            backup(ui).click()
            let device = { ...ui.device, revision: ui.device.revision + 1 }
            if (change === 'serial') {
                device.serial = '1234567890'
                device.drive = { ...device.drive, details: { ...device.drive.details, serialNumber: { availability: 'reported', value: device.serial } } }
            }
            if (change === 'firmware') device.drive = { ...device.drive, firmwareRevision: '0112', details: { ...device.drive.details, firmwareRevision: { availability: 'reported', value: '0112' } } }
            if (change === 'media') {
                device.mediaState = 'present'
                device.media = createFixtureState({ mode: 'one-device' }).devices[0].media
            }
            if (change === 'epoch') ui.store.dispatch({ type: 'service/ready', epoch: 2, listRevision: 0, mode: 'native', privileged: true, hardwareReady: true, hardwareVerified: true, platformCapability: { state: 'available' } })
            ui.store.dispatch({ type: 'device/list-replaced', devices: change === 'removed' ? [] : [device], epoch: change === 'epoch' ? 2 : 1, listRevision: 2 })
            if (change === 'service') ui.store.dispatch({ type: 'service/unavailable', reason: 'service-exited' })
            ui.store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
            await delay(0)
            assert.equal(calls.length, 0, change)
            assert.equal(ui.store.getState().manufacturingLocked, false, change)
            assert.equal(ui.document.querySelector('[data-manufacturing-success]'), null, change)
        } finally {
            ui.close()
        }
    }
})
