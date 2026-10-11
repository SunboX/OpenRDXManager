// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createDashboardDom } from './helpers/renderer-dom.mjs'
import { getCatalog } from '../src/locales/catalogs.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'
import { createDeviceController } from '../src/renderer/device-controller.mjs'
import { RecoveryController } from '../src/renderer/recovery-controller.mjs'

const record = Object.freeze({ backupId: 'record-abcdef-12345', deviceId: 'rdx:7810544062', serial: '7810544062', createdAt: 1789128000000, state: 'valid' })

/** @returns {Promise<void>} Lets completed preload promises update the mounted application. */
async function settled() {
    await new Promise(setImmediate)
}

/** @param {object} overrides - Selected fake API methods. @param {object} stateOverrides - Test state changes. @returns {object} Real mounted application using an isolated, non-hardware manufacturing boundary. */
function mount(overrides = {}, stateOverrides = {}, language = 'en') {
    const base = createFixtureState({ mode: 'one-device' })
    const device = { ...base.devices[0], media: null, mediaState: 'no-media' }
    const response = { ok: true, backups: [record], backupSupported: true, restoreSupported: true }
    const api = { list: async () => response, backup: async () => response, restore: async () => response, ...overrides }
    const ui = createDashboardDom({ ...base, devices: [device], activeArea: 'utilities', settings: { ...base.settings, language, updateChecks: false }, ...(typeof stateOverrides === 'function' ? stateOverrides(device) : stateOverrides) }, { manufacturingApi: api, translator: createTranslator(getCatalog(language), getCatalog('en')) })
    return {
        ...ui,
        device,
        close: () => {
            ui.controller.destroy()
            ui.dom.window.close()
        }
    }
}

/** @param {object} ui - Mounted application. @param {string} field - Closed manufacturing field. @param {string|boolean} value - Operator input. @returns {void} Dispatches an actual form interaction. */
function change(ui, field, value) {
    const control = ui.root.querySelector(`[data-manufacturing-field="${field}"]`)
    assert.ok(control, `${field} control exists`)
    if (typeof value === 'boolean') control.checked = value
    else control.value = value
    control.dispatchEvent(new ui.dom.window.Event(field === 'confirmationSerial' ? 'input' : 'change', { bubbles: true }))
}

/** @param {object} ui - Mounted application. @param {string} action - Closed action. @returns {HTMLButtonElement} Current button after reconciliation. */
function button(ui, action) {
    const control = ui.root.querySelector(`[data-manufacturing-action="${action}"]`)
    assert.ok(control, `${action} control exists`)
    return control
}

test('manufacturing utilities back up the selected dock and require exact explicit restore confirmation', async () => {
    const backups = []
    const restores = []
    const ui = mount({
        backup: async (request) => {
            backups.push(request)
            return { ok: true, backups: [record], backupSupported: true, restoreSupported: true }
        },
        restore: async (request) => {
            restores.push(request)
            return { ok: true, backups: [record], backupSupported: true, restoreSupported: true }
        }
    })
    try {
        await settled()
        assert.ok(ui.root.querySelector('[data-manufacturing-panel]'))
        assert.equal(button(ui, 'restore').disabled, true)
        assert.equal(ui.root.querySelector('[data-manufacturing-field="backup"]').value, '')
        button(ui, 'backup').click()
        await settled()
        assert.deepEqual(backups, [{ deviceId: ui.device.id, deviceRevision: ui.device.revision }])
        assert.equal(ui.root.querySelector('[data-manufacturing-field="backup"]').value, '')
        change(ui, 'backup', record.backupId)
        change(ui, 'acknowledged', true)
        assert.equal(button(ui, 'restore').disabled, true)
        change(ui, 'confirmationSerial', '0000000000')
        assert.equal(button(ui, 'restore').disabled, true)
        change(ui, 'confirmationSerial', record.serial)
        assert.equal(button(ui, 'restore').disabled, false)
        button(ui, 'restore').click()
        await settled()
        assert.deepEqual(restores, [{ deviceId: ui.device.id, deviceRevision: ui.device.revision, backupId: record.backupId, confirmationSerial: record.serial, acknowledged: true }])
        assert.match(ui.root.querySelector('[data-manufacturing-success]').textContent, /power.*off.*on/i)
        assert.equal(button(ui, 'restore').disabled, true)
    } finally {
        ui.close()
    }
})

test('restoring an original identity requires separate consent and consumes it after changing the backup', async () => {
    const calls = []
    const ui = mount(
        {
            restore: async (request) => {
                calls.push(request)
                return { ok: true, backups: [record], backupSupported: true, restoreSupported: true }
            }
        },
        (device) => ({ devices: [anotherDevice(device)], selectedDeviceId: 'rdx:1234567890' })
    )
    try {
        await settled()
        confirmRestore(ui)
        assert.equal(button(ui, 'restore').disabled, true)
        const consent = ui.root.querySelector('[data-manufacturing-field="allowIdentityChange"]')
        assert.ok(consent)
        assert.match(consent.closest('label').textContent, /7810544062/)
        assert.equal(consent.checked, false)
        change(ui, 'allowIdentityChange', true)
        assert.equal(button(ui, 'restore').disabled, false)
        change(ui, 'backup', '')
        confirmRestore(ui)
        assert.equal(button(ui, 'restore').disabled, true)
        assert.equal(ui.root.querySelector('[data-manufacturing-field="allowIdentityChange"]').checked, false)
        change(ui, 'allowIdentityChange', true)
        button(ui, 'restore').click()
        await settled()
        assert.equal(calls.length, 1)
        assert.equal(calls[0].allowIdentityChange, true)
        assert.equal(calls[0].confirmationSerial, record.serial)
        assert.equal(calls[0].acknowledged, true)
        assert.equal(button(ui, 'restore').disabled, true)
    } finally {
        ui.close()
    }
})

/** @param {object} device - First dock snapshot. @returns {object} A distinct validated dock identity for selection races. */
function anotherDevice(device) {
    return { ...device, id: 'rdx:1234567890', serial: '1234567890', drive: { ...device.drive, details: { ...device.drive.details, serialNumber: { availability: 'reported', value: '1234567890' } } } }
}

/** @param {object} ui - Mounted utilities. @returns {void} Explicitly fills every restore gate. */
function confirmRestore(ui) {
    change(ui, 'backup', record.backupId)
    change(ui, 'confirmationSerial', record.serial)
    change(ui, 'acknowledged', true)
}

test('opening the backup folder works during scans without consuming restore confirmation and reports local failures', async () => {
    const pending = Promise.withResolvers()
    let calls = 0
    const ui = mount({
        openFolder: async () => {
            calls += 1
            return pending.promise
        }
    })
    try {
        await settled()
        confirmRestore(ui)
        ui.store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
        const open = button(ui, 'open-folder')
        assert.equal(open.disabled, false)
        open.click()
        open.click()
        assert.equal(calls, 1)
        assert.equal(ui.root.querySelector('[data-manufacturing-field="confirmationSerial"]').value, record.serial)
        pending.resolve({ ok: false, reason: 'manufacturing-folder-open-failed' })
        await settled()
        assert.match(ui.root.querySelector('[data-manufacturing-folder-error]').textContent, /could not open/i)
        assert.equal(button(ui, 'open-folder').disabled, false)
        assert.equal(ui.store.getState().manufacturingLocked, false)
    } finally {
        ui.close()
    }
})

test('saved backup selection retains focus during an unchanged device refresh', async () => {
    const ui = mount({}, { discovery: { ...createFixtureState({ mode: 'one-device' }).discovery, epoch: 1, listRevision: 1 } })
    try {
        await settled()
        const select = ui.root.querySelector('[data-manufacturing-field="backup"]')
        select.focus()
        const state = ui.store.getState()
        ui.store.dispatch({ type: 'device/list-replaced', devices: state.devices, epoch: state.discovery.epoch, listRevision: state.discovery.listRevision + 1 })
        assert.equal(ui.store.getState().discovery.listRevision, 2)
        assert.equal(ui.root.querySelector('[data-manufacturing-field="backup"]'), select)
        assert.equal(ui.dom.window.document.activeElement, select)
        assert.equal(select.disabled, false)
    } finally {
        ui.close()
    }
})

test('automatic scans preserve the backup action and open selector while blocking restore commands', async () => {
    const calls = []
    const ui = mount({
        backup: async () => {
            calls.push('backup')
        },
        restore: async () => {
            calls.push('restore')
        }
    })
    try {
        await settled()
        const select = ui.root.querySelector('[data-manufacturing-field="backup"]')
        select.focus()
        for (let cycle = 0; cycle < 3; cycle += 1) {
            ui.store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
            assert.equal(select.disabled, false)
            assert.equal(ui.dom.window.document.activeElement, select)
            confirmRestore(ui)
            assert.equal(select.value, record.backupId)
            assert.equal(button(ui, 'backup').disabled, false)
            assert.equal(button(ui, 'restore').disabled, true)
            button(ui, 'restore').click()
            assert.deepEqual(calls, [])
            ui.store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
            assert.equal(ui.root.querySelector('[data-manufacturing-field="backup"]'), select)
            assert.equal(ui.dom.window.document.activeElement, select)
            assert.equal(button(ui, 'restore').disabled, false)
        }
    } finally {
        ui.close()
    }
})

test('manufacturing backup owns a synchronous independent lock and cannot submit twice', async () => {
    const pending = Promise.withResolvers()
    const calls = []
    const ui = mount(
        {
            backup: (request) => {
                calls.push(request)
                return pending.promise
            }
        },
        (device) => ({ devices: [device, anotherDevice(device)] })
    )
    try {
        await settled()
        const backup = button(ui, 'backup')
        backup.click()
        backup.dispatchEvent(new ui.dom.window.MouseEvent('click', { bubbles: true }))
        assert.equal(calls.length, 1)
        assert.equal(ui.store.getState().manufacturingLocked, true)
        assert.equal(button(ui, 'refresh').disabled, true)
        assert.equal(button(ui, 'restore').disabled, true)
        ui.store.dispatch({ type: 'device/select', deviceId: 'rdx:1234567890' })
        assert.equal(ui.store.getState().selectedDeviceId, ui.device.id)
        ui.store.dispatch({ type: 'recovery/lock', locked: true })
        pending.resolve({ ok: true, backups: [record], backupSupported: true, restoreSupported: true })
        await settled()
        assert.equal(ui.store.getState().manufacturingLocked, false)
        assert.equal(ui.store.getState().recoveryLocked, true)
        assert.equal(button(ui, 'backup').disabled, true)
    } finally {
        ui.close()
    }
})

test('manufacturing restore submits once and consumes its confirmation before awaiting native work', async () => {
    const pending = Promise.withResolvers()
    const calls = []
    const ui = mount({
        restore: (request) => {
            calls.push(request)
            return pending.promise
        }
    })
    try {
        await settled()
        confirmRestore(ui)
        const restore = button(ui, 'restore')
        restore.click()
        restore.dispatchEvent(new ui.dom.window.MouseEvent('click', { bubbles: true }))
        assert.equal(calls.length, 1)
        assert.equal(ui.root.querySelector('[data-manufacturing-field="confirmationSerial"]').value, '')
        pending.resolve({ ok: false, reason: 'firmware-manufacturing-restore-unsupported' })
        await settled()
        assert.equal(ui.store.getState().manufacturingLocked, false)
        assert.equal(button(ui, 'restore').disabled, true)
        assert.equal(ui.root.querySelector('[data-manufacturing-success]'), null)
        assert.match(ui.root.querySelector('[data-manufacturing-error]').textContent, /does not support/)
    } finally {
        ui.close()
    }
})

test('unsupported restore and erased or corrupt backups stay visible but cannot authorize a write', async () => {
    const evidence = ['erased', 'corrupt'].map((state, index) => ({ ...record, backupId: `record-abc-${index + 1}`, state, serial: null }))
    for (const restoreSupported of [false, true]) {
        const calls = []
        const ui = mount({
            list: async () => ({ ok: true, backups: [record, ...evidence], backupSupported: true, restoreSupported }),
            restore: async (request) => {
                calls.push(request)
                return { ok: false, reason: 'manufacturing-unavailable' }
            }
        })
        try {
            await settled()
            confirmRestore(ui)
            assert.equal(button(ui, 'restore').disabled, !restoreSupported)
            for (const backup of evidence) {
                const option = ui.root.querySelector(`option[value="${backup.backupId}"]`)
                assert.equal(option.disabled, true)
                change(ui, 'backup', backup.backupId)
                change(ui, 'confirmationSerial', record.serial)
                change(ui, 'acknowledged', true)
                assert.equal(button(ui, 'restore').disabled, true)
            }
            change(ui, 'backup', 'record-bad-1')
            button(ui, 'restore').click()
            assert.deepEqual(calls, [])
        } finally {
            ui.close()
        }
    }
})

test('backup support and empty bay are required even when a restore record exists', async () => {
    for (const state of ['unsupported', 'media', 'active']) {
        const ui = mount({ list: async () => ({ ok: true, backups: [record], backupSupported: state !== 'unsupported', restoreSupported: false }) }, state === 'media' ? { devices: createFixtureState({ mode: 'one-device' }).devices } : {})
        try {
            await settled()
            if (state === 'active') ui.store.dispatch({ type: 'operation/started', kind: 'self-test', operationId: 'op:manufacturing-gate' })
            assert.equal(button(ui, 'backup').disabled, true)
            assert.equal(button(ui, 'restore').disabled, true)
        } finally {
            ui.close()
        }
    }
})

test('switching docks ignores a late inventory and clears the previous serial and acknowledgement', async () => {
    const oldList = Promise.withResolvers()
    const other = { ...record, backupId: 'record-abc-2', deviceId: 'rdx:1234567890', serial: '1234567890' }
    const ui = mount({ list: (request) => (request.deviceId === record.deviceId ? oldList.promise : Promise.resolve({ ok: true, backups: [other], backupSupported: true, restoreSupported: true })) }, (device) => ({ devices: [device, anotherDevice(device)] }))
    try {
        ui.store.dispatch({ type: 'device/select', deviceId: other.deviceId })
        assert.equal(ui.root.querySelector('[role="tab"][aria-selected="true"]').dataset.area, 'status')
        ui.root.querySelector('[role="tab"][data-area="utilities"]').click()
        await settled()
        oldList.resolve({ ok: true, backups: [record], backupSupported: true, restoreSupported: true })
        await settled()
        assert.equal(ui.root.querySelector(`option[value="${record.backupId}"]`), null)
        assert.ok(ui.root.querySelector(`option[value="${other.backupId}"]`))
        change(ui, 'backup', other.backupId)
        change(ui, 'confirmationSerial', other.serial)
        change(ui, 'acknowledged', true)
        assert.equal(button(ui, 'restore').disabled, false)
        ui.store.dispatch({ type: 'device/select', deviceId: ui.device.id })
        assert.equal(ui.root.querySelector('[role="tab"][aria-selected="true"]').dataset.area, 'status')
        ui.root.querySelector('[role="tab"][data-area="utilities"]').click()
        await settled()
        assert.equal(ui.root.querySelector('[data-manufacturing-field="backup"]').value, '')
        assert.equal(ui.root.querySelector('[data-manufacturing-field="confirmationSerial"]').value, '')
        assert.equal(ui.root.querySelector('[data-manufacturing-field="acknowledged"]').checked, false)
        assert.equal(button(ui, 'restore').disabled, true)
    } finally {
        ui.close()
    }
})

test('a changed device revision cannot present a late mutation as verified success or release its lock', async () => {
    const pending = Promise.withResolvers()
    const ui = mount({ backup: () => pending.promise })
    try {
        await settled()
        button(ui, 'backup').click()
        ui.store.dispatch({ type: 'device/refreshed', device: { ...ui.device, revision: ui.device.revision + 1 } })
        pending.resolve({ ok: true, backups: [record], backupSupported: true, restoreSupported: true })
        await settled()
        assert.equal(ui.root.querySelector('[data-manufacturing-success]'), null)
        assert.equal(ui.store.getState().manufacturingLocked, true)
        assert.equal(button(ui, 'backup').disabled, true)
        assert.equal(button(ui, 'refresh').disabled, false)
        button(ui, 'refresh').click()
        await settled()
        assert.equal(ui.store.getState().manufacturingLocked, false)
        assert.equal(button(ui, 'restore').disabled, true)
    } finally {
        ui.close()
    }
})

test('lost restore replies remain locked until a successful explicit list and never retry the write', async () => {
    for (const outcome of ['timeout', 'throw', 'malformed']) {
        let writes = 0
        let lists = 0
        const ui = mount({
            list: async () => {
                lists += 1
                return lists === 2 ? { ok: false, reason: 'operation-in-progress' } : { ok: true, backups: [record], backupSupported: true, restoreSupported: true }
            },
            restore: async () => {
                writes += 1
                if (outcome === 'throw') throw new Error('hidden private transport detail')
                return outcome === 'timeout' ? { ok: false, reason: 'service-request-timeout' } : { ok: true, path: '/private/hidden-record' }
            }
        })
        try {
            await settled()
            confirmRestore(ui)
            button(ui, 'restore').click()
            await settled()
            assert.equal(ui.store.getState().manufacturingLocked, true)
            assert.equal(button(ui, 'restore').disabled, true)
            assert.doesNotMatch(ui.root.textContent, /hidden private|hidden-record/)
            button(ui, 'refresh').click()
            await settled()
            assert.equal(ui.store.getState().manufacturingLocked, true)
            button(ui, 'refresh').click()
            await settled()
            assert.equal(ui.store.getState().manufacturingLocked, false)
            assert.equal(writes, 1)
            assert.equal(button(ui, 'restore').disabled, true)
        } finally {
            ui.close()
        }
    }
})

test('saved metadata is newest first and all locales explain automatic backups and exact target restore', async () => {
    const older = { ...record, backupId: 'record-abc-3', createdAt: record.createdAt - 10000 }
    for (const language of ['en', 'de', 'es', 'fr', 'it', 'pt', 'ja', 'zh']) {
        const ui = mount({ list: async () => ({ ok: true, backups: [older, record], backupSupported: true, restoreSupported: true }) }, {}, language)
        try {
            await settled()
            const panel = ui.root.querySelector('[data-manufacturing-panel]')
            for (const key of ['manufacturing.automaticBackup', 'manufacturing.restoreDescription', 'manufacturing.acknowledge']) assert.ok(panel.textContent.includes(getCatalog(language)[key]), `${language}:${key}`)
            assert.deepEqual(
                [...panel.querySelectorAll('option')].map((option) => option.value),
                ['', record.backupId, older.backupId]
            )
            assert.ok(panel.querySelector('select').textContent.includes(record.serial))
            assert.ok(panel.querySelector('[data-manufacturing-target]').textContent.includes(ui.device.serial))
            assert.equal(panel.querySelector('select').value, '')
        } finally {
            ui.close()
        }
    }
})

test('manufacturing ownership blocks background discovery and ROM recovery admission', async () => {
    const pending = Promise.withResolvers()
    const ui = mount({ backup: () => pending.promise })
    let scans = 0
    const discovery = createDeviceController({
        store: ui.store,
        service: {
            scan: async () => {
                scans += 1
                return { ok: true }
            }
        }
    })
    const recovery = new RecoveryController({ list: async () => ({ ok: true, targets: [], bundles: [], status: { state: 'idle', revision: 0 } }), status: async () => ({ ok: true, status: { state: 'idle', revision: 0 } }), start: async () => ({ ok: false, reason: 'operation-in-progress' }), continue: async () => ({ ok: false, reason: 'operation-in-progress' }) }, ui.store, () => {})
    try {
        await settled()
        button(ui, 'backup').click()
        assert.deepEqual(await discovery.refreshForOperation(), { ok: false, reason: 'operation-in-progress' })
        assert.equal(scans, 0)
        assert.equal(recovery.getView().operationBusy, true)
        pending.resolve({ ok: false, reason: 'manufacturing-unavailable' })
        await settled()
    } finally {
        discovery.destroy()
        recovery.destroy()
        ui.close()
    }
})

test('backup pages expose older valid records without carrying confirmation across page changes', async () => {
    const requests = []
    const erased = { ...record, backupId: 'record-abc-9', serial: null, state: 'erased' }
    const ui = mount({
        list: async (request) => {
            requests.push(request)
            const page = request.page ?? 0
            return { ok: true, backups: page === 1 ? [record] : [erased], backupSupported: true, restoreSupported: true, page, hasMore: page === 0 }
        }
    })
    try {
        await settled()
        assert.equal(button(ui, 'previous').disabled, true)
        assert.equal(button(ui, 'next').disabled, false)
        button(ui, 'next').click()
        await settled()
        assert.equal(button(ui, 'next').disabled, true)
        assert.equal(ui.root.querySelector('[data-manufacturing-field="backup"]').value, '')
        confirmRestore(ui)
        assert.equal(button(ui, 'restore').disabled, false)
        button(ui, 'previous').click()
        await settled()
        assert.equal(ui.root.querySelector('[data-manufacturing-field="confirmationSerial"]').value, '')
        assert.equal(button(ui, 'restore').disabled, true)
        assert.deepEqual(
            requests.map((request) => request.page ?? 0),
            [0, 1, 0]
        )
    } finally {
        ui.close()
    }
})

test('a renderer reload reacquires a service-reported uncertain manufacturing owner', async () => {
    let reads = 0
    const ui = mount({
        list: async () => {
            reads += 1
            return reads === 1 ? { ok: false, reason: 'manufacturing-outcome-unknown' } : { ok: true, backups: [record], backupSupported: true, restoreSupported: true }
        }
    })
    try {
        await settled()
        assert.equal(ui.store.getState().manufacturingLocked, true)
        assert.equal(button(ui, 'backup').disabled, true)
        button(ui, 'refresh').click()
        await settled()
        assert.equal(ui.store.getState().manufacturingLocked, false)
    } finally {
        ui.close()
    }
})

test('failed inventory refresh discards previously reported manufacturing support', async () => {
    let reads = 0
    const ui = mount({
        list: async () => {
            reads += 1
            return reads === 1 ? { ok: true, backups: [record], backupSupported: true, restoreSupported: true } : { ok: false, reason: 'manufacturing-unavailable' }
        }
    })
    try {
        await settled()
        assert.equal(button(ui, 'backup').disabled, false)
        button(ui, 'refresh').click()
        await settled()
        assert.equal(button(ui, 'backup').disabled, true)
        assert.equal(button(ui, 'restore').disabled, true)
    } finally {
        ui.close()
    }
})

test('revision refresh preserves settled manufacturing content while revalidating admission after a scan', async () => {
    const pending = Promise.withResolvers()
    const requests = []
    const ui = mount(
        {
            list: (request) => {
                requests.push(request)
                return requests.length === 1 ? Promise.resolve({ ok: true, backups: [record], backupSupported: true, restoreSupported: true }) : pending.promise
            }
        },
        { discovery: { ...createFixtureState({ mode: 'one-device' }).discovery, epoch: 1, listRevision: 1 } }
    )
    try {
        await settled()
        confirmRestore(ui)
        const select = ui.root.querySelector('[data-manufacturing-field="backup"]')
        select.focus()
        ui.store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
        const state = ui.store.getState()
        ui.store.dispatch({ type: 'device/list-replaced', devices: [{ ...ui.device, revision: ui.device.revision + 1 }], epoch: state.discovery.epoch, listRevision: state.discovery.listRevision + 1 })
        assert.ok(ui.root.querySelector(`option[value="${record.backupId}"]`), 'saved metadata survives a background revision')
        assert.equal(ui.root.querySelector('[data-manufacturing-field="backup"]'), select)
        assert.equal(ui.dom.window.document.activeElement, select)
        assert.equal(select.value, '', 'a new revision consumes restore consent')
        assert.equal(button(ui, 'backup').disabled, false, 'routine revision changes keep the backup action stable')
        ui.store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
        assert.equal(requests.length, 2, 'revalidation starts once discovery releases the device')
        assert.equal(requests[1].deviceRevision, ui.device.revision + 1)
        assert.doesNotMatch(ui.root.querySelector('[data-manufacturing-panel]').textContent, /Loading saved backups|does not support manufacturing-data restore/)
        assert.equal(button(ui, 'backup').disabled, false, 'a click may queue while fresh support is checked')
        pending.resolve({ ok: true, backups: [record], backupSupported: true, restoreSupported: true })
        await settled()
        assert.equal(button(ui, 'backup').disabled, false)
        assert.equal(button(ui, 'restore').disabled, true)
    } finally {
        ui.close()
    }
})

test('failed background inventories stay visible without cycling through loading or inventing unsupported firmware', async () => {
    const pending = Promise.withResolvers()
    let reads = 0
    const ui = mount({ list: () => (++reads === 1 ? Promise.resolve({ ok: false, reason: 'manufacturing-unavailable' }) : pending.promise) }, { discovery: { ...createFixtureState({ mode: 'one-device' }).discovery, epoch: 1, listRevision: 1 } })
    try {
        await settled()
        const panel = ui.root.querySelector('[data-manufacturing-panel]')
        assert.ok(panel.querySelector('[data-manufacturing-error]'))
        assert.equal(panel.querySelector('[data-manufacturing-empty]'), null, 'a failed read does not prove an empty inventory')
        assert.doesNotMatch(panel.textContent, /does not support manufacturing-data restore/)
        const state = ui.store.getState()
        ui.store.dispatch({ type: 'device/list-replaced', devices: [{ ...ui.device, revision: ui.device.revision + 1 }], epoch: state.discovery.epoch, listRevision: state.discovery.listRevision + 1 })
        assert.ok(panel.querySelector('[data-manufacturing-error]'), 'keep the settled failure during revalidation')
        assert.doesNotMatch(panel.textContent, /Loading saved backups/)
        pending.resolve({ ok: false, reason: 'manufacturing-unavailable' })
        await settled()
        assert.equal(panel.querySelector('[data-manufacturing-empty]'), null)
        assert.equal(button(ui, 'backup').disabled, true)
    } finally {
        ui.close()
    }
})

test('refresh stays enabled during background work and queues one explicit inventory after the scan', async () => {
    const background = Promise.withResolvers()
    const explicit = Promise.withResolvers()
    const requests = []
    const response = { ok: true, backups: [record], backupSupported: true, restoreSupported: true }
    const ui = mount(
        {
            list: (request) => {
                requests.push(request)
                return requests.length === 1 ? Promise.resolve(response) : requests.length === 2 ? background.promise : explicit.promise
            }
        },
        { discovery: { ...createFixtureState({ mode: 'one-device' }).discovery, epoch: 1, listRevision: 1 } }
    )
    try {
        await settled()
        ui.store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
        assert.equal(button(ui, 'refresh').disabled, false, 'an automatic scan does not disable the refresh action')
        const state = ui.store.getState()
        ui.store.dispatch({ type: 'device/list-replaced', devices: [{ ...ui.device, revision: ui.device.revision + 1 }], epoch: state.discovery.epoch, listRevision: state.discovery.listRevision + 1 })
        ui.store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
        assert.equal(requests.length, 2)
        assert.equal(button(ui, 'refresh').disabled, false, 'a background inventory does not disable the refresh action')
        ui.store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
        button(ui, 'refresh').click()
        button(ui, 'refresh').click()
        assert.equal(button(ui, 'refresh').disabled, true, 'the explicit request latches before awaiting')
        background.resolve(response)
        await settled()
        assert.equal(requests.length, 2, 'explicit inventory waits for the scan and prior read')
        ui.store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
        assert.equal(requests.length, 3, 'one queued click performs one fresh read')
        assert.equal(requests[2].deviceRevision, ui.device.revision + 1)
        assert.equal(button(ui, 'refresh').disabled, true)
        explicit.resolve(response)
        await settled()
        assert.equal(button(ui, 'refresh').disabled, false)
    } finally {
        background.resolve(response)
        explicit.resolve(response)
        ui.close()
    }
})

test('a queued explicit refresh is cancelled when the service disconnects', async () => {
    let reads = 0
    const ui = mount({
        list: async () => {
            reads += 1
            return { ok: true, backups: [record], backupSupported: true, restoreSupported: true }
        }
    })
    try {
        await settled()
        ui.store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
        button(ui, 'refresh').click()
        assert.equal(button(ui, 'refresh').disabled, true)
        ui.store.dispatch({ type: 'service/unavailable', reason: 'service-exited' })
        ui.store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
        await settled()
        assert.equal(reads, 1, 'no request is sent to a disconnected target')
        assert.equal(ui.root.querySelector('[data-manufacturing-action="refresh"]'), null, 'disconnected service removes device controls')
        assert.doesNotMatch(ui.root.textContent, /Loading saved backups/)
    } finally {
        ui.close()
    }
})
