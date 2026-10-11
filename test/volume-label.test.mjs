// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { operationRequestSchema, deviceSnapshotSchema } from '../src/shared/schemas.mjs'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { updateVolumeLabelForm } from '../src/renderer/volume-label-form.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { renderUtilitiesView } from '../src/renderer/views/utilities-view.mjs'
import { completeDeviceSnapshot } from './helpers/device-snapshot.mjs'
import { collectVisualDisabledReasons } from '../electron-test/visual-qa-contract.mjs'

/** @param {object} overrides - Media overrides. @param {number} revision - Device revision. @returns {object} Complete selected cartridge fixture. */
function device(overrides = {}, revision = 12) {
    return completeDeviceSnapshot({ id: 'rdx:label-test', revision, vendor: 'TANDBERG', product: 'RDX QuikStor USB3+ External', serial: 'DOCK-LABEL-01', capabilities: { 'volume-label-set': { state: 'available' } }, media: { id: 'media:label-test', label: 'Backup', filesystem: 'exfat', writable: true, capacityBytes: 1_000_000, usedBytes: 0, ...overrides } })
}

/** @returns {JSDOM} Isolated real renderer document. */
function dom() {
    return new JSDOM('<!doctype html><div id="app"></div>', { pretendToBeVisual: true, url: 'file:///openrdxmanager/src/index.html' })
}

test('volume-label request allows clearing and Unicode but rejects paths, controls, malformed UTF-16 and unknown keys', () => {
    const request = { kind: 'volume-label-set', deviceId: 'rdx:label-test', deviceRevision: 12 }
    for (const label of ['', 'Backup ä', '😀'.repeat(16)]) assert.equal(operationRequestSchema.safeParse({ ...request, label }).success, true)
    for (const label of ['a/b', 'a\\b', 'bad:name', 'bad\nname', '\u0085', '\ud800', '😀'.repeat(17)]) assert.equal(operationRequestSchema.safeParse({ ...request, label }).success, false)
    assert.equal(operationRequestSchema.safeParse({ ...request, label: 'Backup', path: 'C:' }).success, false)
    assert.equal(deviceSnapshotSchema.safeParse(device({ label: '' })).success, true)
})

test('label card displays current label, filesystem limit, and preserves unavailable and busy gates', () => {
    const window = dom()
    const document = window.window.document
    const card = renderUtilitiesView(device(), { document }).querySelector('[data-feature="volume-label"]')
    assert.match(card.textContent, /Backup/)
    assert.equal(card.querySelector('input').value, 'Backup')
    assert.equal(card.querySelector('input').maxLength, 11)
    assert.equal(card.querySelector('button').disabled, true)
    const ntfs = renderUtilitiesView(device({ filesystem: 'ntfs' }), { document })
    assert.equal(ntfs.querySelector('[data-utility-volume-label]').maxLength, 32)
    for (const [selected, options] of [
        [device({ label: undefined }), {}],
        [device(), { locked: true }]
    ]) {
        const view = renderUtilitiesView(selected, { document, ...options })
        assert.equal(view.querySelector('[data-utility-volume-label]').disabled, true)
    }
    window.window.close()
})

test('disabled label input exposes its visible capability reason outside its enclosing label', () => {
    const window = dom()
    const document = window.window.document
    const unsupported = structuredClone(device())
    unsupported.capabilities['volume-label-set'] = { state: 'unsupported-platform', reason: 'unsupported-platform' }
    for (const [selected, options, expectedState] of [
        [unsupported, {}, 'unsupported-platform'],
        [device(), { locked: true }, 'busy'],
        [device({ label: undefined }), {}, 'evidence-incomplete']
    ]) {
        const view = renderUtilitiesView(selected, { document, ...options })
        document.querySelector('#app').replaceChildren(view)
        const input = view.querySelector('[data-utility-volume-label]')
        assert.equal(input.disabled, true)
        const reasons = collectVisualDisabledReasons(input, document, (element) => !element.hidden)
        assert.equal(reasons.length, 1, 'The input must reference rendered reason text, not only a tooltip')
        const capability = input.closest('[data-feature]').querySelector('[data-capability-state]')
        assert.equal(capability.dataset.capabilityState, expectedState)
        assert.equal(reasons[0], capability.querySelector('[data-capability-reason]').textContent.trim())
    }
    window.window.close()
})

for (const platform of ['win32', 'darwin', 'linux'])
    test(`${platform} utility input suppresses no-op and invalid names and submits an exact identity-bound rename`, async () => {
        const window = dom()
        const document = window.window.document
        const selected = device()
        const requests = []
        let releaseStart
        const store = createStore({ activeArea: 'utilities', activeOperation: null, activity: [], authenticationSessions: {}, devices: [selected], discovery: { diagnostics: { acceptedCount: 1, candidateCount: 1, rejections: [] }, epoch: 1, listRevision: 1, scanStatus: 'idle', selectionInitialized: true, tombstones: {} }, lastOperation: null, provenance: 'fixture', selectedDeviceId: selected.id, service: { status: 'ready' }, settings: { autoScan: true } })
        const utilityController = {
            /** @returns {boolean} Fixture bridge availability. */
            isAvailable() {
                return true
            },
            /** @param {object} request - Structured label request. @returns {Promise<object>} Accepted operation. */
            async start(request) {
                requests.push(request)
                if (requests.length > 1)
                    return await new Promise((resolve) => {
                        releaseStart = resolve
                    })
                return { ok: true, operationId: 'op:label-test' }
            }
        }
        const controller = mountApplication(document.querySelector('#app'), { platform, store, utilityController })
        const input = document.querySelector('[data-utility-volume-label]')
        const button = document.querySelector('[data-utility-operation="volume-label-set"]')
        for (const label of ['Backup', 'a/b', '😀'.repeat(6), '\ud800']) {
            input.value = label
            input.dispatchEvent(new window.window.Event('input', { bubbles: true }))
            assert.equal(button.disabled, true)
        }
        input.value = 'Backup02'
        input.focus()
        input.setSelectionRange(3, 5)
        input.dispatchEvent(new window.window.Event('input', { bubbles: true }))
        assert.equal(button.disabled, false)
        for (let index = 0; index < 3; index += 1) {
            store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
            store.dispatch({ type: 'device/list-replaced', devices: [device({}, 13 + index)], epoch: 1, listRevision: index + 2 })
            store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
            assert.equal(input.value, 'Backup02')
            assert.equal(button.disabled, false, 'Background hardware refresh must retain rename readiness')
            assert.equal(document.activeElement, input)
            assert.equal(input.selectionStart, 3)
            assert.equal(input.selectionEnd, 5)
        }
        input.value = ''
        input.dispatchEvent(new window.window.Event('input', { bubbles: true }))
        assert.equal(button.disabled, false)
        store.dispatch({ type: 'device/list-replaced', devices: [device({}, 16)], epoch: 1, listRevision: 5 })
        assert.equal(input.value, '', 'An empty draft must survive a newer discovery revision')
        button.click()
        await new Promise(setImmediate)
        assert.deepEqual(requests, [{ kind: 'volume-label-set', deviceId: selected.id, deviceRevision: 16, label: '' }])
        const replacement = device({ id: 'media:replacement', label: 'New media' }, 17)
        store.dispatch({ type: 'device/list-replaced', devices: [replacement], epoch: 1, listRevision: 6 })
        assert.equal(input.value, 'New media', 'A replaced cartridge must discard the old draft')
        assert.equal(button.disabled, true)
        input.value = 'Backup02'
        input.dispatchEvent(new window.window.Event('input', { bubbles: true }))
        button.click()
        assert.equal(button.disabled, true)
        store.dispatch({ type: 'device/list-replaced', devices: [device({ id: 'media:replacement', label: 'New media' }, 18)], epoch: 1, listRevision: 7 })
        assert.equal(button.disabled, true, 'Refresh must not admit a duplicate while start is pending')
        assert.equal(button.getAttribute('aria-busy'), 'true')
        input.dispatchEvent(new window.window.Event('input', { bubbles: true }))
        button.click()
        assert.equal(requests.length, 2)
        assert.equal(input.value, 'Backup02', 'Pending admission must retain the draft across newer revisions')
        releaseStart({ ok: true, operationId: 'op:label-next' })
        await new Promise(setImmediate)
        const renamed = device({ id: 'media:replacement', label: 'Backup02' }, 19)
        store.dispatch({ type: 'device/list-replaced', devices: [renamed], epoch: 1, listRevision: 8 })
        assert.equal(input.value, 'Backup02')
        assert.equal(button.disabled, true, 'Verified current name must become a no-op')
        input.value = 'Unsubmitted'
        input.dispatchEvent(new window.window.Event('input', { bubbles: true }))
        store.dispatch({ type: 'device/list-replaced', devices: [device({ id: 'media:replacement', label: 'External' }, 20)], epoch: 1, listRevision: 9 })
        assert.equal(input.value, 'External', 'An authoritative name change must discard the outdated draft')
        input.value = 'Unsubmitted'
        input.dispatchEvent(new window.window.Event('input', { bubbles: true }))
        store.dispatch({ type: 'device/list-replaced', devices: [device({ id: 'media:replacement', label: 'External', filesystem: 'ext4' }, 21)], epoch: 1, listRevision: 10 })
        assert.equal(input.value, 'External', 'A filesystem change must discard the old volume draft')
        controller.destroy()
        window.window.close()
    })

/** @returns {void} Verifies Linux names survive service refresh and enforce actual byte limits. */
test('Linux label card displays the freshly formatted name and rejects oversized UTF-8 drafts', () => {
    const window = dom()
    const document = window.window.document
    for (const [filesystem, maximum] of [
        ['ext2', 16],
        ['ext3', 16],
        ['ext4', 16],
        ['xfs', 12],
        ['btrfs', 32],
        ['f2fs', 32],
        ['fat16', 11],
        ['fat32', 11]
    ]) {
        const view = renderUtilitiesView(device({ filesystem, label: 'OPENRDX' }), { document, platform: 'linux' })
        const input = view.querySelector('[data-utility-volume-label]')
        assert.equal(input.value, 'OPENRDX')
        assert.match(view.querySelector('[data-feature="volume-label"]').textContent, /Current name: OPENRDX/)
        assert.equal(input.maxLength, maximum)
        assert.equal(input.disabled, false)
        if (input.dataset.labelByteLimit) {
            const button = view.querySelector('[data-utility-operation="volume-label-set"]')
            input.value = 'ä'.repeat(maximum / 2)
            updateVolumeLabelForm(input)
            assert.equal(button.disabled, false)
            input.value += 'ä'
            updateVolumeLabelForm(input)
            assert.equal(button.disabled, true)
        }
    }
    window.window.close()
})

test('a reported current name remains visible when mounted rename is unsupported', () => {
    const window = dom()
    const document = window.window.document
    for (const filesystem of ['fat16', 'fat32', 'f2fs']) {
        const selected = structuredClone(device({ filesystem, label: 'OPENRDX' }))
        selected.capabilities['volume-label-set'] = { state: 'unsupported-platform', reason: 'unsupported-platform' }
        const view = renderUtilitiesView(selected, { document, platform: 'linux' })
        const input = view.querySelector('[data-utility-volume-label]')
        assert.equal(input.value, 'OPENRDX')
        assert.equal(input.disabled, true)
        assert.match(view.querySelector('[data-feature="volume-label"]').textContent, /Current name: OPENRDX/)
    }
    window.window.close()
})
