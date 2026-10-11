// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { getFormatFilesystemPolicy } from '../src/renderer/workflows/format-filesystem-policy.mjs'
import { operationRequestSchema } from '../src/shared/schemas.mjs'

test('macOS offers the native FAT, HFS+, and APFS personalities including encryption', () => {
    assert.deepEqual(getFormatFilesystemPolicy('darwin').filesystemChoices, ['exfat', 'fat', 'fat12', 'fat16', 'fat32', 'hfs', 'hfs-case-sensitive', 'hfs-journaled', 'hfs-case-sensitive-journaled', 'apfs', 'apfs-case-sensitive', 'apfs-encrypted', 'apfs-case-sensitive-encrypted'])
})

test('encrypted formatting requires a bounded password and ordinary formats reject secrets', () => {
    const request = { kind: 'format', deviceId: 'rdx:format', deviceRevision: 1, filesystem: 'apfs-encrypted', confirmationToken: 'confirm:format' }
    assert.equal(operationRequestSchema.safeParse({ ...request, passphrase: 'temporary test password' }).success, true)
    assert.equal(operationRequestSchema.safeParse(request).success, false)
    assert.equal(operationRequestSchema.safeParse({ ...request, passphrase: 'line\nbreak' }).success, false)
    assert.equal(operationRequestSchema.safeParse({ ...request, filesystem: 'exfat', passphrase: 'unexpected secret' }).success, false)
})

test('encrypted format form survives refresh, clears secrets after submission, and resets for another cartridge', async (context) => {
    const { JSDOM } = await import('jsdom')
    const { mountApplication } = await import('../src/renderer/app-controller.mjs')
    const { createFixtureState } = await import('../src/renderer/fixture-state.mjs')
    const { createStore } = await import('../src/renderer/store.mjs')
    const { createUtilityOperationController } = await import('../src/renderer/workflows/utility-operation-controller.mjs')
    const dom = new JSDOM('<div id="app"></div>', { pretendToBeVisual: true })
    const source = { ...createFixtureState({ mode: 'one-device' }) }
    source.discovery = { ...source.discovery, epoch: 1, listRevision: 1 }
    const device = source.devices[0]
    const store = createStore({ ...source, activeArea: 'utilities' })
    const confirmations = []
    const requests = []
    const utilityController = createUtilityOperationController({
        operations: {
            /** @param {object} request - Exact destructive choice. @returns {Promise<object>} Simulated native confirmation. */
            async confirm(request) {
                confirmations.push(request)
                return { ok: true, confirmationToken: 'confirm:format' }
            },
            /** @param {object} request - Strict native start. @returns {Promise<object>} Simulated admission. */
            async start(request) {
                requests.push(request)
                return { ok: true, operationId: 'op:format' }
            }
        }
    })
    const root = dom.window.document.querySelector('#app')
    const controller = mountApplication(root, { platform: 'darwin', store, utilityController })
    context.after(() => {
        controller.destroy()
        dom.window.close()
    })
    const identity = root.querySelector('[data-format-confirmation]')
    const filesystem = root.querySelector('[data-utility-filesystem]')
    const passwords = [...root.querySelectorAll('[data-format-password]')]
    const button = root.querySelector('[data-action="start-format"]')
    assert.equal(passwords[0].closest('label').hidden, true)
    filesystem.value = 'apfs-encrypted'
    filesystem.dispatchEvent(new dom.window.Event('change', { bubbles: true }))
    identity.value = identity.dataset.expectedIdentity
    identity.dispatchEvent(new dom.window.Event('input', { bubbles: true }))
    assert.equal(passwords[0].closest('label').hidden, false)
    assert.equal(button.disabled, true)
    for (const input of passwords) {
        input.value = 'temporary example password'
        input.dispatchEvent(new dom.window.Event('input', { bubbles: true }))
    }
    assert.equal(button.disabled, false)
    store.dispatch({ type: 'device/list-replaced', epoch: source.discovery.epoch, listRevision: source.discovery.listRevision + 1, devices: [{ ...device, revision: device.revision + 1 }] })
    assert.equal(store.getState().devices[0].revision, device.revision + 1)
    assert.equal(filesystem.value, 'apfs-encrypted')
    assert.equal(button.disabled, false)
    assert.equal(root.innerHTML.includes('temporary example password'), false)
    assert.equal(JSON.stringify(store.getState()).includes('temporary example password'), false)
    button.click()
    await new Promise((resolve) => setImmediate(resolve))
    assert.equal(requests.length, 1)
    assert.equal(requests[0].filesystem, 'apfs-encrypted')
    assert.equal(requests[0].passphrase, 'temporary example password')
    assert.equal('passphrase' in confirmations[0], false)
    assert.equal(
        passwords.every((input) => input.value === ''),
        true
    )
    store.dispatch({ type: 'device/list-replaced', epoch: source.discovery.epoch, listRevision: source.discovery.listRevision + 2, devices: [{ ...device, revision: device.revision + 2, media: { ...device.media, id: 'media:replacement' } }] })
    assert.equal(root.querySelector('[data-format-confirmation]').value, '')
    assert.equal(root.querySelector('[data-action="start-format"]').disabled, true)
})

test('format result remains visible after the formatted cartridge is rediscovered', async (context) => {
    const { JSDOM } = await import('jsdom')
    const { renderUtilitiesView } = await import('../src/renderer/views/utilities-view.mjs')
    const { createFixtureState } = await import('../src/renderer/fixture-state.mjs')
    const dom = new JSDOM('<div></div>')
    context.after(() => dom.window.close())
    const device = createFixtureState({ mode: 'one-device' }).devices[0]
    const view = renderUtilitiesView({ ...device, revision: device.revision + 1 }, { document: dom.window.document, platform: 'darwin', operationIntentAvailable: true, lastOperation: { kind: 'format', operationId: 'op:formatted', deviceId: device.id, deviceRevision: device.revision, status: 'succeeded', stage: 'complete' } })
    assert.equal(view.querySelector('[data-feature="format"] [data-result-status]')?.dataset.resultStatus, 'succeeded')
})
