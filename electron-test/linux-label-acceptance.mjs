// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdir, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { setTimeout as delay } from 'node:timers/promises'
import { app, BrowserWindow } from 'electron'
import { windowOptions } from '../src/window-options.mjs'
import { initializeIsolatedElectronProfile } from './isolated-profile.mjs'

initializeIsolatedElectronProfile(app)
const directory = process.env.OPENRDX_LINUX_LABEL_EVIDENCE_DIRECTORY
if (!directory) throw new Error('An explicit evidence directory is required')
const rendererUrl = new URL('../src/renderer/', import.meta.url).href

/** @returns {Promise<void>} Verifies the actual name card without a hardware bridge. */
async function run() {
    await mkdir(directory, { recursive: true })
    await app.whenReady()
    const window = new BrowserWindow({ ...windowOptions, show: true, webPreferences: { ...windowOptions.webPreferences, preload: undefined, backgroundThrottling: false } })
    try {
        await window.loadFile(fileURLToPath(new URL('../src/index.html', import.meta.url)))
        await window.webContents.executeJavaScript(`
            /** @returns {Promise<void>} Mounts an ext4 cartridge fixture with a known label. */
            (async function mountLinuxLabel() {
                const { mountApplication } = await import(${JSON.stringify(`${rendererUrl}app-controller.mjs`)})
                const { createFixtureState } = await import(${JSON.stringify(`${rendererUrl}fixture-state.mjs`)})
                const { createStore } = await import(${JSON.stringify(`${rendererUrl}store.mjs`)})
                const state = structuredClone(createFixtureState({ mode: 'one-device' }))
                state.discovery = { ...state.discovery, epoch: 1, listRevision: 1 }
                const selected = state.devices[0]
                selected.media = { ...selected.media, filesystem: 'ext4', label: 'OPENRDX' }
                selected.capabilities['volume-label-set'] = { state: 'available' }
                globalThis.__labelRequests = []
                globalThis.__labelStore = createStore({ ...state, activeArea: 'utilities' })
                mountApplication(document.querySelector('#app'), {
                    platform: 'linux', store: globalThis.__labelStore,
                    utilityController: {
                        /** @returns {boolean} Enables fixture intent only. */
                        isAvailable() { return true },
                        /** @param {object} request - Fixture intent. @returns {Promise<object>} Records without writing. */
                        async start(request) { globalThis.__labelRequests.push(request); return { ok: false, reason: 'hardware-unavailable' } }
                    }
                })
                document.querySelector('[data-feature="volume-label"]').scrollIntoView({ block: 'center' })
            })()
        `)
        await delay(400)
        const evidence = await window.webContents.executeJavaScript(`
            /** @returns {object} Reads actual visible card and field state. */
            (function inspectLabel() {
                const card = document.querySelector('[data-feature="volume-label"]')
                const input = card.querySelector('input')
                const bounds = input.getBoundingClientRect()
                return { text: card.textContent, value: input.value, maximum: input.maxLength, disabled: input.disabled, visible: bounds.top >= 0 && bounds.bottom <= innerHeight }
            })()
        `)
        assert.equal(evidence.value, 'OPENRDX')
        assert.match(evidence.text, /Current name: OPENRDX/)
        assert.equal(evidence.disabled, false)
        assert.equal(evidence.maximum, 16)
        assert.equal(evidence.visible, true)
        const refreshEvidence = await window.webContents.executeJavaScript(`
            /** @returns {object} Exercises typing through new device revisions without hardware. */
            (function editAcrossRefreshes() {
                const store = globalThis.__labelStore
                const input = document.querySelector('[data-utility-volume-label]')
                const button = document.querySelector('[data-utility-operation="volume-label-set"]')
                input.value = 'Backup02'
                input.focus()
                input.setSelectionRange(3, 5)
                input.dispatchEvent(new Event('input', { bubbles: true }))
                const initialRevision = store.getState().devices[0].revision
                const snapshots = []
                for (let index = 0; index < 5; index += 1) {
                    const state = store.getState()
                    const selected = state.devices[0]
                    store.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
                    store.dispatch({ type: 'device/list-replaced', devices: [{ ...selected, revision: selected.revision + 1 }], epoch: state.discovery.epoch, listRevision: state.discovery.listRevision + 1 })
                    store.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
                    snapshots.push({ value: input.value, focused: document.activeElement === input, start: input.selectionStart, end: input.selectionEnd, disabled: button.disabled })
                }
                return { initialRevision, snapshots, latestRevision: store.getState().devices[0].revision }
            })()
        `)
        assert.equal(refreshEvidence.latestRevision, refreshEvidence.initialRevision + 5, 'All five discovery revisions must be accepted')
        for (const snapshot of refreshEvidence.snapshots) assert.deepEqual(snapshot, { value: 'Backup02', focused: true, start: 3, end: 5, disabled: false })
        window.webContents.invalidate()
        await delay(400)
        await writeFile(join(directory, 'linux-label.png'), (await window.webContents.capturePage()).toPNG())
        await window.webContents.executeJavaScript(`
            /** @returns {void} Submits only a fixture intent. */
            (function submitRename() {
                const input = document.querySelector('[data-utility-volume-label]')
                input.value = 'Backup02'; input.dispatchEvent(new Event('input', { bubbles: true }))
                document.querySelector('[data-utility-operation="volume-label-set"]').click()
            })()
        `)
        await delay(100)
        const requests = await window.webContents.executeJavaScript('globalThis.__labelRequests')
        assert.equal(requests.length, 1)
        assert.equal(requests[0].label, 'Backup02')
        assert.equal(requests[0].deviceRevision, refreshEvidence.latestRevision)
        await writeFile(join(directory, 'result.json'), JSON.stringify({ fixtureOnly: true, ...evidence, refreshEvidence, requests }, null, 2))
        console.log(`Linux label Electron acceptance passed: ${directory}`)
    } finally {
        window.destroy()
    }
}

/** @returns {Promise<void>} Runs the isolated UI check and reports its actual exit status. */
async function main() {
    try {
        await run()
        app.exit(0)
    } catch (error) {
        console.error(error)
        app.exit(1)
    }
}
void main()
