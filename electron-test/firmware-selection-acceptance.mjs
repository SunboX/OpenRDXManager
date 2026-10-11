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
const directory = process.env.OPENRDX_FIRMWARE_SELECTION_EVIDENCE_DIRECTORY
if (!directory) throw new Error('An explicit evidence directory is required')
const rendererUrl = new URL('../src/renderer/', import.meta.url).href

/** @returns {Promise<void>} Verifies production renderer selection through changing revisions without firmware writes. */
async function run() {
    await app.whenReady()
    await mkdir(directory, { recursive: true })
    const window = new BrowserWindow({ ...windowOptions, show: true, webPreferences: { ...windowOptions.webPreferences, preload: undefined } })
    try {
        await window.loadFile(fileURLToPath(new URL('../src/index.html', import.meta.url)))
        const evidence = await window.webContents.executeJavaScript(`
            /** @returns {Promise<object>} Holds file selection while five new revisions arrive. */
            (async function exerciseSelection() {
                const { mountApplication } = await import(${JSON.stringify(`${rendererUrl}app-controller.mjs`)})
                const { createFixtureState } = await import(${JSON.stringify(`${rendererUrl}fixture-state.mjs`)})
                const { createStore } = await import(${JSON.stringify(`${rendererUrl}store.mjs`)})
                const { createUtilityOperationController } = await import(${JSON.stringify(`${rendererUrl}workflows/utility-operation-controller.mjs`)})
                const state = structuredClone(createFixtureState({ mode: 'one-device' }))
                state.devices[0].media = null; state.devices[0].mediaState = 'no-media'
                state.discovery = { ...state.discovery, epoch: 1, listRevision: 1 }
                const store = createStore(state)
                globalThis.__firmwareStore = store
                let completeSelection
                let selections = 0
                globalThis.__firmwareRequests = []
                const api = {
                    files: {
                        /** @returns {Promise<object>} Holds a fixture file token; no filesystem access. */
                        async chooseFirmware() { selections += 1; return await new Promise(resolve => { completeSelection = resolve; globalThis.__completeFirmwareSelection = resolve }) }
                    },
                    operations: {
                        /** @param {object} request - Fixture intent. @returns {Promise<object>} Records and rejects without hardware. */
                        async start(request) { globalThis.__firmwareRequests.push(request); return { ok: false, reason: 'hardware-unavailable' } }
                    }
                }
                globalThis.__firmwareController = mountApplication(document.querySelector('#app'), { store, platform: 'linux', utilityController: createUtilityOperationController(api) })
                document.querySelector('[role="tab"][data-area="utilities"]').click()
                const action = document.querySelector('[data-action="start-firmware"]')
                action.scrollIntoView({ block: 'center' }); action.click()
                const initialRevision = store.getState().devices[0].revision
                const snapshots = []
                for (let index = 0; index < 5; index += 1) {
                    const state = store.getState()
                    store.dispatch({ type: 'device/list-replaced', devices: [{ ...state.devices[0], revision: state.devices[0].revision + 1 }], epoch: 1, listRevision: state.discovery.listRevision + 1 })
                    action.click()
                    snapshots.push({ revision: store.getState().devices[0].revision, disabled: action.disabled, busy: action.getAttribute('aria-busy'), selections })
                }
                globalThis.__completeFirmwareSelection = completeSelection
                return { initialRevision, latestRevision: store.getState().devices[0].revision, snapshots, feedback: document.querySelector('[data-utility-feedback]').textContent }
            })()
        `)
        assert.equal(evidence.latestRevision, evidence.initialRevision + 5)
        evidence.snapshots.forEach((snapshot, index) => assert.deepEqual(snapshot, { revision: evidence.initialRevision + index + 1, disabled: true, busy: 'true', selections: 1 }))
        assert.match(evidence.feedback, /Firmware update/)
        assert.doesNotMatch(evidence.feedback, /\{operation\}/)
        await delay(200)
        await writeFile(join(directory, 'selection-pending.png'), (await window.webContents.capturePage()).toPNG())
        await window.webContents.executeJavaScript(`globalThis.__completeFirmwareSelection({ ok: true, fileToken: 'firmware:acceptance-selection' })`)
        await delay(100)
        const requests = await window.webContents.executeJavaScript('globalThis.__firmwareRequests')
        assert.equal(requests.length, 1)
        assert.equal(requests[0].deviceRevision, evidence.latestRevision)
        const rejected = await window.webContents.executeJavaScript(`
            /** @returns {Promise<object>} Exercises actionable preflight feedback with no second operation. */
            (async function exerciseMissingManifest() {
                document.querySelector('[data-action="start-firmware"]').click()
                globalThis.__completeFirmwareSelection({ ok: false, reason: 'firmware-openrdx-manifest-missing' })
                await new Promise(resolve => setTimeout(resolve, 0))
                globalThis.__firmwareStore.dispatch({ type: 'discovery/scan-started', trigger: 'auto' })
                globalThis.__firmwareStore.dispatch({ type: 'discovery/scan-completed', trigger: 'auto' })
                const feedback = document.querySelector('[data-utility-feedback]')
                return { feedback: feedback.textContent, card: feedback.closest('[data-feature]')?.dataset.feature, role: feedback.getAttribute('role'), state: feedback.dataset.feedbackState, requests: globalThis.__firmwareRequests.length }
            })()
        `)
        assert.equal(rejected.requests, 1)
        assert.equal(rejected.card, 'firmware')
        assert.equal(rejected.role, 'alert')
        assert.equal(rejected.state, 'failed')
        assert.match(rejected.feedback, /matching OpenRDX release \.json file is missing/)
        assert.match(rejected.feedback, /Then select the \.bin file again/)
        assert.doesNotMatch(rejected.feedback, /Operation accepted/)
        await writeFile(join(directory, 'manifest-missing.png'), (await window.webContents.capturePage()).toPNG())
        const scanAdmission = await window.webContents.executeJavaScript(`
            /** @returns {Promise<object>} Exercises renderer and real main policy through an in-flight fixture scan. */
            (async function exerciseScanAdmission() {
                globalThis.__firmwareController.destroy()
                const { mountApplication } = await import(${JSON.stringify(`${rendererUrl}app-controller.mjs`)})
                const { createFixtureState } = await import(${JSON.stringify(`${rendererUrl}fixture-state.mjs`)})
                const { createStore } = await import(${JSON.stringify(`${rendererUrl}store.mjs`)})
                const { createUtilityOperationController } = await import(${JSON.stringify(`${rendererUrl}workflows/utility-operation-controller.mjs`)})
                const { dispatchApplicationRequest } = await import(${JSON.stringify(new URL('../src/main/application-dispatcher.mjs', import.meta.url).href)})
                const state = structuredClone(createFixtureState({ mode: 'one-device' }))
                state.devices[0].media = null; state.devices[0].mediaState = 'no-media'; state.devices[0].revision = 2
                const store = createStore(state)
                let current = { ...state.devices[0], revision: 3 }
                let scanning = true
                const requests = []
                const services = { operations: {
                    /** @returns {object} Main-owned synthetic hardware context. */
                    getContext() { return { device: current, generation: 1, activeOperation: scanning ? { kind: 'scan' } : null, serviceMode: 'native', hasPrivilege: true, hardwareReady: true, platformCapability: { state: 'available' } } },
                    /** @returns {Promise<void>} Completes an already running scan. */
                    async waitForScan() { scanning = false; current = { ...current, revision: 4 } },
                    /** @param {object} request - Final policy-approved request. @returns {Promise<object>} Stops before hardware dispatch. */
                    async start(request) { requests.push(request); return { ok: false, reason: 'hardware-unavailable' } }
                } }
                const api = {
                    files: { /** @returns {Promise<object>} Fixture token only. */ async chooseFirmware() { return { ok: true, fileToken: 'firmware:scan-acceptance' } } },
                    devices: { /** @returns {Promise<object>} Fresh cached service snapshot. */ async list() { return { ok: true, devices: [current] } } },
                    operations: { /** @param {object} request - Real renderer request. @returns {Promise<object>} Real policy with fixture device boundaries. */ async start(request) { return await dispatchApplicationRequest(services, 'openrdx:operations:start', request) } }
                }
                mountApplication(document.querySelector('#app'), { store, platform: 'linux', utilityController: createUtilityOperationController(api) })
                document.querySelector('[role="tab"][data-area="utilities"]').click()
                document.querySelector('[data-action="start-firmware"]').click()
                await new Promise(resolve => setTimeout(resolve, 100))
                return { requests, feedback: document.querySelector('[data-utility-feedback]').textContent, fixtureOnly: true, deviceWrites: 0 }
            })()
        `)
        assert.equal(scanAdmission.requests.length, 1)
        assert.equal(scanAdmission.requests[0].deviceRevision, 4)
        assert.equal(scanAdmission.deviceWrites, 0)
        assert.doesNotMatch(scanAdmission.feedback, /stale-device-revision/)
        await writeFile(join(directory, 'scan-admission.png'), (await window.webContents.capturePage()).toPNG())
        const disconnected = await window.webContents.executeJavaScript(`
            /** @returns {Promise<object>} Renders a disconnected terminal update without any hardware action. */
            (async function exerciseDisconnectedFailure() {
                const { createFixtureState } = await import(${JSON.stringify(`${rendererUrl}fixture-state.mjs`)})
                const { renderShell } = await import(${JSON.stringify(`${rendererUrl}views/shell-view.mjs`)})
                const { createTranslator } = await import(${JSON.stringify(`${rendererUrl}i18n.mjs`)})
                const { englishCatalog } = await import(${JSON.stringify(new URL('../src/locales/en.mjs', import.meta.url).href)})
                const fixture = createFixtureState({ mode: 'operation-failed' })
                const state = { ...fixture, devices: [], selectedDeviceId: null, lastOperation: { ...fixture.lastOperation, kind: 'firmware-update', error: { ...fixture.lastOperation.error, code: 'firmware-reconnect-failed', stage: 'device-reconnecting', retryable: false } } }
                document.querySelector('#app').innerHTML = renderShell(state, { document, translator: createTranslator(englishCatalog, englishCatalog) })
                const alert = document.querySelector('[data-operation-failure]')
                return { role: alert?.getAttribute('role'), failure: alert?.textContent, discovery: document.querySelector('#main-content')?.textContent, retry: document.querySelector('[data-action="retry-operation"]') !== null }
            })()
        `)
        assert.equal(disconnected.role, 'alert')
        assert.match(disconnected.failure, /Firmware update did not complete/)
        assert.match(disconnected.failure, /firmware-reconnect-failed/)
        assert.match(disconnected.failure, /Firmware may already be installed, but verification is incomplete/)
        assert.match(disconnected.failure, /reconnect the same RDX USB device to the guest/)
        assert.match(disconnected.failure, /support-fixture-01/)
        assert.doesNotMatch(disconnected.failure, /No firmware was written/)
        assert.match(disconnected.discovery, /No RDX drives detected/)
        assert.equal(disconnected.retry, false)
        await writeFile(join(directory, 'disconnected-update-failed.png'), (await window.webContents.capturePage()).toPNG())
        await writeFile(join(directory, 'result.json'), JSON.stringify({ fixtureOnly: true, ...evidence, requests, rejected, disconnected, scanAdmission }, null, 2))
        console.log('Firmware selection Electron acceptance passed')
    } finally {
        window.destroy()
    }
}

/** @returns {Promise<void>} Reports native Electron acceptance status and exits its isolated instance. */
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
