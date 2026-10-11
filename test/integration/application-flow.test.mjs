// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { SupportSummaryService } from '../../src/main/support-summary-service.mjs'
import { mountApplication } from '../../src/renderer/app-controller.mjs'
import { createFixtureState } from '../../src/renderer/fixture-state.mjs'
import { createRendererIntentAdapter } from '../../src/renderer/intent-adapter.mjs'
import { createStore } from '../../src/renderer/store.mjs'
import { completeDeviceSnapshot } from '../helpers/device-snapshot.mjs'

/**
 * Creates a complete fixture device with every operation used by the integrated
 * flow explicitly available. This is renderer evidence, not hardware evidence.
 * @param {{id: string, product: string, revision: number, serial: string, mediaSerial: string}} identity - Stable test identity.
 * @returns {object} Strict renderer-safe RDX snapshot.
 */
function createFlowDevice(identity) {
    return completeDeviceSnapshot({
        capabilities: {
            'drive-mode-set': { state: 'available' },
            'eject-force': { state: 'available' },
            'eject-safe': { state: 'available' },
            'firmware-update': { state: 'available' },
            format: { state: 'available' },
            'led-test': { state: 'available' },
            'self-test': { state: 'available' },
            'status-refresh': { state: 'available' },
            'write-read-test': { state: 'available' }
        },
        drive: {
            connectionType: 'USB 3',
            firmwareRevision: '0283',
            operationMode: 'Removable Disk',
            powerSource: 'Power adapter',
            productType: 'USB 3 / SATA III'
        },
        id: identity.id,
        media: {
            capacityBytes: 2_000_000_000,
            encrypted: false,
            filesystem: 'exfat',
            id: `media:${identity.mediaSerial}`,
            label: 'Disposable integration cartridge',
            mounted: true,
            serial: identity.mediaSerial,
            status: 'ready',
            usedBytes: 500_000_000,
            writable: true
        },
        product: identity.product,
        revision: identity.revision,
        serial: identity.serial,
        vendor: 'TANDBERG'
    })
}

/**
 * Waits for renderer-owned promise continuations and zero-delay UI work.
 * @returns {Promise<void>} Resolves after queued renderer work settles.
 */
async function settleRenderer() {
    await Promise.resolve()
    /** @param {() => void} resolve - Promise resolver. @returns {void} Schedules settlement after zero-delay renderer work. */
    function settleAfterTurn(resolve) {
        setTimeout(resolve, 0)
    }
    await new Promise(settleAfterTurn)
}

/**
 * Activates one real management-area tab in the mounted application.
 * @param {Document} document - Mounted renderer document.
 * @param {'status'|'encryption'|'tests'|'utilities'} area - Published area.
 * @returns {void} Completes after the delegated click is dispatched.
 */
function openArea(document, area) {
    const tab = document.querySelector(`[role="tab"][data-area="${area}"]`)
    assert.notEqual(tab, null, `The ${area} tab must exist`)
    assert.equal(tab.disabled, false, `The ${area} tab must be available`)
    tab.click()
}

/**
 * Drives one diagnostic from its real action through store progress and a
 * terminal result, proving the application lock surrounds the operation.
 * @param {object} harness - Mounted integration harness.
 * @param {'self-test'|'led-test'|'write-read-test'} kind - Diagnostic kind.
 * @param {string} stage - Operation-specific progress stage.
 * @returns {void} Completes after the diagnostic reaches success.
 */
function runDiagnostic(harness, kind, stage) {
    const { document, intents, primary, secondary, store } = harness
    const action = document.querySelector(`[data-action="${kind}"]`)
    assert.notEqual(action, null)
    assert.equal(action.disabled, false)
    action.click()
    assert.deepEqual(intents.at(-1), {
        deviceId: primary.id,
        deviceRevision: primary.revision,
        kind,
        type: 'operation'
    })

    const operationId = `op:${kind}`
    store.dispatch({ kind, operationId, type: 'operation/started' })
    assert.equal(document.querySelector('[data-operation-status]') !== null, true)
    assert.equal(document.querySelector('[role="tab"][data-area="status"]').disabled, true)
    assert.equal(document.querySelector(`[data-device-id="${secondary.id}"]`).disabled, true)

    store.dispatch({ deviceId: secondary.id, type: 'device/select' })
    assert.equal(store.getState().selectedDeviceId, primary.id)

    store.dispatch({ cancellationState: 'closed', operationId, progress: 0.5, stage, type: 'operation/progress' })
    const progress = document.querySelector(`[data-test-kind="${kind}"] progress`)
    assert.notEqual(progress, null)
    assert.equal(progress.value, 0.5)
    assert.equal(document.querySelector(`[data-progress-stage="${stage}"]`).dataset.stageState, 'active')

    store.dispatch({ operationId, type: 'operation/succeeded' })
    assert.equal(store.getState().activeOperation, null)
    assert.equal(document.querySelector(`[data-test-kind="${kind}"] [data-result-status="succeeded"]`) !== null, true)
}

/**
 * Creates a strict security projection whose access state can be changed only
 * by the test's simulated device refresh.
 * @param {{current: 'disabled'|'enabled'}} access - Mutable external fixture fact.
 * @returns {{getModel: (state: object, device: object, workflow: object|null) => object}} Security model provider.
 */
function createSecurityStateProvider(access) {
    return {
        /**
         * Projects the selected device and current access fact into the real Encryption view.
         * @param {object} _state - Current renderer state.
         * @param {object} device - Selected strict device.
         * @param {object|null} workflow - Current local workflow.
         * @returns {object} Complete security view model.
         */
        getModel(_state, device, workflow) {
            return {
                access: access.current,
                automaticAuthentication: {},
                credentials: [],
                device: {
                    drive: device.drive,
                    id: device.id,
                    label: `${device.product} · ${device.media.serial}`,
                    media: device.media,
                    revision: device.revision
                },
                evidence: {
                    'disable-access': { state: 'available' },
                    'enable-access': { state: 'available' }
                },
                mode: 'basic',
                resetWithoutPassword: false,
                workflow
            }
        }
    }
}

/**
 * Adds forbidden fixture data to detached summaries so the real support
 * service proves that it exports only allowlisted fields.
 * @param {object[]} devices - Current strict renderer devices.
 * @returns {object[]} Detached summary inputs with one forbidden property.
 */
function createSummaryDevices(devices) {
    const summaries = []
    for (const device of devices) summaries.push({ ...device, password: 'must-not-export' })
    return summaries
}

/**
 * Checks whether one admitted utility kind reached the structured boundary.
 * @param {object[]} requests - Recorded utility requests.
 * @param {string} kind - Published operation kind.
 * @returns {boolean} True when a matching request exists.
 */
function hasUtilityStart(requests, kind) {
    for (const request of requests) {
        if (request.kind === kind) return true
    }
    return false
}

/**
 * Verifies the complete renderer/store/workflow/support fixture journey and
 * preserves the boundary between application proof and hardware proof.
 * @param {import('node:test').TestContext} context - Node test lifecycle.
 * @returns {Promise<void>} Resolves after every asynchronous UI result settles.
 */
async function testApplicationFlow(context) {
    const primary = createFlowDevice({
        id: 'rdx:integration-primary',
        mediaSerial: 'MEDIA-INTEGRATION-01',
        product: 'RDX QuikStor USB3+ External',
        revision: 21,
        serial: 'DOCK-INTEGRATION-01'
    })
    const secondary = createFlowDevice({
        id: 'rdx:integration-secondary',
        mediaSerial: 'MEDIA-INTEGRATION-02',
        product: 'RDX QuikStor USB3+ Secondary',
        revision: 8,
        serial: 'DOCK-INTEGRATION-02'
    })
    const initial = createFixtureState({ mode: 'one-device' })
    const store = createStore({ ...initial, devices: [primary, secondary], selectedDeviceId: secondary.id })
    const dom = new JSDOM('<!doctype html><html><body><div id="app"></div></body></html>', {
        pretendToBeVisual: true,
        url: 'file:///openrdxmanager/src/index.html'
    })
    const document = dom.window.document
    const root = document.querySelector('#app')
    const intents = []
    const utilityStarts = []
    const languageChanges = []
    const writes = []
    const access = { current: 'disabled' }
    const logger = {
        /** @returns {Promise<object>} Returns one redacted renderer-safe activity entry. */
        async list() {
            return {
                entries: [
                    {
                        id: 'activity:integration-1',
                        messageKey: 'activity.failure',
                        occurredAt: '2026-08-29T08:30:00.000Z',
                        severity: 'error',
                        supportCorrelationId: 'support:integration-1'
                    }
                ],
                ok: true
            }
        }
    }
    const summaryService = new SupportSummaryService({
        /** @returns {Promise<object>} Collects production-shaped local summary input. */
        async collect() {
            return {
                application: { name: 'OpenRDXManager', version: '0.1.0' },
                devices: createSummaryDevices(store.getState().devices),
                generatedAt: '2026-08-29T08:45:00.000Z',
                host: { architecture: 'arm64', platform: 'darwin', release: '25.6.0' },
                service: { hardwareReady: false, hardwareVerified: false, mode: 'no-device', status: 'ready' }
            }
        },
        /** @param {string} defaultName - Documented export filename. @returns {Promise<object>} Controlled safe destination. */
        async chooseDestination(defaultName) {
            return { canceled: false, filePath: `/safe/${defaultName}` }
        },
        /** @param {string} filePath - Controlled destination. @param {string} text - Sanitized export. @returns {Promise<void>} Records the write. */
        async writeText(filePath, text) {
            writes.push({ filePath, text })
        }
    })
    const supportApi = {
        app: {
            /** @returns {Promise<object>} Returns bounded local application metadata. */
            async getInfo() {
                return { app: { name: 'OpenRDXManager', platform: 'darwin', version: '0.1.0' }, ok: true }
            }
        },
        logs: {
            /** @returns {Promise<object>} Returns redacted local activity. */
            async list() {
                return logger.list()
            },
            /** @returns {Promise<object>} Exports through the real summary service. */
            async export() {
                return summaryService.exportActivity(logger)
            },
            /** @param {{enabled: boolean}} _request - Bounded logging preference. @returns {Promise<object>} Accepts the fixture preference. */
            async setEnabled(_request) {
                return { ok: true }
            }
        },
        settings: {
            /** @param {object} request - One bounded setting change. @returns {Promise<object>} Returns the complete accepted settings record. */
            async update(request) {
                return { ok: true, settings: { ...store.getState().settings, ...request } }
            }
        },
        support: {
            /** @returns {Promise<object>} Generates through the real allowlist-only service. */
            async generateSummary() {
                return summaryService.generateSummary()
            }
        },
        updates: {
            /** @param {{silent: boolean}} request - Read-only update-check mode. @returns {Promise<object>} Returns a deterministic unavailable result. */
            async check(request) {
                return {
                    firmware: { status: 'not-applicable', updates: [] },
                    manager: { currentVersion: '0.1.0', status: 'current' },
                    ok: true,
                    silent: request.silent
                }
            }
        }
    }
    const intentAdapter = createRendererIntentAdapter({
        /** @param {object} intent - Validated renderer intent. @returns {boolean} Records admission. */
        invoke(intent) {
            intents.push(intent)
            return true
        },
        supportedIntents: ['operation', 'retry-service']
    })
    const utilityController = {
        /** @returns {boolean} Makes every requested fixture utility boundary available. */
        isAvailable() {
            return true
        },
        /** @param {object} request - Closed structured utility request. @returns {Promise<object>} Records accepted admission. */
        async start(request) {
            utilityStarts.push(request)
            return { ok: true, operationId: `op:${request.kind}` }
        }
    }
    const controller = mountApplication(root, {
        intentAdapter,

        /** @param {string} language - Accepted language code. @returns {boolean} Records the renderer handoff. */
        onLanguageChanged(language) {
            languageChanges.push(language)
            return true
        },
        platform: 'darwin',
        securityStateProvider: createSecurityStateProvider(access),
        store,
        supportApi,
        utilityController
    })
    /** @returns {void} Releases renderer subscriptions and the isolated DOM. */
    function cleanup() {
        controller.destroy()
        dom.window.close()
    }
    context.after(cleanup)

    assert.match(document.querySelector('main').textContent, /RDX QuikStor USB3\+ Secondary/)
    document.querySelector(`[data-device-id="${primary.id}"]`).click()
    assert.equal(store.getState().selectedDeviceId, primary.id)
    assert.match(document.querySelector('main').textContent, /DOCK-INTEGRATION-01/)
    assert.match(document.querySelector('main').textContent, /2\.83/)

    openArea(document, 'encryption')
    assert.equal(document.querySelector('[data-access-status]').dataset.accessStatus, 'disabled')
    assert.equal(document.querySelector('[data-action="enable-access"]').disabled, false)
    assert.equal(document.querySelector('[data-action="disable-access"]').disabled, true)
    access.current = 'enabled'
    store.dispatch({ device: primary, type: 'device/refreshed' })
    assert.equal(document.querySelector('[data-access-status]').dataset.accessStatus, 'enabled')
    assert.equal(document.querySelector('[data-action="enable-access"]').disabled, true)
    assert.equal(document.querySelector('[data-action="disable-access"]').disabled, false)

    openArea(document, 'tests')
    const diagnosticHarness = { document, intents, primary, secondary, store }
    runDiagnostic(diagnosticHarness, 'self-test', 'diagnostic-running')
    runDiagnostic(diagnosticHarness, 'led-test', 'led-testing')
    runDiagnostic(diagnosticHarness, 'write-read-test', 'host-reading')

    openArea(document, 'utilities')
    const safeEject = document.querySelector('[data-action="eject-safe"]')
    assert.equal(safeEject.disabled, false)
    safeEject.click()
    await settleRenderer()
    assert.deepEqual(utilityStarts.at(-1), {
        deviceId: primary.id,
        deviceRevision: primary.revision,
        kind: 'eject-safe'
    })

    const modeSelect = document.querySelector('[data-utility-mode]')
    const modeAction = document.querySelector('[data-action="set-drive-mode"]')
    assert.equal(modeSelect.value, 'removable')
    assert.equal(modeAction.disabled, true)
    assert.match(modeAction.textContent, /Current mode/i)

    const firmwareAction = document.querySelector('[data-action="start-firmware"]')
    assert.equal(firmwareAction.disabled, true)
    assert.match(firmwareAction.closest('[data-feature="firmware"]').textContent, /Eject the cartridge/i)
    firmwareAction.click()
    assert.equal(hasUtilityStart(utilityStarts, 'firmware-update'), false)

    const formatInput = document.querySelector('[data-format-confirmation]')
    const formatAction = document.querySelector('[data-action="start-format"]')
    formatInput.value = 'WRONG-CARTRIDGE'
    formatInput.dispatchEvent(new dom.window.Event('input', { bubbles: true }))
    assert.equal(formatAction.disabled, true)
    formatAction.click()
    assert.equal(hasUtilityStart(utilityStarts, 'format'), false)

    const language = document.querySelector('[data-setting="language"]')
    language.value = 'de'
    language.dispatchEvent(new dom.window.Event('change', { bubbles: true }))
    await settleRenderer()
    assert.equal(store.getState().settings.language, 'de')
    assert.deepEqual(languageChanges, ['de'])
    assert.equal(document.querySelector('[data-setting="language"]').value, 'de')

    document.querySelector('[data-action="open-event-log"]').click()
    await settleRenderer()
    assert.equal(document.querySelectorAll('[data-activity-entry]').length, 1)
    document.querySelector('[data-action="export-logs"]').click()
    await settleRenderer()
    assert.equal(writes[0].filePath, '/safe/RDXManagerActivity.txt')
    assert.match(writes[0].text, /support:integration-1/)
    assert.doesNotMatch(writes[0].text, /must-not-export/)
    document.querySelector('[data-action="close-support-panel"]').click()

    document.querySelector('[data-action="open-support"]').click()
    await settleRenderer()
    document.querySelector('[data-action="generate-summary"]').click()
    await settleRenderer()
    assert.equal(writes[1].filePath, '/safe/RdxSystemSummary.txt')
    assert.match(writes[1].text, /Firmware revision: 0283/)
    assert.doesNotMatch(writes[1].text, /must-not-export|password/i)
    document.querySelector('[data-action="close-support-panel"]').click()

    store.dispatch({ reason: 'service-crashed', type: 'service/unavailable' })
    assert.equal(store.getState().devices.length, 0)
    assert.match(document.querySelector('[role="alert"]').textContent, /service-crashed/)
    document.querySelector('[data-action="retry-service"]').click()
    assert.deepEqual(intents.at(-1), { type: 'retry-service' })

    store.dispatch({ epoch: 1, hardwareReady: true, hardwareVerified: false, listRevision: 0, mode: 'native', platformCapability: { state: 'available' }, privileged: true, type: 'service/ready' })
    store.dispatch({ devices: [primary, secondary], epoch: 1, listRevision: 1, type: 'device/list-replaced' })
    assert.equal(store.getState().service.status, 'ready')
    assert.equal(store.getState().devices.length, 2)
    assert.equal(store.getState().selectedDeviceId, primary.id)
    assert.match(document.querySelector('main').textContent, /DOCK-INTEGRATION-01/)
}

test('mounted application completes the documented fixture flow without manufacturing hardware proof', testApplicationFlow)
