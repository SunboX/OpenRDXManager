// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createRendererIntentAdapter } from '../src/renderer/intent-adapter.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { deviceSnapshotSchema } from '../src/shared/schemas.mjs'
import { completeDeviceSnapshot } from './helpers/device-snapshot.mjs'
import { createDiagnosticResult, createDiagnosticWorkflow } from '../src/renderer/workflows/test-workflow.mjs'
import { renderTestsView } from '../src/renderer/views/tests-view.mjs'

/** @returns {{dom: JSDOM, document: Document}} Isolated diagnostic workflow DOM. */
function createDom() {
    const dom = new JSDOM('<!doctype html><html><head></head><body><div id="app"></div></body></html>', {
        pretendToBeVisual: true,
        url: 'file:///openrdxmanager/src/index.html'
    })
    return { dom, document: dom.window.document }
}

/** @param {object|null} media - Concise media fixture. @returns {object} Complete selected RDX snapshot. */
function diagnosticDevice(media) {
    return completeDeviceSnapshot({
        capabilities: {
            'led-test': { state: 'available' },
            'self-test': { state: 'available' },
            'write-read-test': { state: 'available' }
        },
        id: 'rdx:diagnostic-ui',
        media,
        product: 'RDX QuikStor USB3+ External',
        revision: 11,
        serial: 'DIAGNOSTIC11',
        vendor: 'TANDBERG'
    })
}

/** @returns {object} Inserted but unformatted, read-only, and full cartridge. */
function unformattedReadOnlyMediaFixture() {
    return diagnosticDevice({
        capacityBytes: 1_000_000,
        encrypted: false,
        id: 'media:blocked-test',
        label: 'Blocked test cartridge',
        serial: 'BLOCKED11',
        status: 'ready',
        usedBytes: 1_000_000,
        writable: false
    })
}

/** @returns {object} Inserted, formatted, writable cartridge with sufficient space. */
function readyMediaFixture() {
    return diagnosticDevice({
        capacityBytes: 2_000_000,
        encrypted: false,
        filesystem: 'exfat',
        id: 'media:ready-test',
        label: 'Ready test cartridge',
        mounted: true,
        serial: 'READY11',
        status: 'ready',
        usedBytes: 500_000,
        writable: true
    })
}

/** @returns {object} Strict service-shaped snapshot with mounted-volume facts and no filesystem label. */
function productionMountedMediaFixture() {
    const snapshot = structuredClone(readyMediaFixture())
    delete snapshot.media.filesystem
    snapshot.media.details.mounted = { availability: 'reported', value: true }
    return deviceSnapshotSchema.parse(snapshot)
}

/** @param {object} overrides - Terminal event overrides. @returns {object} Matching terminal renderer operation. */
function terminalOperation(overrides) {
    return {
        deviceId: 'rdx:diagnostic-ui',
        deviceRevision: 11,
        id: 'op:diagnostic-ui',
        kind: 'self-test',
        stage: 'complete',
        status: 'succeeded',
        ...overrides
    }
}

/** @returns {void} Verifies every independently actionable host prerequisite is visible. */
function testWriteReadPrerequisites() {
    const { dom, document } = createDom()
    const view = renderTestsView(unformattedReadOnlyMediaFixture(), { document, operationIntentAvailable: true })
    const card = view.querySelector('[data-test-kind="write-read-test"]')

    assert.match(card.textContent, /formatted cartridge/i)
    assert.match(card.textContent, /write access/i)
    assert.match(card.textContent, /free space/i)
    assert.equal(card.querySelector('[data-prerequisite="media-inserted"]').dataset.prerequisiteState, 'met')
    assert.equal(card.querySelector('[data-prerequisite="media-formatted"]').dataset.prerequisiteState, 'unmet')
    assert.equal(card.querySelector('[data-prerequisite="write-access"]').dataset.prerequisiteState, 'unmet')
    assert.equal(card.querySelector('[data-prerequisite="free-space"]').dataset.prerequisiteState, 'unmet')
    assert.equal(card.querySelector('[data-action="write-read-test"]').disabled, true)

    dom.window.close()
}

/** @returns {void} Verifies native mounted-volume evidence enables real Write/Read diagnostics without fixture labels. */
function testProductionMountedWriteReadReadiness() {
    const device = productionMountedMediaFixture()
    const workflow = createDiagnosticWorkflow(device, 'write-read-test', { operationIntentAvailable: true })

    assert.equal(device.media.filesystem, undefined)
    assert.equal(workflow.prerequisites.find((item) => item.id === 'media-formatted').met, true)
    assert.equal(workflow.capability.state, 'available')
}

/** @returns {void} Verifies the manual's two-pass isolation sequence remains explicit. */
function testSelfTestTwoPassGuidance() {
    const { dom, document } = createDom()
    const device = diagnosticDevice(null)
    const view = renderTestsView(device, { document, operationIntentAvailable: true })
    const card = view.querySelector('[data-test-kind="self-test"]')
    const workflow = createDiagnosticWorkflow(device, 'self-test')

    assert.match(card.textContent, /first.*without a cartridge/i)
    assert.match(card.textContent, /then insert a cartridge and repeat/i)
    assert.match(card.textContent, /1D 04 00 00 00 00/)
    assert.equal(card.querySelector('[data-action="self-test"]').disabled, false)
    assert.deepEqual(
        workflow.stages.map((stage) => stage.id),
        ['diagnostic-running', 'diagnostic-cleanup']
    )
    assert.equal(workflow.twoPass.currentPass, 'drive-only')

    dom.window.close()
}

/** @returns {void} Verifies LED observation guidance and exact active stage presentation. */
function testLedProgressAndLock() {
    const { dom, document } = createDom()
    const activeOperation = terminalOperation({ kind: 'led-test', stage: 'led-restoring', status: 'progress', progress: 0.75, cancellationState: 'closed' })
    const view = renderTestsView(diagnosticDevice(null), {
        activeOperation,
        document,
        locked: true,
        operationIntentAvailable: true
    })
    const ledCard = view.querySelector('[data-test-kind="led-test"]')

    assert.match(ledCard.textContent, /dock LED can be observed without a cartridge/i)
    assert.match(ledCard.textContent, /insert a cartridge to observe its LED/i)
    assert.equal(ledCard.querySelector('[data-progress-stage="led-restoring"]').dataset.stageState, 'active')
    assert.equal(ledCard.querySelector('progress').value, 0.75)
    assert.equal(view.querySelectorAll('[data-test-action]:not([disabled])').length, 0)
    assert.match(view.textContent, /One operation at a time/i)

    dom.window.close()
}

/** @returns {void} Verifies success is earned only after operation-specific cleanup. */
function testSuccessEvidence() {
    const led = createDiagnosticResult(terminalOperation({ kind: 'led-test' }))
    const writeRead = createDiagnosticResult(terminalOperation({ kind: 'write-read-test' }))
    const selfTest = createDiagnosticResult(terminalOperation({ kind: 'self-test' }))

    assert.equal(led.status, 'succeeded')
    assert.deepEqual(led.evidence, [
        { labelKey: 'tests.result.deviceResult', value: 'SCSI GOOD' },
        { labelKey: 'tests.result.ledCleanup', valueKey: 'tests.result.normalLedOwnershipRestored' }
    ])
    assert.deepEqual(writeRead.evidence, [
        { labelKey: 'tests.result.dataPath', valueKey: 'tests.result.dataPathPassed' },
        { labelKey: 'tests.result.testFileCleanup', valueKey: 'tests.result.testFileRemoved' }
    ])
    assert.deepEqual(selfTest.evidence, [
        { labelKey: 'tests.result.deviceResult', value: 'SCSI GOOD' },
        { labelKey: 'tests.result.finalValidation', valueKey: 'tests.result.deviceRevalidated' }
    ])
}

/** @returns {void} Verifies primary and cleanup failures cannot overwrite each other. */
function testSeparateFailureEvidence() {
    const error = {
        attemptHistory: [],
        category: 'platform',
        cleanupEvidence: [{ code: 'cleanup-incomplete', dispatchCertainty: 'completion-unknown', stage: 'host-cleanup' }],
        code: 'data-mismatch',
        dispatchCertainty: 'definitely-rejected',
        messageKey: 'operation.failed',
        retryable: false,
        stage: 'host-reading',
        supportCorrelationId: 'support:diagnostic-ui'
    }
    const result = createDiagnosticResult(terminalOperation({ error, kind: 'write-read-test', stage: 'host-cleanup', status: 'failed' }))
    const { dom, document } = createDom()
    const view = renderTestsView(readyMediaFixture(), {
        document,
        lastOperation: terminalOperation({ error, kind: 'write-read-test', stage: 'host-cleanup', status: 'failed' }),
        operationIntentAvailable: true
    })
    const panel = view.querySelector('[data-test-kind="write-read-test"] [data-result-status="failed"]')

    assert.deepEqual(result.primaryFailure, {
        key: 'tests.result.failureAt',
        params: { code: 'data-mismatch', stage: 'host-reading' }
    })
    assert.deepEqual(result.cleanupFailures, [
        {
            key: 'tests.result.failureAt',
            params: { code: 'cleanup-incomplete', stage: 'host-cleanup' }
        }
    ])
    assert.notEqual(panel.querySelector('[data-primary-result]'), null)
    assert.notEqual(panel.querySelector('[data-cleanup-result]'), null)
    assert.match(panel.querySelector('[data-primary-result]').textContent, /data-mismatch/)
    assert.match(panel.querySelector('[data-cleanup-result]').textContent, /cleanup-incomplete/)

    dom.window.close()
}

/** @returns {void} Verifies action callbacks emit only a published operation kind. */
function testBoundedActionCallback() {
    const { dom, document } = createDom()
    const calls = []
    /** @param {string} kind - Bounded diagnostic operation kind. @returns {void} Records one local action. */
    function recordAction(kind) {
        calls.push(kind)
    }
    const view = renderTestsView(readyMediaFixture(), { document, onAction: recordAction, operationIntentAvailable: true })

    view.querySelector('[data-action="led-test"]').click()
    view.querySelector('[data-action="write-read-test"]').click()

    assert.deepEqual(calls, ['led-test', 'write-read-test'])
    dom.window.close()
}

/** @returns {void} Verifies the Tests tab is connected to the existing intent and lock boundary. */
function testShellIntegration() {
    const { dom, document } = createDom()
    const device = readyMediaFixture()
    const calls = []
    /** @param {object} intent - Validated renderer intent. @returns {boolean} Records accepted intent. */
    function recordIntent(intent) {
        calls.push(intent)
        return true
    }
    const adapter = createRendererIntentAdapter({ invoke: recordIntent, supportedIntents: ['operation'] })
    const store = createStore({
        activeArea: 'tests',
        activeOperation: null,
        activity: [],
        authenticationSessions: {},
        devices: [device],
        discovery: { diagnostics: { acceptedCount: 1, candidateCount: 1, rejections: [] }, epoch: 1, listRevision: 1, scanStatus: 'idle', selectionInitialized: true, tombstones: {} },
        lastOperation: null,
        provenance: 'fixture',
        selectedDeviceId: device.id,
        service: { status: 'ready' },
        settings: { autoScan: true }
    })
    const controller = mountApplication(document.querySelector('#app'), { intentAdapter: adapter, store })

    assert.equal(document.querySelector('[data-tests-view]') !== null, true)
    document.querySelector('[data-action="self-test"]').click()
    assert.deepEqual(calls, [{ deviceId: 'rdx:diagnostic-ui', deviceRevision: 11, kind: 'self-test', type: 'operation' }])

    controller.destroy()
    dom.window.close()
}

/** @returns {Promise<void>} Verifies the complete workspace has a responsive dark diagnostic surface. */
async function testDiagnosticStyles() {
    const { dom, document } = createDom()
    const style = document.createElement('style')
    style.textContent = `${await readFile(new URL('../src/styles/tokens.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/base.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/operation-components.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/test-workflows.css', import.meta.url), 'utf8')}`
    document.head.append(style)
    const view = renderTestsView(readyMediaFixture(), {
        document,
        lastOperation: terminalOperation({ kind: 'led-test' }),
        operationIntentAvailable: true
    })
    document.body.append(view)

    assert.equal(document.defaultView.getComputedStyle(view).display, 'grid')
    assert.equal(document.defaultView.getComputedStyle(view.querySelector('[data-test-kind="self-test"]')).display, 'grid')
    assert.equal(document.defaultView.getComputedStyle(view.querySelector('[data-test-kind="led-test"] [data-result-status="succeeded"]')).borderTopColor, 'rgba(84, 237, 176, 0.56)')

    dom.window.close()
}

/** @returns {Promise<void>} Verifies diagnostic progress stays neutral until terminal success. */
async function testDiagnosticProgressStylesRemainNeutral() {
    const { dom, document } = createDom()
    const style = document.createElement('style')
    style.textContent = `${await readFile(new URL('../src/styles/tokens.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/base.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/operation-components.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/test-workflows.css', import.meta.url), 'utf8')}`
    document.head.append(style)
    const view = renderTestsView(readyMediaFixture(), {
        activeOperation: terminalOperation({ kind: 'self-test', stage: 'diagnostic-cleanup', status: 'progress', progress: 0.7 }),
        document,
        locked: true,
        operationIntentAvailable: true
    })
    document.body.append(view)

    const complete = view.querySelector('[data-progress-stage="diagnostic-running"]')
    const active = view.querySelector('[data-progress-stage="diagnostic-cleanup"]')
    assert.equal(document.defaultView.getComputedStyle(complete).color, 'rgb(168, 184, 193)')
    assert.equal(document.defaultView.getComputedStyle(active).color, 'rgb(168, 184, 193)')

    dom.window.close()
}

test('write-read test explains every unmet prerequisite', testWriteReadPrerequisites)
test('production mounted-volume facts enable Write/Read without a fixture filesystem label', testProductionMountedWriteReadReadiness)
test('self-test presents the documented no-media then with-media two-pass procedure', testSelfTestTwoPassGuidance)
test('LED test exposes observation guidance, staged progress, and the operation lock', testLedProgressAndLock)
test('diagnostic success retains operation-specific pass and cleanup evidence', testSuccessEvidence)
test('diagnostic failures distinguish the primary result from cleanup failure', testSeparateFailureEvidence)
test('diagnostic actions emit only bounded published operation kinds', testBoundedActionCallback)
test('Tests workspace is connected to the Electron renderer operation boundary', testShellIntegration)
test('Tests workspace uses its responsive dark diagnostic surface', testDiagnosticStyles)
test('diagnostic progress remains neutral until terminal success', testDiagnosticProgressStylesRemainNeutral)
