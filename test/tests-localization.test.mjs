// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { renderTestsView } from '../src/renderer/views/tests-view.mjs'
import { createDiagnosticResult, createDiagnosticWorkflow } from '../src/renderer/workflows/test-workflow.mjs'
import { completeDeviceSnapshot } from './helpers/device-snapshot.mjs'

/** @returns {{dom: JSDOM, document: Document}} Isolated Tests DOM. */
function createDom() {
    const dom = new JSDOM('<!doctype html><html><body></body></html>', {
        pretendToBeVisual: true,
        url: 'file:///openrdxmanager/src/index.html'
    })
    return { dom, document: dom.window.document }
}

/**
 * Returns a conspicuous translation proving the exact message key and bounded
 * interpolation parameters reached the visible presentation boundary.
 * @param {string} key - Requested bundled message key.
 * @param {object} [params={}] - Bounded interpolation parameters.
 * @returns {string} Sentinel translation.
 */
function sentinelTranslator(key, params = {}) {
    const entries = Object.entries(params).sort(([left], [right]) => left.localeCompare(right))
    const suffix = entries.length === 0 ? '' : `:${entries.map(([name, value]) => `${name}=${value}`).join(',')}`
    return `§${key}${suffix}§`
}

/** @returns {object} Selected RDX fixture with every diagnostic available. */
function localizedFixture() {
    return completeDeviceSnapshot({
        capabilities: {
            'led-test': { state: 'available' },
            'self-test': { state: 'available' },
            'write-read-test': { state: 'available' }
        },
        id: 'rdx:tests-localization',
        media: null,
        product: 'RAW RDX QuikStor',
        revision: 17,
        serial: 'RAW-SERIAL-17',
        vendor: 'RAW-VENDOR'
    })
}

/** @param {object} overrides - Terminal event overrides. @returns {object} Diagnostic operation. */
function diagnosticOperation(overrides = {}) {
    return {
        deviceId: 'rdx:tests-localization',
        deviceRevision: 17,
        id: 'op:tests-localization',
        kind: 'self-test',
        stage: 'diagnostic-cleanup',
        status: 'succeeded',
        ...overrides
    }
}

test('Tests view translates visible copy while preserving raw device and protocol evidence', () => {
    const { dom, document } = createDom()
    const view = renderTestsView(localizedFixture(), {
        activeOperation: diagnosticOperation({ kind: 'led-test', progress: 0.75, stage: 'led-restoring', status: 'progress' }),
        document,
        lastOperation: diagnosticOperation(),
        operationIntentAvailable: true,
        provenance: 'fixture',
        translator: sentinelTranslator
    })
    const copy = view.textContent

    for (const key of ['tests.eyebrow', 'tests.title', 'tests.description', 'tests.diagnostic.deviceEyebrow', 'tests.diagnostic.hostFilesystemEyebrow', 'tests.selfTest.title', 'tests.selfTest.description', 'tests.selfTest.action', 'tests.ledTest.protocol', 'tests.writeReadTest.protocol', 'tests.twoPass.title', 'tests.twoPass.first', 'tests.prerequisites.title', 'tests.prerequisite.cartridgeObservation.noMedia', 'tests.stage.ledRestoring', 'tests.result.passedTitle', 'tests.result.deviceResult', 'tests.fixtureNote']) {
        assert.match(copy, new RegExp(`§${key}(?::|\\§)`))
    }
    for (const untranslated of ['Hardware & Media Tests', 'DEVICE DIAGNOSTIC', 'Recommended two-pass isolation', 'Validated RDX dock', 'Normal LED ownership is restored', 'Fixture preview only']) {
        assert.doesNotMatch(copy, new RegExp(untranslated.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&')))
    }
    assert.match(copy, /RAW RDX QuikStor/)
    assert.match(copy, /RAW-SERIAL-17/)
    assert.match(copy, /1D 04 00 00 00 00/)
    assert.match(copy, /SCSI GOOD/)

    dom.window.close()
})

test('diagnostic workflow models carry message keys instead of fixed English copy', () => {
    const workflow = createDiagnosticWorkflow(localizedFixture(), 'self-test')

    assert.equal(workflow.titleKey, 'tests.selfTest.title')
    assert.equal(workflow.descriptionKey, 'tests.selfTest.description')
    assert.equal(workflow.actionLabelKey, 'tests.selfTest.action')
    assert.equal(workflow.stages[0].labelKey, 'tests.stage.diagnosticRunning')
    assert.equal(workflow.prerequisites[0].labelKey, 'tests.prerequisite.validatedDock.label')
    assert.equal(workflow.prerequisites[1].detailKey, 'tests.prerequisite.cartridgeState.noMedia')
    assert.equal(workflow.twoPass.firstKey, 'tests.twoPass.first')
    for (const fixedCopyProperty of ['actionLabel', 'description', 'title']) assert.equal(Object.hasOwn(workflow, fixedCopyProperty), false)
    for (const stage of workflow.stages) assert.equal(Object.hasOwn(stage, 'label'), false)
    for (const prerequisite of workflow.prerequisites) {
        assert.equal(Object.hasOwn(prerequisite, 'label'), false)
        assert.equal(Object.hasOwn(prerequisite, 'detail'), false)
    }
})

test('diagnostic result models localize presentation but preserve raw result tokens', () => {
    const succeeded = createDiagnosticResult(diagnosticOperation())
    const failed = createDiagnosticResult(
        diagnosticOperation({
            error: {
                cleanupEvidence: [{ code: 'cleanup-incomplete', stage: 'diagnostic-cleanup' }],
                code: 'diagnostic-failed',
                retryable: false,
                stage: 'diagnostic-running',
                supportCorrelationId: 'support:raw-17'
            },
            status: 'failed'
        })
    )

    assert.equal(succeeded.titleKey, 'tests.result.passedTitle')
    assert.equal(succeeded.testTitleKey, 'tests.selfTest.title')
    assert.deepEqual(succeeded.evidence[0], { labelKey: 'tests.result.deviceResult', value: 'SCSI GOOD' })
    assert.equal(Object.hasOwn(succeeded, 'title'), false)
    assert.equal(Object.hasOwn(succeeded, 'summary'), false)

    assert.deepEqual(failed.primaryFailure, {
        key: 'tests.result.failureAt',
        params: { code: 'diagnostic-failed', stage: 'diagnostic-running' }
    })
    assert.deepEqual(failed.cleanupFailures, [
        {
            key: 'tests.result.failureAt',
            params: { code: 'cleanup-incomplete', stage: 'diagnostic-cleanup' }
        }
    ])
    assert.deepEqual(failed.evidence, [
        { labelKey: 'tests.result.supportId', value: 'support:raw-17' },
        { labelKey: 'tests.result.retryable', valueKey: 'tests.value.no' }
    ])
})

test('Tests view localizes an unavailable support ID instead of exposing its internal token', () => {
    const { dom, document } = createDom()
    const view = renderTestsView(localizedFixture(), {
        document,
        lastOperation: diagnosticOperation({ error: { code: 'diagnostic-failed', retryable: false, stage: 'diagnostic-running' }, status: 'failed' }),
        operationIntentAvailable: true,
        provenance: 'fixture',
        translator: sentinelTranslator
    })
    const result = view.querySelector('[data-test-result="self-test"]').textContent

    assert.match(result, /§state\.notReported§/)
    assert.doesNotMatch(result, /not-reported/)
    dom.window.close()
})
