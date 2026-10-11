// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { englishCatalog } from '../src/locales/en.mjs'
import { renderCapabilityState } from '../src/renderer/components/capability-state.mjs'
import { requestExactDeviceConfirmation } from '../src/renderer/components/confirmation-dialog.mjs'
import { renderOperationDrawer, renderOperationLockBanner } from '../src/renderer/components/operation-drawer.mjs'
import { renderProgressTimeline } from '../src/renderer/components/progress-timeline.mjs'
import { renderOperationResult } from '../src/renderer/components/result-panel.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'
import { renderShell } from '../src/renderer/views/shell-view.mjs'
import { RiskClass } from '../src/shared/contracts.mjs'

const translator = createTranslator(englishCatalog, englishCatalog)

/**
 * Creates an isolated visual DOM for one operation-component behavior.
 * @returns {{dom: JSDOM, document: Document}} Owned DOM and document.
 */
function createComponentDom() {
    const dom = new JSDOM('<!doctype html><html><body><button id="origin">Open workflow</button><main id="mount"></main></body></html>', {
        pretendToBeVisual: true,
        url: 'file:///openrdxmanager/src/index.html'
    })
    return { dom, document: dom.window.document }
}

/**
 * Dispatches a cancellable keyboard event from the supplied element.
 * @param {JSDOM} dom - DOM owning the keyboard constructor.
 * @param {Element} target - Event target.
 * @param {string} key - Keyboard key.
 * @param {boolean} [shiftKey=false] - Whether Shift is held.
 * @returns {KeyboardEvent} Dispatched event for default-prevention assertions.
 */
function pressKey(dom, target, key, shiftKey = false) {
    const event = new dom.window.KeyboardEvent('keydown', { bubbles: true, cancelable: true, key, shiftKey })
    target.dispatchEvent(event)
    return event
}

/** @returns {void} Verifies fail-closed evidence copy and action admission. */
function testEvidenceIncompleteCapability() {
    const { document } = createComponentDom()
    const node = renderCapabilityState(
        {
            action: { labelKey: 'operation.openWorkflow' },
            help: { labelKey: 'operation.openEvidenceHelp' },
            reason: 'security-selector-unproven',
            state: 'evidence-incomplete',
            titleKey: 'operation.capabilityTitle'
        },
        { document, translator }
    )

    assert.equal(node.dataset.capabilityState, 'evidence-incomplete')
    assert.equal(node.querySelector('button:not([disabled])'), null)
    assert.equal(node.querySelector('[data-capability-action]').getAttribute('aria-describedby'), node.querySelector('[data-capability-reason]').id)
    assert.match(node.querySelector('[data-capability-reason]').textContent, /security-selector-unproven/)
    assert.match(node.textContent, /Evidence is incomplete/)
    assert.notEqual(node.querySelector('.ph-warning-diamond[aria-hidden="true"]'), null)
}

/** @returns {void} Verifies available capability action labeling and dispatch. */
function testAvailableCapabilityAction() {
    const { dom, document } = createComponentDom()
    const calls = []
    /** @returns {void} Records the available capability action. */
    function handleAction() {
        calls.push('open')
    }
    const node = renderCapabilityState(
        {
            action: { label: 'Open self-test' },
            description: 'Run the non-destructive diagnostic.',
            state: 'available',
            title: 'Self-test'
        },
        { document, onAction: handleAction, translator }
    )
    document.querySelector('#mount').append(node)

    const action = node.querySelector('[data-capability-action]')
    action.dispatchEvent(new dom.window.MouseEvent('click', { bubbles: true }))

    assert.equal(action.disabled, false)
    assert.equal(action.textContent.trim(), 'Open self-test')
    assert.deepEqual(calls, ['open'])
    assert.notEqual(action.querySelector('.ph-arrow-right[aria-hidden="true"]'), null)
}

/** @returns {Promise<void>} Verifies byte-exact destructive confirmation. */
async function testExactDestructiveConfirmation() {
    const { dom, document } = createComponentDom()
    document.querySelector('#origin').focus()
    const dialog = requestExactDeviceConfirmation(
        {
            deviceLabel: 'RDX QuikStor · 7810544062',
            expected: '858601695580',
            operationLabel: 'Format cartridge',
            risk: 'destructive'
        },
        { document, translator }
    )

    const expected = dialog.element.querySelector('.confirmation-dialog__expected')
    const feedback = dialog.element.querySelector('[data-confirmation-mismatch]')
    const describedBy = dialog.input.getAttribute('aria-describedby').split(/\s+/)
    assert.deepEqual(describedBy, [dialog.element.querySelector('.confirmation-dialog > p').id, expected.id, feedback.id])
    assert.equal(feedback.getAttribute('role'), 'status')
    assert.equal(feedback.getAttribute('aria-live'), 'polite')
    assert.equal(feedback.getAttribute('aria-atomic'), 'true')
    assert.equal(feedback.dataset.matchState, 'required')
    assert.equal(dialog.input.getAttribute('aria-invalid'), 'false')

    dialog.input.value = '7810544062'
    dialog.input.dispatchEvent(new dom.window.Event('input', { bubbles: true }))
    assert.equal(dialog.confirmButton.disabled, true)
    assert.equal(dialog.input.getAttribute('aria-invalid'), 'true')
    assert.equal(feedback.dataset.matchState, 'mismatch')
    assert.match(feedback.textContent, /does not match/i)
    const feedbackId = feedback.id
    const expectedId = expected.id

    dialog.input.value = '858601695580 '
    dialog.input.dispatchEvent(new dom.window.Event('input', { bubbles: true }))
    assert.equal(dialog.confirmButton.disabled, true)

    dialog.input.value = '858601695580'
    dialog.input.dispatchEvent(new dom.window.Event('input', { bubbles: true }))
    assert.equal(dialog.confirmButton.disabled, false)
    assert.equal(dialog.input.getAttribute('aria-invalid'), 'false')
    assert.equal(feedback.dataset.matchState, 'match')
    assert.match(feedback.textContent, /matches/i)
    assert.equal(feedback.id, feedbackId)
    assert.equal(expected.id, expectedId)
    dialog.confirmButton.click()

    assert.deepEqual(await dialog.closed, { confirmed: true, identity: '858601695580' })
    assert.equal(document.querySelector('[data-exact-device-confirmation]'), null)
    assert.equal(document.activeElement.id, 'origin')
}

/** @returns {Promise<void>} Verifies modal focus containment and safe dismissal policy. */
async function testConfirmationFocusAndEscape() {
    const safe = createComponentDom()
    safe.document.querySelector('#origin').focus()
    const dismissible = requestExactDeviceConfirmation({ expected: 'MEDIA-42', operationLabel: 'Force eject', risk: 'critical' }, { document: safe.document, escapeSafe: true, translator })
    dismissible.cancelButton.focus()
    const trapped = pressKey(safe.dom, dismissible.cancelButton, 'Tab')
    assert.equal(trapped.defaultPrevented, true)
    assert.equal(safe.document.activeElement, dismissible.input)
    const escaped = pressKey(safe.dom, dismissible.input, 'Escape')
    assert.equal(escaped.defaultPrevented, true)
    assert.deepEqual(await dismissible.closed, { confirmed: false, reason: 'escape' })
    assert.equal(safe.document.activeElement.id, 'origin')

    const unsafe = createComponentDom()
    const protectedDialog = requestExactDeviceConfirmation({ expected: 'MEDIA-99', operationLabel: 'Format cartridge', risk: 'destructive' }, { document: unsafe.document, escapeSafe: false, translator })
    const ignoredEscape = pressKey(unsafe.dom, protectedDialog.input, 'Escape')
    assert.equal(ignoredEscape.defaultPrevented, false)
    assert.notEqual(unsafe.document.querySelector('[data-exact-device-confirmation]'), null)
    assert.equal(protectedDialog.cancelButton, null)
    protectedDialog.close('test-cleanup')
    assert.deepEqual(await protectedDialog.closed, { confirmed: false, reason: 'test-cleanup' })
}

/** @returns {void} Verifies semantic timeline states and live progress copy. */
function testProgressTimelineAnnouncements() {
    const { document } = createComponentDom()
    const timeline = renderProgressTimeline(
        {
            activeStage: 'media-writing',
            progress: 0.42,
            stages: [
                { id: 'preflight', label: 'Preflight' },
                { id: 'media-writing', label: 'Writing media' },
                { id: 'verification', label: 'Verification' }
            ]
        },
        { document, translator }
    )

    assert.equal(timeline.hasAttribute('role'), false)
    assert.equal(timeline.hasAttribute('aria-live'), false)
    assert.equal(timeline.hasAttribute('aria-atomic'), false)
    assert.equal(timeline.querySelector('progress').value, 0.42)
    assert.deepEqual(readStageStates(timeline.querySelectorAll('[data-progress-stage]')), ['complete', 'active', 'pending'])
    const announcement = timeline.querySelector('[data-progress-announcement]')
    assert.equal(announcement.getAttribute('role'), 'status')
    assert.equal(announcement.getAttribute('aria-live'), 'polite')
    assert.equal(announcement.getAttribute('aria-atomic'), 'true')
    assert.match(announcement.textContent, /Writing media.*42 %/)
    for (const stage of timeline.querySelectorAll('[data-progress-stage]')) {
        assert.equal(stage.closest('[aria-live]'), null)
    }
}

/** @returns {void} Verifies every shared risk class has stable localized presentation. */
function testSharedRiskClassPresentation() {
    const { document } = createComponentDom()
    const expectedLabels = new Map([
        [RiskClass.READ_ONLY, 'Read-only'],
        [RiskClass.ROUTINE, 'Routine'],
        [RiskClass.CONFIGURATION, 'Configuration'],
        [RiskClass.CRITICAL, 'Critical'],
        [RiskClass.DESTRUCTIVE, 'Destructive']
    ])

    assert.deepEqual([...expectedLabels.keys()], Object.values(RiskClass))
    for (const risk of Object.values(RiskClass)) {
        const drawer = renderOperationDrawer({ risk, title: 'Risk mapping' }, { document, translator })
        assert.equal(drawer.dataset.risk, risk)
        assert.equal(drawer.querySelector('.eyebrow').textContent, expectedLabels.get(risk))
    }
}

/** @returns {void} Verifies complete drawer composition and caller-owned safe close. */
function testOperationDrawerComposition() {
    const { dom, document } = createComponentDom()
    const calls = []
    /** @returns {void} Records a safe drawer close request. */
    function handleClose() {
        calls.push('close')
    }
    const drawer = renderOperationDrawer(
        {
            activeOperation: {
                kindLabel: 'Firmware update',
                progress: 0.2,
                stage: 'image-validation',
                stages: [
                    { id: 'preflight', label: 'Preflight' },
                    { id: 'image-validation', label: 'Image validation' }
                ]
            },
            capability: {
                action: { label: 'Start firmware update' },
                reason: 'selected-image-not-validated',
                state: 'evidence-incomplete',
                title: 'Firmware readiness'
            },
            closeSafe: false,
            description: 'Validate the local image before transfer.',
            deviceIdentity: 'RDX QuikStor · 7810544062',
            risk: 'critical',
            title: 'Firmware update'
        },
        { document, onClose: handleClose, translator }
    )

    document.querySelector('#mount').append(drawer)
    assert.equal(drawer.getAttribute('role'), 'dialog')
    assert.equal(drawer.getAttribute('aria-modal'), 'false')
    assert.equal(drawer.querySelector('[data-operation-lock][role="status"]') !== null, true)
    assert.match(drawer.querySelector('[data-operation-lock]').textContent, /One operation at a time/)
    assert.equal(drawer.querySelector('[data-capability-state="evidence-incomplete"] [data-capability-action]').disabled, true)
    assert.equal(drawer.querySelector('[data-drawer-close]'), null)
    pressKey(dom, drawer, 'Escape')
    assert.deepEqual(calls, [])

    const closable = renderOperationDrawer({ closeSafe: true, description: 'No operation has started.', risk: 'routine', title: 'Self-test' }, { document, onClose: handleClose, translator })
    document.querySelector('#mount').append(closable)
    pressKey(dom, closable, 'Escape')
    assert.deepEqual(calls, ['close'])
}

/** @returns {void} Verifies the shared operation-lock reason contract. */
function testOperationLockBanner() {
    const { document } = createComponentDom()
    const banner = renderOperationLockBanner(
        {
            operationLabel: 'Format A&B cartridge',
            reasonId: 'format-drawer-lock-reason',
            stageLabel: 'Unmounting media'
        },
        { document, translator }
    )

    assert.equal(banner.id, 'format-drawer-lock-reason')
    assert.equal(banner.getAttribute('role'), 'status')
    assert.match(banner.textContent, /Format A&B cartridge/)
    assert.doesNotMatch(banner.textContent, /&amp;/)
    assert.match(banner.textContent, /Unmounting media/)
    assert.match(banner.textContent, /Device switching and conflicting actions are locked/)
}

/** @returns {void} Verifies the drawer lock reason cannot duplicate the active shell lock reason. */
function testOperationLockBannerIntegration() {
    const { document } = createComponentDom()
    const mount = document.querySelector('#mount')
    mount.innerHTML = renderShell(createFixtureState({ mode: 'busy' }), {
        intentAvailability: {},
        translator
    })
    mount.append(
        renderOperationDrawer(
            {
                activeOperation: { kindLabel: 'Firmware update', stage: 'firmware-writing', stageLabel: 'Writing firmware' },
                risk: RiskClass.CRITICAL,
                title: 'Firmware update'
            },
            { document, translator }
        )
    )

    assert.equal(document.querySelectorAll('#operation-lock-reason').length, 1)
    const allIds = []
    for (const node of document.querySelectorAll('[id]')) allIds.push(node.id)
    assert.equal(new Set(allIds).size, allIds.length)
}

/** @returns {void} Verifies terminal failure evidence stays independently visible. */
function testFailedResultPanel() {
    const { document } = createComponentDom()
    const panel = renderOperationResult(
        {
            cleanupFailure: 'Temporary verification file could not be removed.',
            evidence: [
                { label: 'Support ID', value: 'SUP-7X2' },
                { label: 'Verified bytes', value: '1048576' }
            ],
            help: { label: 'Open cleanup guidance' },
            primaryFailure: 'Read-back comparison failed.',
            status: 'failed',
            title: 'Write/read test failed'
        },
        { document, translator }
    )

    assert.equal(panel.getAttribute('role'), 'alert')
    assert.equal(panel.dataset.resultStatus, 'failed')
    assert.match(panel.querySelector('[data-primary-result]').textContent, /Read-back comparison failed/)
    assert.match(panel.querySelector('[data-cleanup-result]').textContent, /Temporary verification file/)
    assert.equal(panel.querySelectorAll('dl [data-result-evidence]').length, 2)
    assert.equal(panel.querySelector('[data-result-help]').disabled, false)
    assert.notEqual(panel.querySelector('.ph-x-circle[aria-hidden="true"]'), null)
}

/** @returns {void} Verifies fixture success remains evidence-honest. */
function testSuccessfulResultPanel() {
    const { document } = createComponentDom()
    const panel = renderOperationResult(
        {
            evidence: [{ label: 'Source', value: 'Deterministic fixture' }],
            status: 'succeeded',
            summary: 'The simulated operation reached its terminal state.',
            title: 'Fixture workflow complete'
        },
        { document, translator }
    )

    assert.equal(panel.getAttribute('role'), 'status')
    assert.match(panel.textContent, /simulated operation/)
    assert.doesNotMatch(panel.textContent, /hardware verified/i)
}

/** @returns {Promise<void>} Verifies real component classes receive local surface layout. */
async function testOperationComponentStyles() {
    const { document } = createComponentDom()
    const style = document.createElement('style')
    style.textContent = `${await readFile(new URL('../src/styles/tokens.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/base.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/components.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/operation-components.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/responsive.css', import.meta.url), 'utf8')}`
    document.head.append(style)
    const drawer = renderOperationDrawer({ closeSafe: true, risk: 'critical', title: 'Firmware update' }, { document, translator })
    const capability = renderCapabilityState({ reason: 'fixture-missing', state: 'evidence-incomplete', title: 'Firmware selector' }, { document, translator })
    document.body.append(drawer, capability)
    const confirmation = requestExactDeviceConfirmation({ expected: 'MEDIA-42', operationLabel: 'Format', risk: 'destructive' }, { document, translator })

    assert.equal(document.defaultView.getComputedStyle(drawer).position, 'fixed')
    assert.equal(document.defaultView.getComputedStyle(drawer).insetInlineEnd, '0')
    assert.equal(document.defaultView.getComputedStyle(capability).display, 'grid')
    assert.equal(document.defaultView.getComputedStyle(confirmation.element).position, 'fixed')
    assert.equal(document.defaultView.getComputedStyle(confirmation.element).display, 'grid')
    confirmation.close('test-cleanup')
    await confirmation.closed
}

/**
 * Reads stage states without an anonymous collection callback.
 * @param {NodeListOf<HTMLElement>} stages - Rendered timeline stages.
 * @returns {string[]} Stage states in DOM order.
 */
function readStageStates(stages) {
    const values = []
    for (const stage of stages) values.push(stage.dataset.stageState)
    return values
}

test('evidence incomplete state never renders an enabled action and explains the evidence boundary', testEvidenceIncompleteCapability)
test('available capability exposes one labeled action and invokes the bounded handler', testAvailableCapabilityAction)
test('destructive confirmation requires the displayed cartridge identity exactly', testExactDestructiveConfirmation)
test('confirmation traps focus and Escape closes only when the caller marks dismissal safe', testConfirmationFocusAndEscape)
test('progress timeline publishes restrained live stage updates and exact step states', testProgressTimelineAnnouncements)
test('operation drawer localizes every shared risk class without a parallel enum', testSharedRiskClassPresentation)
test('operation drawer exposes preflight, lock banner, progress, and safe close semantics', testOperationDrawerComposition)
test('operation lock banner names the operation and tells why other controls are unavailable', testOperationLockBanner)
test('operation drawer lock banner does not duplicate the active shell lock reason id', testOperationLockBannerIntegration)
test('result panel separates primary outcome, cleanup failure, evidence, and recovery help', testFailedResultPanel)
test('successful result remains a status message and never invents hardware verification', testSuccessfulResultPanel)
test('operation components use the bundled responsive cyberpunk surface styles', testOperationComponentStyles)
