import assert from 'node:assert/strict'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { englishCatalog } from '../src/locales/en.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'
import { renderShell } from '../src/renderer/views/shell-view.mjs'
import { renderIntentUnavailableReason } from '../src/renderer/views/intent-view.mjs'
import { renderStatusView } from '../src/renderer/views/status-view.mjs'
import { createDashboardDom, createRecordingIntentAdapter } from './helpers/renderer-dom.mjs'

const englishTranslator = createTranslator(englishCatalog, englishCatalog)

const EXPECTED_INTENT_UNAVAILABLE_CODES = Object.freeze({
    scan: 'INTENT_SCAN_UNAVAILABLE',
    operation: 'INTENT_OPERATION_UNAVAILABLE',
    'retry-operation': 'INTENT_RETRY_OPERATION_UNAVAILABLE',
    'retry-service': 'INTENT_RETRY_SERVICE_UNAVAILABLE',
    'open-support': 'INTENT_OPEN_SUPPORT_UNAVAILABLE',
    'open-event-log': 'INTENT_OPEN_EVENT_LOG_UNAVAILABLE'
})

/**
 * Creates two selectable fixture devices for end-to-end selection behavior.
 * @returns {object} Renderer state containing two distinct devices.
 */
function createTwoDeviceState() {
    const fixture = createFixtureState({ mode: 'one-device' })
    const secondDevice = {
        ...fixture.devices[0],
        id: 'rdx:secondary',
        serial: '7810544999',
        product: 'RDX QuikStor Secondary'
    }
    return { ...fixture, devices: [fixture.devices[0], secondDevice] }
}

/**
 * Reads trimmed labels from a list of DOM elements without deriving expected values.
 * @param {NodeListOf<Element>} nodes - Elements whose labels are visible to the user.
 * @returns {string[]} Trimmed text labels in document order.
 */
function readLabels(nodes) {
    const labels = []
    for (const node of nodes) {
        labels.push(node.textContent.trim())
    }
    return labels
}

/**
 * Dispatches one bubbling keyboard event through the real renderer controller.
 * @param {JSDOM} dom - Browser DOM that owns the event constructor.
 * @param {Element} target - Focused tab receiving the key.
 * @param {string} key - KeyboardEvent key value.
 * @returns {void} Completes after the event is dispatched.
 */
function pressKey(dom, target, key) {
    target.dispatchEvent(new dom.window.KeyboardEvent('keydown', { key, bubbles: true, cancelable: true }))
}

/**
 * Verifies one disabled external control owns a stable intent-specific reason.
 * @param {Document} document - DOM containing the control and reason.
 * @param {string} selector - Selector for exactly one physical control.
 * @param {string} reasonId - Stable reason identifier required by the control.
 * @param {string} intentType - Expected unavailable renderer intent type.
 * @returns {void} Throws when availability is aggregate or ambiguously described.
 */
function assertIntentUnavailable(document, selector, reasonId, intentType) {
    const control = document.querySelector(selector)
    const describedBy = control.getAttribute('aria-describedby')?.split(/\s+/) ?? []
    const reason = document.querySelector(`#${reasonId}`)
    const controlGroup = control.closest('[data-intent-group]')

    assert.equal(control.disabled, true)
    assert.equal(describedBy.includes(reasonId), true)
    assert.equal(document.querySelectorAll(`#${reasonId}`).length, 1)
    assert.equal(reason.dataset.intentUnavailable, intentType)
    assert.equal(reason.dataset.intentUnavailableCode, EXPECTED_INTENT_UNAVAILABLE_CODES[intentType])
    assert.equal(reason.textContent.trim(), EXPECTED_INTENT_UNAVAILABLE_CODES[intentType])
    assert.equal(reason.hidden, false)
    assert.equal(reason.getAttribute('aria-hidden'), null)
    assert.notEqual(controlGroup, null)
    assert.equal(reason.closest('[data-intent-group]'), controlGroup)
}

/**
 * Verifies every stable focus key identifies exactly one physical control.
 * @param {Document} document - Rendered dashboard document.
 * @returns {void} Throws when duplicate controls share a logical focus key.
 */
function assertUniqueFocusKeys(document) {
    const keys = []
    for (const control of document.querySelectorAll('[data-focus-key]')) {
        keys.push(control.dataset.focusKey)
    }
    assert.equal(new Set(keys).size, keys.length)
}

/**
 * Creates a renderer state with explicit non-available capabilities.
 * @returns {object} Data-only renderer state suitable for the real store.
 */
function createCapabilityLimitedState() {
    const fixture = createFixtureState({ mode: 'one-device' })
    const sourceDevice = fixture.devices[0]
    const device = {
        ...sourceDevice,
        capabilities: {
            ...sourceDevice.capabilities,
            'self-test': { state: 'evidence-incomplete' },
            'eject-safe': { state: 'wrong-media-state' }
        }
    }
    return { ...fixture, devices: [device] }
}

/**
 * Creates a failed-operation renderer state for a chosen recovery policy.
 * @param {{kind: string, retryable: boolean}} options - Failure kind and retry flag.
 * @returns {object} Data-only renderer state with one terminal failure.
 */
function createFailedOperationState({ kind, retryable }) {
    const fixture = createFixtureState({ mode: 'one-device' })
    return {
        ...fixture,
        lastOperation: {
            id: `op-fixture-${kind}`,
            kind,
            deviceId: fixture.selectedDeviceId,
            status: 'failed',
            error: {
                code: `${kind}-blocked`,
                messageKey: `errors.${kind}.blocked`,
                stage: kind === 'firmware-update' ? 'firmware-writing' : 'diagnostic-running',
                category: 'transport',
                retryable,
                supportCorrelationId: `support-${kind}`
            }
        }
    }
}

/**
 * Verifies the unified workspace preserves the original four management areas
 * and identifies the exact selected fixture device.
 * @returns {void} Throws when primary navigation or selection is missing.
 */
function testRendersManagementAreasAndSelectedDevice() {
    const { dom, controller } = createDashboardDom(createFixtureState({ mode: 'one-device' }))
    const document = dom.window.document

    assert.deepEqual(readLabels(document.querySelectorAll('[role="tab"]')), ['Status', 'Encryption', 'Tests', 'Utilities'])
    assert.match(document.querySelector('main').textContent, /RDX QuikStor USB3\+ External/)
    assert.equal(document.querySelector('[role="tab"][aria-selected="true"]').textContent.trim(), 'Status')
    assert.equal(document.querySelector('[data-action="manage-device"]').getAttribute('aria-current'), 'true')
    assert.equal(document.querySelector('main').id, 'main-content')
    assert.equal(document.querySelector('[role="progressbar"][aria-label="Cartridge capacity used"]').getAttribute('aria-valuenow'), '43')
    assert.match(renderStatusView(createFixtureState({ mode: 'one-device' }).devices[0], { translator: englishTranslator }), /Cartridge data/)
    assert.deepEqual([...document.querySelectorAll('[role="tab"]')].map(readTabIndex), [0, -1, -1, -1])

    /**
     * Reads a native tab button's current tab order value.
     * @param {HTMLButtonElement} tab - Area tab control.
     * @returns {number} Native tabIndex value.
     */
    function readTabIndex(tab) {
        return tab.tabIndex
    }

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies the ready empty state gives a useful discovery action and never
 * presents an invalid device-management action.
 * @returns {void} Throws when empty-state guidance is not actionable.
 */
function testRendersActionableNoDeviceGuidance() {
    const { dom, controller } = createDashboardDom(createFixtureState({ mode: 'no-device' }))
    const document = dom.window.document

    assert.match(document.body.textContent, /No RDX drives detected/)
    assert.match(document.body.textContent, /Connect an RDX dock/)
    assert.equal(document.querySelector('[data-action="manage-device"]'), null)
    assert.equal(document.querySelector('[data-action="scan-devices"]').disabled, true)
    assert.match(document.body.textContent, /INTENT_SCAN_UNAVAILABLE/)
    assert.equal(document.querySelector('main').getAttribute('aria-labelledby'), 'empty-state-title')

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies a failed service handshake is distinct from a successful empty scan
 * and exposes a retry without claiming hardware readiness.
 * @returns {void} Throws when unavailable-service recovery is ambiguous.
 */
function testRendersServiceUnavailableRecovery() {
    const { dom, controller } = createDashboardDom(createFixtureState({ mode: 'service-unavailable' }))
    const document = dom.window.document

    assert.match(document.querySelector('[role="alert"]').textContent, /Hardware service unavailable/)
    assert.match(document.querySelector('[role="alert"]').textContent, /service-unavailable/)
    assert.equal(document.querySelector('[data-action="retry-service"]').disabled, true)
    assert.equal(document.querySelector('[data-service-status]').dataset.serviceStatus, 'unavailable')
    assert.equal(document.querySelector('[data-action="scan-devices"]'), null)
    assert.equal(document.querySelector('[data-setting="auto-scan"]').disabled, true)
    assert.equal(document.querySelector('[data-setting="auto-scan"]').getAttribute('aria-describedby'), 'service-error-title')
    assert.match(document.getElementById('service-error-title').textContent, /Hardware service unavailable/)

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies a running operation reports progress and locks every conflicting
 * device, area, and command action.
 * @returns {void} Throws when the one-operation lock is not visible or enforced.
 */
function testRendersBusyOperationLock() {
    const fixture = createFixtureState({ mode: 'busy' })
    const state = {
        ...fixture,
        activeOperation: {
            ...fixture.activeOperation,
            id: 'op-fixture-eject-safe',
            kind: 'eject-safe',
            stage: 'host-ejecting',
            progress: 0.33
        }
    }
    const { dom, controller } = createDashboardDom(state)
    const document = dom.window.document
    const operationStatus = document.querySelector('[data-operation-status][role="status"]')
    const activity = operationStatus.querySelector('.operation-banner__activity')
    const lockReason = operationStatus.querySelector('#operation-lock-reason.operation-banner__lock')

    assert.match(operationStatus.textContent, /Safe eject in progress/)
    assert.match(operationStatus.textContent, /host-ejecting/)
    assert.equal(operationStatus.getAttribute('aria-live'), 'polite')
    assert.notEqual(activity, null)
    assert.notEqual(activity.querySelector('.operation-banner__icon .ph-eject'), null)
    assert.equal(activity.querySelector('progress').value, 0.33)
    assert.equal(activity.querySelector('progress').getAttribute('aria-label'), 'Operation progress')
    assert.notEqual(lockReason, null)
    assert.equal(lockReason.querySelector('.operation-banner__lock-title').textContent, 'One operation at a time.')
    assert.equal(lockReason.querySelector('.operation-banner__lock-detail').textContent, 'Device switching and other commands are locked.')
    assert.equal(lockReason.textContent.trim(), 'One operation at a time. Device switching and other commands are locked.')
    assert.equal(document.querySelector('[data-action="manage-device"]').disabled, true)
    assert.equal(document.querySelector('[data-action="scan-devices"]').disabled, true)
    assert.deepEqual(document.querySelector('[data-action="scan-devices"]').getAttribute('aria-describedby').split(/\s+/), ['operation-lock-reason', 'intent-scan-rail-unavailable'])
    assert.equal(document.querySelector('[data-setting="auto-scan"]').disabled, true)
    assert.equal(document.querySelector('[data-setting="auto-scan"]').getAttribute('aria-describedby'), 'operation-lock-reason')

    for (const tab of document.querySelectorAll('[role="tab"]:not([aria-selected="true"])')) {
        assert.equal(tab.disabled, true)
        assert.equal(tab.getAttribute('aria-describedby'), 'operation-lock-reason')
        assert.match(document.getElementById(tab.getAttribute('aria-describedby')).textContent, /One operation at a time/)
    }
    for (const action of document.querySelectorAll('[data-operation]')) {
        assert.equal(action.disabled, true)
        assert.match(action.getAttribute('aria-describedby'), /operation-lock-reason/)
    }

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies operation failures expose structured recovery evidence instead of
 * raw stack details or a generic error.
 * @returns {void} Throws when failure guidance omits its stable evidence.
 */
function testRendersOperationFailureRecovery() {
    const { dom, controller } = createDashboardDom(createFixtureState({ mode: 'operation-failed' }))
    const document = dom.window.document
    const alert = document.querySelector('[data-operation-failure][role="alert"]')

    assert.match(alert.textContent, /Self-test did not complete/)
    assert.match(alert.textContent, /transport-timeout/)
    assert.match(alert.textContent, /support-fixture-01/)
    assert.match(alert.textContent, /Retry the diagnostic/)
    assert.equal(alert.querySelector('[data-action="retry-operation"]').disabled, true)

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies non-retryable routine and critical failures provide distinct safe
 * next steps without exposing a retry action.
 * @returns {void} Throws when recovery policy ignores kind or retryability.
 */
function testRendersOperationSpecificNonRetryableGuidance() {
    const routine = createDashboardDom(createFailedOperationState({ kind: 'self-test', retryable: false }))
    const critical = createDashboardDom(createFailedOperationState({ kind: 'firmware-update', retryable: false }))
    const routineAlert = routine.dom.window.document.querySelector('[data-operation-failure]')
    const criticalAlert = critical.dom.window.document.querySelector('[data-operation-failure]')

    assert.equal(routineAlert.querySelector('[data-action="retry-operation"]'), null)
    assert.match(routineAlert.textContent, /Reconnect the dock and refresh status/)
    assert.equal(criticalAlert.querySelector('[data-action="retry-operation"]'), null)
    assert.match(criticalAlert.textContent, /Keep the dock powered and do not disconnect it/)

    routine.controller.destroy()
    routine.dom.window.close()
    critical.controller.destroy()
    critical.dom.window.close()
}

/**
 * Verifies the firmware workflow derives its media prerequisite even when the
 * fixture's static capability entry says available.
 * @returns {void} Throws when inserted media leaves firmware enabled.
 */
function testDisablesFirmwareWhileMediaIsInserted() {
    const { dom, controller } = createDashboardDom(createFixtureState({ mode: 'one-device' }))
    const firmware = dom.window.document.querySelector('[data-operation="firmware-update"]')

    assert.equal(firmware.disabled, true)
    assert.match(firmware.closest('[data-capability-card]').textContent, /wrong-media-state/)
    assert.match(firmware.closest('[data-capability-card]').textContent, /Remove the cartridge/)

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies device capabilities disable only the affected operation and expose
 * the exact stable reason rather than silently falling back.
 * @returns {void} Throws when capability gates are hidden or ignored.
 */
function testRendersCapabilityAwareActions() {
    const { dom, controller } = createDashboardDom(createCapabilityLimitedState())
    const document = dom.window.document
    const selfTest = document.querySelector('[data-operation="self-test"]')
    const eject = document.querySelector('[data-operation="eject-safe"]')
    const refresh = document.querySelector('[data-operation="status-refresh"]')

    assert.equal(selfTest.disabled, true)
    assert.equal(selfTest.closest('[data-capability-card]').textContent.includes('evidence-incomplete'), true)
    assert.equal(eject.disabled, true)
    assert.equal(eject.closest('[data-capability-card]').textContent.includes('wrong-media-state'), true)
    assert.equal(refresh.disabled, true)
    assert.match(refresh.closest('[data-capability-card]').textContent, /operation intent unavailable/)

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies tabs are keyboard-reachable native controls and update the active
 * presentation area when no operation lock is active.
 * @returns {void} Throws when area navigation cannot change the workspace.
 */
function testChangesAreaThroughSemanticTabControl() {
    const { dom, controller } = createDashboardDom(createFixtureState({ mode: 'one-device' }))
    const document = dom.window.document
    const encryptionTab = document.querySelector('[role="tab"][data-area="encryption"]')

    encryptionTab.focus()
    encryptionTab.click()

    assert.equal(document.activeElement, document.querySelector('[role="tab"][data-area="encryption"]'))
    assert.equal(document.querySelector('[role="tab"][data-area="encryption"]').getAttribute('aria-selected'), 'true')
    assert.match(document.querySelector('[role="tabpanel"]').textContent, /Encryption & Access Control/)
    assert.equal(document.querySelector('[role="tabpanel"] .ph-duotone') !== null, true)

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies the ARIA tablist uses roving focus with automatic activation for
 * arrows and Home/End, including wraparound at both boundaries.
 * @returns {void} Throws when keyboard navigation diverges from the tab pattern.
 */
function testNavigatesRovingTabsWithKeyboard() {
    const { dom, controller } = createDashboardDom(createFixtureState({ mode: 'one-device' }))
    let activeTab = dom.window.document.querySelector('[data-area="status"]')
    activeTab.focus()

    pressKey(dom, activeTab, 'ArrowRight')
    activeTab = dom.window.document.activeElement
    assert.equal(activeTab.dataset.area, 'encryption')
    assert.equal(activeTab.getAttribute('aria-selected'), 'true')
    assert.match(dom.window.document.querySelector('[role="tabpanel"]').textContent, /Encryption & Access Control/)

    pressKey(dom, activeTab, 'End')
    activeTab = dom.window.document.activeElement
    assert.equal(activeTab.dataset.area, 'utilities')

    pressKey(dom, activeTab, 'Home')
    activeTab = dom.window.document.activeElement
    assert.equal(activeTab.dataset.area, 'status')

    pressKey(dom, activeTab, 'ArrowLeft')
    activeTab = dom.window.document.activeElement
    assert.equal(activeTab.dataset.area, 'utilities')
    assert.deepEqual([...dom.window.document.querySelectorAll('[role="tab"]')].map(readCurrentTabIndex), [-1, -1, -1, 0])

    controller.destroy()
    dom.window.close()

    /**
     * Reads a tab button's current roving tab order value.
     * @param {HTMLButtonElement} tab - Area tab control.
     * @returns {number} Native tabIndex value.
     */
    function readCurrentTabIndex(tab) {
        return tab.tabIndex
    }
}

/**
 * Verifies the compact device selector uses an accessible expanded state and
 * does not change device data while it opens or closes.
 * @returns {void} Throws when the responsive selector state is inaccessible.
 */
function testTogglesCompactDeviceSelector() {
    const { dom, controller } = createDashboardDom(createFixtureState({ mode: 'one-device' }))
    const document = dom.window.document
    const toggle = document.querySelector('[data-action="toggle-device-rail"]')

    assert.equal(toggle.getAttribute('aria-expanded'), 'false')
    toggle.click()
    assert.equal(document.querySelector('[data-action="toggle-device-rail"]').getAttribute('aria-expanded'), 'true')
    assert.equal(document.querySelector('[data-device-rail]').dataset.open, 'true')

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies a selected-device refresh updates the rendered snapshot without
 * discarding the user's current logical focus.
 * @returns {void} Throws when refresh either fails or loses focus.
 */
function testPreservesFocusAcrossDeviceRefresh() {
    const fixture = createFixtureState({ mode: 'one-device' })
    const { dom, controller, store } = createDashboardDom(fixture)
    const statusTab = dom.window.document.querySelector('[data-area="status"]')
    statusTab.focus()

    store.dispatch({
        type: 'device/refreshed',
        device: {
            ...fixture.devices[0],
            product: 'RDX refreshed',
            revision: 5,
            drive: { ...fixture.devices[0].drive, details: { ...fixture.devices[0].drive.details, product: { availability: 'reported', value: 'RDX refreshed' } } }
        }
    })

    assert.equal(dom.window.document.querySelector('#status-heading').textContent, 'RDX refreshed')
    assert.equal(dom.window.document.activeElement.dataset.area, 'status')

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies operation progress re-renders its visible stage while keeping focus
 * on the same logical control.
 * @returns {void} Throws when progress is stale or focus is reset.
 */
function testPreservesFocusAcrossOperationProgress() {
    const fixture = createFixtureState({ mode: 'busy' })
    const { dom, controller, store } = createDashboardDom(fixture)
    dom.window.document.querySelector('[data-area="status"]').focus()

    store.dispatch({ type: 'operation/progress', operationId: fixture.activeOperation.id, stage: 'firmware-verifying', progress: 0.8, cancellationState: 'closed' })

    assert.equal(dom.window.document.querySelector('[data-operation-status] progress').value, 0.8)
    assert.match(dom.window.document.querySelector('[data-operation-status]').textContent, /firmware-verifying/)
    assert.equal(dom.window.document.activeElement.dataset.area, 'status')

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies a successful terminal transition releases the operation lock while
 * preserving focus on a control that remains present.
 * @returns {void} Throws when completion resets focus or leaves controls locked.
 */
function testPreservesFocusAcrossTerminalTransition() {
    const fixture = createFixtureState({ mode: 'one-device' })
    const { dom, controller, store } = createDashboardDom(fixture)
    store.dispatch({ type: 'operation/started', operationId: 'op-focus', kind: 'self-test' })
    dom.window.document.querySelector('[data-area="status"]').focus()

    store.dispatch({ type: 'operation/succeeded', operationId: 'op-focus' })

    assert.equal(dom.window.document.querySelector('[data-operation-status]'), null)
    assert.equal(dom.window.document.querySelector('[data-action="scan-devices"]').disabled, true)
    assert.equal(dom.window.document.activeElement.dataset.area, 'status')

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies an operation start moves focus from the newly locked command to the
 * live operation status, then a terminal transition returns it to the selected
 * tab instead of the document body.
 * @returns {void} Throws when a disappearing or disabled focus target is lost.
 */
function testUsesIntentionalFocusFallbacksAcrossOperationTransitions() {
    const fixture = createFixtureState({ mode: 'one-device' })
    const recorder = createRecordingIntentAdapter(['operation'])
    const { dom, controller, store } = createDashboardDom(fixture, { intentAdapter: recorder.adapter })
    const operation = dom.window.document.querySelector('[data-operation="status-refresh"]')
    operation.focus()

    store.dispatch({ type: 'operation/started', operationId: 'op-fallback', kind: 'status-refresh' })

    let focused = dom.window.document.activeElement
    assert.equal(focused, dom.window.document.querySelector('[data-operation-status]'))
    assert.equal(focused.dataset.focusKey, 'state:operation-status')
    assert.notEqual(focused, dom.window.document.body)

    store.dispatch({ type: 'operation/succeeded', operationId: 'op-fallback' })

    focused = dom.window.document.activeElement
    assert.equal(focused, dom.window.document.querySelector('[role="tab"][aria-selected="true"]'))
    assert.equal(focused.dataset.area, 'status')
    assert.notEqual(focused, dom.window.document.body)

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies duplicate empty-state and compact-rail controls retain their exact
 * physical focus target across accepted renderer setting transitions.
 * @returns {void} Throws when focus jumps to a duplicate Scan or Support control.
 */
function testPreservesPhysicalEmptyStateFocusAcrossRerenders() {
    const recorder = createRecordingIntentAdapter(['scan', 'open-support'])
    const { dom, controller, store } = createDashboardDom(createFixtureState({ mode: 'no-device' }), { intentAdapter: recorder.adapter })
    const document = dom.window.document
    document.querySelector('[data-action="toggle-device-rail"]').click()
    assertUniqueFocusKeys(document)

    const transitions = [
        { selector: '.empty-state [data-intent="scan"]', enabled: false, focusKey: 'empty:scan' },
        { selector: '.empty-state [data-intent="open-support"]', enabled: true, focusKey: 'empty:support' },
        { selector: '.device-rail [data-intent="scan"]', enabled: false, focusKey: 'rail:scan' },
        { selector: '.topbar [data-intent="open-support"]', enabled: true, focusKey: 'topbar:support' }
    ]

    for (const transition of transitions) {
        document.querySelector(transition.selector).focus()
        store.dispatch({ type: 'setting/auto-scan-changed', enabled: transition.enabled })
        assert.equal(document.activeElement, document.querySelector(transition.selector))
        assert.equal(document.activeElement.dataset.focusKey, transition.focusKey)
        assert.equal(document.querySelector('[data-device-rail]').dataset.open, 'true')
    }

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies clicking another device dispatches the existing safe selection
 * action and updates the selected workspace end to end.
 * @returns {void} Throws when device management remains inert.
 */
function testSelectsAnotherDeviceThroughTheStore() {
    const { dom, controller, store } = createDashboardDom(createTwoDeviceState())
    dom.window.document.querySelector('[data-device-id="rdx:secondary"]').click()

    assert.equal(store.getState().selectedDeviceId, 'rdx:secondary')
    assert.match(dom.window.document.querySelector('main').textContent, /RDX QuikStor Secondary/)
    assert.equal(dom.window.document.querySelector('[data-device-id="rdx:secondary"]').getAttribute('aria-current'), 'true')

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies the selected-device support action has a compact-safe accessible
 * contract and reaches its exact injected renderer intent.
 * @returns {void} Throws when compact presentation would remove or mute support.
 */
function testExposesSelectedDeviceCompactSupportAction() {
    const recorder = createRecordingIntentAdapter(['open-support'])
    const { dom, controller } = createDashboardDom(createFixtureState({ mode: 'one-device' }), { intentAdapter: recorder.adapter })
    const support = dom.window.document.querySelector('.topbar [data-intent="open-support"]')

    assert.equal(support.disabled, false)
    assert.equal(support.tabIndex, 0)
    assert.equal(support.getAttribute('aria-label'), 'Open support')
    support.focus()
    assert.equal(dom.window.document.activeElement, support)
    support.click()
    assert.deepEqual(recorder.calls, [{ type: 'open-support' }])

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies no-device duplicates bind Scan and Support independently, including
 * the Scan control inside the opened compact device disclosure.
 * @returns {void} Throws when one bound intent changes another intent's state.
 */
function testScopesNoDevicePartialIntentAvailability() {
    const scanRecorder = createRecordingIntentAdapter(['scan'])
    const scanDashboard = createDashboardDom(createFixtureState({ mode: 'no-device' }), { intentAdapter: scanRecorder.adapter })
    const scanDocument = scanDashboard.dom.window.document
    scanDocument.querySelector('[data-action="toggle-device-rail"]').click()

    assert.equal(scanDocument.querySelector('.device-rail [data-intent="scan"]').disabled, false)
    assert.equal(scanDocument.querySelector('.empty-state [data-intent="scan"]').disabled, false)
    assert.equal(scanDocument.querySelector('[data-device-rail]').dataset.open, 'true')
    scanDocument.querySelector('.device-rail [data-intent="scan"]').click()
    scanDocument.querySelector('.empty-state [data-intent="scan"]').click()
    assert.deepEqual(scanRecorder.calls, [{ type: 'scan' }, { type: 'scan' }])
    assertIntentUnavailable(scanDocument, '.topbar [data-intent="open-support"]', 'intent-open-support-topbar-unavailable', 'open-support')
    assertIntentUnavailable(scanDocument, '.empty-state [data-intent="open-support"]', 'intent-open-support-empty-unavailable', 'open-support')
    assertIntentUnavailable(scanDocument, '.topbar [data-intent="open-event-log"]', 'intent-open-event-log-topbar-unavailable', 'open-event-log')

    const supportRecorder = createRecordingIntentAdapter(['open-support'])
    const supportDashboard = createDashboardDom(createFixtureState({ mode: 'no-device' }), { intentAdapter: supportRecorder.adapter })
    const supportDocument = supportDashboard.dom.window.document

    assert.equal(supportDocument.querySelector('.topbar [data-intent="open-support"]').disabled, false)
    assert.equal(supportDocument.querySelector('.empty-state [data-intent="open-support"]').disabled, false)
    supportDocument.querySelector('.topbar [data-intent="open-support"]').click()
    supportDocument.querySelector('.empty-state [data-intent="open-support"]').click()
    assert.deepEqual(supportRecorder.calls, [{ type: 'open-support' }, { type: 'open-support' }])
    assertIntentUnavailable(supportDocument, '.device-rail [data-intent="scan"]', 'intent-scan-rail-unavailable', 'scan')
    assertIntentUnavailable(supportDocument, '.empty-state [data-intent="scan"]', 'intent-scan-empty-unavailable', 'scan')
    assert.equal(supportDocument.querySelector('#renderer-bridge-status'), null)

    scanDashboard.controller.destroy()
    scanDashboard.dom.window.close()
    supportDashboard.controller.destroy()
    supportDashboard.dom.window.close()
}

/**
 * Verifies operation, retry-operation, retry-service, Support, and Event Log
 * remain independent across selected, failed, and service-unavailable states.
 * @returns {void} Throws when partial adapters leak availability across intents.
 */
function testScopesStateSpecificPartialIntentAvailability() {
    const operationRecorder = createRecordingIntentAdapter(['operation'])
    const operationDashboard = createDashboardDom(createFixtureState({ mode: 'one-device' }), { intentAdapter: operationRecorder.adapter })
    const operationDocument = operationDashboard.dom.window.document

    assert.equal(operationDocument.querySelector('[data-operation="status-refresh"]').disabled, false)
    assert.equal(operationDocument.querySelector('[data-operation="self-test"]').disabled, false)
    assert.equal(operationDocument.querySelector('[data-operation="eject-safe"]').disabled, false)
    operationDocument.querySelector('[data-operation="status-refresh"]').click()
    operationDocument.querySelector('[data-operation="self-test"]').click()
    operationDocument.querySelector('[data-operation="eject-safe"]').click()
    assert.deepEqual(operationRecorder.calls.map(readOperationKind), ['status-refresh', 'self-test', 'eject-safe'])
    assertIntentUnavailable(operationDocument, '.device-rail [data-intent="scan"]', 'intent-scan-rail-unavailable', 'scan')
    assertIntentUnavailable(operationDocument, '.topbar [data-intent="open-support"]', 'intent-open-support-topbar-unavailable', 'open-support')
    assertIntentUnavailable(operationDocument, '.topbar [data-intent="open-event-log"]', 'intent-open-event-log-topbar-unavailable', 'open-event-log')

    const failureRecorder = createRecordingIntentAdapter(['retry-operation', 'open-event-log'])
    const failureDashboard = createDashboardDom(createFixtureState({ mode: 'operation-failed' }), { intentAdapter: failureRecorder.adapter })
    const failureDocument = failureDashboard.dom.window.document

    assert.equal(failureDocument.querySelector('[data-intent="retry-operation"]').disabled, false)
    assert.equal(failureDocument.querySelector('[data-intent="open-event-log"]').disabled, false)
    failureDocument.querySelector('[data-intent="retry-operation"]').click()
    failureDocument.querySelector('[data-intent="open-event-log"]').click()
    assert.deepEqual(failureRecorder.calls.map(readIntentType), ['retry-operation', 'open-event-log'])
    assertIntentUnavailable(failureDocument, '[data-operation="status-refresh"]', 'intent-operation-status-refresh-unavailable', 'operation')
    assertIntentUnavailable(failureDocument, '.topbar [data-intent="open-support"]', 'intent-open-support-topbar-unavailable', 'open-support')

    const serviceRetryRecorder = createRecordingIntentAdapter(['retry-service'])
    const serviceRetryDashboard = createDashboardDom(createFixtureState({ mode: 'service-unavailable' }), { intentAdapter: serviceRetryRecorder.adapter })
    const serviceRetryDocument = serviceRetryDashboard.dom.window.document

    assert.equal(serviceRetryDocument.querySelector('[data-intent="retry-service"]').disabled, false)
    serviceRetryDocument.querySelector('[data-intent="retry-service"]').click()
    assert.deepEqual(serviceRetryRecorder.calls, [{ type: 'retry-service' }])
    assertIntentUnavailable(serviceRetryDocument, '.topbar [data-intent="open-support"]', 'intent-open-support-topbar-unavailable', 'open-support')
    assertIntentUnavailable(serviceRetryDocument, '.empty-state [data-intent="open-support"]', 'intent-open-support-service-unavailable', 'open-support')
    assertIntentUnavailable(serviceRetryDocument, '.topbar [data-intent="open-event-log"]', 'intent-open-event-log-topbar-unavailable', 'open-event-log')

    const serviceSupportRecorder = createRecordingIntentAdapter(['open-support'])
    const serviceSupportDashboard = createDashboardDom(createFixtureState({ mode: 'service-unavailable' }), { intentAdapter: serviceSupportRecorder.adapter })
    const serviceSupportDocument = serviceSupportDashboard.dom.window.document

    assert.equal(serviceSupportDocument.querySelector('.topbar [data-intent="open-support"]').disabled, false)
    assert.equal(serviceSupportDocument.querySelector('.empty-state [data-intent="open-support"]').disabled, false)
    serviceSupportDocument.querySelector('.topbar [data-intent="open-support"]').click()
    serviceSupportDocument.querySelector('.empty-state [data-intent="open-support"]').click()
    assert.deepEqual(serviceSupportRecorder.calls, [{ type: 'open-support' }, { type: 'open-support' }])
    assertIntentUnavailable(serviceSupportDocument, '[data-intent="retry-service"]', 'intent-retry-service-state-unavailable', 'retry-service')

    assertUniqueFocusKeys(operationDocument)
    assertUniqueFocusKeys(failureDocument)
    assertUniqueFocusKeys(serviceRetryDocument)
    assertUniqueFocusKeys(serviceSupportDocument)

    operationDashboard.controller.destroy()
    operationDashboard.dom.window.close()
    failureDashboard.controller.destroy()
    failureDashboard.dom.window.close()
    serviceRetryDashboard.controller.destroy()
    serviceRetryDashboard.dom.window.close()
    serviceSupportDashboard.controller.destroy()
    serviceSupportDashboard.dom.window.close()

    /**
     * Reads an operation kind from one accepted intent.
     * @param {object} intent - Recorded high-level operation intent.
     * @returns {string} Operation kind.
     */
    function readOperationKind(intent) {
        return intent.kind
    }

    /**
     * Reads the intent type from one accepted intent.
     * @param {object} intent - Recorded high-level renderer intent.
     * @returns {string} Intent type.
     */
    function readIntentType(intent) {
        return intent.type
    }
}

/**
 * Verifies the default unconnected adapter disables and truth-labels every
 * external renderer action instead of leaving enabled inert controls.
 * @returns {void} Throws when any external action appears connected by default.
 */
function testDisablesUnconnectedRendererIntentsByDefault() {
    const { dom, controller } = createDashboardDom(createFixtureState({ mode: 'operation-failed' }))
    const document = dom.window.document

    assertIntentUnavailable(document, '.device-rail [data-intent="scan"]', 'intent-scan-rail-unavailable', 'scan')
    assertIntentUnavailable(document, '[data-operation="status-refresh"]', 'intent-operation-status-refresh-unavailable', 'operation')
    assertIntentUnavailable(document, '[data-operation="self-test"]', 'intent-operation-self-test-unavailable', 'operation')
    assertIntentUnavailable(document, '[data-operation="eject-safe"]', 'intent-operation-eject-safe-unavailable', 'operation')
    assertIntentUnavailable(document, '[data-operation="firmware-update"]', 'intent-operation-firmware-update-unavailable', 'operation')
    assertIntentUnavailable(document, '[data-intent="retry-operation"]', 'intent-retry-operation-failure-unavailable', 'retry-operation')
    assertIntentUnavailable(document, '.topbar [data-intent="open-support"]', 'intent-open-support-topbar-unavailable', 'open-support')
    assertIntentUnavailable(document, '.topbar [data-intent="open-event-log"]', 'intent-open-event-log-topbar-unavailable', 'open-event-log')
    assert.equal(document.querySelector('#renderer-bridge-status'), null)
    assertUniqueFocusKeys(document)

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies Auto Scan is store-backed, reflects on/off styling semantics, and
 * survives unrelated renderer refreshes before it is enabled again.
 * @returns {void} Throws when the control or state becomes desynchronized.
 */
function testTogglesAndPersistsAutoScanState() {
    const fixture = createFixtureState({ mode: 'one-device' })
    const { dom, controller, store } = createDashboardDom(fixture)
    let input = dom.window.document.querySelector('[data-setting="auto-scan"]')

    assert.equal(input.checked, true)
    assert.equal(input.closest('.autoscan-control').dataset.enabled, 'true')
    input.click()
    input = dom.window.document.querySelector('[data-setting="auto-scan"]')
    assert.equal(store.getState().settings.autoScan, false)
    assert.equal(input.checked, false)
    assert.equal(input.closest('.autoscan-control').dataset.enabled, 'false')

    store.dispatch({ type: 'device/refreshed', device: { ...fixture.devices[0], revision: 5 } })
    input = dom.window.document.querySelector('[data-setting="auto-scan"]')
    assert.equal(input.checked, false)
    input.click()
    input = dom.window.document.querySelector('[data-setting="auto-scan"]')
    assert.equal(store.getState().settings.autoScan, true)
    assert.equal(input.checked, true)
    assert.equal(dom.window.document.activeElement.dataset.setting, 'auto-scan')

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies an in-flight discovery pass disables duplicate manual dispatch and
 * exposes restrained live status without hiding the current full snapshot.
 * @returns {void} Throws when scan state is invisible or still actionable.
 */
function testRendersNonOverlappingDiscoveryProgress() {
    const fixture = createFixtureState({ mode: 'one-device' })
    const state = { ...fixture, discovery: { ...fixture.discovery, scanStatus: 'scanning', trigger: 'auto' } }
    const recorder = createRecordingIntentAdapter(['scan'])
    const { dom, controller } = createDashboardDom(state, { intentAdapter: recorder.adapter })
    const document = dom.window.document
    const scan = document.querySelector('[data-action="scan-devices"]')
    const status = document.querySelector('[data-discovery-status][role="status"]')

    assert.equal(scan.disabled, true)
    assert.equal(scan.getAttribute('aria-describedby').split(/\s+/).includes('discovery-scan-rail-status'), true)
    assert.match(status.textContent, /Scanning for RDX drives/)
    assert.equal(document.querySelectorAll('[data-action="manage-device"]').length, 1)

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies renderer-supplied identity text is escaped before it enters the DOM.
 * @returns {void} Throws when device text can create executable markup.
 */
function testEscapesRendererSuppliedDeviceText() {
    const fixture = createFixtureState({ mode: 'one-device' })
    const unsafeDevice = { ...fixture.devices[0], product: '<img src=x onerror=alert(1)>' }
    const unsafeState = { ...fixture, devices: [unsafeDevice] }
    const html = renderShell(unsafeState, { translator: englishTranslator })
    const dom = new JSDOM(html)

    assert.equal(dom.window.document.querySelector('img'), null)
    assert.match(dom.window.document.body.textContent, /<img src=x onerror=alert\(1\)>/)

    dom.window.close()
}

/**
 * Verifies renderer views consume the injected translator while raw fixture
 * identity stays outside the catalog boundary.
 * @returns {void} Throws when a view retains hard-coded shell copy.
 */
function testRendersShellCopyThroughInjectedTranslator() {
    const translator = createTranslator({ 'areas.status': 'Zustand', 'devices.rail': 'Gerätebereich' }, englishCatalog)
    const { dom, controller } = createDashboardDom(createFixtureState({ mode: 'one-device' }), { translator })
    const document = dom.window.document

    assert.equal(document.querySelector('[role="tab"]').textContent.trim(), 'Zustand')
    assert.equal(document.querySelector('.rail-heading .eyebrow').textContent.trim(), 'Gerätebereich')
    assert.match(document.body.textContent, /RDX QuikStor USB3\+ External/)

    controller.destroy()
    dom.window.close()
}

/**
 * Verifies capability display labels come from the injected catalog while the
 * adjacent machine-readable capability states remain unchanged.
 * @returns {void} Throws when capability presentation retains English literals.
 */
function testRendersCapabilityCopyThroughInjectedTranslator() {
    const translator = createTranslator(
        {
            'capability.operationLocked': 'Gesperrt',
            'capability.available': 'Verfügbar',
            'capability.intentUnavailable': 'Nicht verfügbar'
        },
        englishCatalog
    )
    const availableRecorder = createRecordingIntentAdapter(['operation'])
    const available = createDashboardDom(createFixtureState({ mode: 'one-device' }), { intentAdapter: availableRecorder.adapter, translator })
    const unavailable = createDashboardDom(createFixtureState({ mode: 'one-device' }), { translator })
    const locked = createDashboardDom(createFixtureState({ mode: 'busy' }), { translator })

    assert.match(available.dom.window.document.querySelector('[data-operation="self-test"]').closest('[data-capability-card]').textContent, /Verfügbar/)
    assert.match(unavailable.dom.window.document.querySelector('[data-operation="self-test"]').closest('[data-capability-card]').textContent, /Nicht verfügbar/)
    assert.match(locked.dom.window.document.querySelector('[data-operation="self-test"]').closest('[data-capability-card]').textContent, /Gesperrt/)
    assert.equal(locked.dom.window.document.querySelector('[data-operation="self-test"]').closest('[data-capability-card]').querySelector('[data-capability-state]').dataset.capabilityState, 'available')

    available.controller.destroy()
    available.dom.window.close()
    unavailable.controller.destroy()
    unavailable.dom.window.close()
    locked.controller.destroy()
    locked.dom.window.close()
}

/**
 * Verifies nested catalog composition renders trusted ampersands once and
 * hostile raw interpolation as inert text rather than executable markup.
 * @returns {void} Throws when translations double-escape or interpolation injects markup.
 */
function testRendersComposedTranslationsAndEscapedInterpolation() {
    const translator = createTranslator({ 'areas.encryption': 'R&D' }, englishCatalog)
    const dashboard = createDashboardDom(createFixtureState({ mode: 'one-device' }), { translator })
    const encryptionTab = dashboard.dom.window.document.querySelector('[data-area="encryption"]')
    encryptionTab.click()

    assert.equal(encryptionTab.textContent.trim(), 'R&D')
    assert.equal(dashboard.dom.window.document.querySelector('[role="tabpanel"] h2').textContent, 'Encryption & Access Control')

    const unsafeDevice = { ...createFixtureState({ mode: 'one-device' }).devices[0], serial: '<img src=x onerror=alert(1)>' }
    const unsafeDom = new JSDOM(renderStatusView(unsafeDevice, { translator }))
    assert.equal(unsafeDom.window.document.querySelector('img'), null)
    assert.match(unsafeDom.window.document.body.textContent, /Serial <img src=x onerror=alert\(1\)>/)

    dashboard.controller.destroy()
    dashboard.dom.window.close()
    unsafeDom.window.close()
}

/**
 * Verifies an unavailable-intent reason keeps its stable visible code while a
 * translated intent fragment renders once in its ARIA explanation.
 * @returns {void} Throws when nested intent messages double-escape in the DOM.
 */
function testRendersUnavailableIntentReasonWithoutDoubleEscaping() {
    const translator = createTranslator({ 'intent.operation': 'R&D' }, englishCatalog)
    const dom = new JSDOM(renderIntentUnavailableReason('operation', 'direct-regression', false, translator))
    const reason = dom.window.document.querySelector('.intent-unavailable-reason')

    assert.equal(reason.textContent, 'INTENT_OPERATION_UNAVAILABLE')
    assert.equal(reason.dataset.intentUnavailable, 'operation')
    assert.equal(reason.dataset.intentUnavailableCode, 'INTENT_OPERATION_UNAVAILABLE')
    assert.equal(reason.getAttribute('aria-label'), 'R&D intent unavailable. Connect the trusted renderer bridge for this action. Reason code INTENT_OPERATION_UNAVAILABLE.')

    dom.window.close()
}

/**
 * Verifies periodic snapshots patch the existing dashboard instead of replacing
 * its scroll owner, device controls, and unchanged status rows.
 * @returns {void} Throws when a live refresh recreates the mounted view.
 */
function testPatchesLiveSnapshotWithoutResettingScroll() {
    const source = createFixtureState({ mode: 'one-device' })
    const fixture = { ...source, discovery: { ...source.discovery, epoch: 1, listRevision: 1 } }
    const dashboard = createDashboardDom(fixture)
    const document = dashboard.dom.window.document
    const areaPanel = document.querySelector('.area-panel')
    const deviceControl = document.querySelector(`[data-device-id="${fixture.selectedDeviceId}"]`)
    const driveData = document.querySelector('.status-data-card')
    areaPanel.scrollTop = 173

    const device = dashboard.store.getState().devices[0]
    dashboard.store.dispatch({
        type: 'device/list-replaced',
        devices: [
            {
                ...device,
                revision: device.revision + 1,
                media: {
                    ...device.media,
                    usedBytes: 429_000_000_000,
                    details: {
                        ...device.media.details,
                        usedBytes: { availability: 'reported', value: 429_000_000_000 },
                        freeBytes: { availability: 'reported', value: 571_000_000_000 }
                    }
                }
            }
        ],
        epoch: fixture.discovery.epoch,
        listRevision: fixture.discovery.listRevision + 1
    })

    assert.equal(document.querySelector('.area-panel'), areaPanel)
    assert.equal(document.querySelector(`[data-device-id="${fixture.selectedDeviceId}"]`), deviceControl)
    assert.equal(document.querySelector('.status-data-card'), driveData)
    assert.equal(areaPanel.scrollTop, 173)
    assert.match(document.querySelector('.metric-card--capacity').textContent, /429 GB used/)

    dashboard.controller.destroy()
    dashboard.dom.window.close()
}

test('renders the four original management areas and exact selected device', testRendersManagementAreasAndSelectedDevice)
test('renders actionable no-device guidance without a manage action', testRendersActionableNoDeviceGuidance)
test('renders service-unavailable recovery separately from no-device', testRendersServiceUnavailableRecovery)
test('renders busy operation progress and locks conflicting actions', testRendersBusyOperationLock)
test('renders failed-operation evidence and recovery guidance', testRendersOperationFailureRecovery)
test('renders operation-specific non-retryable recovery guidance', testRendersOperationSpecificNonRetryableGuidance)
test('disables firmware while media is inserted', testDisablesFirmwareWhileMediaIsInserted)
test('renders capability-aware actions with stable disable reasons', testRendersCapabilityAwareActions)
test('changes area through a semantic tab control', testChangesAreaThroughSemanticTabControl)
test('navigates roving tabs with automatic keyboard activation', testNavigatesRovingTabsWithKeyboard)
test('toggles the compact device selector accessibly', testTogglesCompactDeviceSelector)
test('preserves logical focus across a selected-device refresh', testPreservesFocusAcrossDeviceRefresh)
test('preserves logical focus across operation progress', testPreservesFocusAcrossOperationProgress)
test('preserves logical focus across a terminal operation transition', testPreservesFocusAcrossTerminalTransition)
test('uses intentional focus fallbacks across operation transitions', testUsesIntentionalFocusFallbacksAcrossOperationTransitions)
test('preserves physical empty-state focus across accepted rerenders', testPreservesPhysicalEmptyStateFocusAcrossRerenders)
test('selects another device through the renderer store', testSelectsAnotherDeviceThroughTheStore)
test('exposes selected-device support as a compact-safe accessible action', testExposesSelectedDeviceCompactSupportAction)
test('scopes no-device partial intent availability', testScopesNoDevicePartialIntentAvailability)
test('scopes state-specific partial intent availability', testScopesStateSpecificPartialIntentAvailability)
test('disables and truth-labels unconnected renderer intents by default', testDisablesUnconnectedRendererIntentsByDefault)
test('toggles and persists Auto Scan state on, off, and on', testTogglesAndPersistsAutoScanState)
test('renders non-overlapping discovery progress without clearing snapshots', testRendersNonOverlappingDiscoveryProgress)
test('escapes renderer-supplied device text', testEscapesRendererSuppliedDeviceText)
test('renders shell copy through the injected translator', testRendersShellCopyThroughInjectedTranslator)
test('renders capability copy through the injected translator', testRendersCapabilityCopyThroughInjectedTranslator)
test('renders composed translations and escaped interpolation', testRendersComposedTranslationsAndEscapedInterpolation)
test('renders unavailable intent reasons without double escaping', testRendersUnavailableIntentReasonWithoutDoubleEscaping)
test('patches live snapshots without resetting scroll or node identity', testPatchesLiveSnapshotWithoutResettingScroll)
