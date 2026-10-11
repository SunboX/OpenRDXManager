// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { FirmwareContinuation } from './firmware-continuation.mjs'
import { RecoveryController } from './recovery-controller.mjs'
import { ManufacturingController } from './manufacturing-controller.mjs'
import { reconcileRenderedShell } from './shell-reconciler.mjs'
import { renderShell } from './views/shell-view.mjs'
import { renderEncryptionView } from './views/encryption-view.mjs'
import { createRendererIntentAdapter, RendererIntentType } from './intent-adapter.mjs'
import { createProductionSecurityModel } from './security-production-model.mjs'
import { createSecurityWorkflow, transitionSecurityWorkflow } from './security-workflow-lifecycle.mjs'
import { isFormatFilesystemSupported } from './workflows/format-filesystem-policy.mjs'
import { findHelpTopic } from '../help/help-index.mjs'
import { englishCatalog } from '../locales/en.mjs'
import { createTranslator } from './i18n.mjs'
import { DiagnosticSubmission } from './diagnostic-submission.mjs'
import { OperationSuccessFeedback } from './operation-success-feedback.mjs'
import { captureVolumeLabelForm, restoreVolumeLabelForm, updateVolumeLabelForm } from './volume-label-form.mjs'
import { captureFormatForm, restoreFormatForm, updateFormatForm } from './format-form.mjs'
import { firmwareFailureReasonKeys } from './firmware-failure-reasons.mjs'
import { UtilityFeedback } from './utility-feedback.mjs'

export { createDeviceController } from './device-controller.mjs'

const USER_REASON_KEYS = Object.freeze({
    ...firmwareFailureReasonKeys,
    'event-log-unavailable': 'reason.eventLogUnavailable',
    'export-cancelled': 'reason.exportCancelled',
    'firmware-file-changed': 'reason.firmwareFileChanged',
    'firmware-file-invalid': 'reason.firmwareFileInvalid',
    'firmware-file-token-invalid': 'reason.firmwareFileTokenInvalid',
    'firmware-file-type-unsupported': 'reason.firmwareFileTypeUnsupported',
    'firmware-selection-cancelled': 'reason.firmwareSelectionCancelled',
    'firmware-selection-capacity-exhausted': 'reason.firmwareSelectionCapacityExhausted',
    'firmware-selection-failed': 'reason.firmwareSelectionFailed',
    'firmware-selection-invalid': 'reason.firmwareSelectionInvalid',
    'firmware-selection-unavailable': 'reason.firmwareSelectionUnavailable',
    'log-export-failed': 'reason.logExportFailed',
    'log-export-unavailable': 'reason.logExportUnavailable',
    'security-service-failure': 'reason.securityServiceFailure',
    'security-service-unavailable': 'reason.securityServiceUnavailable',
    'service-failure': 'reason.serviceFailure',
    'support-service-unavailable': 'reason.supportServiceUnavailable',
    'support-summary-save-failed': 'reason.supportSummarySaveFailed',
    'update-network-failure': 'reason.updateNetworkFailure'
})

/**
 * Resolves only stable app-owned reason codes. Native or injected text never
 * becomes a catalog path and falls back to generic localized copy.
 * @param {unknown} reason - Candidate result reason.
 * @param {(key: string, params?: object) => string} translator - Active locale translator.
 * @returns {string} Localized safe reason fragment.
 */
function translateUserReason(reason, translator) {
    const key = typeof reason === 'string' && Object.hasOwn(USER_REASON_KEYS, reason) ? USER_REASON_KEYS[reason] : 'reason.generic'
    return translator(key)
}

/**
 * Builds one closed structured utility request from trusted controls.
 * No arbitrary dataset keys, paths, tokens, or parameter bags are forwarded.
 * @param {string} kind - Published utility operation kind.
 * @param {object} device - Current selected renderer-safe device.
 * @param {HTMLElement} card - Owning utility card.
 * @param {unknown} platform - Current Electron host platform fact.
 * @returns {object|null} Exact token-free request or null for invalid UI state.
 */
function createUtilityRequest(kind, device, card, platform) {
    const target = { deviceId: device.id, deviceRevision: device.revision, kind }
    switch (kind) {
        case 'firmware-update':
        case 'drive-letter-reset':
        case 'eject-safe':
        case 'eject-force':
            return target
        case 'format': {
            const filesystem = card.querySelector('[data-utility-filesystem]')?.value
            const passphrase = filesystem?.endsWith('-encrypted') ? card.querySelector('[data-format-password]')?.value : undefined
            return isFormatFilesystemSupported(platform, filesystem) ? { ...target, filesystem, ...(passphrase === undefined ? {} : { passphrase }) } : null
        }
        case 'volume-label-set': {
            const label = card.querySelector('[data-utility-volume-label]')?.value
            return typeof label === 'string' ? { ...target, label } : null
        }
        case 'drive-letter-set': {
            const letter = card.querySelector('[data-utility-drive-letter]')?.value
            return typeof letter === 'string' && /^[D-Z]$/.test(letter) ? { ...target, letter } : null
        }
        case 'drive-mode-set': {
            const mode = card.querySelector('[data-utility-mode]')?.value
            return ['fixed', 'removable'].includes(mode) ? { ...target, mode } : null
        }
        case 'sata-mode-set': {
            const mode = card.querySelector('[data-utility-sata-mode]')?.value
            return ['1.5g-3g', '3g-6g'].includes(mode) ? { ...target, mode } : null
        }
        default:
            return null
    }
}

/**
 * Keeps a mode setter disabled for its current value without sending a no-op.
 * @param {HTMLSelectElement} select - Fixed/Removable or SATA select.
 * @param {(key: string, params?: object) => string} translator - Active bounded translator.
 * @returns {void} Completes after updating the owning action.
 */
function updateModeAction(select, translator) {
    const card = select.closest('[data-feature]')
    const button = card?.querySelector('[data-ready-when-changed]')
    if (button === null || button === undefined) return
    const noOp = select.dataset.currentValue !== '' && select.value === select.dataset.currentValue
    button.disabled = button.dataset.readyWhenChanged !== 'true' || noOp
    const label = button.querySelector('span')
    if (label !== null) label.textContent = translator(noOp ? 'utilities.action.currentMode' : card.dataset.feature === 'sata-mode' ? 'utilities.action.applySataMode' : 'utilities.action.applyDriveMode')
}

/**
 * Mounts the renderer shell, observes immutable store snapshots, and owns only
 * local presentation state such as the active area and compact rail disclosure.
 * Recovery uses options.recoveryApi or supportApi.recovery as its closed preload delegate.
 * @param {HTMLElement} root - Trusted application mount element.
 * @param {{store: {getState: () => object, dispatch: (action: object) => object, subscribe: (listener: (state: object) => void) => () => void}, intentAdapter?: {isAvailable: (intentType: string) => boolean, invoke: (intent: object) => Promise<object|boolean>}, deviceController?: {isAvailable: () => boolean, startAutoScan: () => void, stopAutoScan: () => void, requestManualScan: () => Promise<object>, refreshForOperation?: () => Promise<object>, destroy: () => void}, securityController?: {isAvailable: (operation?: string) => boolean, start: (intent: object, credential: Uint8Array|null) => Promise<object>}, securityStateProvider?: {getModel: (state: object, device: object, workflow: object|null) => object}, utilityController?: {isAvailable: (kind?: string) => boolean, start: (request: object) => Promise<object>}, supportApi?: object, onLanguageChanged?: (language: string) => boolean, platform?: string, availableDriveLetters?: string[], currentSataMode?: string, translator?: (key: string, params?: object) => string}} options - Renderer dependencies.
 * @returns {{destroy: () => void}} Controller cleanup API.
 * @throws {TypeError} When the mount or store contract is invalid.
 */
export function mountApplication(root, options) {
    if (root === null || typeof root !== 'object' || typeof root.addEventListener !== 'function') {
        throw new TypeError('Application root must be a DOM element')
    }
    if (options?.store === null || typeof options?.store?.getState !== 'function' || typeof options?.store?.dispatch !== 'function' || typeof options?.store?.subscribe !== 'function') {
        throw new TypeError('Application store must implement getState, dispatch, and subscribe')
    }

    const store = options.store
    const intentAdapter = options.intentAdapter ?? createRendererIntentAdapter()
    const deviceController = options.deviceController ?? null
    const utilityController = options.utilityController ?? null
    const securityController = options.securityController ?? null
    const securityStateProvider = options.securityStateProvider ?? null
    const supportApi = options.supportApi ?? null
    const onLanguageChanged = options.onLanguageChanged ?? (() => false)
    const translator = options.translator ?? createTranslator(englishCatalog, englishCatalog)
    const t = translator
    if (typeof intentAdapter.isAvailable !== 'function' || typeof intentAdapter.invoke !== 'function') {
        throw new TypeError('Intent adapter must implement isAvailable and invoke')
    }
    if (typeof translator !== 'function') {
        throw new TypeError('Renderer translator must be a function')
    }
    if (deviceController !== null && (typeof deviceController.isAvailable !== 'function' || typeof deviceController.startAutoScan !== 'function' || typeof deviceController.stopAutoScan !== 'function' || typeof deviceController.requestManualScan !== 'function' || typeof deviceController.destroy !== 'function')) {
        throw new TypeError('Device controller must implement the discovery lifecycle')
    }
    if (utilityController !== null && (typeof utilityController.isAvailable !== 'function' || typeof utilityController.start !== 'function')) {
        throw new TypeError('Utility controller must implement availability and structured start')
    }
    if (securityController !== null && (typeof securityController.isAvailable !== 'function' || typeof securityController.start !== 'function')) {
        throw new TypeError('Security controller must implement availability and transient structured start')
    }
    if (securityStateProvider !== null && typeof securityStateProvider.getModel !== 'function') {
        throw new TypeError('Security state provider must implement strict model projection')
    }
    let activeArea = store.getState().activeArea
    let observedSelectedDeviceId = getSelectedDevice()?.id ?? null
    let deviceRailOpen = false
    let destroyed = false
    let firmwareSubmitting = false
    let volumeLabelSubmitting = false
    const utilityFeedback = new UtilityFeedback(root, translator, translateUserReason)
    const operationSuccess = new OperationSuccessFeedback(root)
    const firmwareContinuation = new FirmwareContinuation(store, intentAdapter, () => renderState(store.getState()))
    const diagnosticSubmission = new DiagnosticSubmission(store, intentAdapter, () => renderState(store.getState()))
    const recovery = new RecoveryController(options.recoveryApi ?? supportApi?.recovery, store, () => renderState(store.getState()))
    const manufacturing = new ManufacturingController(options.manufacturingApi ?? supportApi?.manufacturing, store, () => renderState(store.getState()))
    let securityWorkflow = null
    let supportPanel = null
    let supportReturnFocusKey = null
    let supportRequestRevision = 0
    let activeLanguage = store.getState().settings?.language ?? 'en'
    let updateCheckPreferenceObserved = false
    let supportModel = {
        activeTopic: 'troubleshooting',
        activity: { busy: false, enabled: store.getState().settings?.eventLogging !== false, entries: [], filter: 'all', result: '' },
        app: null,
        busy: null,
        result: '',
        update: null
    }

    /**
     * Builds immutable availability flags for the current renderer view.
     * @returns {object} Intent type to availability mapping.
     */
    function getIntentAvailability() {
        return Object.freeze({
            scan: deviceController?.isAvailable() === true || intentAdapter.isAvailable(RendererIntentType.SCAN) === true,
            operation: intentAdapter.isAvailable(RendererIntentType.OPERATION) === true,
            'utility-operation': utilityController?.isAvailable() === true,
            'retry-operation': intentAdapter.isAvailable(RendererIntentType.RETRY_OPERATION) === true,
            'retry-service': intentAdapter.isAvailable(RendererIntentType.RETRY_SERVICE) === true,
            'hardware-service-register': typeof supportApi?.service?.register === 'function',
            'hardware-service-approval': typeof supportApi?.service?.openApprovalSettings === 'function',
            'open-support': typeof supportApi?.support?.generateSummary === 'function' || intentAdapter.isAvailable(RendererIntentType.OPEN_SUPPORT) === true,
            'open-event-log': typeof supportApi?.logs?.list === 'function' || intentAdapter.isAvailable(RendererIntentType.OPEN_EVENT_LOG) === true
        })
    }

    /** @param {object} changes - Bounded local support presentation changes. @param {string|null} [requestedFocusKey=getCurrentFocusKey()] - Control to restore after replacement. @returns {void} Merges and renders them. */
    function updateSupportModel(changes, requestedFocusKey = getCurrentFocusKey()) {
        supportModel = { ...supportModel, ...changes }
        renderState(store.getState(), requestedFocusKey)
    }

    /** @param {object} changes - Bounded local activity changes. @param {string|null} [requestedFocusKey=getCurrentFocusKey()] - Control to restore after replacement. @returns {void} Merges and renders them. */
    function updateActivityModel(changes, requestedFocusKey = getCurrentFocusKey()) {
        supportModel = { ...supportModel, activity: { ...supportModel.activity, ...changes } }
        renderState(store.getState(), requestedFocusKey)
    }

    /** @returns {Promise<void>} Refreshes the closed privileged-service setup state. */
    async function refreshPrivilegedServiceSetup() {
        if (typeof supportApi?.service?.getSetup !== 'function') return
        let response
        try {
            response = await supportApi.service.getSetup({})
        } catch {
            return
        }
        if (!destroyed && response?.ok === true) store.dispatch({ type: 'service/setup', setup: { state: response.state, ...(response.reason === undefined ? {} : { reason: response.reason }) } })
    }

    /** @returns {Promise<void>} Runs the fixed daemon registration action then refreshes setup truth. */
    async function registerPrivilegedService() {
        if (typeof supportApi?.service?.register !== 'function') return
        try {
            await supportApi.service.register({})
        } catch {
            // The subsequent bounded status read remains the source of UI truth.
        }
        await refreshPrivilegedServiceSetup()
    }

    /** @returns {Promise<void>} Opens the standard macOS approval panel. */
    async function openPrivilegedServiceApproval() {
        if (typeof supportApi?.service?.openApprovalSettings !== 'function') return
        try {
            await supportApi.service.openApprovalSettings({})
        } catch {
            // Native navigation failures stay contained at the bridge boundary.
        }
    }

    /** @returns {Promise<void>} Loads bounded redacted local activity into the open panel. */
    async function loadActivity() {
        if (typeof supportApi?.logs?.list !== 'function') return
        const revision = ++supportRequestRevision
        updateActivityModel({ busy: true, result: t('activity.loading') })
        let result
        try {
            result = await supportApi.logs.list({})
        } catch {
            result = { ok: false, reason: 'event-log-unavailable' }
        }
        if (destroyed || revision !== supportRequestRevision || supportPanel !== 'activity') return
        updateActivityModel({ busy: false, entries: result?.ok === true ? result.entries : [], result: result?.ok === true ? '' : t('activity.unavailable', { reason: translateUserReason(result?.reason, t) }) })
    }

    /** @returns {Promise<void>} Caches About metadata through the safe bridge. */
    async function loadAbout() {
        if (supportModel.app !== null || typeof supportApi?.app?.getInfo !== 'function') return
        try {
            const result = await supportApi.app.getInfo({})
            if (!destroyed && result?.ok === true) updateSupportModel({ app: result.app })
        } catch {
            // About remains useful with its local fallback when metadata is unavailable.
        }
    }

    /** @param {object|null} result - Validated update result. @returns {boolean} Whether Manager or applicable firmware availability should remain visible. */
    function hasAvailableUpdate(result) {
        return result?.ok === true && (result.manager?.status === 'available' || result.firmware?.status === 'available')
    }

    /** @param {object} result - Validated successful update result. @returns {string} Localized Manager and firmware availability. */
    function describeUpdateResult(result) {
        const manager = result.manager.status === 'available' ? t('update.manager.available', { version: result.manager.availableVersion }) : t('update.manager.current', { version: result.manager.currentVersion })
        const firmware = result.firmware.status === 'available' ? t(result.firmware.updates.length === 1 ? 'update.firmware.availableOne' : 'update.firmware.availableMany', { count: result.firmware.updates.length }) : t(result.firmware.status === 'current' ? 'update.firmware.current' : 'update.firmware.notApplicable')
        return t('update.result', { firmware, manager })
    }

    /** @param {'activity'|'compatibility'|'help'|'support'} panel - Local support surface. @param {string|null} returnFocusKey - Logical opener focus. @returns {void} Opens and starts safe reads. */
    function openSupportPanel(panel, returnFocusKey) {
        supportPanel = panel
        supportReturnFocusKey = returnFocusKey
        supportModel = { ...supportModel, activeTopic: panel === 'support' ? 'troubleshooting' : supportModel.activeTopic, result: hasAvailableUpdate(supportModel.update) ? describeUpdateResult(supportModel.update) : '' }
        renderState(store.getState(), 'support:title')
        if (panel === 'activity') void loadActivity()
        else if (panel !== 'compatibility') void loadAbout()
    }

    /** @returns {void} Closes local support and restores the logical opener. */
    function closeSupportPanel() {
        if (supportPanel === null) return
        supportRequestRevision += 1
        const focusKey = supportReturnFocusKey
        supportPanel = null
        supportReturnFocusKey = null
        renderState(store.getState(), focusKey)
    }

    /** @param {boolean} [silent=false] - Whether only available results should be published. @returns {Promise<void>} Performs one read-only signed metadata check. */
    async function checkForUpdates(silent = false) {
        if (typeof supportApi?.updates?.check !== 'function') return
        const focusKey = getCurrentFocusKey()
        if (!silent) updateSupportModel({ busy: 'updates', result: t('update.checking') }, focusKey)
        let result
        try {
            result = await supportApi.updates.check({ silent })
        } catch {
            result = { ok: false, reason: 'update-network-failure' }
        }
        if (destroyed) return
        if (result?.ok !== true) {
            if (silent || supportPanel === null) return
            updateSupportModel({ busy: null, result: t('update.failure', { reason: translateUserReason(result?.reason, t) }), update: null }, focusKey)
            return
        }
        if ((silent && !hasAvailableUpdate(result)) || (!silent && supportPanel === null)) return
        updateSupportModel({ busy: null, result: describeUpdateResult(result), update: result }, focusKey)
    }

    /** @returns {Promise<void>} Saves one main-collected local sanitized summary. */
    async function generateSupportSummary() {
        if (typeof supportApi?.support?.generateSummary !== 'function') return
        const focusKey = getCurrentFocusKey()
        updateSupportModel({ busy: 'summary', result: t('summary.collecting') }, focusKey)
        let result
        try {
            result = await supportApi.support.generateSummary({})
        } catch {
            result = { ok: false, reason: 'support-summary-save-failed' }
        }
        if (destroyed || supportPanel === null) return
        updateSupportModel({ busy: null, result: result?.ok === true ? t(result.deviceCount === 1 ? 'summary.savedOne' : 'summary.savedMany', { count: result.deviceCount, path: result.savedPath }) : t('summary.failed', { reason: translateUserReason(result?.reason, t) }) }, focusKey)
    }

    /** @returns {Promise<void>} Saves only already-redacted local activity. */
    async function exportActivity() {
        if (typeof supportApi?.logs?.export !== 'function') return
        const focusKey = getCurrentFocusKey()
        updateActivityModel({ busy: true, result: t('activity.exportChoosing') }, focusKey)
        let result
        try {
            result = await supportApi.logs.export({})
        } catch {
            result = { ok: false, reason: 'log-export-failed' }
        }
        if (destroyed || supportPanel !== 'activity') return
        updateActivityModel({ busy: false, result: result?.ok === true ? t('activity.exportSaved', { path: result.savedPath }) : t('activity.exportFailed', { reason: translateUserReason(result?.reason, t) }) }, focusKey)
    }

    /** @param {boolean} enabled - Requested optional diagnostic logging state. @returns {Promise<void>} Persists through the named logger method. */
    async function setEventLogging(enabled) {
        if (typeof supportApi?.logs?.setEnabled !== 'function') return
        const focusKey = getCurrentFocusKey()
        updateActivityModel({ busy: true, result: t(enabled ? 'activity.loggingTurningOn' : 'activity.loggingTurningOff') }, focusKey)
        let result
        try {
            result = await supportApi.logs.setEnabled({ enabled })
        } catch {
            result = { ok: false, reason: 'event-log-unavailable' }
        }
        if (result?.ok === true) store.dispatch({ type: 'settings/changed', settings: { ...store.getState().settings, eventLogging: enabled } })
        if (destroyed || supportPanel !== 'activity') return
        updateActivityModel({ busy: false, enabled: result?.ok === true ? enabled : supportModel.activity.enabled, result: result?.ok === true ? t(enabled ? 'activity.loggingEnabled' : 'activity.loggingDisabled') : t('activity.loggingFailed', { reason: translateUserReason(result?.reason, t) }) }, focusKey)
    }

    /** @param {string} key - Strict published setting key. @param {boolean|string} value - Bounded setting value. @param {string|null} focusKey - Focus restoration key. @returns {Promise<void>} Persists and applies the accepted response. */
    async function persistSetting(key, value, focusKey = null) {
        if (typeof supportApi?.settings?.update !== 'function') {
            const settings = { ...store.getState().settings, [key]: value }
            store.dispatch({ type: 'settings/changed', settings })
            restoreFocus(focusKey, store.getState())
            return
        }
        let result
        try {
            result = await supportApi.settings.update({ [key]: value })
        } catch {
            result = { ok: false, reason: 'settings-write-failed' }
        }
        if (destroyed) return
        if (result?.ok === true) {
            store.dispatch({ type: 'settings/changed', settings: result.settings })
        } else renderState(store.getState(), focusKey)
        restoreFocus(focusKey, store.getState())
    }

    /** @param {string} area - Accepted safe management area. @returns {void} Saves without blocking navigation. */
    function persistSafeView(area) {
        void persistSetting('lastSafeView', area)
    }

    /**
     * Finds the selected device in the current store snapshot.
     * @returns {object|null} Selected renderer-safe device or null.
     */
    function getSelectedDevice() {
        const state = store.getState()
        for (const device of state.devices) {
            if (device.id === state.selectedDeviceId) {
                return device
            }
        }
        return null
    }

    /** @param {object} state - Current store snapshot. @returns {object|null} Current strict Encryption model. */
    function getSecurityModel(state) {
        const device = getSelectedDevice()
        if (device === null) return null
        return securityStateProvider?.getModel(state, device, securityWorkflow, translator) ?? createProductionSecurityModel(state, device, securityWorkflow, translator)
    }

    /** @param {object} intent - Gated non-secret action intent. @returns {void} Opens its local workflow. */
    function handleSecurityAction(intent) {
        const model = getSecurityModel(store.getState())
        if (model === null) return
        securityWorkflow = createSecurityWorkflow(intent, model)
        renderState(store.getState())
    }

    /** @param {object} event - State-machine workflow event. @returns {void} Applies and renders the next state. */
    function handleSecurityWorkflowEvent(event) {
        if (securityWorkflow === null) return
        securityWorkflow = transitionSecurityWorkflow(securityWorkflow, event)
        renderState(store.getState())
    }

    /** @returns {void} Closes a non-running local workflow. */
    function handleSecurityWorkflowClose() {
        if (securityWorkflow?.phase === 'running') return
        securityWorkflow = null
        renderState(store.getState())
    }

    /** @param {string} reason - Stable local validation reason. @returns {void} Keeps the workflow visible without dispatch. */
    function handleSecurityWorkflowError(reason) {
        if (typeof reason !== 'string' || securityWorkflow === null) return
        renderState(store.getState())
    }

    /**
     * Sends one already-confirmed intent only through the injected privileged
     * boundary. The transient credential buffer is neither copied nor retained.
     * @param {object} intent - Confirmed structured intent.
     * @param {Uint8Array|null} credential - Transient credential bytes.
     * @returns {Promise<object>} Bounded admission result.
     */
    async function handleSecurityIntent(intent, credential) {
        if (securityController?.isAvailable(intent.operation) !== true) return { ok: false, reason: 'security-service-unavailable' }
        let result
        try {
            result = await securityController.start(intent, credential)
        } catch {
            result = { ok: false, reason: 'security-service-failure' }
        }
        if (result?.ok !== true && securityWorkflow?.phase === 'running') {
            securityWorkflow = transitionSecurityWorkflow(securityWorkflow, { result: { status: 'failed', summary: translateUserReason(result?.reason, translator) }, type: 'finish' })
            renderState(store.getState())
        }
        return result
    }

    /** @param {object} model - Current model. @returns {void} Replaces serialized Encryption markup with its live callback-owning node. */
    function mountLiveEncryptionView(model) {
        const serializedView = root.querySelector('[data-encryption-view]')
        if (serializedView === null) return
        const liveView = renderEncryptionView(model, {
            document: root.ownerDocument,
            onAction: handleSecurityAction,
            onIntent: handleSecurityIntent,
            onWorkflowClose: handleSecurityWorkflowClose,
            onWorkflowError: handleSecurityWorkflowError,
            onWorkflowEvent: handleSecurityWorkflowEvent,
            translator
        })
        serializedView.replaceWith(liveView)
    }

    /**
     * Reads the stable key for the currently focused application control.
     * @returns {string|null} Logical focus key, or null outside keyed app controls.
     */
    function getCurrentFocusKey() {
        const activeElement = root.ownerDocument.activeElement
        if (activeElement === null || !root.contains(activeElement)) {
            return null
        }
        return activeElement.dataset.focusKey ?? null
    }

    /**
     * Focuses the enabled control that owns a logical key in the current view.
     * When that physical control disappeared or became disabled, focus moves to
     * the active operation status, selected tab/heading, or primary state anchor.
     * @param {string|null} focusKey - Stable control key captured before render.
     * @param {object} state - Current renderer snapshot used to choose a fallback.
     * @param {boolean} [preventScroll] - Keep the viewport still during background refresh.
     * @returns {void} Completes after focus is restored when the control exists.
     */
    function restoreFocus(focusKey, state, preventScroll = false) {
        if (focusKey === null) {
            return
        }
        for (const candidate of root.querySelectorAll('[data-focus-key]')) {
            if (candidate.dataset.focusKey === focusKey && !candidate.disabled) {
                if (candidate !== root.ownerDocument.activeElement) candidate.focus({ preventScroll })
                return
            }
        }

        let selectedDeviceAvailable = false
        for (const device of state.devices) {
            selectedDeviceAvailable = selectedDeviceAvailable || device.id === state.selectedDeviceId
        }
        const fallbackSelectors = state.activeOperation !== null ? ['[data-focus-fallback="operation-status"]'] : selectedDeviceAvailable ? ['[role="tab"][aria-selected="true"]', '[data-focus-fallback="selected-heading"]'] : ['[data-focus-fallback="primary-state"]']
        for (const selector of fallbackSelectors) {
            const fallback = root.querySelector(selector)
            if (fallback !== null && !fallback.disabled) {
                fallback.focus({ preventScroll })
                return
            }
        }
    }

    /**
     * Reconciles the mounted view from a complete immutable store snapshot.
     * @param {object} state - Current renderer store snapshot.
     * @param {string|null} [requestedFocusKey] - Optional logical focus key after render.
     * @returns {void} Completes after the DOM is updated and focus restored.
     */
    function renderState(state, requestedFocusKey = getCurrentFocusKey()) {
        if (destroyed) {
            return
        }

        const formatDraft = captureFormatForm(root)
        const volumeLabelDraft = captureVolumeLabelForm(root)
        const encryptionModel = getSecurityModel(state)
        const renderedShell = renderShell(state, {
            activeArea,
            availableDriveLetters: options.availableDriveLetters,
            currentSataMode: options.currentSataMode,
            deviceRailOpen,
            document: root.ownerDocument,
            encryptionModel,
            operationSuccessVisible: operationSuccess.visible,
            firmwareContinuation: firmwareContinuation.getState(state.activeOperation),
            recovery: recovery.getView(),
            manufacturing: manufacturing.getView(),
            diagnosticRequest: diagnosticSubmission.request,
            intentAvailability: getIntentAvailability(),
            platform: options.platform,
            supportModel,
            supportPanel,
            translator
        })
        // Every tab must retain its scroll owner during background refreshes.
        // Encryption still remounts its callback-owning subtree below.
        if (root.childNodes.length === 0) root.innerHTML = renderedShell
        else reconcileRenderedShell(root, renderedShell)
        restoreFormatForm(root, formatDraft, translator)
        restoreVolumeLabelForm(root, volumeLabelDraft, volumeLabelSubmitting)
        if (firmwareSubmitting) {
            const action = root.querySelector('[data-action="start-firmware"]')
            if (action) {
                action.disabled = true
                action.setAttribute('aria-busy', 'true')
            }
        }
        utilityFeedback.sync(getSelectedDevice())
        if (activeArea === 'encryption' && encryptionModel !== null) mountLiveEncryptionView(encryptionModel)
        restoreFocus(requestedFocusKey, state, arguments.length < 2)
        operationSuccess.syncVisibility()
    }

    /**
     * Re-renders after an accepted store transition.
     * @param {object} state - New immutable renderer store snapshot.
     * @returns {void} Completes after the new snapshot is displayed.
     */
    function handleStoreState(state) {
        const selectedDeviceId = state.devices.some((device) => device.id === state.selectedDeviceId) ? state.selectedDeviceId : null
        if (selectedDeviceId !== observedSelectedDeviceId) {
            observedSelectedDeviceId = selectedDeviceId
            // A newly established selection starts on Status, not the previous
            // drive's Tools tab. Refreshing the same drive preserves navigation.
            if (selectedDeviceId !== null) activeArea = 'status'
        }
        recovery.observe(state)
        manufacturing.observe(state)
        operationSuccess.observe(state)
        diagnosticSubmission.observe(state)
        if (typeof state.settings?.language === 'string' && state.settings.language !== activeLanguage) {
            activeLanguage = state.settings.language
            onLanguageChanged(activeLanguage)
        }
        if (typeof state.settings?.eventLogging === 'boolean' && supportModel.activity.enabled !== state.settings.eventLogging) {
            supportModel = { ...supportModel, activity: { ...supportModel.activity, enabled: state.settings.eventLogging } }
        }
        if (!updateCheckPreferenceObserved && typeof state.settings?.updateChecks === 'boolean') {
            updateCheckPreferenceObserved = true
            if (state.settings.updateChecks) void checkForUpdates(true)
        }
        renderState(state)
    }

    /**
     * Handles local shell controls without issuing device or operating-system commands.
     * @param {MouseEvent} event - Delegated click event from the application root.
     * @returns {Promise<void>} Resolves after the selected action and its presentation update.
     */
    async function handleClick(event) {
        const target = event.target
        if (target === null || typeof target.closest !== 'function') {
            return
        }

        if (target.closest('[data-action="close-support-panel"]') !== null) {
            closeSupportPanel()
            return
        }

        const helpTopic = target.closest('[data-help-topic]')
        if (helpTopic !== null && findHelpTopic(helpTopic.dataset.helpTopic) !== null) {
            supportModel = { ...supportModel, activeTopic: helpTopic.dataset.helpTopic }
            renderState(store.getState(), helpTopic.dataset.focusKey ?? null)
            return
        }

        const localAction = target.closest('[data-action]')
        const manufacturingAction = target.closest('[data-manufacturing-action]')
        if (manufacturingAction !== null && !manufacturingAction.disabled) {
            if (manufacturingAction.dataset.manufacturingAction === 'open-folder') await manufacturing.openFolder()
            else if (manufacturingAction.dataset.manufacturingAction === 'refresh') await manufacturing.refresh()
            else if (['previous', 'next'].includes(manufacturingAction.dataset.manufacturingAction)) await manufacturing.navigate(manufacturingAction.dataset.manufacturingAction)
            else await manufacturing.submit(manufacturingAction.dataset.manufacturingAction)
            return
        }
        const recoveryAction = target.closest('[data-recovery-action]')
        if (recoveryAction !== null && !recoveryAction.disabled) {
            if (recoveryAction.dataset.recoveryAction === 'refresh') await recovery.refresh()
            else await recovery.submit(recoveryAction.dataset.recoveryAction)
            return
        }
        if (localAction?.dataset.action === 'continue-firmware-installation' && !localAction.disabled) {
            await firmwareContinuation.submit()
            return
        }
        if (localAction?.dataset.action === 'open-firmware-workflow' && !localAction.disabled && getSelectedDevice() !== null && store.getState().activeOperation === null) {
            // This shortcut opens preflight; only its explicit action may choose
            // an image and submit the required main-owned firmware file token.
            activeArea = 'utilities'
            renderState(store.getState(), 'utilities:firmware:heading')
            persistSafeView(activeArea)
            return
        }
        if (localAction?.dataset.action === 'open-help') {
            openSupportPanel('help', localAction.dataset.focusKey ?? null)
            return
        }
        if (localAction?.dataset.action === 'open-compatibility') {
            openSupportPanel('compatibility', localAction.dataset.focusKey ?? null)
            return
        }
        if (localAction?.dataset.action === 'open-event-log' && typeof supportApi?.logs?.list === 'function') {
            openSupportPanel('activity', localAction.dataset.focusKey ?? null)
            return
        }
        if (localAction?.dataset.action === 'open-support' && typeof supportApi?.support?.generateSummary === 'function') {
            openSupportPanel('support', localAction.dataset.focusKey ?? null)
            return
        }
        if (localAction?.dataset.action === 'check-updates') {
            void checkForUpdates()
            return
        }
        if (localAction?.dataset.action === 'generate-summary') {
            void generateSupportSummary()
            return
        }
        if (localAction?.dataset.action === 'export-logs') {
            void exportActivity()
            return
        }

        const areaButton = target.closest('[role="tab"][data-area]')
        if (areaButton !== null && !areaButton.disabled) {
            activeArea = areaButton.dataset.area
            renderState(store.getState(), areaButton.dataset.focusKey)
            persistSafeView(activeArea)
            return
        }

        const railToggle = target.closest('[data-action="toggle-device-rail"]')
        if (railToggle !== null) {
            deviceRailOpen = !deviceRailOpen
            renderState(store.getState(), railToggle.dataset.focusKey)
            return
        }

        const deviceButton = target.closest('[data-action="manage-device"][data-device-id]')
        if (deviceButton !== null && !deviceButton.disabled) {
            store.dispatch({ type: 'device/select', deviceId: deviceButton.dataset.deviceId })
            return
        }

        const utilityControl = target.closest('[data-utility-operation]')
        if (utilityControl !== null && !utilityControl.disabled && utilityController !== null) {
            const device = getSelectedDevice()
            const card = utilityControl.closest('[data-feature]')
            if (device === null || card === null) return
            const request = createUtilityRequest(utilityControl.dataset.utilityOperation, device, card, options.platform)
            if (request === null) return
            if (request.kind === 'firmware-update') {
                if (firmwareSubmitting) return
                firmwareSubmitting = true
            }
            if (request.kind === 'volume-label-set') {
                if (volumeLabelSubmitting) return
                volumeLabelSubmitting = true
            }
            for (const password of card.querySelectorAll('[data-format-password]')) password.value = ''
            utilityControl.disabled = true
            utilityControl.setAttribute('aria-busy', 'true')
            const feedbackTicket = utilityFeedback.begin(device, request.kind)

            let result
            try {
                result = await utilityController.start(request, { getSelectedDevice })
            } catch {
                result = { ok: false, reason: 'service-failure' }
            } finally {
                if (request.kind === 'firmware-update') firmwareSubmitting = false
                if (request.kind === 'volume-label-set') volumeLabelSubmitting = false
            }
            if (destroyed) return
            utilityFeedback.complete(feedbackTicket, result, getSelectedDevice())
            if (request.kind === 'firmware-update') {
                renderState(store.getState())
                return
            }
            utilityControl.removeAttribute('aria-busy')
            if (result?.ok !== true) utilityControl.disabled = false
            return
        }

        const hardwareSetupAction = target.closest('[data-action="register-hardware-service"], [data-action="open-hardware-approval"]')
        if (hardwareSetupAction !== null && !hardwareSetupAction.disabled) {
            hardwareSetupAction.disabled = true
            if (hardwareSetupAction.dataset.action === 'register-hardware-service') void registerPrivilegedService()
            else void openPrivilegedServiceApproval()
            return
        }

        const intentControl = target.closest('[data-intent]')
        if (intentControl === null || intentControl.disabled) {
            return
        }

        const intentType = intentControl.dataset.intent
        if (intentType === RendererIntentType.SCAN && deviceController !== null) {
            void deviceController.requestManualScan()
            return
        }
        if (intentType === RendererIntentType.OPERATION) {
            const device = getSelectedDevice()
            if (device !== null) {
                // Use the validated snapshot; a preflight scan would seize USB and race eject.
                const intent = { type: intentType, kind: intentControl.dataset.operation, deviceId: device.id, deviceRevision: device.revision }
                if (diagnosticSubmission.handles(intent)) await diagnosticSubmission.start(intent)
                else await intentAdapter.invoke(intent)
            }
            return
        }
        if (intentType === RendererIntentType.RETRY_OPERATION) {
            const lastOperation = store.getState().lastOperation
            const device = getSelectedDevice()
            if (lastOperation?.status === 'failed' && lastOperation.error.retryable === true && device?.id === lastOperation.deviceId) {
                await intentAdapter.invoke({ type: intentType, kind: lastOperation.kind, deviceId: lastOperation.deviceId, deviceRevision: device.revision, operationId: lastOperation.id })
            }
            return
        }

        await intentAdapter.invoke({ type: intentType })
    }

    /**
     * Implements horizontal ARIA tab navigation with automatic activation.
     * Arrow keys wrap, while Home and End select the first and last enabled tab.
     * @param {KeyboardEvent} event - Delegated keyboard event from the application root.
     * @returns {void} Completes after any area and focus update.
     */
    function handleKeyDown(event) {
        const target = event.target
        if (target === null || typeof target.closest !== 'function') {
            return
        }

        const currentTab = target.closest('[role="tab"][data-area]')
        if (currentTab === null || currentTab.disabled || !['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
            return
        }

        const enabledTabs = []
        for (const tab of root.querySelectorAll('[role="tab"][data-area]')) {
            if (!tab.disabled) {
                enabledTabs.push(tab)
            }
        }
        const currentIndex = enabledTabs.indexOf(currentTab)
        if (currentIndex === -1 || enabledTabs.length === 0) {
            return
        }

        let nextIndex = currentIndex
        if (event.key === 'Home') {
            nextIndex = 0
        } else if (event.key === 'End') {
            nextIndex = enabledTabs.length - 1
        } else if (event.key === 'ArrowRight') {
            nextIndex = (currentIndex + 1) % enabledTabs.length
        } else {
            nextIndex = (currentIndex - 1 + enabledTabs.length) % enabledTabs.length
        }

        event.preventDefault()
        const nextTab = enabledTabs[nextIndex]
        activeArea = nextTab.dataset.area
        renderState(store.getState(), nextTab.dataset.focusKey)
        persistSafeView(activeArea)
    }

    /**
     * Persists presentation settings through the immutable renderer store.
     * The store independently rejects changes while an operation is active.
     * @param {Event} event - Delegated form change event from the application root.
     * @returns {void} Completes after any accepted setting transition.
     */
    function handleChange(event) {
        const target = event.target
        if (target?.matches?.('[data-manufacturing-field]') && !target.disabled) {
            manufacturing.select(target.dataset.manufacturingField, target.type === 'checkbox' ? target.checked : target.value)
            return
        }
        if (target?.matches?.('[data-recovery-field]') && !target.disabled) {
            recovery.select(target.dataset.recoveryField, target.type === 'checkbox' ? target.checked : target.value)
            return
        }
        if (target?.matches?.('[data-utility-filesystem]')) {
            updateFormatForm(target.closest('[data-feature]'), translator)
            return
        }
        if (target?.matches?.('[data-activity-filter]')) {
            updateActivityModel({ filter: target.value })
            return
        }
        if (target?.dataset?.setting === 'event-logging' && !target.disabled) {
            void setEventLogging(target.checked === true)
            return
        }
        if (target?.dataset?.setting === 'language') {
            void persistSetting('language', target.value, target.dataset.focusKey ?? null)
            return
        }
        if (target?.dataset?.setting === 'update-checks') {
            void persistSetting('updateChecks', target.checked === true, target.dataset.focusKey ?? null)
            return
        }
        if (target?.matches?.('[data-utility-mode], [data-utility-sata-mode]')) {
            updateModeAction(target, translator)
            return
        }
        if (target?.matches?.('[data-force-risk]')) {
            const button = target.closest('[data-feature]')?.querySelector('[data-action="eject-force"]')
            if (button !== null) button.disabled = target.checked !== true || button.dataset.readyWhenAcknowledged !== 'true'
            return
        }
        if (target?.dataset?.setting !== 'auto-scan' || target.disabled) {
            return
        }
        const focusKey = target.dataset.focusKey ?? null
        void persistSetting('autoScan', target.checked === true, focusKey)
    }

    /**
     * Updates the exact-confirmation button without retaining the typed identity.
     * @param {Event} event - Delegated input event.
     * @returns {void} Completes after matching visible identity text.
     */
    function handleInput(event) {
        const input = event.target
        if (input?.matches?.('[data-manufacturing-field="confirmationSerial"]') && !input.disabled) {
            manufacturing.select('confirmationSerial', input.value)
            return
        }
        if (input?.matches?.('[data-utility-volume-label]')) {
            updateVolumeLabelForm(input, volumeLabelSubmitting)
            return
        }
        if (!input?.matches?.('[data-format-confirmation], [data-format-password]')) return
        updateFormatForm(input.closest('[data-feature]'), translator)
    }

    /**
     * Implements F1 local help, safe Escape close, and modal focus containment.
     * @param {KeyboardEvent} event - Renderer document keyboard event.
     * @returns {void} Completes after local support navigation.
     */
    function handleDocumentKeyDown(event) {
        if (event.key === 'F1') {
            event.preventDefault()
            const focusKey = root.contains(root.ownerDocument.activeElement) ? (root.ownerDocument.activeElement?.dataset?.focusKey ?? null) : null
            openSupportPanel('help', focusKey)
            return
        }
        if (supportPanel === null) return
        if (event.key === 'Escape') {
            event.preventDefault()
            closeSupportPanel()
            return
        }
        if (event.key !== 'Tab') return
        const overlay = root.querySelector('[data-support-overlay]')
        const controls = overlay === null ? [] : [...overlay.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), [href], [tabindex]:not([tabindex="-1"])')]
        if (controls.length === 0) return
        const first = controls[0]
        const last = controls.at(-1)
        const active = root.ownerDocument.activeElement
        if (event.shiftKey && (active === first || !overlay.contains(active))) {
            event.preventDefault()
            last.focus()
        } else if (!event.shiftKey && (active === last || !overlay.contains(active))) {
            event.preventDefault()
            first.focus()
        }
    }

    const unsubscribe = store.subscribe(handleStoreState)
    root.addEventListener('click', handleClick)
    root.addEventListener('keydown', handleKeyDown)
    root.addEventListener('change', handleChange)
    root.addEventListener('input', handleInput)
    root.ownerDocument.addEventListener('keydown', handleDocumentKeyDown)
    handleStoreState(store.getState())
    void loadAbout()

    /**
     * Removes subscriptions and delegated listeners without mutating app state.
     * Repeated calls are safe.
     * @returns {void} Completes after the controller becomes inactive.
     */
    function destroy() {
        if (destroyed) {
            return
        }
        destroyed = true
        recovery.destroy()
        manufacturing.destroy()
        operationSuccess.destroy()
        diagnosticSubmission.destroy()
        root.removeEventListener('click', handleClick)
        root.removeEventListener('keydown', handleKeyDown)
        root.removeEventListener('change', handleChange)
        root.removeEventListener('input', handleInput)
        root.ownerDocument.removeEventListener('keydown', handleDocumentKeyDown)
        unsubscribe()
        deviceController?.destroy()
    }

    return Object.freeze({ destroy })
}
