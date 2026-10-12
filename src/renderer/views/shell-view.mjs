// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { getFirmwareInstallationGuidanceKey } from '../firmware-installation-stages.mjs'
import { renderRecoveryView } from './recovery-view.mjs'
import { createProductionSecurityModel } from '../security-production-model.mjs'
import { HELP_TOPICS } from '../../help/help-index.mjs'
import { renderActivityView } from './activity-view.mjs'
import { createCompatibilityModel, renderCompatibilityView } from './compatibility-view.mjs'
import { renderEncryptionView } from './encryption-view.mjs'
import { renderHelpView } from './help-view.mjs'
import { renderStatusView } from './status-view.mjs'
import { renderTestsView } from './tests-view.mjs'
import { renderUtilitiesView } from './utilities-view.mjs'
import { getIntentUnavailableMessage, getIntentUnavailableReasonId, renderIntentUnavailableReason } from './intent-view.mjs'
import { escapeHtml, formatLocalizedSentenceToken, formatLocalizedToken, toDomToken } from './view-helpers.mjs'
import { getFirmwareFailureReasonKey, getFirmwarePreflightFailureReasonKey } from '../firmware-failure-reasons.mjs'

const AREAS = Object.freeze([
    { id: 'status', labelKey: 'areas.status', icon: 'ph-gauge' },
    { id: 'encryption', labelKey: 'areas.encryption', icon: 'ph-shield-check' },
    { id: 'tests', labelKey: 'areas.tests', icon: 'ph-flask' },
    { id: 'utilities', labelKey: 'areas.utilities', icon: 'ph-wrench' }
])

/**
 * Checks whether a presentation area belongs to the approved four-area model.
 * @param {unknown} areaId - Candidate presentation area identifier.
 * @returns {boolean} True when the identifier names a published area.
 */
function isKnownArea(areaId) {
    for (const area of AREAS) {
        if (area.id === areaId) {
            return true
        }
    }
    return false
}

/**
 * Locates the currently selected device without accepting a stale identifier.
 * @param {object} state - Renderer store snapshot.
 * @returns {object|null} Selected snapshot or null when unavailable.
 */
function getSelectedDevice(state) {
    for (const device of state.devices) {
        if (device.id === state.selectedDeviceId) {
            return device
        }
    }
    return null
}

/**
 * Reports whether the current service has proven privileged native hardware access.
 * @param {object} service - Renderer-safe service state.
 * @returns {boolean} True only when discovery can reach native hardware.
 */
export function isDiscoveryAvailable(service) {
    return service?.status === 'ready' && service.mode === 'native' && service.privileged === true && service.platformCapability?.state === 'available'
}

/**
 * Renders service readiness and connection status from validated discovery state.
 * @param {object} state - Renderer snapshot with service, provenance, and validated devices.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @param {object} setup - Renderer-safe privileged service setup state.
 * @returns {string} Service status pill markup.
 */
function renderServiceStatus(state, t, setup) {
    const { service, provenance, devices } = state
    const setupRequired = provenance === 'service' && ['not-registered', 'not-found', 'invalid-signature', 'registration-failed', 'installer-required', 'repair-required'].includes(setup?.state)
    const approvalRequired = provenance === 'service' && setup?.state === 'requires-approval'
    const unavailable = service.status === 'unavailable'
    const pending = ['starting', 'restarting', 'recovering', 'reconciling'].includes(service.status)
    const noHardware = provenance === 'service' && service.status === 'ready' && service.hardwareReady !== true
    // hardwareReady describes transport access; only validated current devices
    // prove a connection, including after a removal or an empty rescan.
    const discoveryReady = provenance === 'service' && service.status === 'ready' && service.hardwareReady === true
    const connectedHardware = discoveryReady && devices.length > 0
    const noDevices = discoveryReady && devices.length === 0
    const label = setupRequired ? t('service.setupRequiredBadge') : approvalRequired ? t('service.approvalRequiredBadge') : unavailable ? t('service.unavailable') : pending ? t(`service.${service.status}`) : noHardware ? t('service.noHardware') : noDevices ? t('service.noDevices') : connectedHardware ? t('service.hardwareConnected') : t('service.ready')
    const icon = setupRequired ? 'ph-shield-check' : approvalRequired ? 'ph-gear' : unavailable || noHardware ? 'ph-warning-circle' : pending ? 'ph-circle-notch' : noDevices ? 'ph-plugs' : 'ph-check-circle'
    const tone = unavailable ? ' service-pill--error' : setupRequired || approvalRequired || noHardware || noDevices || pending ? ' service-pill--warning' : ''

    return `<span class="service-pill${tone}" data-service-status="${escapeHtml(service.status)}"><i class="ph-fill ${icon}" aria-hidden="true"></i>${label}</span>`
}

/**
 * Renders the highest-priority packaged macOS launch-daemon setup state.
 * @param {object} setup - Closed renderer-safe ServiceManagement state.
 * @param {object} availability - Exact setup method availability.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {string} Actionable setup card without native paths or errors.
 */
function renderPrivilegedServiceSetup(setup, availability, t) {
    if (['installer-required', 'repair-required'].includes(setup.state)) {
        const repair = setup.state === 'repair-required'
        const checkAttributes = availability['hardware-service-check'] === true ? '' : ' disabled'
        return `<main class="state-workspace" id="main-content" aria-labelledby="empty-state-title"><section class="empty-state empty-state--warning" data-hardware-setup="${escapeHtml(setup.state)}"><span class="state-icon"><i class="ph-duotone ph-shield-check" aria-hidden="true"></i></span><span class="eyebrow">${t('service.hardwareSetup')}</span><h1 id="empty-state-title" data-focus-fallback="primary-state" data-focus-key="state:hardware-setup" tabindex="-1">${t(repair ? 'service.repairRequiredTitle' : 'service.installerRequiredTitle')}</h1><p>${t(repair ? 'service.macosRepairDescription' : 'service.macosInstallerDescription')}</p><button class="button button--primary" type="button" data-action="check-hardware-setup"${checkAttributes}><i class="ph ph-arrow-clockwise" aria-hidden="true"></i><span>${t('service.checkApproval')}</span></button></section></main>`
    }
    const approval = setup.state === 'requires-approval'
    const registerAvailable = availability['hardware-service-register'] === true
    const approvalAvailable = availability['hardware-service-approval'] === true
    const registerAttributes = registerAvailable ? '' : ' disabled'
    const approvalAttributes = approvalAvailable ? '' : ' disabled'
    const icon = approval ? 'ph-gear' : 'ph-shield-check'
    const title = approval ? t('service.approvalRequiredTitle') : t('service.setupRequiredTitle')
    const description = approval ? t('service.approvalRequiredDescription') : t('service.setupRequiredDescription')
    return `<main class="state-workspace" id="main-content" aria-labelledby="empty-state-title"><section class="empty-state empty-state--warning" data-hardware-setup="${escapeHtml(setup.state)}"><span class="state-icon"><i class="ph-duotone ${icon}" aria-hidden="true"></i></span><span class="eyebrow">${t('service.hardwareSetup')}</span><h1 id="empty-state-title" data-focus-fallback="primary-state" data-focus-key="state:hardware-setup" tabindex="-1">${title}</h1><p>${description}</p>${approval ? `<button class="button button--primary" type="button" data-action="open-hardware-approval"${approvalAttributes}><i class="ph ph-sliders-horizontal" aria-hidden="true"></i><span>${t('service.openApprovalSettings')}</span></button><button class="text-link" type="button" data-action="register-hardware-service"${registerAttributes}><i class="ph ph-arrow-clockwise" aria-hidden="true"></i>${t('service.checkApproval')}</button>` : `<button class="button button--primary" type="button" data-action="register-hardware-service"${registerAttributes}><i class="ph ph-shield-check" aria-hidden="true"></i><span>${t('service.setupAction')}</span></button>`}</section></main>`
}

/** @param {object} service - Ready but hardware-blocked service. @param {(key: string) => string} t - Translator. @param {string} [failure=''] - Trusted operation failure markup. @returns {string} Exact permission recovery card. */
function renderHardwareAccessUnavailable(service, t, failure = '', platform) {
    const reason = service.platformCapability?.reason ?? 'hardware-unavailable'
    return `<main class="state-workspace" id="main-content" aria-labelledby="empty-state-title">${failure}<section class="empty-state empty-state--error"><span class="state-icon"><i class="ph-duotone ph-plugs-connected" aria-hidden="true"></i></span><span class="eyebrow">${t('service.boundary')}</span><h1 id="empty-state-title" data-focus-fallback="primary-state" data-focus-key="state:hardware-unavailable" tabindex="-1">${t('service.hardwareUnavailable')}</h1><p>${t('service.permissionDescription')}</p>${platform === 'win32' ? `<p>${t('service.windowsRepairDescription')}</p>` : ''}<code id="hardware-access-unavailable-reason">${escapeHtml(reason)}</code><button class="button button--primary" type="button" data-action="scan-devices" data-intent="scan" aria-describedby="hardware-access-unavailable-reason" title="${t('capability.hardwareUnavailable')}" disabled><i class="ph ph-magnifying-glass" aria-hidden="true"></i><span>${t('devices.scan')}</span></button></section></main>`
}

/** @param {object} discovery - Current aggregate discovery outcome. @returns {boolean} True for one or more safely classified mounted candidates. */
function hasMountedCandidate(discovery) {
    return discovery?.diagnostics?.rejections?.some((rejection) => rejection.reason === 'media-mounted' && rejection.count > 0) === true
}

/** @param {object} availability - Intent availability. @param {boolean} scanBusy - Active scan state. @param {(key: string) => string} t - Translator. @param {string} [failure=''] - Trusted operation failure markup. @returns {string} Mounted-media guidance. */
function renderMountedCandidateState(availability, scanBusy, t, failure = '') {
    const scanAvailable = availability.scan === true && !scanBusy
    return `<main class="state-workspace" id="main-content" aria-labelledby="empty-state-title">${failure}<section class="empty-state empty-state--warning" data-mounted-candidate><span class="state-icon"><i class="ph-duotone ph-hard-drive" aria-hidden="true"></i></span><span class="eyebrow">${t('empty.mountedEyebrow')}</span><h1 id="empty-state-title" data-focus-fallback="primary-state" data-focus-key="state:mounted-candidate" tabindex="-1">${t('empty.mountedTitle')}</h1><p>${t('empty.mountedDescription')}</p><button class="button button--primary" type="button" data-action="scan-devices" data-intent="scan"${scanAvailable ? '' : ' disabled'}><i class="ph ph-arrow-clockwise" aria-hidden="true"></i><span>${t('empty.mountedScanAgain')}</span></button></section></main>`
}

/**
 * Renders event-log and support controls through the external intent boundary.
 * @param {object} availability - Intent availability flags from the controller.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @returns {string} Top-bar action markup.
 */
function renderTopbarActions(availability, t) {
    const logAvailable = availability['open-event-log'] === true
    const supportAvailable = availability['open-support'] === true
    const logReasonId = getIntentUnavailableReasonId('open-event-log', 'topbar')
    const supportReasonId = getIntentUnavailableReasonId('open-support', 'topbar')
    const logAttributes = logAvailable ? ` title="${t('topbar.openEventLog')}"` : ` title="${getIntentUnavailableMessage('open-event-log', t)}" aria-describedby="${logReasonId}" disabled`
    const supportAttributes = supportAvailable ? '' : ` title="${getIntentUnavailableMessage('open-support', t)}" aria-describedby="${supportReasonId}" disabled`
    return `<div class="topbar__actions" data-intent-group="topbar-actions"><div class="topbar__action-buttons"><button class="icon-button" type="button" data-action="open-mcp" data-focus-key="topbar:mcp" aria-label="${t('topbar.openMcp')}" title="${t('topbar.openMcp')}"><i class="ph ph-plugs-connected" aria-hidden="true"></i></button><button class="icon-button" type="button" data-action="open-help" data-focus-key="topbar:help" aria-label="${t('topbar.openHelp')}" title="${t('topbar.openHelpShortcut')}"><i class="ph ph-question" aria-hidden="true"></i></button><button class="icon-button" type="button" data-action="open-compatibility" data-focus-key="topbar:compatibility" aria-label="${t('topbar.openCompatibility')}" title="${t('topbar.openCompatibility')}"><i class="ph ph-check-square-offset" aria-hidden="true"></i></button><button class="icon-button" type="button" data-action="open-event-log" data-intent="open-event-log" data-focus-key="topbar:event-log" aria-label="${t('topbar.openEventLog')}"${logAttributes}><i class="ph ph-clock-counter-clockwise" aria-hidden="true"></i></button><button class="button button--warning topbar__support-button" type="button" data-action="open-support" data-intent="open-support" data-focus-key="topbar:support" aria-label="${t('topbar.openSupport')}"${supportAttributes}><i class="ph ph-lifebuoy" aria-hidden="true"></i><span class="topbar__support-label">${t('topbar.helpSupport')}</span></button></div><div class="topbar__intent-reasons">${renderIntentUnavailableReason('open-event-log', 'topbar', logAvailable, t)}${renderIntentUnavailableReason('open-support', 'topbar', supportAvailable, t)}</div></div>`
}

/**
 * Renders the active local support surface outside the inert application shell.
 * @param {'activity'|'compatibility'|'help'|'support'|null} panel - Current support surface.
 * @param {object} model - Local presentation state.
 * @param {Document|undefined} document - Owning renderer document.
 * @param {(key: string, params?: object) => string} t - Active bounded translator.
 * @returns {string} Accessible modal markup or empty text.
 */
function renderSupportOverlay(panel, model, document, t) {
    if (panel === null || document === undefined) return ''
    const view = panel === 'activity' ? renderActivityView(model.activity ?? {}, { document, translator: t }) : panel === 'compatibility' ? renderCompatibilityView(model.compatibility ?? {}, { document, translator: t }) : renderHelpView({ activeTopic: model.activeTopic, app: model.app, busy: model.busy, mode: panel === 'support' ? 'support' : 'help', summaryResult: model.result, topics: HELP_TOPICS, update: model.update }, { document, translator: t })
    const titleId = panel === 'activity' ? 'activity-title' : panel === 'compatibility' ? 'compatibility-title' : 'help-title'
    return `<div class="support-overlay" data-support-overlay role="dialog" aria-modal="true" aria-labelledby="${titleId}">${view.outerHTML}</div>`
}

/**
 * Renders a stable visible reason when the ready service has no hardware transport.
 * @param {string} context - Unique physical Scan-control context.
 * @param {boolean} hardwareAvailable - Whether native hardware is reconciled.
 * @param {(key: string, params?: object) => string} t - Active bounded translator.
 * @returns {string} Visible reason markup or empty text.
 */
function renderHardwareUnavailableReason(context, hardwareAvailable, t) {
    return hardwareAvailable ? '' : `<span class="capability-reason" id="hardware-scan-${toDomToken(context)}-unavailable" data-capability-state="hardware-unavailable">${t('capability.hardwareUnavailable')}</span>`
}

/**
 * Renders the selected-device rail and its compact-layout disclosure control.
 * @param {object} state - Renderer store snapshot.
 * @param {object|null} selectedDevice - Selected device or null.
 * @param {{deviceRailOpen: boolean, hardwareAvailable: boolean, locked: boolean, scanBusy: boolean, scanIntentAvailable: boolean, translator: (key: string, params?: object) => string}} options - Rail presentation state.
 * @returns {string} Device selection rail markup.
 */
function renderDeviceRail(state, selectedDevice, options) {
    const t = options.translator
    const deviceCards = []
    const autoScanEnabled = state.settings?.autoScan === true
    const serviceReady = state.service.status === 'ready'
    const checkedAttribute = autoScanEnabled ? ' checked' : ''
    const lockAttributes = options.locked ? ' disabled aria-describedby="operation-lock-reason"' : ''
    const scanReasonId = getIntentUnavailableReasonId('scan', 'rail')
    const hardwareReasonId = 'hardware-scan-rail-unavailable'
    const progressReasonId = 'discovery-scan-rail-status'
    const scanDescribedBy = [options.locked ? 'operation-lock-reason' : '', options.scanBusy ? progressReasonId : '', options.scanIntentAvailable ? '' : scanReasonId, options.hardwareAvailable ? '' : hardwareReasonId].filter(Boolean).join(' ')
    const scanEnabled = !options.locked && !options.scanBusy && options.scanIntentAvailable && options.hardwareAvailable
    const scanTitle = !options.hardwareAvailable ? t('capability.hardwareUnavailable') : options.scanBusy ? t('devices.scanning') : getIntentUnavailableMessage('scan', t)
    const scanAttributes = scanEnabled ? '' : ` disabled aria-describedby="${scanDescribedBy}" title="${scanTitle}"`
    const autoScanAttributes = options.locked ? lockAttributes : !serviceReady ? ' disabled aria-describedby="service-error-title"' : options.hardwareAvailable ? '' : ` disabled aria-describedby="${hardwareReasonId}"`
    const languageOptions = [
        ['en', 'settings.language.en'],
        ['zh', 'settings.language.zh'],
        ['de', 'settings.language.de'],
        ['fr', 'settings.language.fr'],
        ['it', 'settings.language.it'],
        ['pt', 'settings.language.pt'],
        ['es', 'settings.language.es'],
        ['ja', 'settings.language.ja']
    ]
        .map(([code, key]) => `<option value="${code}"${state.settings?.language === code ? ' selected' : ''}>${t(key)}</option>`)
        .join('')
    for (const device of state.devices) {
        const selected = device.id === state.selectedDeviceId
        const current = selected ? ' aria-current="true"' : ''
        deviceCards.push(`<button class="device-card${selected ? ' device-card--selected' : ''}" type="button" data-action="manage-device" data-focus-key="device:${escapeHtml(device.id)}" data-device-id="${escapeHtml(device.id)}"${current}${lockAttributes}>
            <span class="device-card__icon"><i class="ph-duotone ph-hard-drives" aria-hidden="true"></i></span>
            <span class="device-card__body"><strong>${escapeHtml(device.product)}</strong><small>${escapeHtml(device.vendor)} · ${escapeHtml(device.serial)}</small><span>${device.media === null ? t('devices.noCartridge') : `${escapeHtml(device.media.label)} · ${formatLocalizedToken(t, device.media.status)}`}</span></span>
            <i class="ph ph-caret-right" aria-hidden="true"></i>
        </button>`)
    }

    const emptyRail = `<div class="device-rail__empty"><i class="ph-duotone ph-plugs" aria-hidden="true"></i><p>${t('devices.noValidated')}</p></div>`
    const openAttribute = options.deviceRailOpen ? ' data-open="true"' : ''

    return `<aside class="device-rail" aria-labelledby="device-rail-heading" data-device-rail${openAttribute}>
        <button class="device-rail__toggle" type="button" data-action="toggle-device-rail" data-focus-key="rail:toggle" aria-expanded="${options.deviceRailOpen}" aria-controls="device-rail-content">
            <i class="ph ph-list" aria-hidden="true"></i><span>${t('devices.label')}</span><i class="ph ph-caret-down" aria-hidden="true"></i>
        </button>
        <div class="device-rail__content" id="device-rail-content">
            <div class="rail-heading"><div><span class="eyebrow">${t('devices.rail')}</span><h2 id="device-rail-heading">${t('devices.heading')}</h2></div><span class="device-count">${state.devices.length.toString().padStart(2, '0')}</span></div>
            ${state.provenance === 'fixture' ? `<div class="fixture-note"><i class="ph ph-info" aria-hidden="true"></i><span>${t('devices.demoData')}</span></div>` : ''}
            <div class="device-list">${deviceCards.length > 0 ? deviceCards.join('') : emptyRail}</div>
            ${renderDiscoveryFailure(state.discovery, t)}
            ${state.service.status === 'ready' ? `<div class="device-rail__scan" data-intent-group="rail-scan"><button class="button button--secondary button--wide" type="button" data-action="scan-devices" data-intent="scan" data-focus-key="rail:scan"${scanAttributes}><i class="ph ${options.scanBusy ? 'ph-circle-notch' : 'ph-magnifying-glass'}" aria-hidden="true"></i><span>${t('devices.scan')}</span></button>${options.scanBusy ? `<span class="capability-reason" id="${progressReasonId}" data-discovery-status role="status" aria-live="polite">${t('devices.scanning')}</span>` : ''}${renderIntentUnavailableReason('scan', 'rail', options.scanIntentAvailable, t)}${renderHardwareUnavailableReason('rail', options.hardwareAvailable, t)}</div>` : ''}
            <label class="autoscan-control${options.locked || !serviceReady || !options.hardwareAvailable ? ' autoscan-control--locked' : ''}" data-enabled="${autoScanEnabled}"><span><strong>${t('devices.autoScan')}</strong><small>${t('devices.autoScanHelp')}</small></span><input type="checkbox" data-setting="auto-scan" data-focus-key="rail:auto-scan"${checkedAttribute}${autoScanAttributes} /><span class="switch" aria-hidden="true"></span></label>
            <div class="desktop-settings" aria-label="${t('settings.heading')}">
                <label><span>${t('settings.language')}</span><select data-setting="language" data-focus-key="rail:language">${languageOptions}</select></label>
                <label class="autoscan-control" data-enabled="${state.settings?.updateChecks === true}"><span><strong>${t('settings.updateChecks')}</strong><small>${t('settings.updateChecksHelp')}</small></span><input type="checkbox" data-setting="update-checks" data-focus-key="rail:update-checks"${state.settings?.updateChecks === true ? ' checked' : ''} /><span class="switch" aria-hidden="true"></span></label>
            </div>
        </div>
    </aside>`
}

/**
 * Renders the four-area tablist and enforces the application operation lock.
 * @param {string} activeArea - Current presentation area.
 * @param {boolean} locked - Whether a device operation is active.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @returns {string} Accessible tab navigation markup.
 */
function renderAreaTabs(activeArea, locked, t) {
    const tabs = []
    for (const area of AREAS) {
        const selected = area.id === activeArea
        const disabled = locked && !selected ? ' disabled aria-describedby="operation-lock-reason"' : ''
        tabs.push(`<button id="tab-${area.id}" class="area-tab${selected ? ' area-tab--active' : ''}" type="button" role="tab" aria-selected="${selected}" aria-controls="panel-${area.id}" tabindex="${selected ? '0' : '-1'}" data-area="${area.id}" data-focus-key="area:${area.id}"${disabled}><i class="ph ${area.icon}" aria-hidden="true"></i><span>${t(area.labelKey)}</span></button>`)
    }
    return `<nav class="area-tabs" role="tablist" aria-label="${t('areas.label')}" aria-orientation="horizontal">${tabs.join('')}</nav>`
}

/**
 * Renders a scoped placeholder for an approved management area whose workflow
 * is implemented by later phases.
 * @param {string} activeArea - Current non-status area identifier.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @returns {string} Semantic placeholder panel markup.
 */
function renderFutureArea(activeArea, t) {
    let selectedArea = AREAS[0]
    for (const area of AREAS) {
        if (area.id === activeArea) {
            selectedArea = area
            break
        }
    }

    return `<section class="future-workspace" aria-labelledby="${selectedArea.id}-heading">
        <i class="ph-duotone ${selectedArea.icon}" aria-hidden="true"></i>
        <span class="eyebrow">${t('future.eyebrow')}</span>
        <h1 id="${selectedArea.id}-heading">${t('future.workspace', { area: t(selectedArea.labelKey) })}</h1>
        <p>${t('future.description')}</p>
        <span class="evidence-chip"><i class="ph ph-lock-key" aria-hidden="true"></i>${t('future.noCommand')}</span>
    </section>`
}

/**
 * Renders the selected area as a tab panel.
 * @param {string} activeArea - Current presentation area.
 * @param {object} state - Complete renderer snapshot owning the selected device and operations.
 * @param {object} device - Selected renderer-safe device snapshot.
 * @param {boolean} locked - Whether another operation owns the application lock.
 * @param {boolean} operationIntentAvailable - Whether operation intents are bound.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @param {Document|undefined} document - Owning document for DOM-based feature views.
 * @param {{availableDriveLetters?: string[], currentSataMode?: string, operationIntentAvailable?: boolean, platform?: string}} [utilityOptions={}] - Utility-specific host presentation facts.
 * @param {{model?: object, onAction?: Function, onIntent?: Function, onWorkflowClose?: Function, onWorkflowError?: Function, onWorkflowEvent?: Function}} [encryptionOptions={}] - Encryption model and local workflow callbacks.
 * @param {object|null} [diagnosticRequest=null] - Pending or rejected diagnostic admission.
 * @returns {string} Active workspace panel markup.
 */
function renderAreaPanel(activeArea, state, device, locked, operationIntentAvailable, t, provenance, document, utilityOptions = {}, encryptionOptions = {}, diagnosticRequest = null) {
    let content
    if (activeArea === 'status') {
        content = renderStatusView(device, { locked, operationIntentAvailable, provenance, platform: utilityOptions.platform, translator: t })
    } else if (activeArea === 'encryption' && document !== undefined) {
        content = renderEncryptionView(encryptionOptions.model ?? createProductionSecurityModel(state, device, null, t), {
            document,
            onAction: encryptionOptions.onAction,
            onIntent: encryptionOptions.onIntent,
            onWorkflowClose: encryptionOptions.onWorkflowClose,
            onWorkflowError: encryptionOptions.onWorkflowError,
            onWorkflowEvent: encryptionOptions.onWorkflowEvent,
            translator: t
        }).outerHTML
    } else if (activeArea === 'tests' && document !== undefined) {
        content = renderTestsView(device, {
            activeOperation: state.activeOperation,
            document,
            lastOperation: state.lastOperation,
            request: diagnosticRequest,
            locked,
            operationIntentAvailable,
            provenance,
            translator: t
        }).outerHTML
    } else if (activeArea === 'utilities' && document !== undefined) {
        content = renderUtilitiesView(device, {
            activeOperation: state.activeOperation,
            availableDriveLetters: utilityOptions.availableDriveLetters,
            currentSataMode: utilityOptions.currentSataMode,
            document,
            lastOperation: state.lastOperation,
            locked,
            manufacturing: utilityOptions.manufacturing,
            operationIntentAvailable: utilityOptions.operationIntentAvailable === true,
            platform: utilityOptions.platform,
            provenance,
            translator: t
        }).outerHTML
    } else {
        content = renderFutureArea(activeArea, t)
    }
    return `<div class="area-panel" id="panel-${toDomToken(activeArea)}" role="tabpanel" aria-labelledby="tab-${toDomToken(activeArea)}" tabindex="0">${content}</div>`
}

/**
 * Chooses a bundled Phosphor glyph for the active operation family.
 * @param {string} kind - Validated operation kind.
 * @returns {string} Trusted icon class without user-controlled content.
 */
function getOperationStatusIcon(kind) {
    switch (kind) {
        case 'eject-safe':
        case 'eject-force':
            return 'ph-eject'
        case 'firmware-update':
            return 'ph-download-simple'
        case 'self-test':
        case 'led-test':
        case 'write-read-test':
            return 'ph-pulse'
        case 'format':
            return 'ph-eraser'
        case 'access-enable':
        case 'access-disable':
        case 'credential-create':
        case 'credential-change':
        case 'credential-delete':
        case 'credential-reset':
        case 'credential-configure':
            return 'ph-shield-check'
        default:
            return 'ph-sliders-horizontal'
    }
}

/**
 * Renders progress for the single operation that currently owns the app lock.
 * @param {object|null} operation - Active renderer operation, when present.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @param {object} [continuation={}] - Current gate acknowledgement presentation.
 * @returns {string} Polite live-region progress markup or empty text.
 */
function renderOperationStatus(operation, t, continuation = {}) {
    if (operation === null) {
        return ''
    }

    const progress = typeof operation.progress === 'number' ? Math.min(1, Math.max(0, operation.progress)) : 0
    const guidanceKey = getFirmwareInstallationGuidanceKey(operation)
    const guidance = operation.kind === 'firmware-update' && operation.stage === 'device-reconnecting' ? `<p data-firmware-reconnect-guidance>${t('utilities.firmware.reconnectingGuidance')}</p>` : guidanceKey === undefined ? '' : `<p data-firmware-installation-guidance>${t(guidanceKey)}</p>`
    const awaiting = operation.kind === 'firmware-update' && ['firmware-awaiting-bootloader', 'firmware-awaiting-bootstrap'].includes(operation.stage)
    const continueDisabled = !continuation.available || !['idle', 'failed'].includes(continuation.state)
    const continueFeedback = ['pending', 'accepted', 'uncertain', 'failed'].includes(continuation.state) ? `<p data-firmware-continuation-status>${t(`utilities.firmware.continue.${continuation.state}`)}</p>` : ''
    const continueAction = awaiting ? `<button type="button" class="button button--primary" data-action="continue-firmware-installation" data-focus-key="firmware:continue:${escapeHtml(operation.stage)}"${continueDisabled ? ' disabled' : ''}>${t('utilities.firmware.continue.action')}</button>${continueFeedback}` : ''
    const icon = getOperationStatusIcon(operation.kind)
    return `<section class="operation-banner" data-operation-status data-focus-fallback="operation-status" data-focus-key="state:operation-status" role="status" aria-live="polite" tabindex="-1">
        <div class="operation-banner__activity">
            <span class="operation-banner__icon"><i class="ph-duotone ${icon}" aria-hidden="true"></i></span>
            <div class="operation-banner__content"><strong>${t('operation.inProgress', { operation: formatLocalizedSentenceToken(t, operation.kind) })}</strong><span class="operation-banner__stage">${formatLocalizedToken(t, operation.stage ?? 'starting')} <code>${escapeHtml(operation.stage ?? 'starting')}</code> · ${Math.round(progress * 100)} %</span>${guidance}${continueAction}<progress max="1" value="${progress}" aria-label="${escapeHtml(t('operation.progressLabel'))}">${Math.round(progress * 100)} %</progress></div>
        </div>
        <div class="operation-banner__lock" id="operation-lock-reason"><i class="ph ph-lock" aria-hidden="true"></i><span class="operation-banner__lock-copy"><strong class="operation-banner__lock-title">${t('operation.lockReasonTitle')}</strong> <span class="operation-banner__lock-detail">${t('operation.lockReasonDetail')}</span></span></div>
    </section>`
}

/**
 * Renders accepted operation completion while the controller's banner is visible.
 * A reconnect can change the discovery revision; completed history belongs
 * to the same stable dock identity and is replaced when another operation starts.
 * @param {object} state - Current renderer state and accepted terminal result.
 * @param {object} device - Selected renderer-safe dock.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {string} Polite green confirmation or empty text without matching success.
 */
function renderOperationSuccess(state, device, t) {
    const operation = state.lastOperation
    if (state.activeOperation !== null || operation?.status !== 'succeeded' || operation.deviceId !== device.id) return ''

    const firmware = operation.kind === 'firmware-update'
    const title = firmware ? t('operation.firmwareSuccessTitle') : t('utilities.result.succeededTitle', { operation: formatLocalizedSentenceToken(t, operation.kind) })
    const description = firmware ? `<p>${t('operation.firmwareSuccessDescription')}</p>` : ''
    return `<section class="success-banner" data-operation-success role="status" aria-live="polite" aria-atomic="true" aria-labelledby="operation-success-title">
        <span class="success-banner__icon"><i class="ph-fill ph-check-circle" aria-hidden="true"></i></span>
        <div><h2 id="operation-success-title">${title}</h2><p><strong>${escapeHtml(device.vendor)} · ${t('status.serial', { serial: device.serial })}</strong></p>${description}</div>
    </section>`
}

/**
 * Resolves operation-specific safe recovery copy for a terminal failure.
 * @param {object} operation - Failed renderer operation with structured error.
 * @returns {{descriptionKey: string, retryKey: string, reasonKey?: string}} Safe next-step, failure-cause, and retry-message keys.
 */
function getFailureRecovery(operation) {
    const firmwareReasonKey = getFirmwarePreflightFailureReasonKey(operation)
    switch (operation.kind) {
        case 'self-test':
        case 'led-test':
        case 'write-read-test':
            return {
                descriptionKey: 'operation.failureDescription.diagnostic',
                retryKey: 'operation.retryDiagnostic'
            }
        case 'firmware-update':
            if (firmwareReasonKey !== undefined) {
                return {
                    descriptionKey: 'operation.failureDescription.firmwareBeforeTransfer',
                    reasonKey: firmwareReasonKey,
                    retryKey: 'operation.retryFirmware'
                }
            }
            return {
                descriptionKey: operation.error?.stage === 'queued' ? 'operation.failureDescription.firmwarePreflight' : 'operation.failureDescription.firmware',
                reasonKey: getFirmwareFailureReasonKey(operation),
                retryKey: 'operation.retryFirmware'
            }
        default:
            return {
                descriptionKey: 'operation.failureDescription.default',
                retryKey: 'operation.retryGeneric'
            }
    }
}

/**
 * Renders structured failure evidence and a bounded recovery action.
 * @param {object|null} operation - Most recent terminal operation result.
 * @param {boolean} retryIntentAvailable - Whether retry intents are bound.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @returns {string} Assertive failure markup or empty text.
 */
function renderOperationFailure(operation, retryIntentAvailable, t) {
    if (operation?.status !== 'failed') {
        return ''
    }

    const recovery = getFailureRecovery(operation)
    const reason = recovery.reasonKey === undefined ? '' : `<p>${t(recovery.reasonKey)}</p>`
    const retryReasonId = getIntentUnavailableReasonId('retry-operation', 'failure')
    const retryAttributes = retryIntentAvailable ? '' : ` disabled aria-describedby="${retryReasonId}" title="${getIntentUnavailableMessage('retry-operation', t)}"`
    const retryLabel = recovery.retryKey === 'operation.retryGeneric' ? t(recovery.retryKey, { operation: formatLocalizedSentenceToken(t, operation.kind).toLowerCase() }) : t(recovery.retryKey)
    const retryAction = operation.error.retryable === true ? `<div class="failure-banner__action" data-intent-group="failure-retry"><button class="button button--danger" type="button" data-action="retry-operation" data-intent="retry-operation" data-focus-key="failure:retry"${retryAttributes}><i class="ph ph-arrow-counter-clockwise" aria-hidden="true"></i><span>${retryLabel}</span></button>${renderIntentUnavailableReason('retry-operation', 'failure', retryIntentAvailable, t)}</div>` : ''

    return `<section class="failure-banner" data-operation-failure role="alert">
        <i class="ph-duotone ph-x-circle" aria-hidden="true"></i>
        <div><span class="eyebrow">${t('operation.failed')}</span><h2>${t('operation.didNotComplete', { operation: formatLocalizedSentenceToken(t, operation.kind) })}</h2>${reason}<p>${t(recovery.descriptionKey, { stage: formatLocalizedToken(t, operation.error.stage) })}</p><dl><div><dt>${t('operation.errorCode')}</dt><dd>${escapeHtml(operation.error.code)}</dd></div><div><dt>${t('operation.supportId')}</dt><dd>${escapeHtml(operation.error.supportCorrelationId)}</dd></div></dl></div>
        ${retryAction}
    </section>`
}

/**
 * Renders only bounded aggregate rejection counts and stable reason codes.
 * @param {object} discovery - Current renderer discovery state.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {string} Safe diagnostics markup, or an empty string without rejections.
 */
function renderDiscoveryDiagnostics(discovery, t) {
    const diagnostics = discovery?.diagnostics
    if (!Array.isArray(diagnostics?.rejections) || diagnostics.rejections.length === 0) return ''
    let reasons = ''
    let rejected = 0
    for (const rejection of diagnostics.rejections) {
        rejected += rejection.count
        reasons += `<li><code>${escapeHtml(rejection.reason)}</code><span>× ${rejection.count}</span></li>`
    }
    const summaryKey = rejected === 1 ? 'empty.candidateRejected' : 'empty.candidatesRejected'
    return `<aside class="discovery-diagnostics" data-discovery-diagnostics><strong>${t('empty.candidateDiagnostics')}</strong><p>${t(summaryKey, { count: rejected })}</p><ul>${reasons}</ul></aside>`
}

/**
 * Renders one bounded path-free whole-pass failure without discarding stale snapshots.
 * @param {object} discovery - Current path-free discovery state.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {string} Visible failure markup, or an empty string when no failure exists.
 */
function renderDiscoveryFailure(discovery, t) {
    const reason = discovery?.lastFailure
    if (typeof reason !== 'string') return ''
    return `<aside class="discovery-diagnostics discovery-diagnostics--failure" data-discovery-failure role="status"><strong>${t('empty.discoveryFailure')}</strong><p>${t('empty.discoveryFailureDescription', { reason })}</p></aside>`
}

/**
 * Renders ready-service guidance when no validated RDX device is present.
 * @param {object} discovery - Current path-free discovery state.
 * @param {object} availability - Exact renderer intent availability flags.
 * @param {boolean} hardwareAvailable - Whether native hardware is reconciled.
 * @param {boolean} scanBusy - Whether one discovery pass currently owns dispatch.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @param {string} [failure=''] - Trusted operation failure markup.
 * @returns {string} Actionable no-device main content.
 */
function renderNoDeviceState(discovery, availability, hardwareAvailable, scanBusy, t, failure = '') {
    const scanIntentAvailable = availability.scan === true
    const scanAvailable = scanIntentAvailable && hardwareAvailable
    const supportAvailable = availability['open-support'] === true
    const scanReasonId = getIntentUnavailableReasonId('scan', 'empty')
    const supportReasonId = getIntentUnavailableReasonId('open-support', 'empty')
    const hardwareReasonId = 'hardware-scan-empty-unavailable'
    const progressReasonId = 'discovery-scan-empty-status'
    const describedBy = [scanBusy ? progressReasonId : '', scanIntentAvailable ? '' : scanReasonId, hardwareAvailable ? '' : hardwareReasonId].filter(Boolean).join(' ')
    const scanTitle = !hardwareAvailable ? t('capability.hardwareUnavailable') : scanBusy ? t('devices.scanning') : getIntentUnavailableMessage('scan', t)
    const scanAttributes = scanAvailable && !scanBusy ? '' : ` disabled aria-describedby="${describedBy}" title="${scanTitle}"`
    const supportAttributes = supportAvailable ? '' : ` disabled aria-describedby="${supportReasonId}" title="${getIntentUnavailableMessage('open-support', t)}"`
    return `<main class="state-workspace" id="main-content" aria-labelledby="empty-state-title">
        ${failure}
        <section class="empty-state" data-intent-group="empty-state-actions"><span class="state-icon"><i class="ph-duotone ph-hard-drives" aria-hidden="true"></i></span><span class="eyebrow">${t('empty.discovery')}</span><h1 id="empty-state-title" data-focus-fallback="primary-state" data-focus-key="state:empty-heading" tabindex="-1">${t('empty.noDrives')}</h1><p>${t('empty.description')}</p>${renderDiscoveryFailure(discovery, t)}${renderDiscoveryDiagnostics(discovery, t)}<button class="button button--primary" type="button" data-action="scan-devices" data-intent="scan" data-focus-key="empty:scan"${scanAttributes}><i class="ph ${scanBusy ? 'ph-circle-notch' : 'ph-magnifying-glass'}" aria-hidden="true"></i><span>${t('devices.scan')}</span></button>${scanBusy ? `<span class="capability-reason" id="${progressReasonId}" data-discovery-status role="status" aria-live="polite">${t('devices.scanning')}</span>` : ''}${renderIntentUnavailableReason('scan', 'empty', scanIntentAvailable, t)}${renderHardwareUnavailableReason('empty', hardwareAvailable, t)}<button class="text-link" type="button" data-action="open-support" data-intent="open-support" data-focus-key="empty:support"${supportAttributes}><i class="ph ph-lifebuoy" aria-hidden="true"></i>${t('empty.troubleshooting')}</button>${renderIntentUnavailableReason('open-support', 'empty', supportAvailable, t)}</section>
    </main>`
}

/**
 * Offers explicit selection when validated devices remain after selection was cleared.
 * Discovery and selection are separate: a removed target must not silently retarget
 * an operation, but its replacement must not be presented as an empty inventory.
 * @param {object[]} devices - Current validated renderer snapshots.
 * @param {(key: string, params?: object) => string} t - Active message translator.
 * @param {string} [failure=''] - Trusted operation failure markup.
 * @returns {string} Selection guidance and identity-bound local controls.
 */
function renderDeviceSelectionState(devices, t, failure = '') {
    const controls = devices.map((device) => `<button class="button button--primary" type="button" data-action="manage-device" data-focus-key="select:${escapeHtml(device.id)}" data-device-id="${escapeHtml(device.id)}"><i class="ph ph-hard-drives" aria-hidden="true"></i><span>${escapeHtml(device.product)} · ${escapeHtml(device.serial)}</span></button>`).join('')
    return `<main class="state-workspace" id="main-content" aria-labelledby="device-selection-title">${failure}<section class="empty-state" data-device-selection><span class="state-icon"><i class="ph-duotone ph-hard-drives" aria-hidden="true"></i></span><span class="eyebrow">${t('devices.heading')}</span><h1 id="device-selection-title" data-focus-fallback="primary-state" data-focus-key="state:selection-heading" tabindex="-1">${t('devices.selectTitle')}</h1><p>${t('devices.selectDescription')}</p>${controls}</section></main>`
}

/**
 * Renders an unavailable native-service state separately from an empty scan.
 * @param {object} service - Renderer-safe unavailable service state.
 * @param {object} availability - Intent availability flags from the controller.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @returns {string} Service recovery main content.
 */
function renderServiceUnavailable(service, availability, t, platform) {
    const retryAvailable = availability['retry-service'] === true
    const supportAvailable = availability['open-support'] === true
    const retryReasonId = getIntentUnavailableReasonId('retry-service', 'state')
    const supportReasonId = getIntentUnavailableReasonId('open-support', 'service')
    const retryAttributes = retryAvailable ? '' : ` disabled aria-describedby="${retryReasonId}" title="${getIntentUnavailableMessage('retry-service', t)}"`
    const supportAttributes = supportAvailable ? '' : ` disabled aria-describedby="${supportReasonId}" title="${getIntentUnavailableMessage('open-support', t)}"`
    return `<main class="state-workspace" id="main-content" aria-labelledby="service-error-title">
        <section class="empty-state empty-state--error" role="alert" data-intent-group="service-state-actions"><span class="state-icon"><i class="ph-duotone ph-plugs-connected" aria-hidden="true"></i></span><span class="eyebrow">${t('service.boundary')}</span><h1 id="service-error-title" data-focus-fallback="primary-state" data-focus-key="state:service-heading" tabindex="-1">${t('service.hardwareUnavailable')}</h1><p>${t('service.description')}</p>${platform === 'win32' ? `<p>${t('service.windowsRepairDescription')}</p>` : ''}<code>${escapeHtml(service.reason ?? 'service-unavailable')}</code><button class="button button--primary" type="button" data-action="retry-service" data-intent="retry-service" data-focus-key="service:retry"${retryAttributes}><i class="ph ph-arrow-clockwise" aria-hidden="true"></i><span>${t('service.retry')}</span></button>${renderIntentUnavailableReason('retry-service', 'state', retryAvailable, t)}<button class="text-link" type="button" data-action="open-support" data-intent="open-support" data-focus-key="service:support"${supportAttributes}><i class="ph ph-lifebuoy" aria-hidden="true"></i>${t('service.supportGuidance')}</button>${renderIntentUnavailableReason('open-support', 'service', supportAvailable, t)}</section>
    </main>`
}

/**
 * Renders a capability-aware command for the wide activity rail.
 * @param {object} device - Selected renderer-safe device snapshot.
 * @param {boolean} locked - Whether an operation owns the application lock.
 * @param {boolean} operationIntentAvailable - Whether operation intents are bound.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @returns {string} Firmware command card markup.
 */
function renderFirmwareCommand(device, locked, operationIntentAvailable, t) {
    const publishedState = device.capabilities?.['firmware-update']?.state ?? 'unsupported-product'
    const state = publishedState === 'available' && device.mediaState !== 'no-media' ? 'wrong-media-state' : publishedState
    const disabled = locked || state !== 'available' || !operationIntentAvailable
    const intentReasonId = getIntentUnavailableReasonId('operation', 'firmware-update')
    const describedBy = [locked ? 'operation-lock-reason' : 'capability-firmware-update-reason', operationIntentAvailable ? '' : intentReasonId].filter(Boolean).join(' ')
    const reason = locked ? t('capability.operationLocked') : state === 'wrong-media-state' ? t('firmware.removeMedia', { reason: state }) : state !== 'available' ? state : operationIntentAvailable ? t('capability.available') : t('capability.intentUnavailable')
    const title = operationIntentAvailable ? '' : ` title="${getIntentUnavailableMessage('operation', t)}"`

    return `<article class="rail-card rail-card--recommended" data-capability-card data-intent-group="firmware-operation"><span class="eyebrow">${t('firmware.eyebrow')}</span><h3><i class="ph-duotone ph-file-arrow-up" aria-hidden="true"></i>${t('firmware.title')}</h3><p>${t('firmware.description')}</p><span class="capability-reason" id="capability-firmware-update-reason">${escapeHtml(reason)}</span><button class="button button--warning button--wide" type="button" data-action="open-firmware-workflow" data-focus-key="command:operation:firmware-update" data-operation="firmware-update" aria-describedby="${describedBy}"${title}${disabled ? ' disabled' : ''}><i class="ph ph-arrow-right" aria-hidden="true"></i><span>${t('firmware.openWorkflow')}</span></button>${renderIntentUnavailableReason('operation', 'firmware-update', operationIntentAvailable, t)}</article>`
}

/**
 * Renders wide-window commands and a truthful fixture activity stream.
 * @param {object} device - Selected renderer-safe device snapshot.
 * @param {boolean} locked - Whether an operation owns the application lock.
 * @param {object} availability - Intent availability flags from the controller.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @returns {string} Command/activity rail markup.
 */
function renderCommandRail(device, locked, availability, t, provenance) {
    const activity = provenance === 'fixture' ? `<ol class="activity-list"><li><i class="ph-fill ph-check-circle" aria-hidden="true"></i><div><strong>${t('rail.fixtureLoaded')}</strong><span>${t('rail.fixtureLoadedDescription')}</span></div></li><li><i class="ph-fill ph-info" aria-hidden="true"></i><div><strong>${t('rail.rendererActive')}</strong><span>${t('rail.rendererActiveDescription')}</span></div></li><li><i class="ph-fill ph-clock" aria-hidden="true"></i><div><strong>${t('rail.servicePending')}</strong><span>${t('rail.servicePendingDescription')}</span></div></li></ol>` : `<p class="activity-empty">${t('rail.noActivity')}</p>`
    return `<aside class="command-rail" aria-labelledby="command-rail-heading">
        <div class="rail-heading"><div><span class="eyebrow">${t('rail.selectedContext')}</span><h2 id="command-rail-heading">${t('rail.heading')}</h2></div></div>
        ${renderFirmwareCommand(device, locked, availability.operation === true, t)}
        <section class="activity-panel" aria-labelledby="activity-heading"><div class="section-heading"><span class="eyebrow">${t('rail.localEvidence')}</span><h3 id="activity-heading">${t('rail.recentActivity')}</h3></div>${activity}</section>
        <div class="rail-support" id="support"><i class="ph-duotone ph-lifebuoy" aria-hidden="true"></i><div><strong>${t('rail.handoffTitle')}</strong><p>${t('rail.handoffDescription')}</p></div></div>
    </aside>`
}

/**
 * Renders the complete responsive application shell for a renderer snapshot.
 * @param {object} state - Immutable renderer store snapshot.
 * @param {{activeArea?: string, deviceRailOpen?: boolean, document?: Document, diagnosticRequest?: object|null, encryptionModel?: object, operationSuccessVisible?: boolean, onSecurityAction?: Function, onSecurityIntent?: Function, onSecurityWorkflowClose?: Function, onSecurityWorkflowError?: Function, onSecurityWorkflowEvent?: Function, intentAvailability?: object, translator: (key: string, params?: object) => string, platform?: string, availableDriveLetters?: string[], currentSataMode?: string, supportPanel?: 'activity'|'compatibility'|'help'|'support'|null, supportModel?: object}} options - Presentation-only controller state.
 * @returns {string} Trusted application markup with escaped state values.
 */
export function renderShell(state, options = {}) {
    const t = options.translator
    const selectedDevice = getSelectedDevice(state)
    const activeArea = isKnownArea(options.activeArea) ? options.activeArea : state.activeArea
    const locked = state.activeOperation !== null || state.recoveryLocked === true || state.manufacturingLocked === true || options.manufacturing?.locked === true
    const recoveryCard = renderRecoveryView(options.recovery, t)
    const deviceRailOpen = options.deviceRailOpen === true
    const intentAvailability = options.intentAvailability ?? {}
    const discoveryAvailable = state.provenance !== 'service' || isDiscoveryAvailable(state.service)
    const scanBusy = state.discovery?.scanStatus === 'scanning'
    const selectedLabel = selectedDevice?.product ?? t('devices.noneSelected')
    const supportModel = {
        ...(options.supportModel ?? {}),
        compatibility: createCompatibilityModel(state, options.platform)
    }
    const brand = `<a class="brand" href="#main-content" aria-label="${t('app.home')}">${t('app.brand.open')}<span>${t('app.brand.rdx')}</span></a>`
    const supportOverlay = renderSupportOverlay(options.supportPanel ?? null, supportModel, options.document, t)
    const inert = options.supportPanel === null || options.supportPanel === undefined ? '' : ' inert aria-hidden="true"'
    const privilegedSetup = state.privilegedServiceSetup ?? { state: 'not-applicable' }
    const setupBlocked = state.provenance === 'service' && !['not-applicable', 'enabled'].includes(privilegedSetup.state)

    if (setupBlocked) {
        return `<div class="application-shell"${inert}><header class="topbar">${brand}<div class="topbar__path"><span>${t('topbar.devices')}</span><i class="ph ph-caret-right" aria-hidden="true"></i><strong>${t('topbar.serviceRecovery')}</strong></div>${renderServiceStatus(state, t, privilegedSetup)}${renderTopbarActions(intentAvailability, t)}</header><div class="shell-grid shell-grid--state">${renderDeviceRail(state, null, { deviceRailOpen, hardwareAvailable: false, locked: false, scanBusy, scanIntentAvailable: intentAvailability.scan === true, translator: t })}${renderPrivilegedServiceSetup(privilegedSetup, intentAvailability, t)}</div></div>${supportOverlay}`
    }

    if (options.recovery?.locked && (options.recovery.hydrated || state.service.status === 'ready')) {
        return `<div class="application-shell"${inert}><header class="topbar">${brand}${renderServiceStatus(state, t, privilegedSetup)}${renderTopbarActions(intentAvailability, t)}</header><div class="shell-grid shell-grid--state">${renderDeviceRail(state, selectedDevice, { deviceRailOpen, hardwareAvailable: discoveryAvailable, locked: true, scanBusy, scanIntentAvailable: false, translator: t })}<main class="main-workspace" id="main-content">${recoveryCard}</main></div></div>${supportOverlay}`
    }

    if (state.service.status === 'unavailable') {
        return `<div class="application-shell"${inert}><header class="topbar">${brand}<div class="topbar__path"><span>${t('topbar.devices')}</span><i class="ph ph-caret-right" aria-hidden="true"></i><strong>${t('topbar.serviceRecovery')}</strong></div>${renderServiceStatus(state, t, privilegedSetup)}${renderTopbarActions(intentAvailability, t)}</header><div class="shell-grid shell-grid--state">${renderDeviceRail(state, null, { deviceRailOpen, hardwareAvailable: discoveryAvailable, locked, scanBusy, scanIntentAvailable: intentAvailability.scan === true, translator: t })}${renderServiceUnavailable(state.service, intentAvailability, t, options.platform)}</div></div>${supportOverlay}`
    }

    if (['starting', 'restarting', 'recovering', 'reconciling'].includes(state.service.status)) {
        return `<div class="application-shell"${inert}><header class="topbar">${brand}${renderServiceStatus(state, t, privilegedSetup)}${renderTopbarActions(intentAvailability, t)}</header><main id="main-content" class="state-workspace" data-service-pending="${escapeHtml(state.service.status)}">${renderOperationStatus(state.activeOperation, t, options.firmwareContinuation)}<h1>${t(`service.${state.service.status}`)}</h1></main></div>${supportOverlay}`
    }

    if (selectedDevice === null) {
        // A firmware reset may remove the target from discovery. Keep its
        // terminal evidence visible without allowing a retry on another unit.
        const failure = renderOperationFailure(state.lastOperation, false, t)
        const noDeviceContent = locked || recoveryCard !== '' ? `<main class="main-workspace" id="main-content">${renderOperationStatus(state.activeOperation, t, options.firmwareContinuation)}${failure}${recoveryCard}</main>` : !discoveryAvailable ? renderHardwareAccessUnavailable(state.service, t, failure, options.platform) : state.devices.length > 0 ? renderDeviceSelectionState(state.devices, t, failure) : hasMountedCandidate(state.discovery) ? renderMountedCandidateState(intentAvailability, scanBusy, t, failure) : renderNoDeviceState(state.discovery, intentAvailability, discoveryAvailable, scanBusy, t, failure)
        return `<div class="application-shell"${inert}><header class="topbar">${brand}<div class="topbar__path"><span>${t('topbar.devices')}</span><i class="ph ph-caret-right" aria-hidden="true"></i><strong>${t('topbar.discovery')}</strong></div>${renderServiceStatus(state, t, privilegedSetup)}${renderTopbarActions(intentAvailability, t)}</header><div class="shell-grid shell-grid--state">${renderDeviceRail(state, null, { deviceRailOpen, hardwareAvailable: discoveryAvailable, locked, scanBusy, scanIntentAvailable: intentAvailability.scan === true, translator: t })}${noDeviceContent}</div></div>${supportOverlay}`
    }

    return `<div class="application-shell"${inert}>
        <header class="topbar">
            ${brand}
            <div class="topbar__path"><span>${t('topbar.devices')}</span><i class="ph ph-caret-right" aria-hidden="true"></i><strong>${escapeHtml(selectedLabel)}</strong></div>
            ${state.provenance === 'fixture' ? `<span class="fixture-chip"><i class="ph ph-beaker" aria-hidden="true"></i>${t('topbar.fixturePreview')}</span>` : ''}
            ${renderServiceStatus(state, t, privilegedSetup)}
            ${renderTopbarActions(intentAvailability, t)}
        </header>
        <div class="shell-grid">
            ${renderDeviceRail(state, selectedDevice, { deviceRailOpen, hardwareAvailable: discoveryAvailable, locked, scanBusy, scanIntentAvailable: intentAvailability.scan === true, translator: t })}
            <main class="main-workspace" id="main-content" aria-label="${t('status.selectedDevice')}">
                ${renderOperationStatus(state.activeOperation, t, options.firmwareContinuation)}
                ${recoveryCard}
                ${options.operationSuccessVisible === false ? '' : renderOperationSuccess(state, selectedDevice, t)}
                ${renderOperationFailure(state.lastOperation, intentAvailability['retry-operation'] === true, t)}
                ${renderAreaTabs(activeArea, locked, t)}
                ${renderAreaPanel(activeArea, state, selectedDevice, locked, intentAvailability.operation === true, t, state.provenance, options.document, { availableDriveLetters: options.availableDriveLetters, currentSataMode: options.currentSataMode, operationIntentAvailable: intentAvailability['utility-operation'] === true, platform: options.platform, manufacturing: options.manufacturing }, { model: options.encryptionModel, onAction: options.onSecurityAction, onIntent: options.onSecurityIntent, onWorkflowClose: options.onSecurityWorkflowClose, onWorkflowError: options.onSecurityWorkflowError, onWorkflowEvent: options.onSecurityWorkflowEvent }, options.diagnosticRequest)}
            </main>
            ${renderCommandRail(selectedDevice, locked, intentAvailability, t, state.provenance)}
        </div>
    </div>${supportOverlay}`
}
