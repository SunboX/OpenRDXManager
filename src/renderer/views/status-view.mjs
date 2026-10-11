// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { escapeHtml, formatLocalizedToken, toDomToken } from './view-helpers.mjs'
import { formatFirmwareRevision } from './firmware-revision.mjs'
import { getIntentUnavailableMessage, getIntentUnavailableReasonId, renderIntentUnavailableReason } from './intent-view.mjs'

/**
 * Formats a non-negative byte count with compact decimal storage units.
 * @param {unknown} bytes - Renderer-supplied byte count.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @returns {string} Bounded user-facing storage value or Not reported.
 */
function formatBytes(bytes, t) {
    if (typeof bytes !== 'number' || !Number.isFinite(bytes) || bytes < 0) {
        return t('state.notReported')
    }

    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    let value = bytes
    let unitIndex = 0
    while (value >= 1000 && unitIndex < units.length - 1) {
        value /= 1000
        unitIndex += 1
    }

    const digits = value >= 100 || unitIndex === 0 ? 0 : value >= 10 ? 1 : 2
    return `${value.toFixed(digits)} ${units[unitIndex]}`
}

/**
 * Calculates a clamped whole-number percentage for a capacity indicator.
 * @param {object|undefined} details - Canonical typed media details.
 * @returns {number} Integer percentage from zero through one hundred.
 */
function getCapacityPercentage(details) {
    const capacityBytes = reportedStatusValue(details?.capacityBytes)
    const usedBytes = reportedStatusValue(details?.usedBytes)
    if (typeof capacityBytes !== 'number' || capacityBytes <= 0 || typeof usedBytes !== 'number') {
        return 0
    }

    return Math.round(Math.min(1, Math.max(0, usedBytes / capacityBytes)) * 100)
}

/** @param {object|undefined} field - Canonical typed status field. @returns {unknown} Reported value or undefined. */
function reportedStatusValue(field) {
    return field?.availability === 'reported' ? field.value : undefined
}

/**
 * Formats one typed status field with a localized unavailable explanation.
 * @param {object|undefined} field - Reported-or-unavailable native status field.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {string} User-visible typed value or meaningful absence.
 */
function formatStatusField(field, t) {
    if (field?.availability === 'reported' && ['string', 'number'].includes(typeof field.value)) return String(field.value)
    if (field?.availability === 'unavailable') return formatLocalizedToken(t, field.reason)
    return t('state.notReported')
}

/**
 * Formats a reported machine status as localized explanatory copy.
 * @param {object|undefined} field - Reported-or-unavailable token field.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {string} Localized status text.
 */
function formatStatusTokenField(field, t) {
    if (field?.availability === 'reported' && typeof field.value === 'string') return formatLocalizedToken(t, field.value)
    return formatStatusField(field, t)
}

/**
 * Formats a typed Celsius temperature with its required unit.
 * @param {object|undefined} field - Reported-or-unavailable temperature field.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {string} Temperature with Celsius unit or meaningful absence.
 */
function formatTemperature(field, t) {
    if (field?.availability === 'reported' && typeof field.value === 'number' && Number.isFinite(field.value)) return `${field.value} °C`
    return formatStatusField(field, t)
}

/**
 * Formats one typed byte-count field with the shared compact unit policy.
 * @param {object|undefined} field - Reported-or-unavailable byte field.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {string} Formatted byte value or reason-bearing absence.
 */
function formatStatusBytes(field, t) {
    if (field?.availability === 'reported') return formatBytes(field.value, t)
    return formatStatusField(field, t)
}

/**
 * Formats a typed encryption field without treating absence as false.
 * @param {object|undefined} field - Reported-or-unavailable boolean field.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {string} Explicit encryption status.
 */
function formatEncryption(field, t) {
    if (field?.availability === 'reported' && typeof field.value === 'boolean') return field.value ? t('state.encrypted') : t('state.notEncrypted')
    if (field?.availability === 'unavailable') return formatStatusField(field, t)
    return t('state.notReported')
}

/**
 * Renders one semantic key/value row for compact status details.
 * @param {string} labelKey - Catalog key for the row heading.
 * @param {unknown} value - Renderer-safe value.
 * @param {(key: string, params?: object) => string} t - Active bounded message translator.
 * @returns {string} Escaped definition-list row markup.
 */
function renderDataRow(labelKey, value, t) {
    return `<div class="data-row"><dt>${t(labelKey)}</dt><dd>${escapeHtml(value)}</dd></div>`
}

/**
 * Renders an ordered documented-field inventory without inline callback logic.
 * @param {Array<[string, unknown]>} rows - Catalog keys and renderer-safe values.
 * @param {(key: string, params?: object) => string} t - Active bounded translator.
 * @returns {string} Concatenated definition-list markup.
 */
function renderDataRows(rows, t) {
    let markup = ''
    for (const [label, value] of rows) markup += renderDataRow(label, value, t)
    return markup
}

/**
 * Resolves the selected device's published capability state for an operation.
 * @param {object} device - Selected renderer-safe device snapshot.
 * @param {string} operation - High-level operation kind.
 * @returns {string} Stable capability state or unsupported-product fallback.
 */
function getCapabilityState(device, operation) {
    return device.capabilities?.[operation]?.state ?? 'unsupported-product'
}

/**
 * Renders a capability-aware routine command with a visible stable reason.
 * @param {object} device - Selected renderer-safe device snapshot.
 * @param {{operation: string, icon: string, titleKey: string, descriptionKey: string, labelKey: string, locked: boolean, intentAvailable: boolean, tone?: string, translator: (key: string, params?: object) => string}} options - Command presentation.
 * @returns {string} Semantic command card markup.
 */
function renderCapabilityAction(device, options) {
    const t = options.translator
    const capabilityState = getCapabilityState(device, options.operation)
    const disabled = options.locked || capabilityState !== 'available' || !options.intentAvailable
    const operationToken = toDomToken(options.operation)
    const localReasonId = `capability-${operationToken}-reason`
    const intentReasonId = getIntentUnavailableReasonId('operation', operationToken)
    const describedBy = [options.locked ? 'operation-lock-reason' : localReasonId, options.intentAvailable ? '' : intentReasonId].filter(Boolean).join(' ')
    const reason = options.locked ? t('capability.operationLocked') : capabilityState !== 'available' ? capabilityState : options.intentAvailable ? t('capability.available') : t('capability.intentUnavailable')
    const tone = options.tone ? ` command-card--${toDomToken(options.tone)}` : ''
    const disabledAttribute = disabled ? ' disabled' : ''
    const titleAttribute = options.intentAvailable ? '' : ` title="${getIntentUnavailableMessage('operation', t)}"`

    return `<article class="command-card${tone}" data-capability-card data-intent-group="status-operation-${operationToken}">
        <div class="command-card__icon" aria-hidden="true"><i class="ph-duotone ${escapeHtml(options.icon)}"></i></div>
        <div class="command-card__copy">
            <span class="eyebrow">${formatLocalizedToken(t, options.operation)}</span>
            <h3>${t(options.titleKey)}</h3>
            <p>${t(options.descriptionKey)}</p>
            <span class="capability-reason" id="${localReasonId}" data-capability-state="${escapeHtml(capabilityState)}">${escapeHtml(reason)}</span>
            ${renderIntentUnavailableReason('operation', operationToken, options.intentAvailable, t)}
        </div>
        <button class="button button--compact" type="button" data-intent="operation" data-focus-key="status:operation:${escapeHtml(options.operation)}" data-operation="${escapeHtml(options.operation)}" aria-describedby="${describedBy}"${titleAttribute}${disabledAttribute}>
            <i class="ph ph-arrow-right" aria-hidden="true"></i><span>${t(options.labelKey)}</span>
        </button>
    </article>`
}

/**
 * Renders the selected device's complete Status workspace. All values come
 * from the renderer-safe snapshot; unavailable telemetry is labeled honestly.
 * @param {object} device - Selected renderer-safe device snapshot.
 * @param {{locked?: boolean, operationIntentAvailable?: boolean, provenance?: string, platform?: string, translator: (key: string, params?: object) => string}} options - Presentation-only operation, platform and intent state.
 * @returns {string} Semantic status workspace markup.
 */
export function renderStatusView(device, options = {}) {
    const t = options.translator
    const media = device.media
    const drive = device.drive ?? {}
    const driveDetails = drive.details ?? {}
    const mediaDetails = media?.details ?? {}
    const capacityBytes = reportedStatusValue(mediaDetails.capacityBytes)
    const usedBytes = reportedStatusValue(mediaDetails.usedBytes)
    const freeBytes = reportedStatusValue(mediaDetails.freeBytes)
    const mediaMounted = reportedStatusValue(mediaDetails.mounted)
    const usedPercentage = getCapacityPercentage(mediaDetails)
    // Missing status and reported errors must never look like a healthy cartridge.
    const cartridgeHealthy = reportedStatusValue(mediaDetails.status) === 'Good'
    const cartridgeStatus = media === null ? t('state.noMedia') : formatStatusField(mediaDetails.status, t)
    const writeProtected = reportedStatusValue(mediaDetails.writeProtected)
    const writableStatus = media === null ? t('state.notApplicable') : typeof writeProtected !== 'boolean' ? t('state.notReported') : writeProtected ? t('state.writeProtected') : t('state.readWrite')
    const encryptionStatus = media === null ? t('state.notApplicable') : formatEncryption(mediaDetails.encrypted, t)
    // A missing encryption probe must not obscure the known write-protect state.
    const encryptionReported = typeof reportedStatusValue(mediaDetails.encrypted) === 'boolean'
    const protectionStatus = encryptionReported ? encryptionStatus : writableStatus
    const protectionDetail = encryptionReported || media === null ? writableStatus : t('status.writeProtect')
    const policyIsWindowsOnly = ['darwin', 'linux'].includes(options.platform) && driveDetails.policy?.availability === 'unavailable' && driveDetails.policy.reason === 'field-decoder-unavailable'
    const locked = options.locked === true
    const intentAvailable = options.operationIntentAvailable === true
    const fixture = options.provenance === 'fixture'
    const driveStatus = formatStatusField(driveDetails.status, t)
    const healthStatus = fixture ? t('status.operational') : t('status.serviceReported')
    const evidenceLabel = fixture ? t('status.fixtureUnverified') : t('status.serviceValidated')
    const filesystemEvidence = fixture ? t('status.fixtureReported') : t('status.serviceValidated')
    // Values already visible in the identity heading or overview cards stay out
    // of these lists so every technical fact has one obvious reading location.
    const driveRows = [
        ['status.oemName', formatStatusField(driveDetails.oemName, t)],
        ['status.firmwareRevision', formatFirmwareRevision(formatStatusField(driveDetails.firmwareRevision, t))],
        ['status.bornOnDate', formatStatusField(driveDetails.bornOnDate, t)],
        ['status.productType', formatStatusField(driveDetails.productType, t)],
        ['status.loadCount', formatStatusField(driveDetails.loadCount, t)],
        ['status.driveErrors', formatStatusField(driveDetails.errors, t)],
        ['status.camState', formatStatusField(driveDetails.camState, t)],
        ['status.drivePolicy', policyIsWindowsOnly ? t('status.windowsPolicyOnly') : formatStatusField(driveDetails.policy, t)],
        ['status.powerSource', formatStatusField(driveDetails.powerSource, t)],
        ['status.supportStatus', formatStatusTokenField(driveDetails.supportStatus, t)],
        ['status.senseSummary', formatStatusTokenField(driveDetails.senseSummary, t)]
    ]
    const cartridgeRows =
        media === null
            ? [['status.status', t('state.noMedia')]]
            : [
                  ['utilities.volumeLabel.newLabel', typeof media.label === 'string' ? (media.label === '' ? t('utilities.volumeLabel.unnamed') : media.label) : t('state.notReported')],
                  ['status.vendor', formatStatusField(mediaDetails.vendor, t)],
                  ['status.model', formatStatusField(mediaDetails.model, t)],
                  ['status.serialNumber', formatStatusField(mediaDetails.serialNumber, t)],
                  ['status.loadCount', formatStatusField(mediaDetails.loadCount, t)],
                  ['status.hddFirmware', formatStatusField(mediaDetails.hddFirmware, t)],
                  ['status.cartridgeType', formatStatusField(mediaDetails.cartridgeType, t)],
                  ['status.temperature', formatTemperature(mediaDetails.temperatureCelsius, t)],
                  ['status.bytesRead', formatStatusBytes(mediaDetails.bytesRead, t)],
                  ['status.bytesWritten', formatStatusBytes(mediaDetails.bytesWritten, t)],
                  ['status.supportStatus', formatStatusTokenField(mediaDetails.supportStatus, t)],
                  ['status.senseSummary', formatStatusTokenField(mediaDetails.senseSummary, t)]
              ]

    return `<section class="status-workspace" aria-labelledby="status-heading">
        <div class="workspace-heading">
            <div>
                <span class="eyebrow">${t('status.selectedDevice')}</span>
                <h1 id="status-heading" data-focus-fallback="selected-heading" data-focus-key="state:selected-heading" tabindex="-1">${escapeHtml(device.product)}</h1>
                <p class="device-identity">${escapeHtml(device.vendor)} · ${t('status.serial', { serial: device.serial })}</p>
            </div>
            <div class="health-state${fixture ? ' health-state--healthy' : ''}">
                <span><i class="ph-fill ${fixture ? 'ph-check-circle' : 'ph-info'}" aria-hidden="true"></i> ${healthStatus}</span>
                <small>${evidenceLabel}</small>
            </div>
        </div>

        <div class="metric-grid" aria-label="${t('status.summary')}">
            <article class="metric-card${fixture ? ' metric-card--healthy' : ''}"><span>${t('status.drive')}</span><strong>${driveStatus}</strong><small>${t('status.identityAvailable')}</small></article>
            <article class="metric-card${cartridgeHealthy ? ' metric-card--healthy' : ''}"><span>${t('status.cartridge')}</span><strong>${cartridgeStatus}</strong><small>${writableStatus}</small></article>
            <article class="metric-card"><span>${t('status.operationMode')}</span><strong>${escapeHtml(formatStatusField(driveDetails.operationMode, t))}</strong><small>${fixture ? t('status.awaitingNative') : evidenceLabel}</small></article>
            <article class="metric-card"><span>${t('status.connection')}</span><strong>${escapeHtml(formatStatusField(driveDetails.connectionType, t))}</strong><small>${fixture ? t('status.noTransportClaim') : evidenceLabel}</small></article>
            <article class="metric-card metric-card--capacity">
                <span>${t('status.capacity')}</span>
                <strong>${media === null ? t('devices.noCartridge') : mediaMounted === false ? t('status.capacityTotal', { value: formatBytes(capacityBytes, t) }) : t('status.capacityUsed', { value: formatBytes(usedBytes, t) })}</strong>
                <small>${media === null ? t('status.insertMedia') : mediaMounted === false ? t('status.capacityUnmounted') : t('status.capacityFree', { free: formatBytes(freeBytes, t), capacity: formatBytes(capacityBytes, t) })}</small>
                ${media !== null && mediaMounted !== false ? `<progress class="capacity-track" role="progressbar" aria-label="${t('status.capacityAria')}" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${usedPercentage}" max="100" value="${usedPercentage}">${usedPercentage} %</progress>` : ''}
            </article>
            <article class="metric-card"><span>${t('status.filesystem')}</span><strong>${escapeHtml(media?.filesystem?.toUpperCase() ?? t('state.notReported'))}</strong><small>${filesystemEvidence}</small></article>
            <article class="metric-card"><span>${t('status.protection')}</span><strong>${protectionStatus}</strong><small>${protectionDetail}</small></article>
        </div>

        <div class="detail-grid">
            <section class="data-panel" aria-labelledby="drive-data-heading">
                <h2 id="drive-data-heading"><i class="ph-duotone ph-hard-drives" aria-hidden="true"></i> ${t('status.driveData')}</h2>
                <dl>
                    ${renderDataRows(driveRows, t)}
                </dl>
            </section>
            <section class="data-panel" aria-labelledby="cartridge-data-heading">
                <h2 id="cartridge-data-heading"><i class="ph-duotone ph-disc" aria-hidden="true"></i> ${t('status.cartridgeData')}</h2>
                <dl>
                    ${renderDataRows(cartridgeRows, t)}
                </dl>
            </section>
        </div>

        <section class="status-actions" aria-labelledby="status-actions-heading">
            <div class="section-heading"><span class="eyebrow">${t('status.commandCenter')}</span><h2 id="status-actions-heading">${t('status.safeActions')}</h2></div>
            <div class="command-grid">
                ${renderCapabilityAction(device, { operation: 'status-refresh', icon: 'ph-arrows-clockwise', titleKey: 'action.refreshTitle', descriptionKey: 'action.refreshDescription', labelKey: 'action.refresh', locked, intentAvailable, translator: t })}
                ${renderCapabilityAction(device, { operation: 'self-test', icon: 'ph-stethoscope', titleKey: 'action.healthTitle', descriptionKey: 'action.healthDescription', labelKey: 'action.openTests', locked, intentAvailable, tone: 'recommended', translator: t })}
                ${renderCapabilityAction(device, { operation: 'eject-safe', icon: 'ph-eject', titleKey: 'action.ejectTitle', descriptionKey: 'action.ejectDescription', labelKey: 'action.eject', locked, intentAvailable, translator: t })}
            </div>
        </section>
    </section>`
}
