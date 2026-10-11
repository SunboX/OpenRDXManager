// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { escapeHtml } from './view-helpers.mjs'
import { firmwareFailureReasonKeys } from '../firmware-failure-reasons.mjs'

const REASON_KEYS = Object.freeze({
    ...firmwareFailureReasonKeys,
    'manufacturing-restore-unsupported': 'manufacturing.error.restoreUnsupported',
    'firmware-manufacturing-restore-unsupported': 'manufacturing.error.restoreUnsupported',
    'manufacturing-unavailable': 'manufacturing.error.unavailable',
    'operation-in-progress': 'reason.operationInProgress',
    'service-unavailable': 'manufacturing.error.uncertain',
    'service-request-timeout': 'manufacturing.error.uncertain',
    'service-response-timeout': 'manufacturing.error.uncertain',
    'operation-outcome-unknown': 'manufacturing.error.uncertain',
    'manufacturing-outcome-unknown': 'manufacturing.error.uncertain',
    'invalid-service-response': 'manufacturing.error.uncertain'
})
const STATE_KEYS = Object.freeze({ valid: 'manufacturing.state.valid', erased: 'manufacturing.state.erased', corrupt: 'manufacturing.state.corrupt' })

/** @param {Document} document - Owning DOM. @param {object|undefined} view - Controller's bounded presentation. @param {Function} t - Active escaped translator. @returns {HTMLElement|null} Manufacturing utility card using the common utility styles. */
export function renderManufacturingView(document, view, t) {
    if (!view?.available) return null
    const card = document.createElement('article')
    card.className = 'utility-card'
    card.dataset.manufacturingPanel = ''
    /** @param {string} action - Closed action. @param {string} label - Localized button text. @param {boolean} disabled - Admission gate. @param {string} tone - Existing design-system tone. @returns {string} Explicit action button. */
    const button = (action, label, disabled, tone = 'primary') => `<button class="button button--${tone}" type="button" data-manufacturing-action="${action}" data-focus-key="manufacturing:${action}"${disabled ? ' disabled' : ''}>${label}</button>`
    /** @param {string} value - Opaque saved-record identifier. @param {string} label - Escaped date/identity/state label. @param {boolean} selected - Explicit current selection. @param {boolean} disabled - Non-restorable evidence. @returns {string} Saved-record option. */
    const option = (value, label, selected, disabled = false) => `<option value="${escapeHtml(value)}"${selected ? ' selected' : ''}${disabled ? ' disabled' : ''}>${label}</option>`
    const locale = document.documentElement.lang || undefined
    /** @param {object} backup - Public saved metadata. @returns {string} Localized date, original serial, and integrity state. */
    const label = (backup) => t('manufacturing.backupLabel', { date: new Date(backup.createdAt).toLocaleString(locale), serial: backup.serial ?? t('manufacturing.serialUnavailable'), state: t(STATE_KEYS[backup.state]) })
    const disabled = view.formDisabled ? ' disabled' : ''
    const backupOptions = view.backups.map((backup) => option(backup.backupId, label(backup), backup.backupId === view.backupId, backup.state !== 'valid' || backup.serial === null)).join('')
    const reasonKey = Object.hasOwn(REASON_KEYS, view.reason) ? REASON_KEYS[view.reason] : 'manufacturing.error.failed'
    card.innerHTML = `<header class="utility-card__header"><span class="utility-card__icon"><i class="ph-duotone ph-database" aria-hidden="true"></i></span><div><span class="eyebrow">${t('manufacturing.eyebrow')}</span><h3>${t('manufacturing.title')}</h3></div></header>
        <p class="utility-card__description">${t('manufacturing.description')}</p>
        <p class="utility-card__description">${t('manufacturing.automaticBackup')}</p>
        <div class="recovery-actions">${button('backup', view.pending ? t('manufacturing.pending') : t('manufacturing.backup'), !view.canBackup)}${button('refresh', t('manufacturing.refresh'), view.refreshDisabled, 'secondary')}${button('open-folder', t(view.openingFolder ? 'manufacturing.openingFolder' : 'manufacturing.openFolder'), view.openFolderDisabled, 'secondary')}</div>
        <p class="utility-card__description">${t('manufacturing.folderDescription')}</p>
        ${view.folderError ? `<p data-manufacturing-folder-error role="alert">${t('manufacturing.error.openFolder')}</p>` : ''}
        ${!view.backupSupported && view.supportKnown ? `<p class="capability-reason">${t('manufacturing.error.unavailable')}</p>` : ''}
        ${view.device?.mediaState !== 'no-media' ? `<p class="capability-reason">${t('manufacturing.removeMedia')}</p>` : ''}
        <p class="utility-card__description">${t('manufacturing.restoreDescription')}</p>
        ${view.loading ? `<p role="status">${t('manufacturing.loading')}</p>` : ''}
        ${view.hydrated && !view.reason && view.backups.length === 0 ? `<p data-manufacturing-empty>${t('manufacturing.empty')}</p>` : ''}
        <div class="utility-form manufacturing-form"><label>${t('manufacturing.savedBackups')}<select data-manufacturing-field="backup" data-focus-key="manufacturing:backup-selection"${disabled}>${option('', t('manufacturing.choose'), !view.backupId)}${backupOptions}</select></label><label>${t('manufacturing.confirmSerial')}<input type="text" inputmode="numeric" autocomplete="off" maxlength="10" data-controlled-value data-manufacturing-field="confirmationSerial" data-focus-key="manufacturing:confirmationSerial" value="${escapeHtml(view.confirmationSerial)}"${disabled || !view.backupId ? ' disabled' : ''}/></label></div>
        <div class="recovery-actions">${button('previous', t('manufacturing.previous'), view.locked || view.refreshDisabled || view.page === 0, 'secondary')}<span>${t('manufacturing.page', { page: view.page + 1 })}</span>${button('next', t('manufacturing.next'), view.locked || view.refreshDisabled || !view.hasMore || view.page >= 31, 'secondary')}</div>
        <p class="utility-card__description" data-manufacturing-target>${t('manufacturing.target', { product: view.device?.product ?? '', serial: view.device?.serial ?? '' })}</p>
        <label class="recovery-ack"><input type="checkbox" data-manufacturing-field="acknowledged" data-focus-key="manufacturing:acknowledged"${view.acknowledged ? ' checked' : ''}${disabled || !view.backupId ? ' disabled' : ''}/><span>${t('manufacturing.acknowledge')}</span></label>
        ${view.identityChangeRequired ? `<label class="recovery-ack"><input type="checkbox" data-manufacturing-field="allowIdentityChange" data-focus-key="manufacturing:allowIdentityChange"${view.allowIdentityChange ? ' checked' : ''}${disabled}/><span>${t('manufacturing.acknowledgeIdentityChange', { serial: view.restoreSerial })}</span></label>` : ''}
        ${!view.restoreSupported && view.supportKnown ? `<p class="capability-reason">${t('manufacturing.error.restoreUnsupported')}</p>` : ''}
        ${view.uncertain ? `<p role="alert">${t('manufacturing.error.uncertain')}</p>` : ''}
        ${view.reason && !view.uncertain ? `<p data-manufacturing-error role="alert">${t(reasonKey)}</p>` : ''}
        ${view.result ? `<p data-manufacturing-success role="status">${t(view.result === 'restore' ? 'manufacturing.restoreSucceeded' : 'manufacturing.backupSucceeded')}</p>` : ''}
        <div class="recovery-actions">${button('restore', t('manufacturing.restore'), !view.canRestore, 'danger')}</div>`
    return card
}
