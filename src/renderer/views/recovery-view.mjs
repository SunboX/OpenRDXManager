// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { escapeHtml } from './view-helpers.mjs'
import { recoveryReasonKey } from '../recovery-reasons.mjs'

const STAGES = Object.freeze(['recovery-preparing', 'recovery-identifying-rom', 'recovery-setting-up-rom', 'recovery-programming-bootstrap', 'recovery-resetting-rom', 'recovery-awaiting-power-cycle', 'recovery-verifying-bootstrap', 'recovery-transferring-final-release', 'recovery-activating-final-release', 'recovery-verifying-final-release'])

/** @param {object|undefined} view - Strict controller presentation. @param {Function} t - Active translator. @returns {string} Independent ROM recovery card, including empty-inventory guidance. */
export function renderRecoveryView(view, t) {
    if (!view?.available || !view.visible) return ''
    const status = view.status
    const running = status.state === 'running'
    const disabled = view.locked || view.loading || view.operationBusy || !view.hydrated
    const stageIndex = STAGES.indexOf(status.stage)
    const phase = stageIndex < 0 ? t('recovery.loading') : t(`recovery.stage.${stageIndex}`)
    /** @param {string} value - Opaque form value. @param {string} label - Visible safe label. @param {boolean} selected - Local selection. @returns {string} Escaped option. */
    const option = (value, label, selected) => `<option value="${escapeHtml(value)}"${selected ? ' selected' : ''}>${escapeHtml(label)}</option>`
    /** @param {string} action - Closed action. @param {string} label - Localized label. @param {boolean} blocked - Disabled state. @returns {string} Explicit action button. */
    const button = (action, label, blocked) => `<button type="button" class="button button--primary" data-recovery-action="${action}" data-focus-key="recovery:${action}"${blocked ? ' disabled' : ''}>${escapeHtml(label)}</button>`
    const selection = `<div class="recovery-form"><label>${t('recovery.bundle')}<select data-recovery-field="bundle" data-focus-key="recovery:bundle"${disabled ? ' disabled' : ''}>${option('', t('recovery.choose'), !view.bundleId)}${view.bundles.map((bundle) => option(bundle.bundleId, t('recovery.bundleLabel', { serial: bundle.serial, version: bundle.targetVersion }), bundle.bundleId === view.bundleId)).join('')}</select></label><label>${t('recovery.target')}<select data-recovery-field="target" data-focus-key="recovery:target"${disabled ? ' disabled' : ''}>${option('', t('recovery.choose'), !view.targetToken)}${view.targets.map((target) => option(target.token, target.label, target.token === view.targetToken)).join('')}</select></label></div><label class="recovery-ack"><input type="checkbox" data-recovery-field="acknowledged" data-focus-key="recovery:acknowledged"${view.acknowledged ? ' checked' : ''}${disabled ? ' disabled' : ''}/><span>${t('recovery.acknowledge')}</span></label><div class="recovery-actions">${button('start', view.pending ? t('recovery.pending') : t('recovery.start'), disabled || !view.bundleId || !view.targetToken || !view.acknowledged)}${button('refresh', t('recovery.refresh'), view.loading || view.locked || view.operationBusy)}</div>`
    const progress = `<div class="recovery-progress" role="status"><strong>${escapeHtml(phase)}</strong><progress max="10" value="${Math.max(0, stageIndex)}" aria-label="${escapeHtml(phase)}"></progress><p>${t(status.stage === 'recovery-awaiting-power-cycle' ? 'recovery.powerCycle' : 'recovery.keepConnected')}</p>${status.stage === 'recovery-awaiting-power-cycle' ? button('continue', status.awaitingAcknowledgment && !view.continuationConsumed ? t('recovery.continue') : t('recovery.waiting'), view.pending || !status.awaitingAcknowledgment || view.continuationConsumed) : ''}</div>`
    const reason = view.reason ?? status.reason
    const failure = reason ? `<p data-recovery-error role="alert">${t(recoveryReasonKey(reason))} <code>${escapeHtml(reason)}</code></p>` : ''
    return `<section class="recovery-card" data-recovery-panel aria-labelledby="recovery-heading"><header><i class="ph ph-first-aid" aria-hidden="true"></i><h2 id="recovery-heading">${t('recovery.title')}</h2></header><p>${t('recovery.description')}</p>${!view.hydrated ? `<p role="status">${t('recovery.loading')}</p>` : ''}${failure}${status.state === 'failed' ? `<p class="recovery-result" role="alert">${t('recovery.failed')} ${escapeHtml(phase)}</p>` : ''}${status.state === 'succeeded' ? `<p class="recovery-result" data-recovery-success role="status">${t('recovery.succeeded')}</p><progress max="10" value="10" aria-label="${escapeHtml(t('recovery.succeeded'))}"></progress>` : ''}${running ? progress : `<p>${t('recovery.safety')}</p>${view.hydrated && view.bundles.length === 0 ? `<p data-recovery-empty>${t('recovery.noBundles')}</p>` : ''}${view.hydrated && view.targets.length === 0 ? `<p>${t('recovery.noTargets')}</p>` : ''}${selection}`}</section>`
}
