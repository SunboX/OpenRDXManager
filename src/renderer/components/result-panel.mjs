// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createComponentIcon, createComponentId, getComponentContext, resolveComponentText } from './capability-state.mjs'

const RESULT_PRESENTATION = Object.freeze({
    cancelled: Object.freeze({ icon: 'ph-minus-circle', tone: 'warning' }),
    failed: Object.freeze({ icon: 'ph-x-circle', tone: 'danger' }),
    succeeded: Object.freeze({ icon: 'ph-check-circle', tone: 'success' })
})

/**
 * Renders a terminal result while keeping primary failure, cleanup failure,
 * recovery help, and operation evidence independently visible.
 * @param {{status: 'succeeded'|'failed'|'cancelled', title?: string, titleKey?: string, summary?: string, summaryKey?: string, primaryFailure?: string, cleanupFailure?: string, evidence?: Array<{label: string, value: string|number}>, help?: {label?: string, labelKey?: string}, action?: {label?: string, labelKey?: string}}} model - Terminal result presentation.
 * @param {{document?: Document, translator?: (key: string, params?: object) => string, onHelp?: (event: Event) => void, onAction?: (event: Event) => void}} [options={}] - DOM, translation, and local handlers.
 * @returns {HTMLElement} Accessible terminal result panel.
 */
export function renderOperationResult(model, options = {}) {
    const { document, translator } = getComponentContext(options)
    const status = Object.hasOwn(RESULT_PRESENTATION, model?.status) ? model.status : 'failed'
    const presentation = RESULT_PRESENTATION[status]
    const titleId = createComponentId('operation-result-title')
    const panel = document.createElement('section')
    panel.className = `operation-result operation-result--${presentation.tone}`
    panel.dataset.resultStatus = status
    panel.setAttribute('role', status === 'failed' ? 'alert' : 'status')
    panel.setAttribute('aria-labelledby', titleId)

    const header = document.createElement('header')
    header.className = 'operation-result__header'
    header.append(createComponentIcon(document, presentation.icon, 'ph-duotone'))
    const title = document.createElement('h3')
    title.id = titleId
    title.textContent = resolveComponentText(model, 'title', 'titleKey', translator, `operation.result.${status}`)
    header.append(title)
    panel.append(header)

    if (typeof model?.summary === 'string' || typeof model?.summaryKey === 'string') {
        const summary = document.createElement('p')
        summary.className = 'operation-result__summary'
        summary.textContent = resolveComponentText(model, 'summary', 'summaryKey', translator, 'operation.resultSummary')
        panel.append(summary)
    }
    if (typeof model?.primaryFailure === 'string') {
        panel.append(createFailureNotice(document, translator('operation.primaryFailure'), model.primaryFailure, 'primary'))
    }
    if (typeof model?.cleanupFailure === 'string') {
        panel.append(createFailureNotice(document, translator('operation.cleanupFailure'), model.cleanupFailure, 'cleanup'))
    }
    if (Array.isArray(model?.evidence) && model.evidence.length > 0) {
        const evidence = document.createElement('dl')
        evidence.className = 'operation-result__evidence'
        for (const entry of model.evidence) {
            if (typeof entry?.label !== 'string' || !['string', 'number'].includes(typeof entry.value)) continue
            const row = document.createElement('div')
            row.dataset.resultEvidence = ''
            const term = document.createElement('dt')
            term.textContent = entry.label
            const description = document.createElement('dd')
            description.textContent = String(entry.value)
            row.append(term, description)
            evidence.append(row)
        }
        if (evidence.childElementCount > 0) panel.append(evidence)
    }

    const actions = document.createElement('footer')
    actions.className = 'operation-result__actions'
    if (model?.help !== undefined) actions.append(createResultButton(document, model.help, 'help', 'ph-question', 'operation.openResultHelp', options.onHelp, translator))
    if (model?.action !== undefined) actions.append(createResultButton(document, model.action, 'action', 'ph-arrow-right', 'operation.continue', options.onAction, translator))
    if (actions.childElementCount > 0) panel.append(actions)
    return panel
}

/**
 * Creates one separately identified failure notice.
 * @param {Document} document - Owning browser document.
 * @param {string} label - Failure category label.
 * @param {string} message - Trusted renderer-safe failure copy.
 * @param {'primary'|'cleanup'} kind - Stable failure kind.
 * @returns {HTMLElement} Visible failure notice.
 */
function createFailureNotice(document, label, message, kind) {
    const notice = document.createElement('div')
    notice.className = `operation-result__failure operation-result__failure--${kind}`
    notice.dataset[`${kind}Result`] = ''
    const strong = document.createElement('strong')
    strong.textContent = label
    const copy = document.createElement('p')
    copy.textContent = message
    notice.append(strong, copy)
    return notice
}

/**
 * Creates one visibly labeled result action using bundled icon assets.
 * @param {Document} document - Owning browser document.
 * @param {object} model - Button label model.
 * @param {'help'|'action'} kind - Result action kind.
 * @param {string} icon - Bundled icon class.
 * @param {string} fallbackKey - Bundled fallback message key.
 * @param {Function|undefined} handler - Optional local click handler.
 * @param {(key: string, params?: object) => string} translator - Bounded translator.
 * @returns {HTMLButtonElement} Labeled result action.
 */
function createResultButton(document, model, kind, icon, fallbackKey, handler, translator) {
    const button = document.createElement('button')
    button.className = kind === 'action' ? 'button button--primary' : 'button button--secondary'
    button.type = 'button'
    button.dataset[`result${kind.charAt(0).toUpperCase()}${kind.slice(1)}`] = ''
    button.append(createComponentIcon(document, icon))
    const label = document.createElement('span')
    label.textContent = resolveComponentText(model, 'label', 'labelKey', translator, fallbackKey)
    button.append(label)
    if (typeof handler === 'function') button.addEventListener('click', handler)
    return button
}
