// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** @param {string} name - Element name. @param {Document} document - Owning document. @param {string} [className] - CSS class. @returns {HTMLElement} New element. */
function element(name, document, className = '') {
    const node = document.createElement(name)
    if (className !== '') node.className = className
    return node
}

/** @param {object} entry - Renderer-safe activity. @param {Document} document - Owning document. @param {(key: string, params?: object) => string} t - Active translator. @returns {HTMLElement} One semantic activity row. */
function renderEntry(entry, document, t) {
    const row = element('li', document, `activity-entry activity-entry--${entry.severity}`)
    row.dataset.activityEntry = entry.id
    const icon = element('i', document, `ph ${entry.severity === 'error' ? 'ph-warning-octagon' : entry.severity === 'warning' ? 'ph-warning' : 'ph-info'}`)
    icon.setAttribute('aria-hidden', 'true')
    const body = element('div', document)
    const message = element('strong', document)
    message.textContent = t(entry.messageKey)
    const time = element('time', document)
    time.dateTime = entry.occurredAt
    time.textContent = new Date(entry.occurredAt).toLocaleString()
    body.append(message, time)
    if (entry.supportCorrelationId !== undefined) {
        const support = element('code', document)
        support.textContent = entry.supportCorrelationId
        body.append(support)
    }
    row.append(icon, body)
    return row
}

/**
 * Renders local redacted activity controls and entries.
 * @param {{enabled?: boolean, entries?: object[], filter?: string, busy?: boolean, result?: string}} model - Activity presentation state.
 * @param {{document: Document, translator: (key: string, params?: object) => string}} options - DOM and localization dependencies.
 * @returns {HTMLElement} Activity dialog content.
 */
export function renderActivityView(model, options) {
    const document = options.document
    const t = options.translator
    const section = element('section', document, 'support-panel activity-view')
    section.dataset.activityView = 'true'
    section.setAttribute('aria-labelledby', 'activity-title')
    const header = element('header', document, 'support-panel__header')
    const heading = element('div', document)
    const eyebrow = element('span', document, 'eyebrow')
    eyebrow.textContent = t('activity.eyebrow')
    const title = element('h1', document)
    title.id = 'activity-title'
    title.tabIndex = -1
    title.dataset.focusKey = 'support:title'
    title.textContent = t('activity.title')
    heading.append(eyebrow, title)
    const close = element('button', document, 'icon-button')
    close.type = 'button'
    close.dataset.action = 'close-support-panel'
    close.dataset.focusKey = 'support:close'
    close.setAttribute('aria-label', t('activity.close'))
    close.innerHTML = '<i class="ph ph-x" aria-hidden="true"></i>'
    header.append(heading, close)

    const toolbar = element('div', document, 'activity-toolbar')
    const toggleLabel = element('label', document, 'activity-toggle')
    const toggle = element('input', document)
    toggle.type = 'checkbox'
    toggle.checked = model.enabled !== false
    if (toggle.checked) toggle.setAttribute('checked', '')
    toggle.disabled = model.busy === true
    toggle.dataset.setting = 'event-logging'
    toggle.dataset.focusKey = 'activity:logging'
    const toggleText = element('span', document)
    toggleText.textContent = t('activity.logging')
    toggleLabel.append(toggle, toggleText)
    const filterLabel = element('label', document)
    filterLabel.textContent = t('activity.filter.label')
    const filter = element('select', document)
    filter.dataset.activityFilter = 'true'
    filter.dataset.focusKey = 'activity:filter'
    for (const value of ['all', 'info', 'warning', 'error']) {
        const option = element('option', document)
        option.value = value
        option.textContent = t(`activity.filter.${value}`)
        option.selected = (model.filter ?? 'all') === value
        filter.append(option)
    }
    filterLabel.append(filter)
    const exportButton = element('button', document, 'button button--secondary')
    exportButton.type = 'button'
    exportButton.dataset.action = 'export-logs'
    exportButton.dataset.focusKey = 'activity:export'
    exportButton.disabled = model.busy === true
    exportButton.innerHTML = `<i class="ph ph-export" aria-hidden="true"></i><span>${t('activity.export')}</span>`
    toolbar.append(toggleLabel, filterLabel, exportButton)

    const note = element('p', document, 'privacy-note')
    note.innerHTML = `<i class="ph ph-lock-key" aria-hidden="true"></i><span>${t('activity.privacy')}</span>`
    const entries = Array.isArray(model.entries) ? model.entries : []
    const visible = []
    for (const entry of entries) {
        if ((model.filter ?? 'all') === 'all' || entry.severity === model.filter) visible.push(entry)
    }
    const list = element('ol', document, 'activity-list')
    for (const entry of visible) list.append(renderEntry(entry, document, t))
    if (visible.length === 0) {
        const empty = element('li', document, 'activity-empty')
        empty.textContent = t('activity.empty')
        list.append(empty)
    }
    const result = element('p', document, 'support-result')
    result.dataset.supportResult = 'activity'
    result.setAttribute('role', 'status')
    result.setAttribute('aria-live', 'polite')
    result.innerHTML = model.result ?? ''
    section.append(header, toolbar, note, list, result)
    return section
}
