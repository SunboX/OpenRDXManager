// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { findHelpTopic } from '../../help/help-index.mjs'

/** @param {string} name - Element name. @param {Document} document - Owning document. @param {string} [className] - CSS class. @returns {HTMLElement} New element. */
function element(name, document, className = '') {
    const node = document.createElement(name)
    if (className !== '') node.className = className
    return node
}

/** @param {object} topic - Bundled local topic. @param {Document} document - Owning document. @param {(key: string, params?: object) => string} t - Active translator. @returns {HTMLElement} Local topic article. */
function renderTopic(topic, document, t) {
    const article = element('article', document, 'help-topic')
    article.dataset.helpTopic = topic.id
    const title = element('h2', document)
    title.textContent = t(topic.titleKey)
    const summary = element('p', document, 'help-topic__summary')
    summary.textContent = t(topic.summaryKey)
    article.append(title, summary)
    for (const paragraphKey of topic.paragraphKeys) {
        const text = element('p', document)
        text.textContent = t(paragraphKey)
        article.append(text)
    }
    if (Array.isArray(topic.contactKeys)) {
        const contacts = element('ul', document, 'support-contacts')
        for (const contactKey of topic.contactKeys) {
            const item = element('li', document)
            item.textContent = t(contactKey)
            contacts.append(item)
        }
        article.append(contacts)
    }
    const source = element('small', document, 'help-topic__source')
    source.innerHTML = t('help.source', { source: topic.source })
    article.append(source)
    return article
}

/**
 * Renders local help, About, Support, and update/summary actions.
 * @param {{activeTopic?: string, topics: object[], mode?: 'help'|'support', app?: object|null, update?: object|null, summaryResult?: string, busy?: string|null}} model - Help presentation state.
 * @param {{document: Document, translator: (key: string, params?: object) => string}} options - DOM and localization dependencies.
 * @returns {HTMLElement} Help dialog content.
 */
export function renderHelpView(model, options) {
    const document = options.document
    const t = options.translator
    const topics = Array.isArray(model.topics) ? model.topics : []
    const activeTopic = findHelpTopic(model.activeTopic) ?? topics[0] ?? null
    const section = element('section', document, 'support-panel help-view')
    section.dataset.helpView = model.mode ?? 'help'
    section.setAttribute('aria-labelledby', 'help-title')
    const header = element('header', document, 'support-panel__header')
    const heading = element('div', document)
    const eyebrow = element('span', document, 'eyebrow')
    eyebrow.textContent = t(model.mode === 'support' ? 'help.eyebrow.support' : 'help.eyebrow.local')
    const title = element('h1', document)
    title.id = 'help-title'
    title.tabIndex = -1
    title.dataset.focusKey = 'support:title'
    title.textContent = t(model.mode === 'support' ? 'help.title.support' : 'help.title.local')
    heading.append(eyebrow, title)
    const close = element('button', document, 'icon-button')
    close.type = 'button'
    close.dataset.action = 'close-support-panel'
    close.dataset.focusKey = 'support:close'
    close.setAttribute('aria-label', t('help.close'))
    close.innerHTML = '<i class="ph ph-x" aria-hidden="true"></i>'
    header.append(heading, close)

    const body = element('div', document, 'help-layout')
    const navigation = element('nav', document, 'help-navigation')
    navigation.setAttribute('aria-label', t('help.navigationLabel'))
    for (const topic of topics) {
        const button = element('button', document, topic.id === activeTopic?.id ? 'help-navigation__item help-navigation__item--active' : 'help-navigation__item')
        button.type = 'button'
        button.dataset.helpTopic = topic.id
        button.dataset.focusKey = `support:topic:${topic.id}`
        button.setAttribute('aria-current', topic.id === activeTopic?.id ? 'page' : 'false')
        const icon = element('i', document, `ph ${topic.icon}`)
        icon.setAttribute('aria-hidden', 'true')
        const label = element('span', document)
        label.textContent = t(topic.titleKey)
        button.append(icon, label)
        navigation.append(button)
    }

    const content = element('div', document, 'help-content')
    if (activeTopic !== null) content.append(renderTopic(activeTopic, document, t))
    const actions = element('section', document, 'support-actions')
    const actionTitle = element('h2', document)
    actionTitle.textContent = t('help.supportTools.title')
    const actionCopy = element('p', document)
    actionCopy.textContent = t('help.supportTools.privacy')
    const buttonRow = element('div', document, 'support-actions__buttons')
    const update = element('button', document, 'button button--secondary')
    update.type = 'button'
    update.dataset.action = 'check-updates'
    update.dataset.focusKey = 'support:updates'
    update.disabled = model.busy !== null && model.busy !== undefined
    update.innerHTML = `<i class="ph ph-arrows-clockwise" aria-hidden="true"></i><span>${t('help.checkUpdates')}</span>`
    const summary = element('button', document, 'button button--primary')
    summary.type = 'button'
    summary.dataset.action = 'generate-summary'
    summary.dataset.focusKey = 'support:summary'
    summary.disabled = model.busy !== null && model.busy !== undefined
    summary.innerHTML = `<i class="ph ph-file-arrow-down" aria-hidden="true"></i><span>${t('help.generateSummary')}</span>`
    buttonRow.append(update, summary)
    const result = element('div', document, 'support-result')
    result.dataset.supportResult = 'help'
    result.setAttribute('role', 'status')
    result.setAttribute('aria-live', 'polite')
    result.innerHTML = model.summaryResult ?? ''
    actions.append(actionTitle, actionCopy, buttonRow, result)
    content.append(actions)

    const about = element('aside', document, 'about-card')
    const aboutTitle = element('h2', document)
    aboutTitle.textContent = t('help.about.title')
    const app = model.app ?? {}
    const aboutText = element('p', document)
    aboutText.innerHTML = t('help.about.versionPlatform', { name: app.name ?? t('help.about.appFallback'), platform: app.platform ?? t('help.about.platformUnavailable'), version: app.version ?? t('help.about.versionUnavailable') })
    const copyright = element('p', document)
    copyright.textContent = t('help.about.copyright')
    const aboutBoundary = element('p', document)
    aboutBoundary.textContent = t('help.about.hardwareBoundary')
    about.append(aboutTitle, aboutText, copyright, aboutBoundary)
    body.append(navigation, content, about)
    section.append(header, body)
    return section
}
