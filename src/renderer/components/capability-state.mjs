// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { englishCatalog } from '../../locales/en.mjs'
import { createTranslator } from '../i18n.mjs'

const defaultTranslator = createTranslator(englishCatalog, englishCatalog)
const KNOWN_STATES = new Set(['available', 'busy', 'unsupported-product', 'unsupported-platform', 'wrong-media-state', 'authentication-required', 'insufficient-permission', 'host-dependency-missing', 'evidence-incomplete', 'transport-unavailable', 'hardware-unverified'])
const STATE_PRESENTATION = Object.freeze({
    available: Object.freeze({ icon: 'ph-check-circle', tone: 'available' }),
    busy: Object.freeze({ icon: 'ph-circle-notch', tone: 'busy' }),
    'evidence-incomplete': Object.freeze({ icon: 'ph-warning-diamond', tone: 'warning' }),
    'hardware-unverified': Object.freeze({ icon: 'ph-warning-circle', tone: 'warning' }),
    'wrong-media-state': Object.freeze({ icon: 'ph-disc', tone: 'warning' }),
    'authentication-required': Object.freeze({ icon: 'ph-lock-key', tone: 'warning' }),
    'insufficient-permission': Object.freeze({ icon: 'ph-shield-warning', tone: 'danger' }),
    'host-dependency-missing': Object.freeze({ icon: 'ph-package', tone: 'danger' }),
    'transport-unavailable': Object.freeze({ icon: 'ph-plugs', tone: 'danger' }),
    'unsupported-platform': Object.freeze({ icon: 'ph-desktop-tower', tone: 'muted' }),
    'unsupported-product': Object.freeze({ icon: 'ph-hard-drives', tone: 'muted' })
})
let componentIdentifier = 0

/**
 * Returns the next document-local-enough component identifier. The identifier
 * is presentation-only and never crosses the renderer boundary.
 * @param {string} prefix - Stable component prefix.
 * @returns {string} Unique identifier for this renderer module instance.
 */
export function createComponentId(prefix) {
    componentIdentifier += 1
    return `${prefix}-${componentIdentifier}`
}

/**
 * Resolves a DOM and translator without allowing renderer components to load
 * remote resources or depend on Node.js.
 * @param {{document?: Document, translator?: (key: string, params?: object) => string}} [options={}] - Component dependencies.
 * @returns {{document: Document, translator: (key: string, params?: object) => string}} Validated dependencies.
 * @throws {TypeError} When no browser document or translator is available.
 */
export function getComponentContext(options = {}) {
    const document = options.document ?? globalThis.document
    const sourceTranslator = options.translator ?? defaultTranslator
    if (document === null || typeof document?.createElement !== 'function') {
        throw new TypeError('Operation component requires a browser document')
    }
    if (typeof sourceTranslator !== 'function') {
        throw new TypeError('Operation component translator must be a function')
    }
    /**
     * Converts the renderer translator's HTML-safe interpolation output back to
     * plain text before assigning it through `textContent`. This preserves
     * literal ampersands without enabling markup from parameters.
     * @param {string} key - Bundled message key.
     * @param {object} [params={}] - Bounded interpolation parameters.
     * @returns {string} Plain visible translation.
     */
    function translator(key, params = {}) {
        const decoder = document.createElement('textarea')
        decoder.innerHTML = sourceTranslator(key, params)
        return decoder.value
    }
    return { document, translator }
}

/**
 * Resolves visible component copy from direct trusted text, a translated key,
 * or a translated fallback key in that order.
 * @param {object} model - Renderer-owned presentation model.
 * @param {string} property - Direct-copy property name.
 * @param {string} keyProperty - Translation-key property name.
 * @param {(key: string, params?: object) => string} translator - Bounded translator.
 * @param {string} fallbackKey - Bundled fallback message key.
 * @param {object} [params={}] - Safe primitive translation parameters.
 * @returns {string} Visible trusted copy.
 */
export function resolveComponentText(model, property, keyProperty, translator, fallbackKey, params = {}) {
    if (typeof model?.[property] === 'string' && model[property].length > 0) {
        return model[property]
    }
    if (typeof model?.[keyProperty] === 'string' && model[keyProperty].length > 0) {
        return translator(model[keyProperty], params)
    }
    return translator(fallbackKey, params)
}

/**
 * Creates one decorative bundled Phosphor icon. Visible adjacent copy always
 * carries the semantic label.
 * @param {Document} document - Owning browser document.
 * @param {string} icon - Bundled Phosphor class.
 * @param {'ph'|'ph-fill'|'ph-duotone'} [weight='ph'] - Bundled icon weight.
 * @returns {HTMLElement} Decorative icon element.
 */
export function createComponentIcon(document, icon, weight = 'ph') {
    const element = document.createElement('i')
    element.className = `${weight} ${icon}`
    element.setAttribute('aria-hidden', 'true')
    return element
}

/**
 * Renders a visible capability state and its stable reason/action relationship.
 * Only an exact `available` state may enable its action; evidence-incomplete and
 * every other blocked state fail closed.
 * @param {{state: string, reason?: string, title?: string, titleKey?: string, description?: string, descriptionKey?: string, action?: {label?: string, labelKey?: string}, help?: {label?: string, labelKey?: string}}} model - Capability presentation model.
 * @param {{document?: Document, translator?: (key: string, params?: object) => string, onAction?: (event: Event) => void, onHelp?: (event: Event) => void}} [options={}] - DOM, translation, and local UI handlers.
 * @returns {HTMLElement} Accessible capability card.
 */
export function renderCapabilityState(model, options = {}) {
    const { document, translator } = getComponentContext(options)
    const state = KNOWN_STATES.has(model?.state) ? model.state : 'evidence-incomplete'
    const presentation = STATE_PRESENTATION[state]
    const reasonId = createComponentId('capability-reason')
    const titleId = createComponentId('capability-title')
    const card = document.createElement('article')
    card.className = `capability-state capability-state--${presentation.tone}`
    card.dataset.capabilityState = state
    card.setAttribute('aria-labelledby', titleId)

    const header = document.createElement('header')
    header.className = 'capability-state__header'
    header.append(createComponentIcon(document, presentation.icon, state === 'available' ? 'ph-fill' : 'ph-duotone'))
    const heading = document.createElement('h3')
    heading.id = titleId
    heading.textContent = resolveComponentText(model, 'title', 'titleKey', translator, 'operation.capabilityTitle')
    header.append(heading)
    card.append(header)

    if (typeof model?.description === 'string' || typeof model?.descriptionKey === 'string') {
        const description = document.createElement('p')
        description.className = 'capability-state__description'
        description.textContent = resolveComponentText(model, 'description', 'descriptionKey', translator, 'operation.capabilityDescription')
        card.append(description)
    }

    const reason = document.createElement('p')
    reason.className = 'capability-state__reason'
    reason.dataset.capabilityReason = ''
    reason.id = reasonId
    reason.append(createComponentIcon(document, state === 'available' ? 'ph-check' : 'ph-info'))
    const stateLabel = translator(`token.${state.replaceAll(/-([a-z])/g, capitalizeTokenSegment)}`)
    const blockedReasonKey = state === 'evidence-incomplete' ? 'operation.evidenceIncompleteReason' : 'operation.capabilityBlockedReason'
    reason.append(document.createTextNode(state === 'available' ? stateLabel : translator(blockedReasonKey, { reason: model?.reason ?? state, state: stateLabel })))
    card.append(reason)

    if (model?.help !== undefined) {
        const helpLabel = resolveComponentText(model.help, 'label', 'labelKey', translator, 'operation.openEvidenceHelp')
        if (typeof options.onHelp === 'function') {
            const helpButton = document.createElement('button')
            helpButton.className = 'text-link capability-state__help'
            helpButton.type = 'button'
            helpButton.dataset.capabilityHelp = ''
            helpButton.append(createComponentIcon(document, 'ph-question'))
            const helpText = document.createElement('span')
            helpText.textContent = helpLabel
            helpButton.append(helpText)
            helpButton.addEventListener('click', options.onHelp)
            card.append(helpButton)
        } else {
            const help = document.createElement('span')
            help.className = 'capability-state__help-copy'
            help.dataset.capabilityHelp = ''
            help.append(createComponentIcon(document, 'ph-question'))
            help.append(document.createTextNode(helpLabel))
            card.append(help)
        }
    }

    if (model?.action !== undefined) {
        const action = document.createElement('button')
        action.className = 'button button--secondary capability-state__action'
        action.type = 'button'
        action.dataset.capabilityAction = ''
        action.disabled = state !== 'available'
        action.setAttribute('aria-describedby', reasonId)
        action.append(createComponentIcon(document, 'ph-arrow-right'))
        const label = document.createElement('span')
        label.textContent = resolveComponentText(model.action, 'label', 'labelKey', translator, 'operation.openWorkflow')
        action.append(label)
        if (typeof options.onAction === 'function') action.addEventListener('click', options.onAction)
        card.append(action)
    }

    return card
}

/**
 * Uppercases one token segment for flat camel-case translation keys.
 * @param {string} match - Full hyphenated match.
 * @param {string} letter - Captured lowercase letter.
 * @returns {string} Uppercase segment without the hyphen.
 */
function capitalizeTokenSegment(match, letter) {
    return letter.toUpperCase()
}
