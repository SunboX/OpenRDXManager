// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { FEATURE_MANIFEST } from '../feature-manifest.mjs'
import { formatLocalizedToken } from './view-helpers.mjs'
import { formatFirmwareRevision } from './firmware-revision.mjs'

const WINDOWS_HISTORY = Object.freeze([Object.freeze(['Windows 7', 'compatibility.qualification.x86X64AllServicePacks']), Object.freeze(['Windows 8', 'compatibility.qualification.x86X64AllServicePacks']), Object.freeze(['Windows 8.1', 'compatibility.qualification.x86X64AllServicePacks']), Object.freeze(['Windows 10', 'compatibility.qualification.x86X64AllEditions']), Object.freeze(['Windows Small Business Server 2011', 'compatibility.qualification.x64AllEditions']), Object.freeze(['Windows Server 2012', 'compatibility.qualification.x64AllEditions']), Object.freeze(['Windows Server 2012 R2', 'compatibility.qualification.x64AllEditions']), Object.freeze(['Windows Server 2016', 'compatibility.qualification.allEditions']), Object.freeze(['Windows Server 2019', 'compatibility.qualification.allEditions'])])

const PRODUCT_HISTORY = Object.freeze([
    Object.freeze(['compatibility.product.models', 'compatibility.product.modelsQualification']),
    Object.freeze(['compatibility.product.cartridges', 'compatibility.product.cartridgesQualification']),
    Object.freeze(['compatibility.product.driveLetter', 'compatibility.product.driveLetterQualification']),
    Object.freeze(['compatibility.product.usb3Password', 'compatibility.product.usb3PasswordQualification']),
    Object.freeze(['compatibility.product.protectedInterchange', 'compatibility.product.protectedInterchangeQualification']),
    Object.freeze(['compatibility.product.automaticAuth', 'compatibility.product.automaticAuthQualification']),
    Object.freeze(['compatibility.product.sataMode', 'compatibility.product.sataModeQualification']),
    Object.freeze(['compatibility.product.driveMode', 'compatibility.product.driveModeQualification']),
    Object.freeze(['compatibility.product.quickFormat', 'compatibility.product.quickFormatQualification']),
    Object.freeze(['compatibility.product.firmwareImages', 'compatibility.product.firmwareImagesQualification'])
])

const DIAGNOSTIC_ORDER = Object.freeze(['compatibility.troubleshooting.step1', 'compatibility.troubleshooting.step2', 'compatibility.troubleshooting.step3', 'compatibility.troubleshooting.step4', 'compatibility.troubleshooting.step5'])

const TROUBLESHOOTING_NOTES = Object.freeze([Object.freeze(['compatibility.troubleshooting.cannotWriteTitle', 'compatibility.troubleshooting.cannotWriteCopy']), Object.freeze(['compatibility.troubleshooting.sataTitle', 'compatibility.troubleshooting.sataCopy']), Object.freeze(['compatibility.troubleshooting.firmwareTitle', 'compatibility.troubleshooting.firmwareCopy'])])

const KNOWN_LIMITS = Object.freeze(['compatibility.limits.item1', 'compatibility.limits.item2', 'compatibility.limits.item3', 'compatibility.limits.item4', 'compatibility.limits.item5', 'compatibility.limits.item6'])

const HISTORICAL_FIXES = Object.freeze(['compatibility.history.item1', 'compatibility.history.item2', 'compatibility.history.item3', 'compatibility.history.item4', 'compatibility.history.item5', 'compatibility.history.item6', 'compatibility.history.item7', 'compatibility.history.item8'])

/**
 * Projects a typed reported-or-unavailable status field to bounded display
 * evidence without treating an unavailable reason as a reported value.
 * @param {object|undefined} field - Renderer-safe typed status field.
 * @returns {string} Reported value, unavailable reason, or not-reported token.
 */
function projectStatusField(field) {
    if (field?.availability === 'reported' && ['string', 'number', 'boolean'].includes(typeof field.value)) return String(field.value)
    if (field?.availability === 'unavailable' && typeof field.reason === 'string') return field.reason
    return 'not-reported'
}

/**
 * Builds the compatibility presentation model from the current renderer-safe
 * store snapshot. It never derives physical verification from fixture data or
 * from the existence of a device alone.
 * @param {object} state - Complete immutable renderer store snapshot.
 * @param {string} platform - Main-owned runtime platform token.
 * @returns {{host: object, device: object|null}} Bounded live evidence model.
 */
export function createCompatibilityModel(state, platform) {
    let selectedDevice = null
    for (const device of Array.isArray(state?.devices) ? state.devices : []) {
        if (device.id === state.selectedDeviceId) {
            selectedDevice = device
            break
        }
    }
    const service = state?.service ?? {}
    const host = Object.freeze({
        platform,
        hardwareReady: state?.provenance === 'service' && service.hardwareReady === true,
        hardwareVerified: state?.provenance === 'service' && service.hardwareVerified === true,
        managementPrerequisite: platform === 'darwin' ? 'macos-unmount-volume' : null,
        privilege: typeof service.privilege === 'string' ? service.privilege : service.mode === 'native' ? 'native-service' : (service.reason ?? 'not-reported')
    })
    if (selectedDevice === null) return Object.freeze({ host, device: null })
    const details = selectedDevice.drive?.details ?? {}
    const device = Object.freeze({
        id: selectedDevice.id,
        product: selectedDevice.product,
        firmware: formatFirmwareRevision(projectStatusField(details.firmwareRevision)),
        connectionType: projectStatusField(details.connectionType),
        capabilities: selectedDevice.capabilities ?? Object.freeze({})
    })
    return Object.freeze({ host, device })
}

/**
 * Creates one DOM element with an optional class.
 * @param {string} name - HTML element name.
 * @param {Document} document - Owning document.
 * @param {string} [className] - Optional CSS class list.
 * @returns {HTMLElement} New element.
 */
function element(name, document, className = '') {
    const node = document.createElement(name)
    if (className !== '') node.className = className
    return node
}

/**
 * Formats an internal token without interpreting it as markup.
 * @param {unknown} value - Candidate token.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {string} Human-readable bounded text.
 */
function formatToken(value, t) {
    if (typeof value !== 'string' || value.trim() === '') return t('state.notReported')
    const words = value.replaceAll(/[-_:./]+/g, ' ').trim()
    return words.charAt(0).toUpperCase() + words.slice(1)
}

/**
 * Appends a standard section heading block.
 * @param {HTMLElement} section - Target section.
 * @param {string} eyebrowText - Small context label.
 * @param {string} titleText - Visible heading.
 * @param {string} descriptionText - Supporting explanation.
 * @param {Document} document - Owning document.
 * @returns {void} Completes after appending the heading.
 */
function appendSectionHeading(section, eyebrowText, titleText, descriptionText, document) {
    const heading = element('div', document, 'compatibility-heading')
    const eyebrow = element('span', document, 'eyebrow')
    eyebrow.textContent = eyebrowText
    const title = element('h2', document)
    title.textContent = titleText
    const description = element('p', document)
    description.textContent = descriptionText
    heading.append(eyebrow, title, description)
    section.append(heading)
}

/**
 * Appends one definition-list fact.
 * @param {HTMLElement} list - Target definition list.
 * @param {string} term - Fact label.
 * @param {string} description - Fact value.
 * @param {Document} document - Owning document.
 * @returns {void} Completes after appending the fact.
 */
function appendFact(list, term, description, document) {
    const row = element('div', document, 'compatibility-fact')
    const label = element('dt', document)
    label.textContent = term
    const value = element('dd', document)
    value.textContent = description
    row.append(label, value)
    list.append(row)
}

/**
 * Renders current host, device, and capability evidence without converting
 * absence or fixture data into a compatibility claim.
 * @param {object} model - Renderer-owned compatibility model.
 * @param {Document} document - Owning document.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {HTMLElement} Live capability section.
 */
function renderLiveSection(model, document, t) {
    const host = model.host ?? {}
    const device = model.device ?? null
    const section = element('section', document, 'compatibility-section compatibility-section--live')
    section.dataset.compatibilitySection = 'live'
    appendSectionHeading(section, t('compatibility.live.eyebrow'), t('compatibility.live.title'), t('compatibility.live.description'), document)
    const facts = element('dl', document, 'compatibility-facts')
    appendFact(facts, t('compatibility.fact.hostPlatform'), formatToken(host.platform, t), document)
    appendFact(facts, t('compatibility.fact.hardwareAccess'), host.hardwareReady === true ? t('compatibility.value.nativeHardwareReady') : t('compatibility.value.hardwareAccessUnavailable'), document)
    appendFact(facts, t('compatibility.fact.privilegeEndpoint'), formatToken(host.privilege, t), document)
    appendFact(facts, t('compatibility.fact.physicalVerification'), host.hardwareVerified === true ? t('compatibility.value.hardwareVerified') : t('compatibility.value.hardwarePending'), document)
    if (device === null) {
        appendFact(facts, t('compatibility.fact.selectedDock'), t('compatibility.value.noDock'), document)
    } else {
        appendFact(facts, t('compatibility.fact.selectedDock'), typeof device.product === 'string' ? device.product : device.id, document)
        appendFact(facts, t('compatibility.fact.firmware'), formatToken(device.firmware, t), document)
        appendFact(facts, t('compatibility.fact.connection'), formatToken(device.connectionType, t), document)
    }
    section.append(facts)

    if (host.managementPrerequisite === 'macos-unmount-volume') {
        const prerequisite = element('p', document, 'compatibility-note compatibility-note--prerequisite')
        prerequisite.dataset.managementPrerequisite = host.managementPrerequisite
        prerequisite.textContent = t('compatibility.value.macosUnmountPrerequisite')
        section.append(prerequisite)
    }

    if (device !== null && device.capabilities !== null && typeof device.capabilities === 'object') {
        const grid = element('div', document, 'live-capability-grid')
        for (const [name, capability] of Object.entries(device.capabilities)) {
            const card = element('article', document, 'live-capability')
            card.dataset.liveCapability = name
            const title = element('h3', document)
            title.textContent = formatLocalizedToken(t, name)
            const state = element('strong', document)
            const stateName = typeof capability?.state === 'string' ? capability.state : 'unsupported-product'
            state.dataset.capabilityState = stateName
            state.textContent = formatLocalizedToken(t, stateName)
            const reason = element('p', document)
            reason.textContent = capability?.reason === undefined ? t('compatibility.value.noAdditionalReason') : formatToken(capability.reason, t)
            card.append(title, state, reason)
            grid.append(card)
        }
        section.append(grid)
    }
    return section
}

/**
 * Appends a semantic two-column table from immutable evidence rows.
 * @param {HTMLElement} parent - Parent section.
 * @param {string} captionText - Visible table caption.
 * @param {string} firstHeading - First column label.
 * @param {string} secondHeading - Second column label.
 * @param {ReadonlyArray<ReadonlyArray<string>>} rows - Historical evidence rows.
 * @param {Document} document - Owning document.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @param {boolean} translateFirstColumn - Whether first-column values are catalog keys.
 * @returns {void} Completes after appending the table.
 */
function appendEvidenceTable(parent, captionText, firstHeading, secondHeading, rows, document, t, translateFirstColumn) {
    const table = element('table', document, 'compatibility-table')
    const caption = element('caption', document)
    caption.textContent = captionText
    const head = element('thead', document)
    const headRow = element('tr', document)
    const first = element('th', document)
    first.scope = 'col'
    first.textContent = firstHeading
    const second = element('th', document)
    second.scope = 'col'
    second.textContent = secondHeading
    headRow.append(first, second)
    head.append(headRow)
    const body = element('tbody', document)
    for (const row of rows) {
        const tableRow = element('tr', document)
        const name = element('th', document)
        name.scope = 'row'
        name.textContent = translateFirstColumn ? t(row[0]) : row[0]
        const qualification = element('td', document)
        qualification.textContent = t(row[1])
        tableRow.append(name, qualification)
        body.append(tableRow)
    }
    table.append(caption, head, body)
    parent.append(table)
}

/**
 * Renders the published historical matrix separately from current runtime
 * capability evidence.
 * @param {Document} document - Owning document.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {HTMLElement} Historical vendor evidence section.
 */
function renderHistoricalSection(document, t) {
    const section = element('section', document, 'compatibility-section')
    section.dataset.compatibilitySection = 'historical'
    appendSectionHeading(section, t('compatibility.historical.eyebrow'), t('compatibility.historical.title'), t('compatibility.historical.description'), document)
    appendEvidenceTable(section, t('compatibility.historical.windowsCaption'), t('compatibility.historical.operatingSystem'), t('compatibility.historical.publishedQualification'), WINDOWS_HISTORY, document, t, false)
    const windowsDifference = element('p', document, 'compatibility-note')
    windowsDifference.textContent = t('compatibility.historical.windowsDifference')
    const mac = element('p', document, 'compatibility-note')
    mac.textContent = t('compatibility.historical.macDifference')
    section.append(windowsDifference, mac)
    appendEvidenceTable(section, t('compatibility.historical.productsCaption'), t('compatibility.historical.productFeature'), t('compatibility.historical.publishedQualification'), PRODUCT_HISTORY, document, t, true)
    return section
}

/**
 * Renders the manual's ordered support workflow.
 * @param {Document} document - Owning document.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {HTMLElement} Troubleshooting order section.
 */
function renderTroubleshootingSection(document, t) {
    const section = element('section', document, 'compatibility-section')
    section.dataset.compatibilitySection = 'troubleshooting'
    appendSectionHeading(section, t('compatibility.troubleshooting.eyebrow'), t('compatibility.troubleshooting.title'), t('compatibility.troubleshooting.description'), document)
    const list = element('ol', document, 'diagnostic-order')
    let stepNumber = 0
    for (const key of DIAGNOSTIC_ORDER) {
        stepNumber += 1
        const item = element('li', document)
        item.dataset.diagnosticStep = String(stepNumber)
        const number = element('span', document, 'diagnostic-order__number')
        number.textContent = String(stepNumber).padStart(2, '0')
        const copy = element('span', document)
        copy.textContent = t(key)
        item.append(number, copy)
        list.append(item)
    }
    section.append(list)
    const notes = element('div', document, 'troubleshooting-notes')
    for (const note of TROUBLESHOOTING_NOTES) {
        const article = element('article', document)
        const title = element('h3', document)
        title.textContent = t(note[0])
        const copy = element('p', document)
        copy.textContent = t(note[1])
        article.append(title, copy)
        notes.append(article)
    }
    section.append(notes)
    return section
}

/**
 * Renders important historical and implementation boundaries as visible
 * limitations instead of implied capability.
 * @param {Document} document - Owning document.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {HTMLElement} Known-limits section.
 */
function renderKnownLimitsSection(document, t) {
    const section = element('section', document, 'compatibility-section')
    section.dataset.compatibilitySection = 'limits'
    appendSectionHeading(section, t('compatibility.limits.eyebrow'), t('compatibility.limits.title'), t('compatibility.limits.description'), document)
    const list = element('ul', document, 'known-limits')
    for (const key of KNOWN_LIMITS) {
        const item = element('li', document)
        const icon = element('i', document, 'ph ph-warning')
        icon.setAttribute('aria-hidden', 'true')
        const copy = element('span', document)
        copy.textContent = t(key)
        item.append(icon, copy)
        list.append(item)
    }
    section.append(list)
    return section
}

/**
 * Renders the bounded historical fixed-issue inventory for diagnosis of older
 * Manager and firmware versions.
 * @param {Document} document - Owning document.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {HTMLElement} Historical release-fix section.
 */
function renderHistorySection(document, t) {
    const section = element('section', document, 'compatibility-section')
    section.dataset.compatibilitySection = 'history'
    appendSectionHeading(section, t('compatibility.history.eyebrow'), t('compatibility.history.title'), t('compatibility.history.description'), document)
    const list = element('ul', document, 'known-limits')
    for (const key of HISTORICAL_FIXES) {
        const item = element('li', document)
        const icon = element('i', document, 'ph ph-check-circle')
        icon.setAttribute('aria-hidden', 'true')
        const copy = element('span', document)
        copy.textContent = t(key)
        item.append(icon, copy)
        list.append(item)
    }
    section.append(list)
    return section
}

/**
 * Renders all numbered documents with their honest current production mapping.
 * @param {Document} document - Owning document.
 * @param {(key: string, params?: object) => string} t - Active translator.
 * @returns {HTMLElement} Feature coverage section.
 */
function renderFeatureCoverageSection(document, t) {
    const section = element('section', document, 'compatibility-section')
    section.dataset.compatibilitySection = 'coverage'
    appendSectionHeading(section, t('compatibility.coverage.eyebrow'), t('compatibility.coverage.title'), t('compatibility.coverage.description'), document)
    const list = element('ol', document, 'feature-coverage-list')
    for (const entry of FEATURE_MANIFEST) {
        const item = element('li', document)
        item.value = entry.documentNumber
        item.dataset.featureNumber = String(entry.documentNumber)
        const copy = element('div', document)
        const title = element('strong', document)
        title.textContent = t(`compatibility.feature.${String(entry.documentNumber).padStart(2, '0')}`)
        const source = element('small', document)
        source.textContent = entry.source
        copy.append(title, source)
        const mapping = element('code', document)
        mapping.dataset.mappingType = entry.mapping.type
        mapping.textContent = `${entry.mapping.type} · ${entry.mapping.target}`
        item.append(copy, mapping)
        list.append(item)
    }
    section.append(list)
    return section
}

/**
 * Renders local compatibility, troubleshooting, and feature-coverage evidence.
 * @param {{host?: object, device?: object|null}} model - Current renderer-safe host and selected-device state.
 * @param {{document: Document, translator: (key: string, params?: object) => string}} options - DOM and localization dependencies.
 * @returns {HTMLElement} Accessible compatibility overlay content.
 */
export function renderCompatibilityView(model, options) {
    const document = options.document
    const t = options.translator
    if (typeof t !== 'function') throw new TypeError('Compatibility view requires a translator')
    const view = element('section', document, 'support-panel compatibility-view')
    view.dataset.compatibilityView = 'true'
    view.setAttribute('aria-labelledby', 'compatibility-title')
    const header = element('header', document, 'support-panel__header')
    const heading = element('div', document)
    const eyebrow = element('span', document, 'eyebrow')
    eyebrow.textContent = t('compatibility.eyebrow')
    const title = element('h1', document)
    title.id = 'compatibility-title'
    title.tabIndex = -1
    title.dataset.focusKey = 'support:title'
    title.textContent = t('compatibility.title')
    const intro = element('p', document)
    intro.textContent = t('compatibility.intro')
    heading.append(eyebrow, title, intro)
    const close = element('button', document, 'icon-button')
    close.type = 'button'
    close.dataset.action = 'close-support-panel'
    close.setAttribute('aria-label', t('compatibility.close'))
    close.innerHTML = '<i class="ph ph-x" aria-hidden="true"></i>'
    header.append(heading, close)
    const body = element('div', document, 'compatibility-body')
    body.append(renderLiveSection(model, document, t), renderHistoricalSection(document, t), renderTroubleshootingSection(document, t), renderKnownLimitsSection(document, t), renderHistorySection(document, t), renderFeatureCoverageSection(document, t))
    view.append(header, body)
    return view
}
