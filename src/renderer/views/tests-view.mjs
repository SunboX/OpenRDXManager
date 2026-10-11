// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createComponentIcon, getComponentContext, renderCapabilityState } from '../components/capability-state.mjs'
import { renderOperationLockBanner } from '../components/operation-drawer.mjs'
import { renderProgressTimeline } from '../components/progress-timeline.mjs'
import { renderOperationResult } from '../components/result-panel.mjs'
import { OperationKind } from '../../shared/contracts.mjs'
import { createDiagnosticResult, createDiagnosticWorkflow } from '../workflows/test-workflow.mjs'
import { formatLocalizedToken } from './view-helpers.mjs'

const TEST_KINDS = Object.freeze([OperationKind.SELF_TEST, OperationKind.LED_TEST, OperationKind.WRITE_READ_TEST])

/**
 * Creates a visible paragraph from bundled trusted copy.
 * @param {Document} document - Owning document.
 * @param {string} text - Visible bundled copy.
 * @param {string} className - Presentation class.
 * @returns {HTMLParagraphElement} Paragraph node.
 */
function paragraph(document, text, className) {
    const node = document.createElement('p')
    node.className = className
    node.textContent = text
    return node
}

/**
 * Checks whether one renderer operation belongs to the selected diagnostic.
 * @param {object|null|undefined} operation - Active or terminal operation.
 * @param {object} device - Selected device snapshot.
 * @param {string} kind - Diagnostic kind.
 * @returns {boolean} True for the same device and kind; results retain their original revision.
 */
function matchesOperation(operation, device, kind) {
    // Revisions gate command admission in the store, not the display of an
    // already accepted operation after a background status refresh.
    return operation?.kind === kind && operation.deviceId === device?.id
}

/**
 * Renders every current prerequisite, including multiple simultaneous blockers.
 * @param {Document} document - Owning document.
 * @param {object[]} prerequisites - Immutable prerequisite rows.
 * @param {(key: string, params?: object) => string} translator - Active translator.
 * @returns {HTMLElement} Semantic prerequisite section.
 */
function renderPrerequisites(document, prerequisites, translator) {
    const section = document.createElement('section')
    section.className = 'test-prerequisites'
    const heading = document.createElement('h4')
    heading.textContent = translator('tests.prerequisites.title')
    const list = document.createElement('ul')
    for (const item of prerequisites) {
        const row = document.createElement('li')
        row.dataset.prerequisite = item.id
        row.dataset.prerequisiteState = item.met ? 'met' : 'unmet'
        row.append(createComponentIcon(document, item.met ? 'ph-check-circle' : 'ph-x-circle', item.met ? 'ph-fill' : 'ph-duotone'))
        const copy = document.createElement('div')
        const label = document.createElement('strong')
        label.textContent = translator(item.labelKey)
        const detail = document.createElement('span')
        detail.textContent = translator(item.detailKey)
        copy.append(label, detail)
        row.append(copy)
        list.append(row)
    }
    section.append(heading, list)
    return section
}

/**
 * Renders the two-pass Self Test isolation procedure as ordered guidance.
 * @param {Document} document - Owning document.
 * @param {object} twoPass - Immutable procedure model.
 * @param {(key: string, params?: object) => string} translator - Active translator.
 * @returns {HTMLElement} Ordered two-pass guidance.
 */
function renderTwoPass(document, twoPass, translator) {
    const aside = document.createElement('aside')
    aside.className = 'test-guidance test-guidance--two-pass'
    aside.dataset.currentSelfTestPass = twoPass.currentPass
    const header = document.createElement('strong')
    header.append(createComponentIcon(document, 'ph-signpost', 'ph-duotone'))
    header.append(document.createTextNode(translator('tests.twoPass.title')))
    const list = document.createElement('ol')
    for (const key of [twoPass.firstKey, twoPass.secondKey]) {
        const item = document.createElement('li')
        item.textContent = translator(key)
        list.append(item)
    }
    aside.append(header, list)
    return aside
}

/**
 * Resolves a diagnostic result's message-key model at the DOM boundary while
 * preserving raw protocol, device, error, stage, and support tokens.
 * @param {object} result - Immutable diagnostic result message model.
 * @param {(key: string, params?: object) => string} translator - Active translator.
 * @returns {object} Shared result-panel presentation.
 */
function localizeDiagnosticResult(result, translator) {
    const test = translator(result.testTitleKey)
    const localized = {
        evidence: result.evidence.map((entry) => ({
            label: translator(entry.labelKey),
            value: typeof entry.value === 'string' || typeof entry.value === 'number' ? entry.value : translator(entry.valueKey)
        })),
        status: result.status,
        summary: translator(result.summaryKey, { test }),
        title: translator(result.titleKey, { test })
    }
    if (result.primaryFailure !== undefined) {
        localized.primaryFailure = translator(result.primaryFailure.key, result.primaryFailure.params)
    }
    if (Array.isArray(result.cleanupFailures) && result.cleanupFailures.length > 0) {
        localized.cleanupFailure = result.cleanupFailures.map((failure) => translator(failure.key, failure.params)).join('; ')
    }
    return localized
}

/**
 * Shows admission without claiming a device outcome or exposing bridge exceptions.
 * @param {Document} document - Owning document.
 * @param {object} request - Bounded submission state.
 * @param {string} test - Localized diagnostic name.
 * @param {Function} translator - Active locale translator.
 * @returns {HTMLElement} Live submission status or an explicit start failure.
 */
function renderSubmission(document, request, test, translator) {
    if (request.status === 'failed') {
        const reason = typeof request.reason === 'string' && /^[a-z][a-z0-9-]{0,127}$/.test(request.reason) ? request.reason : 'service-failure'
        return renderOperationResult(
            {
                status: 'failed',
                title: translator('tests.request.failedTitle', { test }),
                summary: translator('tests.request.failedSummary', { reason })
            },
            { document, translator }
        )
    }
    const status = paragraph(document, request.status === 'submitting' ? translator('utilities.feedback.submitting', { operation: test }) : translator('tests.request.accepted', { test }), 'test-guidance')
    status.dataset.testSubmission = request.status
    status.setAttribute('role', 'status')
    status.setAttribute('aria-live', 'polite')
    status.setAttribute('aria-atomic', 'true')
    status.prepend(createComponentIcon(document, 'ph-circle-notch'))
    return status
}

/**
 * Renders one complete diagnostic card with capability, prerequisites, active
 * stages, terminal evidence, and a single bounded action.
 * @param {Document} document - Owning document.
 * @param {object} device - Selected renderer-safe device.
 * @param {string} kind - Diagnostic kind.
 * @param {object} options - View state and callbacks.
 * @returns {HTMLElement} Diagnostic card.
 */
function renderTestCard(document, device, kind, options) {
    const translator = options.translator
    const workflow = createDiagnosticWorkflow(device, kind, {
        locked: options.locked,
        operationIntentAvailable: options.operationIntentAvailable
    })
    const activeOperation = matchesOperation(options.activeOperation, device, kind) ? options.activeOperation : null
    const request = matchesOperation(options.request, device, kind) ? options.request : null
    const terminalOperation = request === null && matchesOperation(options.lastOperation, device, kind) ? options.lastOperation : null
    const card = document.createElement('article')
    card.className = 'test-card'
    card.dataset.testKind = kind

    const header = document.createElement('header')
    header.className = 'test-card__header'
    const icon = document.createElement('span')
    icon.className = 'test-card__icon'
    icon.append(createComponentIcon(document, workflow.icon, 'ph-duotone'))
    const copy = document.createElement('div')
    const eyebrow = document.createElement('span')
    eyebrow.className = 'eyebrow'
    eyebrow.textContent = translator(kind === OperationKind.WRITE_READ_TEST ? 'tests.diagnostic.hostFilesystemEyebrow' : 'tests.diagnostic.deviceEyebrow')
    const heading = document.createElement('h3')
    heading.textContent = translator(workflow.titleKey)
    copy.append(eyebrow, heading)
    header.append(icon, copy)
    card.append(header, paragraph(document, translator(workflow.descriptionKey), 'test-card__description'))

    const protocol = document.createElement('p')
    protocol.className = 'test-protocol'
    protocol.append(createComponentIcon(document, 'ph-code', 'ph'))
    const protocolLabel = document.createElement('span')
    protocolLabel.textContent = kind === OperationKind.WRITE_READ_TEST ? translator(workflow.protocolKey) : translator('tests.protocol.provenCommand')
    protocol.append(protocolLabel)
    if (kind !== OperationKind.WRITE_READ_TEST) {
        const code = document.createElement('code')
        code.textContent = typeof workflow.protocol === 'string' ? workflow.protocol : translator(workflow.protocolKey)
        protocol.append(code)
    }
    card.append(protocol)

    if (workflow.twoPass !== undefined) card.append(renderTwoPass(document, workflow.twoPass, translator))
    if (typeof workflow.cleanupGuidanceKey === 'string') {
        const guidance = paragraph(document, translator(workflow.cleanupGuidanceKey), 'test-guidance test-guidance--cleanup')
        guidance.prepend(createComponentIcon(document, 'ph-broom', 'ph-duotone'))
        card.append(guidance)
    }
    card.append(renderPrerequisites(document, workflow.prerequisites, translator))

    /** @returns {void} Emits only this closed diagnostic operation kind. */
    function handleAction() {
        if (typeof options.onAction === 'function') options.onAction(kind)
    }
    const capability = renderCapabilityState(
        {
            action: { labelKey: workflow.actionLabelKey },
            descriptionKey: 'tests.capabilityDescription',
            reason: workflow.capability.reason,
            state: workflow.capability.state,
            title: translator('tests.readiness', { test: translator(workflow.titleKey) })
        },
        { document, onAction: typeof options.onAction === 'function' ? handleAction : undefined, translator: options.translator }
    )
    capability.classList.add('test-capability')
    const action = capability.querySelector('[data-capability-action]')
    action.dataset.action = kind
    action.dataset.testAction = ''
    action.dataset.operation = kind
    action.dataset.intent = 'operation'
    action.dataset.focusKey = `tests:operation:${kind}`
    if (request !== null && activeOperation === null) card.append(renderSubmission(document, request, translator(workflow.titleKey), translator))

    if (activeOperation !== null) {
        const progress = renderProgressTimeline(
            {
                activeStage: activeOperation.stage,
                progress: activeOperation.progress,
                stages: workflow.stages
            },
            { document, translator: options.translator }
        )
        progress.classList.add('test-progress')
        card.append(progress)
    }

    const result = createDiagnosticResult(terminalOperation)
    if (result !== null) {
        const panel = renderOperationResult(localizeDiagnosticResult(result, translator), { document, translator })
        panel.classList.add('diagnostic-result')
        panel.dataset.testResult = kind
        card.append(panel)
    }
    card.append(capability)
    return card
}

/**
 * Renders the complete Self Test, LED Test, and Write/Read Test workspace.
 * Hardware calls remain behind the existing high-level operation intent; this
 * view never receives native paths, CDB buffers, file contents, or filenames.
 * @param {object} device - Selected renderer-safe RDX snapshot.
 * @param {{document?: Document, translator?: (key: string, params?: object) => string, activeOperation?: object|null, lastOperation?: object|null, request?: object|null, locked?: boolean, operationIntentAvailable?: boolean, provenance?: string, onAction?: (kind: string) => void}} [options={}] - DOM, shell state, and bounded callback.
 * @returns {HTMLElement} Complete Tests workspace.
 */
export function renderTestsView(device, options = {}) {
    const { document, translator } = getComponentContext(options)
    const effectiveOptions = {
        ...options,
        locked: options.locked === true || (options.activeOperation !== null && options.activeOperation !== undefined) || ['submitting', 'accepted'].includes(options.request?.status),
        operationIntentAvailable: options.operationIntentAvailable !== false,
        translator
    }
    const view = document.createElement('section')
    view.className = 'tests-workspace'
    view.dataset.testsView = ''

    const header = document.createElement('header')
    header.className = 'tests-workspace__header'
    const title = document.createElement('div')
    title.append(createComponentIcon(document, 'ph-flask', 'ph-duotone'))
    const titleCopy = document.createElement('div')
    const eyebrow = document.createElement('span')
    eyebrow.className = 'eyebrow'
    eyebrow.textContent = translator('tests.eyebrow')
    const heading = document.createElement('h2')
    heading.textContent = translator('tests.title')
    const description = paragraph(document, translator('tests.description'), 'tests-workspace__description')
    titleCopy.append(eyebrow, heading, description)
    title.append(titleCopy)
    const identity = document.createElement('p')
    identity.className = 'tests-device-identity'
    identity.append(createComponentIcon(document, 'ph-hard-drives', 'ph-duotone'))
    identity.append(document.createTextNode(`${device?.product ?? translator('tests.unknownDevice')} · ${device?.serial ?? translator('tests.identityUnavailable')}`))
    header.append(title, identity)
    view.append(header)

    if (effectiveOptions.locked) {
        view.append(
            renderOperationLockBanner(
                {
                    operationLabel: formatLocalizedToken(translator, options.activeOperation?.kind ?? 'self-test'),
                    stageLabel: formatLocalizedToken(translator, options.activeOperation?.stage ?? 'starting')
                },
                { document, translator }
            )
        )
    }
    const grid = document.createElement('div')
    grid.className = 'tests-grid'
    for (const kind of TEST_KINDS) grid.append(renderTestCard(document, device, kind, effectiveOptions))
    view.append(grid)
    if (options.provenance === 'fixture') {
        const note = paragraph(document, translator('tests.fixtureNote'), 'tests-hardware-note')
        note.prepend(createComponentIcon(document, 'ph-warning-circle', 'ph-duotone'))
        view.append(note)
    }
    return view
}
