// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { volumeLabelLimits } from '../volume-label-form.mjs'
import { resolveUtilityCapability, utilityStages } from '../workflows/utility-workflow-helpers.mjs'
import { firmwareInstallationStageKeys } from '../firmware-installation-stages.mjs'
import { renderManufacturingView } from './manufacturing-view.mjs'
import { renderCapabilityState, createComponentIcon, getComponentContext } from '../components/capability-state.mjs'
import { renderOperationLockBanner } from '../components/operation-drawer.mjs'
import { renderProgressTimeline } from '../components/progress-timeline.mjs'
import { renderOperationResult } from '../components/result-panel.mjs'
import { createEjectWorkflow } from '../workflows/eject-workflow.mjs'
import { createFirmwareWorkflow } from '../workflows/firmware-workflow.mjs'
import { createFormatWorkflow } from '../workflows/format-workflow.mjs'
import { createDriveLetterWorkflow, createDriveModeWorkflow, createSataModeWorkflow } from '../workflows/mode-workflow.mjs'
import { firmwareFailureReasonKeys, getFirmwareFailureReasonKey, getFirmwarePreflightFailureReasonKey } from '../firmware-failure-reasons.mjs'

const UTILITY_KINDS = new Set(['volume-label-set', 'firmware-update', 'drive-letter-set', 'drive-letter-reset', 'format', 'drive-mode-set', 'sata-mode-set', 'eject-safe', 'eject-force'])
const UTILITY_KIND_KEYS = Object.freeze({
    'volume-label-set': 'utilities.volumeLabel.title',
    'drive-letter-reset': 'utilities.operation.driveLetterReset',
    'drive-letter-set': 'utilities.operation.driveLetterSet',
    'drive-mode-set': 'utilities.operation.driveModeSet',
    'eject-force': 'utilities.operation.ejectForce',
    'eject-safe': 'utilities.operation.ejectSafe',
    'firmware-update': 'utilities.operation.firmwareUpdate',
    format: 'utilities.operation.format',
    'sata-mode-set': 'utilities.operation.sataModeSet'
})
const UTILITY_REASON_KEYS = Object.freeze({
    ...firmwareFailureReasonKeys,
    'available-drive-letters-unreported': 'reason.availableDriveLettersUnreported',
    'current-drive-mode-unavailable': 'reason.currentDriveModeUnavailable',
    'current-sata-mode-unavailable': 'reason.currentSataModeUnavailable',
    'drive-letter-prerequisites-not-met': 'reason.driveLetterPrerequisitesNotMet',
    'drive-letter-windows-only': 'reason.driveLetterWindowsOnly',
    'firmware-file-changed': 'reason.firmwareFileChanged',
    'firmware-file-invalid': 'reason.firmwareFileInvalid',
    'firmware-file-token-invalid': 'reason.firmwareFileTokenInvalid',
    'firmware-file-type-unsupported': 'reason.firmwareFileTypeUnsupported',
    'firmware-selection-cancelled': 'reason.firmwareSelectionCancelled',
    'firmware-selection-capacity-exhausted': 'reason.firmwareSelectionCapacityExhausted',
    'firmware-selection-failed': 'reason.firmwareSelectionFailed',
    'firmware-selection-invalid': 'reason.firmwareSelectionInvalid',
    'firmware-selection-unavailable': 'reason.firmwareSelectionUnavailable',
    'firmware-update-prerequisites-not-met': 'reason.utilityPrerequisitesNotMet',
    'format-host-filesystem-unavailable': 'utilities.format.tooling.unavailable',
    'format-prerequisites-not-met': 'reason.utilityPrerequisitesNotMet',
    'media-must-be-ejected': 'reason.mediaMustBeEjected',
    'operation-in-progress': 'reason.operationInProgress',
    'operation-intent-unavailable': 'reason.operationIntentUnavailable',
    'sata-iii-product-required': 'reason.sataProductRequired'
})
const UTILITY_STAGE_KEYS = Object.freeze({
    ...firmwareInstallationStageKeys,
    'device-configuring': 'utilities.stage.deviceConfiguring',
    'device-readback': 'utilities.stage.deviceReadback',
    'device-reconnecting': 'utilities.stage.deviceReconnecting',
    'eject-readback': 'utilities.stage.ejectReadback',
    'firmware-finalizing': 'utilities.stage.firmwareFinalizing',
    'firmware-readback': 'utilities.stage.firmwareReadback',
    'firmware-validating': 'utilities.stage.firmwareValidating',
    'firmware-writing': 'utilities.stage.firmwareWriting',
    'format-finalizing': 'utilities.stage.formatFinalizing',
    'format-readback': 'utilities.stage.formatReadback',
    'format-validating': 'utilities.stage.formatValidating',
    'format-writing': 'utilities.stage.formatWriting',
    'host-ejecting': 'utilities.stage.hostEjecting',
    'host-unmounting': 'utilities.stage.hostUnmounting',
    'host-volume-changing': 'utilities.stage.hostVolumeChanging',
    'host-volume-readback': 'utilities.stage.hostVolumeReadback'
})

/**
 * Translates a stable utility operation kind without deriving a catalog path
 * from renderer or native input.
 * @param {unknown} kind - Candidate operation kind.
 * @param {(key: string, params?: object) => string} translator - Bounded translator.
 * @returns {string} Localized operation label.
 */
function translateUtilityKind(kind, translator) {
    return translator(typeof kind === 'string' && Object.hasOwn(UTILITY_KIND_KEYS, kind) ? UTILITY_KIND_KEYS[kind] : 'utilities.operation.generic')
}

/**
 * Translates only explicitly allowlisted reason tokens. Unknown device or
 * service reasons use generic local copy and are never interpreted as keys.
 * @param {unknown} reason - Candidate stable reason token.
 * @param {(key: string, params?: object) => string} translator - Bounded translator.
 * @returns {string} Localized safe reason copy.
 */
function translateUtilityReason(reason, translator) {
    return translator(typeof reason === 'string' && Object.hasOwn(UTILITY_REASON_KEYS, reason) ? UTILITY_REASON_KEYS[reason] : 'reason.generic')
}

/**
 * Translates an allowlisted utility stage without constructing a key from the
 * native token.
 * @param {unknown} stage - Candidate stage token.
 * @param {(key: string, params?: object) => string} translator - Bounded translator.
 * @returns {string} Localized stage label.
 */
function translateUtilityStage(stage, translator) {
    return translator(typeof stage === 'string' && Object.hasOwn(UTILITY_STAGE_KEYS, stage) ? UTILITY_STAGE_KEYS[stage] : 'utilities.stage.generic')
}

/**
 * Accepts only bounded stable native reason tokens for raw diagnostic evidence.
 * @param {unknown} value - Candidate reason token.
 * @param {string} fallback - Safe fallback token.
 * @returns {string} Stable token.
 */
function safeUtilityToken(value, fallback) {
    return typeof value === 'string' && /^[a-z][a-z0-9-]{0,127}$/.test(value) ? value : fallback
}

/**
 * Creates one trusted text paragraph.
 * @param {Document} document - Owning document.
 * @param {string} text - Trusted bundled copy.
 * @param {string} [className=''] - Optional CSS class.
 * @returns {HTMLParagraphElement} Text paragraph.
 */
function paragraph(document, text, className = '') {
    const node = document.createElement('p')
    node.className = className
    node.textContent = text
    return node
}

/**
 * Checks whether one renderer operation belongs to a utility on this device.
 * @param {object|null|undefined} operation - Candidate operation record.
 * @param {object} device - Selected renderer-safe RDX device.
 * @param {string[]} kinds - Matching operation kinds.
 * @returns {boolean} True for an exact utility/device match.
 */
function matchesUtility(operation, device, kinds) {
    // Firmware reconnect and formatting advance discovery revision. Keep their
    // terminal history for this dock while active operations remain revision-bound.
    const completedFirmware = operation?.kind === 'firmware-update' && operation.status === 'succeeded'
    const completedFormat = operation?.kind === 'format' && ['succeeded', 'failed', 'cancelled'].includes(operation.status)
    return kinds.includes(operation?.kind) && operation.deviceId === device?.id && (completedFirmware || completedFormat || operation.deviceRevision === undefined || operation.deviceRevision === device?.revision)
}

/**
 * Builds a bounded generic terminal result for one utility operation.
 * @param {object|null} operation - Matching terminal operation.
 * @returns {object|null} Localizable result-panel model or null.
 */
function createUtilityResult(operation) {
    if (!UTILITY_KINDS.has(operation?.kind) || !['succeeded', 'failed', 'cancelled'].includes(operation?.status)) return null
    if (operation.status === 'succeeded') {
        return Object.freeze({
            evidence: Object.freeze([Object.freeze({ labelKey: 'utilities.result.finalStage', stage: safeUtilityToken(operation.stage, 'complete') }), Object.freeze({ labelKey: 'utilities.result.selectedDevice', value: operation.deviceId })]),
            operationKey: UTILITY_KIND_KEYS[operation.kind],
            status: 'succeeded',
            summaryKey: 'utilities.result.succeededSummary',
            titleKey: 'utilities.result.succeededTitle'
        })
    }
    if (operation.status === 'cancelled') {
        return Object.freeze({
            evidence: Object.freeze([{ labelKey: 'utilities.result.safeTerminalStage', stage: safeUtilityToken(operation.stage, 'cancelled') }]),
            operationKey: UTILITY_KIND_KEYS[operation.kind],
            status: 'cancelled',
            summaryKey: 'utilities.result.cancelledSummary',
            titleKey: 'utilities.result.cancelledTitle'
        })
    }
    const code = safeUtilityToken(operation.error?.code, 'utility-failed')
    const stage = safeUtilityToken(operation.error?.stage ?? operation.stage, 'unknown-stage')
    const firmwareReasonKey = getFirmwarePreflightFailureReasonKey(operation)
    return Object.freeze({
        evidence: Object.freeze([Object.freeze({ code, labelKey: 'utilities.result.failure', stage }), Object.freeze(typeof operation.error?.supportCorrelationId === 'string' ? { labelKey: 'utilities.result.supportId', value: operation.error.supportCorrelationId } : { labelKey: 'utilities.result.supportId', valueKey: 'state.notReported' })]),
        operationKey: UTILITY_KIND_KEYS[operation.kind],
        status: 'failed',
        primaryFailureKey: getFirmwareFailureReasonKey(operation),
        summaryKey: firmwareReasonKey === undefined ? 'utilities.result.failedSummary' : 'operation.failureDescription.firmwareBeforeTransfer',
        titleKey: 'utilities.result.failedTitle'
    })
}

/**
 * Resolves a utility result's fixed keys while preserving raw device, support,
 * and bounded native evidence values.
 * @param {object} result - Localizable result model.
 * @param {(key: string, params?: object) => string} translator - Bounded translator.
 * @returns {object} Shared result-panel model.
 */
function localizeUtilityResult(result, translator) {
    const operation = translator(result.operationKey)
    const evidence = []
    for (const entry of result.evidence) {
        let value = entry.value
        if (typeof entry.stage === 'string' && typeof entry.code === 'string') {
            value = translator('utilities.result.failureAt', { code: entry.code, stage: translateUtilityStage(entry.stage, translator) })
        } else if (typeof entry.stage === 'string') {
            value = translateUtilityStage(entry.stage, translator)
        } else if (typeof entry.valueKey === 'string') {
            value = translator(entry.valueKey)
        }
        evidence.push(Object.freeze({ label: translator(entry.labelKey), value }))
    }
    return Object.freeze({
        evidence: Object.freeze(evidence),
        primaryFailure: result.primaryFailureKey === undefined ? undefined : translator(result.primaryFailureKey),
        status: result.status,
        summary: translator(result.summaryKey, { operation }),
        title: translator(result.titleKey, { operation })
    })
}

/**
 * Renders a complete prerequisite list.
 * @param {Document} document - Owning document.
 * @param {object[]} prerequisites - Workflow prerequisites.
 * @param {(key: string, params?: object) => string} translator - Bounded translator.
 * @returns {HTMLElement} Prerequisite section.
 */
function renderPrerequisites(document, prerequisites, translator) {
    const section = document.createElement('section')
    section.className = 'utility-prerequisites'
    const heading = document.createElement('h4')
    heading.textContent = translator('utilities.preflight')
    const list = document.createElement('ul')
    for (const prerequisite of prerequisites) {
        const item = document.createElement('li')
        item.dataset.prerequisite = prerequisite.id
        item.dataset.prerequisiteState = prerequisite.met ? 'met' : 'unmet'
        item.append(createComponentIcon(document, prerequisite.met ? 'ph-check-circle' : 'ph-x-circle', prerequisite.met ? 'ph-fill' : 'ph-duotone'))
        const copy = document.createElement('div')
        const label = document.createElement('strong')
        label.textContent = translator(prerequisite.labelKey)
        const detail = document.createElement('span')
        detail.textContent = translator(prerequisite.detailKey, prerequisite.detailParams)
        copy.append(label, detail)
        item.append(copy)
        list.append(item)
    }
    section.append(heading, list)
    return section
}

/**
 * Appends capability, active progress, and terminal result presentation.
 * @param {HTMLElement} card - Utility card.
 * @param {object} workflow - Workflow model.
 * @param {object} device - Selected renderer-safe device.
 * @param {string[]} kinds - Operation kinds belonging to the card.
 * @param {object} options - View state and translator.
 * @returns {void} Completes after appending state.
 */
function appendWorkflowState(card, workflow, device, kinds, options) {
    const capability = renderCapabilityState(
        {
            descriptionKey: 'utilities.capability.description',
            reason: translateUtilityReason(workflow.capability.reason, options.translator),
            state: workflow.capability.state,
            titleKey: 'utilities.capability.title'
        },
        { document: card.ownerDocument, translator: options.translator }
    )
    capability.classList.add('utility-capability')
    card.append(capability)
    const active = matchesUtility(options.activeOperation, device, kinds) ? options.activeOperation : null
    if (active !== null) {
        card.append(
            renderProgressTimeline(
                {
                    activeStage: active.stage,
                    progress: active.progress,
                    stages: workflow.stages
                },
                { document: card.ownerDocument, translator: options.translator }
            )
        )
    }
    const terminal = matchesUtility(options.lastOperation, device, kinds) ? options.lastOperation : null
    const result = createUtilityResult(terminal)
    if (result !== null) card.append(renderOperationResult(localizeUtilityResult(result, options.translator), { document: card.ownerDocument, translator: options.translator }))
}

/**
 * Creates a standard utility card shell.
 * @param {Document} document - Owning document.
 * @param {string} feature - Stable feature identifier.
 * @param {string} iconName - Bundled Phosphor icon.
 * @param {string} eyebrowKey - Small category message key.
 * @param {string} titleKey - Card-title message key.
 * @param {string} descriptionKey - Card-description message key.
 * @param {(key: string, params?: object) => string} translator - Bounded translator.
 * @returns {HTMLElement} Utility card.
 */
function utilityCard(document, feature, iconName, eyebrowKey, titleKey, descriptionKey, translator) {
    const card = document.createElement('article')
    card.className = 'utility-card'
    card.dataset.feature = feature
    const header = document.createElement('header')
    header.className = 'utility-card__header'
    const icon = document.createElement('span')
    icon.className = 'utility-card__icon'
    icon.append(createComponentIcon(document, iconName, 'ph-duotone'))
    const copy = document.createElement('div')
    const eyebrow = document.createElement('span')
    eyebrow.className = 'eyebrow'
    eyebrow.textContent = translator(eyebrowKey)
    const heading = document.createElement('h3')
    heading.textContent = translator(titleKey)
    copy.append(eyebrow, heading)
    header.append(icon, copy)
    card.append(header, paragraph(document, translator(descriptionKey), 'utility-card__description'))
    return card
}

/**
 * Creates one structured operation button for delegated controller handling.
 * @param {Document} document - Owning document.
 * @param {{action: string, kind: string, label: string, disabled: boolean, tone?: 'primary'|'warning'|'danger', reason: string}} model - Button presentation.
 * @returns {HTMLButtonElement} Structured utility button.
 */
function utilityButton(document, model) {
    const button = document.createElement('button')
    button.className = `button button--${model.tone ?? 'secondary'}`
    button.type = 'button'
    button.dataset.action = model.action
    button.dataset.utilityOperation = model.kind
    button.dataset.focusKey = `utilities:${model.kind}:${model.action}`
    button.disabled = model.disabled
    button.title = model.reason
    button.append(createComponentIcon(document, 'ph-arrow-right'))
    const label = document.createElement('span')
    label.textContent = model.label
    button.append(label)
    return button
}

/**
 * Associates a control with the visible capability explanation in its card.
 * @param {HTMLElement} card - Utility card that owns the capability status.
 * @param {HTMLButtonElement|HTMLInputElement} button - Control to describe.
 * @returns {HTMLButtonElement|HTMLInputElement} The same control with an accessible description.
 */
function describeUtilityButton(card, button) {
    const reason = card.querySelector('.utility-capability [data-capability-reason]')
    if (reason !== null) {
        button.setAttribute('aria-describedby', reason.id)
    }
    return button
}

/**
 * Renders the firmware card and its non-negotiable warnings.
 * @param {Document} document - Owning document.
 * @param {object} device - Selected device.
 * @param {object} options - View state.
 * @returns {HTMLElement} Firmware utility card.
 */
function renderFirmwareCard(document, device, options) {
    const workflow = createFirmwareWorkflow(device, options)
    const card = utilityCard(document, 'firmware', 'ph-file-arrow-up', 'utilities.firmware.eyebrow', 'utilities.firmware.title', 'utilities.firmware.description', options.translator)
    const heading = card.querySelector('h3')
    heading.tabIndex = -1
    heading.dataset.focusKey = 'utilities:firmware:heading'
    const family = paragraph(
        document,
        options.translator(workflow.image.familyKey, {
            extension: workflow.image.extension ?? options.translator('utilities.firmware.noCompatibleExtension'),
            family: workflow.image.family ?? options.translator('utilities.firmware.unknownFamily')
        }),
        'utility-protocol'
    )
    family.prepend(createComponentIcon(document, 'ph-file-code'))
    card.append(family, renderPrerequisites(document, workflow.prerequisites, options.translator))
    const warnings = document.createElement('ul')
    warnings.className = 'utility-warnings'
    for (const key of workflow.warnings) {
        const warning = document.createElement('li')
        warning.append(createComponentIcon(document, 'ph-warning-diamond', 'ph-duotone'), document.createTextNode(options.translator(key)))
        warnings.append(warning)
    }
    card.append(warnings)
    appendWorkflowState(card, workflow, device, [workflow.kind], options)
    card.append(
        describeUtilityButton(
            card,
            utilityButton(document, {
                action: 'start-firmware',
                disabled: workflow.capability.state !== 'available',
                kind: workflow.kind,
                label: options.translator('utilities.firmware.action'),
                reason: translateUtilityReason(workflow.capability.reason, options.translator),
                tone: 'warning'
            })
        )
    )
    return card
}

/**
 * Renders safe and forced eject as visibly separate actions.
 * @param {Document} document - Owning document.
 * @param {object} device - Selected device.
 * @param {object} options - View state.
 * @returns {HTMLElement} Eject utility card.
 */
function renderEjectCard(document, device, options) {
    const safe = createEjectWorkflow(device, 'safe', options)
    const forced = createEjectWorkflow(device, 'force', { ...options, riskAccepted: false })
    const forceReady = createEjectWorkflow(device, 'force', { ...options, riskAccepted: true })
    const card = utilityCard(document, 'eject', 'ph-eject', 'utilities.eject.eyebrow', 'utilities.eject.title', 'utilities.eject.description', options.translator)
    card.append(paragraph(document, options.translator(safe.guidanceKey), 'utility-guidance'), renderPrerequisites(document, safe.prerequisites, options.translator))
    appendWorkflowState(card, safe, device, [safe.kind, forced.kind], options)
    const actions = document.createElement('div')
    actions.className = 'utility-actions'
    actions.append(describeUtilityButton(card, utilityButton(document, { action: 'eject-safe', disabled: safe.capability.state !== 'available', kind: safe.kind, label: options.translator('utilities.eject.safeAction'), reason: translateUtilityReason(safe.capability.reason, options.translator), tone: 'primary' })))
    const risk = document.createElement('label')
    risk.className = 'utility-risk-check'
    const checkbox = document.createElement('input')
    checkbox.type = 'checkbox'
    checkbox.dataset.forceRisk = ''
    risk.append(checkbox, document.createTextNode(options.translator('utilities.eject.forceAcknowledgement')))
    const forceButton = utilityButton(document, {
        action: 'eject-force',
        disabled: forced.capability.state !== 'available',
        kind: forced.kind,
        label: options.translator('utilities.eject.forceAction'),
        reason: translateUtilityReason(forced.capability.reason, options.translator),
        tone: 'danger'
    })
    forceButton.dataset.readyWhenAcknowledged = String(forceReady.capability.state === 'available')
    actions.append(risk, describeUtilityButton(card, forceButton))
    card.append(actions, paragraph(document, options.translator(forced.guidanceKey), 'utility-danger-copy'))
    return card
}

/**
 * Renders the destructive format card with exact device/media identity input.
 * @param {Document} document - Owning document.
 * @param {object} device - Selected device.
 * @param {object} options - View state.
 * @returns {HTMLElement} Format utility card.
 */
function renderFormatCard(document, device, options) {
    const workflow = createFormatWorkflow(device, options)
    const confirmed = createFormatWorkflow(device, { ...options, confirmationValue: workflow.expectedIdentity ?? undefined })
    const card = utilityCard(document, 'format', 'ph-warning-octagon', 'utilities.format.eyebrow', 'utilities.format.title', 'utilities.format.description', options.translator)
    card.dataset.formatTarget = JSON.stringify([device.id, device.media?.id])
    const devicePrerequisites = workflow.prerequisites.filter(({ id }) => id !== 'exact-identity')
    card.append(paragraph(document, options.translator(workflow.toolingKey), 'utility-guidance'), renderPrerequisites(document, devicePrerequisites, options.translator))
    const form = document.createElement('div')
    form.className = 'utility-form'
    const filesystemLabel = document.createElement('label')
    filesystemLabel.textContent = options.translator('utilities.format.filesystemLabel')
    const filesystem = document.createElement('select')
    filesystem.dataset.utilityFilesystem = ''
    filesystem.disabled = workflow.filesystemChoices.length === 0
    for (const value of workflow.filesystemChoices) {
        const option = document.createElement('option')
        option.value = value
        option.textContent = options.translator(`utilities.format.filesystem.${value}${options.platform === 'linux' && value === 'ntfs' ? '.linux' : ''}`)
        const capacityLimit = { fat12: 32 * 1024 ** 2, fat16: 2 * 1024 ** 3, fat32: 2 * 1024 ** 4 }[value]
        option.disabled = capacityLimit !== undefined && device.media?.capacityBytes > capacityLimit
        if (option.disabled) option.textContent += ` — ${options.translator('utilities.format.capacityUnsupported')}`
        option.selected = value === workflow.filesystem
        filesystem.append(option)
    }
    filesystemLabel.append(filesystem)
    const confirmationLabel = document.createElement('label')
    confirmationLabel.textContent = workflow.expectedIdentity === null ? options.translator('utilities.format.identityUnavailable') : options.translator('utilities.format.typeIdentity', { identity: workflow.expectedIdentity })
    const confirmation = document.createElement('input')
    confirmation.type = 'text'
    confirmation.autocomplete = 'off'
    confirmation.spellcheck = false
    confirmation.dataset.formatConfirmation = ''
    confirmation.disabled = workflow.expectedIdentity === null
    if (workflow.expectedIdentity !== null) confirmation.dataset.expectedIdentity = workflow.expectedIdentity
    confirmationLabel.append(confirmation)
    form.append(filesystemLabel, confirmationLabel)
    if (options.platform === 'darwin') {
        for (const key of ['utilities.format.password', 'utilities.format.passwordConfirm']) {
            const label = document.createElement('label')
            label.textContent = options.translator(key)
            label.hidden = true
            const password = document.createElement('input')
            password.type = 'password'
            password.autocomplete = 'new-password'
            password.maxLength = 512
            password.dataset.formatPassword = ''
            label.append(password)
            form.append(label)
        }
    }
    form.append(paragraph(document, options.translator(workflow.consequenceKey), 'utility-danger-copy'))
    card.append(form)
    appendWorkflowState(card, confirmed, device, [workflow.kind], options)
    const button = utilityButton(document, {
        action: 'start-format',
        disabled: true,
        kind: workflow.kind,
        label: options.translator('utilities.format.action'),
        reason: translateUtilityReason(workflow.capability.reason, options.translator),
        tone: 'danger'
    })
    button.dataset.readyWhenConfirmed = String(confirmed.capability.state === 'available')
    button.dataset.unavailableReason = translateUtilityReason(confirmed.capability.reason, options.translator)
    card.append(describeUtilityButton(card, button))
    const hint = paragraph(document, options.translator('utilities.prerequisite.exactIdentity.required', { identity: workflow.expectedIdentity ?? '' }), 'utility-guidance')
    hint.dataset.formatHint = ''
    hint.id = 'format-confirmation-hint'
    button.setAttribute('aria-describedby', `${button.getAttribute('aria-describedby') ?? ''} ${hint.id}`.trim())
    card.append(hint)
    return card
}

/**
 * Renders Fixed/Removable mode selection with current-value suppression.
 * @param {Document} document - Owning document.
 * @param {object} device - Selected device.
 * @param {object} options - View state.
 * @returns {HTMLElement} Drive-mode utility card.
 */
function renderDriveModeCard(document, device, options) {
    const initial = createDriveModeWorkflow(device, options)
    const card = utilityCard(document, 'drive-mode', 'ph-sliders-horizontal', 'utilities.driveMode.eyebrow', 'utilities.driveMode.title', 'utilities.driveMode.description', options.translator)
    card.append(renderPrerequisites(document, initial.prerequisites, options.translator), paragraph(document, options.translator(initial.guidanceKey), 'utility-guidance'))
    const label = document.createElement('label')
    label.className = 'utility-select-label'
    label.textContent = options.translator('utilities.driveMode.requestedLabel')
    const select = document.createElement('select')
    select.dataset.utilityMode = ''
    select.dataset.currentValue = initial.currentMode ?? ''
    for (const [value, text] of [
        ['removable', options.translator('utilities.driveMode.removable')],
        ['fixed', options.translator('utilities.driveMode.fixed')]
    ]) {
        const option = document.createElement('option')
        option.value = value
        option.textContent = text
        option.selected = initial.currentMode === value
        select.append(option)
    }
    label.append(select)
    card.append(label)
    appendWorkflowState(card, initial, device, [initial.kind], options)
    const button = utilityButton(document, {
        action: 'set-drive-mode',
        disabled: initial.capability.state !== 'available' || initial.noOp,
        kind: initial.kind,
        label: options.translator(initial.noOp ? 'utilities.action.currentMode' : 'utilities.action.applyDriveMode'),
        reason: options.translator(initial.guidanceKey)
    })
    button.dataset.readyWhenChanged = String(initial.capability.state === 'available')
    card.append(describeUtilityButton(card, button))
    return card
}

/**
 * Renders SATA link mode selection with recommended default and SSD qualification.
 * @param {Document} document - Owning document.
 * @param {object} device - Selected device.
 * @param {object} options - View state.
 * @returns {HTMLElement} SATA utility card.
 */
function renderSataModeCard(document, device, options) {
    const initial = createSataModeWorkflow(device, { ...options, currentMode: options.currentSataMode })
    const card = utilityCard(document, 'sata-mode', 'ph-lightning', 'utilities.sataMode.eyebrow', 'utilities.sataMode.title', 'utilities.sataMode.description', options.translator)
    card.append(paragraph(document, options.translator(initial.guidanceKey), 'utility-guidance'), renderPrerequisites(document, initial.prerequisites, options.translator))
    const label = document.createElement('label')
    label.className = 'utility-select-label'
    label.textContent = options.translator('utilities.sataMode.requestedLabel')
    const select = document.createElement('select')
    select.dataset.utilitySataMode = ''
    select.dataset.currentValue = initial.currentMode ?? ''
    for (const [value, text] of [
        ['1.5g-3g', options.translator('utilities.sataMode.recommended')],
        ['3g-6g', options.translator('utilities.sataMode.ssdOnly')]
    ]) {
        const option = document.createElement('option')
        option.value = value
        option.textContent = text
        option.selected = initial.currentMode === value || (initial.currentMode === null && value === initial.recommendedMode)
        select.append(option)
    }
    label.append(select)
    card.append(label)
    appendWorkflowState(card, initial, device, [initial.kind], options)
    const button = utilityButton(document, {
        action: 'set-sata-mode',
        disabled: initial.capability.state !== 'available' || initial.noOp,
        kind: initial.kind,
        label: options.translator(initial.noOp ? 'utilities.action.currentMode' : 'utilities.action.applySataMode'),
        reason: translateUtilityReason(initial.capability.reason, options.translator)
    })
    button.dataset.readyWhenChanged = String(initial.capability.state === 'available')
    card.append(describeUtilityButton(card, button))
    return card
}

/**
 * Renders the current cartridge label and a bounded rename action.
 * @param {Document} document - Owning document.
 * @param {object} device - Selected device.
 * @param {object} options - View state.
 * @returns {HTMLElement} Cartridge-name utility card.
 */
function renderVolumeLabelCard(document, device, options) {
    const t = options.translator
    const card = utilityCard(document, 'volume-label', 'ph-tag', 'utilities.volumeLabel.eyebrow', 'utilities.volumeLabel.title', 'utilities.volumeLabel.description', t)
    const current = device.media?.label
    card.append(paragraph(document, t('utilities.volumeLabel.current', { label: typeof current === 'string' ? (current === '' ? t('utilities.volumeLabel.unnamed') : current) : t('state.notReported') }), 'utility-guidance'))
    const capability = resolveUtilityCapability(device, 'volume-label-set', [{ met: typeof current === 'string' }], { ...options, unmetState: 'evidence-incomplete', unmetReason: 'volume-label-current-name-unreported' })
    const { maximum, bytes } = volumeLabelLimits(device.media?.filesystem)
    const label = document.createElement('label')
    label.className = 'utility-select-label'
    label.textContent = t('utilities.volumeLabel.newLabel')
    const input = document.createElement('input')
    input.type = 'text'
    input.dataset.utilityVolumeLabel = ''
    input.dataset.currentValue = current ?? ''
    // Discovery revisions change during polling; only cartridge, filesystem or
    // authoritative name changes invalidate an unfinished local name draft.
    input.dataset.labelBinding = JSON.stringify([device.id, device.media?.id, device.media?.filesystem, current])
    input.dataset.labelAvailable = String(capability.state === 'available' && typeof current === 'string')
    input.dataset.focusKey = 'utilities:volume-label:input'
    input.maxLength = maximum
    if (bytes) input.dataset.labelByteLimit = String(bytes)
    input.value = current ?? ''
    input.disabled = input.dataset.labelAvailable !== 'true'
    label.append(input)
    card.append(label, paragraph(document, t('utilities.volumeLabel.guidance', { maximum }), 'utility-guidance'))
    const workflow = {
        kind: 'volume-label-set',
        capability,
        prerequisites: [],
        stages: utilityStages([
            ['host-volume-changing', 'utilities.stage.hostVolumeChanging'],
            ['host-volume-readback', 'utilities.stage.hostVolumeReadback']
        ])
    }
    appendWorkflowState(card, workflow, device, [workflow.kind], options)
    describeUtilityButton(card, input)
    card.append(describeUtilityButton(card, utilityButton(document, { action: 'set-volume-label', kind: workflow.kind, label: t('utilities.volumeLabel.action'), disabled: true, reason: translateUtilityReason(capability.reason, t) })))
    return card
}

/** Renders the exact serial-specific drive-letter preference. @param {Document} document - DOM. @param {object} device - Selected device. @param {object} options - View state. @returns {HTMLElement} Utility card. */
function renderDriveLetterCard(document, device, options) {
    const workflow = createDriveLetterWorkflow(device, { ...options, availableLetters: device?.drive?.availableDriveLetters ?? options.availableDriveLetters, platform: options.platform })
    const card = utilityCard(document, 'drive-letter', 'ph-letter-circle-p', 'utilities.driveLetter.eyebrow', 'utilities.driveLetter.title', 'utilities.driveLetter.description', options.translator)
    card.append(paragraph(document, options.translator(workflow.guidanceKey), 'utility-guidance'), renderPrerequisites(document, workflow.prerequisites, options.translator))
    const label = document.createElement('label')
    label.className = 'utility-select-label'
    label.textContent = options.translator('utilities.driveLetter.availableLabel')
    const select = document.createElement('select')
    select.dataset.utilityDriveLetter = ''
    if (workflow.availableLetters.length === 0) {
        const option = document.createElement('option')
        option.textContent = options.translator('utilities.driveLetter.noneAvailable')
        option.value = ''
        select.append(option)
    } else {
        for (const letter of workflow.availableLetters) {
            const option = document.createElement('option')
            option.value = letter
            option.textContent = `${letter}:`
            select.append(option)
        }
    }
    label.append(select)
    card.append(label)
    appendWorkflowState(card, workflow, device, [workflow.kind, workflow.resetKind], options)
    const resetReadiness = paragraph(document, workflow.resetCapability.state === 'available' ? options.translator('utilities.driveLetter.resetReady') : options.translator('utilities.driveLetter.resetUnavailable', { reason: translateUtilityReason(workflow.resetCapability.reason, options.translator) }), 'utility-action-readiness')
    resetReadiness.id = 'utility-reset-drive-letter-readiness'
    const actions = document.createElement('div')
    actions.className = 'utility-actions utility-actions--inline'
    const resetButton = utilityButton(document, {
        action: 'reset-drive-letter',
        disabled: workflow.resetCapability.state !== 'available',
        kind: workflow.resetKind,
        label: options.translator('utilities.driveLetter.resetAction'),
        reason: translateUtilityReason(workflow.resetCapability.reason, options.translator)
    })
    resetButton.setAttribute('aria-describedby', resetReadiness.id)
    actions.append(
        describeUtilityButton(
            card,
            utilityButton(document, {
                action: 'set-drive-letter',
                disabled: workflow.setCapability.state !== 'available',
                kind: workflow.kind,
                label: options.translator('utilities.driveLetter.setAction'),
                reason: translateUtilityReason(workflow.setCapability.reason, options.translator)
            })
        ),
        resetButton
    )
    card.append(resetReadiness, actions)
    return card
}

/**
 * Renders the complete Utilities workspace and every documented utility card.
 * @param {object} device - Selected renderer-safe RDX device.
 * @param {{document?: Document, translator?: (key: string, params?: object) => string, activeOperation?: object|null, lastOperation?: object|null, locked?: boolean, operationIntentAvailable?: boolean, provenance?: string, availableDriveLetters?: string[], currentSataMode?: string, platform?: string}} [options={}] - DOM, shell, and host presentation facts.
 * @returns {HTMLElement} Complete Utilities workspace.
 */
export function renderUtilitiesView(device, options = {}) {
    const { document, translator } = getComponentContext(options)
    const effectiveOptions = {
        ...options,
        locked: options.locked === true || (options.activeOperation !== null && options.activeOperation !== undefined),
        operationIntentAvailable: options.operationIntentAvailable !== false,
        translator
    }
    const view = document.createElement('section')
    view.className = 'utilities-workspace'
    view.dataset.utilitiesView = ''
    const header = document.createElement('header')
    header.className = 'utilities-workspace__header'
    const title = document.createElement('div')
    title.append(createComponentIcon(document, 'ph-wrench', 'ph-duotone'))
    const copy = document.createElement('div')
    const eyebrow = document.createElement('span')
    eyebrow.className = 'eyebrow'
    eyebrow.textContent = translator('utilities.eyebrow')
    const heading = document.createElement('h2')
    heading.textContent = translator('utilities.title')
    copy.append(eyebrow, heading, paragraph(document, translator('utilities.description'), 'utilities-workspace__description'))
    title.append(copy)
    const identity = paragraph(document, `${device?.product ?? translator('utilities.unknownDevice')} · ${device?.serial ?? translator('utilities.identityUnavailable')}`, 'utilities-device-identity')
    identity.prepend(createComponentIcon(document, 'ph-hard-drives', 'ph-duotone'))
    header.append(title, identity)
    view.append(header)
    if (effectiveOptions.locked) {
        view.append(
            renderOperationLockBanner(
                {
                    operationLabel: translateUtilityKind(options.activeOperation?.kind, translator),
                    stageLabel: translateUtilityStage(options.activeOperation?.stage, translator)
                },
                { document, translator }
            )
        )
    }
    const grid = document.createElement('div')
    grid.className = 'utilities-grid'
    grid.append(renderFirmwareCard(document, device, effectiveOptions), renderEjectCard(document, device, effectiveOptions), renderDriveModeCard(document, device, effectiveOptions), renderSataModeCard(document, device, effectiveOptions), renderDriveLetterCard(document, device, effectiveOptions), renderVolumeLabelCard(document, device, effectiveOptions), renderFormatCard(document, device, effectiveOptions))
    const manufacturingCard = renderManufacturingView(document, options.manufacturing, translator)
    if (manufacturingCard !== null) grid.insertBefore(manufacturingCard, grid.children[1])
    view.append(grid)
    const feedback = paragraph(document, '', 'utility-feedback')
    feedback.dataset.utilityFeedback = ''
    feedback.setAttribute('role', 'status')
    feedback.setAttribute('aria-live', 'polite')
    view.append(feedback)
    if (options.provenance === 'fixture') {
        const note = paragraph(document, translator('utilities.fixtureNote'), 'utilities-hardware-note')
        note.prepend(createComponentIcon(document, 'ph-warning-circle', 'ph-duotone'))
        view.append(note)
    }
    return view
}
