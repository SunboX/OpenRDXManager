// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createComponentIcon, createComponentId, getComponentContext, renderCapabilityState, resolveComponentText } from './capability-state.mjs'
import { renderProgressTimeline } from './progress-timeline.mjs'
import { renderOperationResult } from './result-panel.mjs'
import { RiskClass } from '../../shared/contracts.mjs'

const riskLabelKeys = Object.freeze({
    [RiskClass.READ_ONLY]: 'token.readOnly',
    [RiskClass.ROUTINE]: 'token.routine',
    [RiskClass.CONFIGURATION]: 'token.configuration',
    [RiskClass.CRITICAL]: 'token.critical',
    [RiskClass.DESTRUCTIVE]: 'token.destructive'
})

/**
 * Resolves an operation risk through the shared cross-process enum.
 * @param {unknown} candidate - Candidate renderer model risk.
 * @returns {string} Known risk, defaulting fail-closed to routine presentation.
 */
function resolveRiskClass(candidate) {
    return typeof candidate === 'string' && Object.hasOwn(riskLabelKeys, candidate) ? candidate : RiskClass.ROUTINE
}

/**
 * Resolves a caller-scoped lock description ID without claiming the shell's
 * global `operation-lock-reason` identifier.
 * @param {unknown} candidate - Optional caller-owned DOM identifier.
 * @returns {string} Caller ID when valid, otherwise a generated component ID.
 */
function resolveLockReasonId(candidate) {
    return typeof candidate === 'string' && /^[A-Za-z][A-Za-z0-9_-]{0,127}$/.test(candidate) ? candidate : createComponentId('operation-lock-reason')
}

/**
 * Renders the persistent one-operation lock reason used by all conflicting
 * controls through the returned caller-scoped identifier.
 * @param {{operationLabel?: string, stageLabel?: string, reasonId?: string}} model - Current operation lock copy and optional unique ID.
 * @param {{document?: Document, translator?: (key: string, params?: object) => string}} [options={}] - Component dependencies.
 * @returns {HTMLElement} Accessible lock banner.
 */
export function renderOperationLockBanner(model, options = {}) {
    const { document, translator } = getComponentContext(options)
    const banner = document.createElement('aside')
    banner.className = 'operation-lock-banner'
    banner.dataset.operationLock = ''
    banner.id = resolveLockReasonId(model?.reasonId)
    banner.setAttribute('role', 'status')
    banner.setAttribute('aria-live', 'polite')
    banner.append(createComponentIcon(document, 'ph-lock-key', 'ph-duotone'))
    const copy = document.createElement('div')
    const title = document.createElement('strong')
    title.textContent = translator('operation.lockBannerTitle', { operation: model?.operationLabel ?? translator('operation.unknown') })
    const description = document.createElement('p')
    description.textContent = translator('operation.lockBannerDescription', { stage: model?.stageLabel ?? translator('operation.startingStage') })
    copy.append(title, description)
    banner.append(copy)
    return banner
}

/**
 * Renders a focused workflow drawer. The caller retains ownership of lifecycle
 * state; the component only emits close requests when that state is safe.
 * @param {{title?: string, titleKey?: string, description?: string, descriptionKey?: string, risk?: 'read-only'|'routine'|'configuration'|'critical'|'destructive', deviceIdentity?: string, closeSafe?: boolean, capability?: object, activeOperation?: {kindLabel?: string, stage?: string, stageLabel?: string, lockReasonId?: string, stages?: Array<object>, progress?: number, terminalStatus?: string}, result?: object}} model - Operation workflow presentation.
 * @param {{document?: Document, translator?: (key: string, params?: object) => string, onClose?: (event: Event) => void, onCapabilityAction?: (event: Event) => void, onCapabilityHelp?: (event: Event) => void, onResultAction?: (event: Event) => void, onResultHelp?: (event: Event) => void}} [options={}] - DOM, translation, and handlers.
 * @returns {HTMLElement} Accessible operation drawer.
 */
export function renderOperationDrawer(model, options = {}) {
    const { document, translator } = getComponentContext(options)
    const titleId = createComponentId('operation-drawer-title')
    const descriptionId = createComponentId('operation-drawer-description')
    const risk = resolveRiskClass(model?.risk)
    const drawer = document.createElement('aside')
    drawer.className = 'operation-drawer'
    drawer.dataset.operationDrawer = ''
    drawer.dataset.risk = risk
    drawer.setAttribute('role', 'dialog')
    drawer.setAttribute('aria-modal', 'false')
    drawer.setAttribute('aria-labelledby', titleId)
    drawer.setAttribute('aria-describedby', descriptionId)
    drawer.tabIndex = -1

    const header = document.createElement('header')
    header.className = 'operation-drawer__header'
    const titleGroup = document.createElement('div')
    const eyebrow = document.createElement('span')
    eyebrow.className = 'eyebrow'
    eyebrow.textContent = translator(riskLabelKeys[risk])
    const title = document.createElement('h2')
    title.id = titleId
    title.textContent = resolveComponentText(model, 'title', 'titleKey', translator, 'operation.workflowTitle')
    titleGroup.append(eyebrow, title)
    header.append(titleGroup)
    if (model?.closeSafe === true) {
        const close = document.createElement('button')
        close.className = 'icon-button operation-drawer__close'
        close.type = 'button'
        close.dataset.drawerClose = ''
        close.setAttribute('aria-label', translator('operation.closeWorkflow'))
        close.append(createComponentIcon(document, 'ph-x'))
        if (typeof options.onClose === 'function') close.addEventListener('click', options.onClose)
        header.append(close)
    }
    drawer.append(header)

    const description = document.createElement('p')
    description.className = 'operation-drawer__description'
    description.id = descriptionId
    description.textContent = resolveComponentText(model, 'description', 'descriptionKey', translator, 'operation.workflowDescription')
    drawer.append(description)
    if (typeof model?.deviceIdentity === 'string') {
        const identity = document.createElement('p')
        identity.className = 'operation-drawer__identity'
        identity.append(createComponentIcon(document, 'ph-hard-drives', 'ph-duotone'))
        identity.append(document.createTextNode(model.deviceIdentity))
        drawer.append(identity)
    }

    if (model?.capability !== undefined) {
        drawer.append(
            renderCapabilityState(model.capability, {
                document,
                onAction: options.onCapabilityAction,
                onHelp: options.onCapabilityHelp,
                translator
            })
        )
    }

    if (model?.activeOperation !== undefined) {
        drawer.append(
            renderOperationLockBanner(
                {
                    operationLabel: model.activeOperation.kindLabel ?? title.textContent,
                    reasonId: model.activeOperation.lockReasonId,
                    stageLabel: model.activeOperation.stageLabel ?? model.activeOperation.stage
                },
                { document, translator }
            )
        )
        if (Array.isArray(model.activeOperation.stages) && model.activeOperation.stages.length > 0) {
            drawer.append(
                renderProgressTimeline(
                    {
                        activeStage: model.activeOperation.stage,
                        progress: model.activeOperation.progress,
                        stages: model.activeOperation.stages,
                        terminalStatus: model.activeOperation.terminalStatus
                    },
                    { document, translator }
                )
            )
        }
    }
    if (model?.result !== undefined) {
        drawer.append(renderOperationResult(model.result, { document, onAction: options.onResultAction, onHelp: options.onResultHelp, translator }))
    }

    /**
     * Emits Escape as a close request only when the caller's latest model marks
     * dismissal safe; an active irreversible workflow therefore stays visible.
     * @param {KeyboardEvent} event - Drawer keyboard event.
     * @returns {void} Completes after an optional close request.
     */
    function handleKeyDown(event) {
        if (event.key !== 'Escape' || model?.closeSafe !== true || typeof options.onClose !== 'function') return
        event.preventDefault()
        options.onClose(event)
    }
    drawer.addEventListener('keydown', handleKeyDown)
    return drawer
}
