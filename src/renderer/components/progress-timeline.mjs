// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createComponentIcon, getComponentContext } from './capability-state.mjs'

/**
 * Clamps a candidate normalized progress value without coercing objects.
 * @param {unknown} value - Candidate progress value.
 * @returns {number|null} Normalized progress or null when not reported.
 */
function normalizeProgress(value) {
    if (typeof value !== 'number' || !Number.isFinite(value)) return null
    return Math.min(1, Math.max(0, value))
}

/**
 * Renders a semantic operation timeline with one restrained atomic live update.
 * @param {{stages: Array<{id: string, label?: string, labelKey?: string}>, activeStage?: string, progress?: number, terminalStatus?: 'succeeded'|'failed'|'cancelled'}} model - Renderer-safe progress model.
 * @param {{document?: Document, translator?: (key: string, params?: object) => string}} [options={}] - Component dependencies.
 * @returns {HTMLElement} Accessible timeline with one isolated live summary.
 * @throws {TypeError} When no stable stage list is supplied.
 */
export function renderProgressTimeline(model, options = {}) {
    const { document, translator } = getComponentContext(options)
    if (!Array.isArray(model?.stages) || model.stages.length === 0) {
        throw new TypeError('Progress timeline requires at least one stage')
    }
    const progress = normalizeProgress(model.progress)
    const activeIndex = findActiveStageIndex(model.stages, model.activeStage)
    const timeline = document.createElement('section')
    timeline.className = 'progress-timeline'
    timeline.dataset.progressTimeline = ''

    const list = document.createElement('ol')
    list.className = 'progress-timeline__steps'
    for (let index = 0; index < model.stages.length; index += 1) {
        const stage = model.stages[index]
        const state = getStageState(model, index, activeIndex)
        const item = document.createElement('li')
        item.className = `progress-timeline__stage progress-timeline__stage--${state}`
        item.dataset.progressStage = stage.id
        item.dataset.stageState = state
        if (state === 'active') item.setAttribute('aria-current', 'step')
        item.append(createComponentIcon(document, getStageIcon(state), state === 'complete' ? 'ph-fill' : 'ph'))
        const label = document.createElement('span')
        label.textContent = typeof stage.label === 'string' ? stage.label : typeof stage.labelKey === 'string' ? translator(stage.labelKey) : stage.id
        item.append(label)
        list.append(item)
    }
    timeline.append(list)

    if (progress !== null) {
        const progressElement = document.createElement('progress')
        progressElement.max = 1
        progressElement.value = progress
        progressElement.setAttribute('aria-label', translator('operation.progressLabel'))
        timeline.append(progressElement)
    }

    const activeStage = activeIndex >= 0 ? model.stages[activeIndex] : model.stages.at(-1)
    const activeLabel = typeof activeStage.label === 'string' ? activeStage.label : typeof activeStage.labelKey === 'string' ? translator(activeStage.labelKey) : activeStage.id
    const announcement = document.createElement('span')
    announcement.className = 'progress-timeline__announcement'
    announcement.dataset.progressAnnouncement = ''
    announcement.setAttribute('role', 'status')
    announcement.setAttribute('aria-live', 'polite')
    announcement.setAttribute('aria-atomic', 'true')
    announcement.textContent = progress === null ? translator('operation.progressAnnouncementStage', { stage: activeLabel }) : translator('operation.progressAnnouncement', { stage: activeLabel, percent: Math.round(progress * 100) })
    timeline.append(announcement)
    return timeline
}

/**
 * Finds the active stage without an undocumented collection callback.
 * @param {Array<{id: string}>} stages - Ordered operation stages.
 * @param {unknown} activeStage - Candidate active identifier.
 * @returns {number} Matching stage index or -1.
 */
function findActiveStageIndex(stages, activeStage) {
    for (let index = 0; index < stages.length; index += 1) {
        if (stages[index]?.id === activeStage) return index
    }
    return -1
}

/**
 * Computes one stage's stable state from the active and terminal positions.
 * @param {object} model - Complete timeline model.
 * @param {number} index - Current stage index.
 * @param {number} activeIndex - Active stage index, or -1.
 * @returns {'complete'|'active'|'pending'|'failed'|'cancelled'} Visible stage state.
 */
function getStageState(model, index, activeIndex) {
    if (activeIndex < 0) return model.terminalStatus === 'succeeded' ? 'complete' : 'pending'
    if (index < activeIndex) return 'complete'
    if (index > activeIndex) return 'pending'
    if (model.terminalStatus === 'failed') return 'failed'
    if (model.terminalStatus === 'cancelled') return 'cancelled'
    if (model.terminalStatus === 'succeeded') return 'complete'
    return 'active'
}

/**
 * Maps one progress stage state to a bundled Phosphor icon.
 * @param {string} state - Stable stage state.
 * @returns {string} Bundled icon class.
 */
function getStageIcon(state) {
    if (state === 'complete') return 'ph-check-circle'
    if (state === 'active') return 'ph-circle-notch'
    if (state === 'failed') return 'ph-x-circle'
    if (state === 'cancelled') return 'ph-minus-circle'
    return 'ph-circle'
}
