// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createComponentIcon, createComponentId, getComponentContext } from './capability-state.mjs'

/**
 * Returns tabbable dialog controls in DOM order.
 * @param {HTMLElement} dialog - Dialog whose focus must remain contained.
 * @returns {HTMLElement[]} Enabled focus targets.
 */
function getFocusableControls(dialog) {
    const controls = []
    for (const candidate of dialog.querySelectorAll('button:not([disabled]), input:not([disabled]), [href], [tabindex]:not([tabindex="-1"])')) {
        if (candidate.getAttribute('aria-hidden') !== 'true') controls.push(candidate)
    }
    return controls
}

/**
 * Opens a local exact-identity confirmation dialog and returns its bounded
 * controller. Text comparison is deliberately byte-exact: no trim, case fold,
 * or numeric coercion can confirm a different cartridge.
 * @param {{risk: 'critical'|'destructive'|string, expected: string, operationLabel?: string, deviceLabel?: string}} model - Exact visible confirmation model.
 * @param {{document?: Document, translator?: (key: string, params?: object) => string, container?: HTMLElement, escapeSafe?: boolean}} [options={}] - DOM, translation, mounting, and dismissal policy.
 * @returns {{element: HTMLElement, input: HTMLInputElement, confirmButton: HTMLButtonElement, cancelButton: HTMLButtonElement|null, closed: Promise<object>, close: (reason?: string) => void}} Dialog controller.
 * @throws {TypeError} When the expected identity is empty or unbounded.
 */
export function requestExactDeviceConfirmation(model, options = {}) {
    const { document, translator } = getComponentContext(options)
    if (typeof model?.expected !== 'string' || model.expected.length === 0 || model.expected.length > 256) {
        throw new TypeError('Exact-device confirmation requires a bounded identity')
    }
    const escapeSafe = options.escapeSafe !== false
    const container = options.container ?? document.body
    if (container === null || typeof container?.append !== 'function') {
        throw new TypeError('Exact-device confirmation requires a mount container')
    }
    const previouslyFocused = document.activeElement
    const titleId = createComponentId('exact-device-title')
    const descriptionId = createComponentId('exact-device-description')
    const expectedId = createComponentId('exact-device-expected')
    const mismatchId = createComponentId('exact-device-mismatch')
    const inputId = createComponentId('exact-device-input')
    const overlay = document.createElement('div')
    overlay.className = 'confirmation-overlay'
    overlay.dataset.exactDeviceConfirmation = ''
    const dialog = document.createElement('section')
    dialog.className = `confirmation-dialog confirmation-dialog--${model.risk === 'destructive' ? 'destructive' : 'critical'}`
    dialog.setAttribute('role', 'alertdialog')
    dialog.setAttribute('aria-modal', 'true')
    dialog.setAttribute('aria-labelledby', titleId)
    dialog.setAttribute('aria-describedby', descriptionId)

    const icon = document.createElement('span')
    icon.className = 'confirmation-dialog__icon'
    icon.append(createComponentIcon(document, model.risk === 'destructive' ? 'ph-warning-octagon' : 'ph-warning', 'ph-duotone'))
    dialog.append(icon)
    const title = document.createElement('h2')
    title.id = titleId
    title.textContent = translator(model.risk === 'destructive' ? 'operation.confirmDestructiveTitle' : 'operation.confirmCriticalTitle')
    dialog.append(title)
    const description = document.createElement('p')
    description.id = descriptionId
    description.textContent = translator('operation.confirmExactIdentity', { operation: model.operationLabel ?? translator('operation.unknown') })
    dialog.append(description)
    if (typeof model.deviceLabel === 'string') {
        const device = document.createElement('p')
        device.className = 'confirmation-dialog__device'
        device.append(createComponentIcon(document, 'ph-hard-drives'))
        device.append(document.createTextNode(model.deviceLabel))
        dialog.append(device)
    }
    const expected = document.createElement('output')
    expected.className = 'confirmation-dialog__expected'
    expected.id = expectedId
    expected.htmlFor = inputId
    expected.textContent = model.expected
    dialog.append(expected)
    const label = document.createElement('label')
    label.htmlFor = inputId
    label.textContent = translator('operation.typeExactIdentity')
    dialog.append(label)
    const input = document.createElement('input')
    input.id = inputId
    input.type = 'text'
    input.autocomplete = 'off'
    input.spellcheck = false
    input.setAttribute('autocapitalize', 'off')
    input.setAttribute('aria-describedby', `${descriptionId} ${expectedId} ${mismatchId}`)
    input.setAttribute('aria-invalid', 'false')
    dialog.append(input)
    const mismatch = document.createElement('p')
    mismatch.className = 'confirmation-dialog__feedback'
    mismatch.id = mismatchId
    mismatch.dataset.confirmationMismatch = ''
    mismatch.dataset.matchState = 'required'
    mismatch.setAttribute('role', 'status')
    mismatch.setAttribute('aria-live', 'polite')
    mismatch.setAttribute('aria-atomic', 'true')
    mismatch.textContent = translator('operation.confirmIdentityRequired')
    dialog.append(mismatch)
    const actions = document.createElement('footer')
    actions.className = 'confirmation-dialog__actions'
    let cancelButton = null
    if (escapeSafe) {
        cancelButton = document.createElement('button')
        cancelButton.className = 'button button--secondary'
        cancelButton.type = 'button'
        cancelButton.dataset.confirmationCancel = ''
        cancelButton.append(createComponentIcon(document, 'ph-x'))
        const cancelLabel = document.createElement('span')
        cancelLabel.textContent = translator('operation.cancel')
        cancelButton.append(cancelLabel)
        actions.append(cancelButton)
    }
    const confirmButton = document.createElement('button')
    confirmButton.className = 'button button--danger'
    confirmButton.type = 'button'
    confirmButton.dataset.confirmationConfirm = ''
    confirmButton.disabled = true
    confirmButton.append(createComponentIcon(document, 'ph-check'))
    const confirmLabel = document.createElement('span')
    confirmLabel.textContent = translator('operation.confirmExact')
    confirmButton.append(confirmLabel)
    actions.append(confirmButton)
    dialog.append(actions)
    overlay.append(dialog)

    const { promise: closed, resolve: settleClosed } = Promise.withResolvers()
    let settled = false

    /** @returns {void} Updates exact-match admission and restrained visible feedback after one local edit. */
    function handleInput() {
        const matches = input.value === model.expected
        confirmButton.disabled = !matches
        input.setAttribute('aria-invalid', input.value.length > 0 && !matches ? 'true' : 'false')
        if (matches) {
            mismatch.dataset.matchState = 'match'
            mismatch.textContent = translator('operation.confirmIdentityMatch')
        } else if (input.value.length > 0) {
            mismatch.dataset.matchState = 'mismatch'
            mismatch.textContent = translator('operation.confirmIdentityMismatch')
        } else {
            mismatch.dataset.matchState = 'required'
            mismatch.textContent = translator('operation.confirmIdentityRequired')
        }
    }

    /**
     * Closes the dialog once, removes listeners, resolves its result, and
     * restores focus to the control that opened it when still usable.
     * @param {object} result - Exact terminal dialog result.
     * @returns {void} Completes after focus restoration.
     */
    function finish(result) {
        if (settled) return
        settled = true
        dialog.removeEventListener('keydown', handleKeyDown)
        input.removeEventListener('input', handleInput)
        confirmButton.removeEventListener('click', handleConfirm)
        cancelButton?.removeEventListener('click', handleCancel)
        overlay.remove()
        settleClosed(result)
        if (previouslyFocused instanceof document.defaultView.HTMLElement && previouslyFocused.isConnected && previouslyFocused.getAttribute('aria-disabled') !== 'true' && previouslyFocused.disabled !== true) {
            previouslyFocused.focus()
        }
    }

    /** @returns {void} Confirms only the currently exact input. */
    function handleConfirm() {
        if (input.value !== model.expected) return
        finish({ confirmed: true, identity: input.value })
    }

    /** @returns {void} Cancels a safely dismissible dialog. */
    function handleCancel() {
        finish({ confirmed: false, reason: 'cancel' })
    }

    /**
     * Traps Tab focus and honors Escape only while dismissal is explicitly safe.
     * @param {KeyboardEvent} event - Dialog keyboard event.
     * @returns {void} Completes after focus wrapping or safe dismissal.
     */
    function handleKeyDown(event) {
        if (event.key === 'Escape') {
            if (!escapeSafe) return
            event.preventDefault()
            finish({ confirmed: false, reason: 'escape' })
            return
        }
        if (event.key !== 'Tab') return
        const focusable = getFocusableControls(dialog)
        if (focusable.length === 0) {
            event.preventDefault()
            dialog.focus()
            return
        }
        const first = focusable[0]
        const last = focusable.at(-1)
        if (event.shiftKey && document.activeElement === first) {
            event.preventDefault()
            last.focus()
        } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault()
            first.focus()
        }
    }

    /**
     * Programmatically dismisses the dialog for caller-owned teardown.
     * @param {string} [reason='closed'] - Stable local dismissal reason.
     * @returns {void} Completes after one terminal dismissal.
     */
    function close(reason = 'closed') {
        finish({ confirmed: false, reason })
    }

    input.addEventListener('input', handleInput)
    confirmButton.addEventListener('click', handleConfirm)
    cancelButton?.addEventListener('click', handleCancel)
    dialog.addEventListener('keydown', handleKeyDown)
    container.append(overlay)
    input.focus()
    return Object.freeze({ cancelButton, close, closed, confirmButton, element: overlay, input })
}
