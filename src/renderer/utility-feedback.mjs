// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

// These published admission codes distinguish actionable failures currently
// covered only by generic catalog copy. Arbitrary service strings stay hidden.
const ADMISSION_CODES = new Set(['invalid-operation-request', 'invalid-request', 'operation-in-progress', 'stale-device-revision', 'device-not-found', 'privileged-service-unavailable', 'insufficient-permission', 'volume-busy', 'native-operation-failed', 'confirmation-required', 'confirmation-expired', 'confirmation-mismatch', 'confirmation-unavailable', 'hardware-unavailable', 'transport-unavailable', 'unsupported-platform', 'manufacturing-in-progress', 'operation-outcome-unknown'])

/** Retains path-free utility admission feedback through renderer refreshes. */
export class UtilityFeedback {
    #root
    #translator
    #translateReason
    #current = null

    /** @param {HTMLElement} root - Application shell. @param {Function} translator - Live catalog translator. @param {Function} translateReason - Closed reason-to-copy resolver. */
    constructor(root, translator, translateReason) {
        this.#root = root
        this.#translator = translator
        this.#translateReason = translateReason
    }

    /** @param {object} device - Exact selected dock and cartridge. @param {string} [kind] - Submitted utility kind. @returns {object} Private presentation ticket with no password, path, or confirmation token. */
    begin(device, kind) {
        this.#current = { deviceId: device.id, mediaId: device.media?.id, kind, pending: true }
        this.sync(device)
        return this.#current
    }

    /** @param {object} ticket - Original submission ticket. @param {object} result - Admission response. @param {object|null} device - Current selection. @returns {void} Keeps one latest outcome, excluding arbitrary native text. */
    complete(ticket, result, device) {
        if (this.#current !== ticket) return
        ticket.pending = false
        ticket.ok = result?.ok === true
        ticket.operationId = result?.operationId
        ticket.reason = typeof result?.reason === 'string' && /^[a-z][a-z0-9-]{0,127}$/.test(result.reason) ? result.reason : 'service-failure'
        this.sync(device)
    }

    /** @param {object|null} device - Current selected dock/cartridge. @returns {void} Restores localized feedback after a render and discards it on a target change. */
    sync(device) {
        if (this.#current !== null && (this.#current.deviceId !== device?.id || this.#current.mediaId !== device?.media?.id)) this.#current = null
        const feedback = this.#root.querySelector('[data-utility-feedback]')
        if (feedback === null) return
        const t = this.#translator
        const current = this.#current
        const failed = current !== null && !current.pending && current.ok === false
        feedback.dataset.feedbackState = current === null ? 'empty' : current.pending ? 'pending' : failed ? 'failed' : 'accepted'
        feedback.setAttribute('role', failed ? 'alert' : 'status')
        feedback.setAttribute('aria-live', failed ? 'assertive' : 'polite')
        // Keep chooser and admission feedback beside the action the user clicked.
        // A background render recreates the status node; reattach it each time.
        const action = [...this.#root.querySelectorAll('[data-utility-operation]')].find((button) => button.dataset.utilityOperation === current?.kind)
        const card = action?.closest('[data-feature]')
        if (card && feedback.parentElement !== card) card.append(feedback)
        if (current === null) feedback.textContent = ''
        else if (current.pending) feedback.textContent = t('utilities.feedback.submitting', { operation: t(current.kind === 'firmware-update' ? 'utilities.operation.firmwareUpdate' : 'utilities.operation.generic') })
        else if (current.ok) feedback.textContent = t('utilities.feedback.accepted', { operationId: current.operationId })
        else {
            const reason = this.#translateReason(current.reason, t)
            const message = t('utilities.feedback.failed', { reason })
            feedback.textContent = ADMISSION_CODES.has(current.reason) && reason === t('reason.generic') ? t('intent.reason', { message, code: current.reason }) : message
        }
    }
}
