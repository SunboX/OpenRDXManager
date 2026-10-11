// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Owns the readable success banner without changing accepted operation history. */
export class OperationSuccessFeedback {
    #operationId = null
    #timer = null
    #visible = false
    #root
    #remainingMs = 8_000
    #startedAt = 0
    #destroyed = false

    /**
     * Watches the mounted document's visibility and native window focus.
     * @param {HTMLElement} root - Application mount containing the success banner.
     */
    constructor(root) {
        this.#root = root
        root.ownerDocument.addEventListener('visibilitychange', this.syncVisibility)
        root.ownerDocument.defaultView.addEventListener('focus', this.syncVisibility)
        root.ownerDocument.defaultView.addEventListener('blur', this.syncVisibility)
    }

    /** @returns {boolean} Whether the current success is still within its display period. */
    get visible() {
        return this.#visible
    }

    /**
     * Prepares one eight-second display period per successful operation.
     * Rendering and foreground visibility determine when that period can run.
     * @param {object} state - Current immutable renderer state.
     * @returns {void} Updates only local presentation and its pending timeout.
     */
    observe(state) {
        const operation = state.lastOperation
        const operationId = state.activeOperation === null && operation?.status === 'succeeded' ? operation.id : null
        if (operationId === this.#operationId) return

        this.#pause()
        this.#operationId = operationId
        this.#visible = operationId !== null
        this.#remainingMs = 8_000
    }

    /**
     * Counts only time when the banner is mounted in the foreground window.
     * Called after rendering and on host focus/visibility changes, so reconnect
     * screens and time away from the app cannot consume an unseen confirmation.
     * @returns {void} Starts, retains, or pauses the current display deadline.
     */
    syncVisibility = () => {
        if (this.#destroyed) return
        const document = this.#root.ownerDocument
        if (!this.#visible || document.visibilityState !== 'visible' || !document.hasFocus() || this.#root.querySelector('[data-operation-success]') === null) {
            this.#pause()
            return
        }
        if (this.#timer !== null) return
        this.#startedAt = Date.now()
        this.#timer = setTimeout(this.#expire, this.#remainingMs)
    }

    /** @returns {void} Retains the unused display time without changing operation history. */
    #pause() {
        if (this.#timer === null) return
        clearTimeout(this.#timer)
        this.#timer = null
        this.#remainingMs = Math.max(0, this.#remainingMs - (Date.now() - this.#startedAt))
    }

    /** @returns {void} Removes expired feedback while preserving live form input and focus. */
    #expire = () => {
        this.#timer = null
        this.#visible = false
        this.#root.querySelector('[data-operation-success]')?.remove()
    }

    /** @returns {void} Cancels pending presentation work when the renderer unmounts. */
    destroy() {
        this.#destroyed = true
        this.#pause()
        this.#root.ownerDocument.removeEventListener('visibilitychange', this.syncVisibility)
        this.#root.ownerDocument.defaultView.removeEventListener('focus', this.syncVisibility)
        this.#root.ownerDocument.defaultView.removeEventListener('blur', this.syncVisibility)
    }
}
