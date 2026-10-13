// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Preserve startup failure status through the application's guarded quit lifecycle. */
export class StartupFailureExitController {
    #app
    #failed = false
    #getShutdownPolicy

    /**
     * @param {{app: {quit: Function, exit: Function}, getShutdownPolicy: Function}} options - Electron lifecycle and current ownership policy.
     * @throws {TypeError} When lifecycle methods or policy lookup are unavailable.
     */
    constructor(options) {
        if (typeof options?.app?.quit !== 'function' || typeof options?.app?.exit !== 'function' || typeof options?.getShutdownPolicy !== 'function') throw new TypeError('Startup failure exit configuration is invalid')
        this.#app = options.app
        this.#getShutdownPolicy = options.getShutdownPolicy
    }

    /** Record a failure and request normal guarded shutdown. @returns {void} */
    requestFailure() {
        this.#failed = true
        this.#app.quit()
    }

    /**
     * Completes only an already approved failed quit, retaining unknown ownership.
     * @param {{preventDefault: Function}} event - Electron's final quit event.
     * @returns {void} Leaves normal exits unchanged.
     */
    handleWillQuit(event) {
        if (!this.#failed) return
        // before-quit and the shutdown controller already ran. Recheck current
        // ownership before replacing Electron's default successful exit status.
        event.preventDefault()
        let allowed = false
        try {
            allowed = this.#getShutdownPolicy()?.allowed === true
        } catch {
            // Unknown ownership may not become permission to abandon work.
        }
        if (allowed) this.#app.exit(1)
    }
}
