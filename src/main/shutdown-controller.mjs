// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { setTimeout as delay } from 'node:timers/promises'

/** Coordinates operation-safe, bounded, idempotent Electron shutdown. */
export class ShutdownController {
    #app
    #coordinator
    #reentering = false
    #runtime
    #shutdownPromise = null
    #timeoutMs

    /**
     * @param {{app: {quit: Function}, coordinator: {getShutdownPolicy: Function, beginShutdown?: Function}, runtime: {stop: Function}, timeoutMs?: number}} options - Owned shutdown dependencies.
     * @throws {TypeError} When dependencies or bounds are invalid.
     */
    constructor(options) {
        const timeoutMs = options?.timeoutMs ?? 3_000
        if (typeof options?.app?.quit !== 'function' || typeof options?.coordinator?.getShutdownPolicy !== 'function' || typeof options?.runtime?.stop !== 'function' || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10_000) {
            throw new TypeError('ShutdownController configuration is invalid')
        }
        this.#app = options.app
        this.#coordinator = options.coordinator
        this.#runtime = options.runtime
        this.#timeoutMs = timeoutMs
    }

    /**
     * Prevents the first quit, guards active work, and begins bounded teardown.
     * @param {{preventDefault: Function}} event - Electron before-quit event.
     * @returns {void} Completes after synchronously applying the quit guard.
     */
    handleBeforeQuit(event) {
        if (this.#reentering) return
        event.preventDefault()
        if (this.#shutdownPromise !== null || !this.#isShutdownAllowed()) return
        // Main admission must close before MCP or service teardown can yield.
        if (typeof this.#coordinator.beginShutdown === 'function' && this.#coordinator.beginShutdown() !== true) return
        this.#shutdownPromise = this.#shutdown()
    }

    /**
     * Prevents a renderer window from closing while a global operation is owned.
     * @param {{preventDefault: Function}} event - Electron close event.
     * @returns {void} Completes after synchronous policy evaluation.
     */
    handleWindowClose(event) {
        if (!this.#isShutdownAllowed()) {
            event.preventDefault()
        }
    }

    /** @returns {boolean} True only when coordinator policy is available and affirmative. */
    #isShutdownAllowed() {
        try {
            return this.#coordinator.getShutdownPolicy().allowed === true
        } catch {
            return false
        }
    }

    /** @returns {Promise<void>} Resolves after current teardown or immediately when none began. */
    async waitForShutdown() {
        await this.#shutdownPromise
    }

    /** @returns {Promise<void>} Resolves after bounded runtime stop and safe quit re-entry. */
    async #shutdown() {
        const timeoutController = new AbortController()

        /** @returns {Promise<void>} Stops after the shared shutdown promise is published and contains late failures. */
        const stopRuntime = async () => {
            // A synchronous stop may reenter before-quit; publish its owner first.
            await Promise.resolve()
            try {
                await this.#runtime.stop()
            } catch {
                // Teardown failure cannot prevent the already approved exit.
            }
        }

        const timeoutPromise = delay(this.#timeoutMs, undefined, { signal: timeoutController.signal })
        try {
            await Promise.race([stopRuntime(), timeoutPromise])
        } finally {
            timeoutController.abort()
            this.#reentering = true
            this.#app.quit()
        }
    }
}
