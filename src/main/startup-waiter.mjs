// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Owns the single shared startup waiter for one supervised launch sequence. */
export class StartupWaiter {
    #promise = null
    #resolve = null

    /** @returns {Promise<object>|null} Current shared waiter or null. */
    getPending() {
        return this.#promise
    }

    /** @returns {Promise<object>} Creates and returns a fresh shared waiter. */
    create() {
        /** @param {(state: object) => void} resolve - Captured resolver. @returns {void} Stores it. */
        const capture = (resolve) => {
            this.#resolve = resolve
        }
        this.#promise = new Promise(capture)
        return this.#promise
    }

    /** @param {object} state - First terminal startup state. @returns {void} Resolves once. */
    settle(state) {
        if (this.#resolve === null) return
        const resolve = this.#resolve
        this.#resolve = null
        this.#promise = null
        resolve(state)
    }
}
