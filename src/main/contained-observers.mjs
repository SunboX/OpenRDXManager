// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Publishes in subscription order, contains thrown observers, and stops at an
 * explicit synchronous or asynchronous `false` protocol rejection.
 * @param {Set<Function>} listeners - Current observer set.
 * @param {object} value - Frozen lifecycle or event value.
 * @param {() => boolean} [isCurrent] - Optional delivery-currency guard.
 * @returns {boolean|Promise<boolean>} True after acceptance or false at rejection.
 */
export function publishContained(listeners, value, isCurrent = () => true) {
    const observers = [...listeners]

    /** @param {number} start - Next observer index. @returns {boolean|Promise<boolean>} Ordered result. */
    function publishFrom(start) {
        for (let index = start; index < observers.length; index += 1) {
            if (!isCurrent()) return false
            let result
            try {
                result = observers[index](value)
            } catch {
                continue
            }
            if (result === false) return false
            if (typeof result?.then === 'function') {
                return continuePublication(result, index + 1)
            }
        }
        return true
    }

    /** @param {PromiseLike<unknown>} pending - Suspended observer result. @param {number} next - Next observer index. @returns {Promise<boolean>} Ordered acceptance after the barrier. */
    async function continuePublication(pending, next) {
        let accepted
        try {
            accepted = await pending
        } catch {
            return false
        }
        return accepted === false || !isCurrent() ? false : publishFrom(next)
    }

    return publishFrom(0)
}

/**
 * Registers one listener in an owned set and returns an idempotent unsubscribe.
 * @param {Set<Function>} listeners - Owning listener set.
 * @param {Function} listener - Candidate listener.
 * @param {string} label - Stable validation label.
 * @returns {() => void} Idempotent unsubscribe callback.
 * @throws {TypeError} When the listener is not callable.
 */
export function subscribeContained(listeners, listener, label) {
    if (typeof listener !== 'function') throw new TypeError(`${label} listener must be a function`)
    listeners.add(listener)
    let subscribed = true

    /** @returns {void} Removes this exact listener once. */
    function unsubscribe() {
        if (!subscribed) return
        subscribed = false
        listeners.delete(listener)
    }
    return unsubscribe
}

/**
 * Recursively freezes renderer-safe lifecycle and event data.
 * @template T
 * @param {T} value - Data-only value.
 * @returns {T} Deeply frozen value.
 */
export function deepFreeze(value) {
    if (value === null || typeof value !== 'object' || Object.isFrozen(value)) {
        return value
    }
    for (const nestedValue of Object.values(value)) {
        deepFreeze(nestedValue)
    }
    return Object.freeze(value)
}
