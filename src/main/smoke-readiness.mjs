// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

const DEFAULT_TIMEOUT_MS = 15_000
const LIFECYCLE_FAILURE_CODES = Object.freeze(new Set(['smoke-renderer-destroyed', 'smoke-renderer-load-failed', 'smoke-renderer-process-gone']))

/**
 * Requires an authenticated native handshake for installed-service acceptance.
 * Zero attached devices can pass authentication; physical access is separate.
 * @param {object} readiness - Validated service readiness state.
 * @returns {void} Resolves only after a privileged native handshake.
 * @throws {Error} For unavailable, development or unprivileged service state.
 */
export function assertAuthenticatedServiceReadiness(readiness) {
    if (readiness?.status !== 'ready' || readiness.mode !== 'native' || readiness.privileged !== true) throw new Error('installed-service-authentication-unverified')
}

/**
 * Reports a bounded failure category without exposing paths or native messages.
 * @param {object} readiness - Internal service readiness snapshot.
 * @returns {string} Stable unavailable reason, or none for non-failed startup.
 */
export function getServiceReadinessFailureReason(readiness) {
    if (readiness?.status !== 'unavailable') return 'none'
    return typeof readiness.reason === 'string' && /^[a-z][a-z0-9-]{0,127}$/u.test(readiness.reason) ? readiness.reason : 'service-unavailable'
}

/**
 * Connects a smoke gate to the renderer lifecycle and removes every listener
 * as soon as readiness resolves or rejects.
 * @param {object} webContents - Electron WebContents-compatible event emitter.
 * @param {SmokeReadinessGate} gate - Smoke gate owned by the target renderer.
 * @returns {() => void} Idempotent listener cleanup function.
 */
export function attachSmokeReadinessListeners(webContents, gate) {
    let attached = true

    /** Rejects when the selected renderer is destroyed before smoke completion. @returns {void} */
    function handleDestroyed() {
        gate.fail('smoke-renderer-destroyed')
    }

    /**
     * Rejects main-frame load failures while ignoring unrelated subframes.
     * @param {object} _event - Electron event.
     * @param {number} _errorCode - Chromium load error code.
     * @param {string} _errorDescription - Chromium load error description.
     * @param {string} _validatedUrl - Failed URL.
     * @param {boolean} isMainFrame - Whether the failed navigation is the application document.
     * @returns {void}
     */
    function handleLoadFailure(_event, _errorCode, _errorDescription, _validatedUrl, isMainFrame) {
        if (isMainFrame) gate.fail('smoke-renderer-load-failed')
    }

    /** Rejects an unexpected renderer-process exit. @returns {void} */
    function handleRendererGone() {
        gate.fail('smoke-renderer-process-gone')
    }

    /** Removes every renderer lifecycle listener exactly once. @returns {void} */
    function cleanup() {
        if (!attached) return
        attached = false
        webContents.removeListener('destroyed', handleDestroyed)
        webContents.removeListener('did-fail-load', handleLoadFailure)
        webContents.removeListener('render-process-gone', handleRendererGone)
    }

    webContents.on('destroyed', handleDestroyed)
    webContents.on('did-fail-load', handleLoadFailure)
    webContents.on('render-process-gone', handleRendererGone)
    /** @returns {Promise<void>} Detaches listeners after either outcome without consuming the caller's readiness result. */
    async function detachAfterReadiness() {
        try {
            await gate.wait()
        } catch {
            // Startup owns readiness failures; this observer only owns listeners.
        } finally {
            cleanup()
        }
    }

    void detachAfterReadiness()
    return cleanup
}

/** Stable, non-sensitive failure emitted by the smoke-readiness gate. */
export class SmokeReadinessError extends Error {
    /**
     * Creates a readiness error with a machine-readable code.
     * @param {string} code - Stable readiness failure code.
     */
    constructor(code) {
        super(code)
        this.name = 'SmokeReadinessError'
        this.code = code
    }
}

/**
 * Coordinates the two independent facts required for a meaningful Electron
 * smoke result: a mounted renderer and a terminal service handshake state.
 */
export class SmokeReadinessGate {
    #cancelTimeout
    #reject
    #rendererMounted = false
    #resolve
    #scheduleTimeout
    #service = null
    #settled = false
    #timer = null
    #timeoutMs
    #value = null

    /**
     * Creates an unresolved smoke-readiness gate with an injectable bound.
     * @param {object} [options] - Timeout dependencies.
     * @param {number} [options.timeoutMs=15000] - Maximum wait in milliseconds.
     * @param {typeof setTimeout} [options.scheduleTimeout=setTimeout] - Timer scheduler.
     * @param {typeof clearTimeout} [options.cancelTimeout=clearTimeout] - Timer canceller.
     */
    constructor({ timeoutMs = DEFAULT_TIMEOUT_MS, scheduleTimeout = setTimeout, cancelTimeout = clearTimeout } = {}) {
        if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || typeof scheduleTimeout !== 'function' || typeof cancelTimeout !== 'function') {
            throw new TypeError('Smoke readiness requires a positive timeout and timer functions')
        }
        this.#timeoutMs = timeoutMs
        this.#scheduleTimeout = scheduleTimeout
        this.#cancelTimeout = cancelTimeout
        // Renderer and service events settle one promise shared by all waiters.
        const readiness = Promise.withResolvers()
        this.#resolve = readiness.resolve
        this.#reject = readiness.reject
        this.promise = readiness.promise
    }

    /**
     * Records that the application renderer mounted its shell.
     * @returns {void} Completes after attempting to settle the gate.
     */
    markRendererMounted() {
        if (this.#settled) return
        this.#rendererMounted = true
        this.#settle()
    }

    /**
     * Records only a well-formed terminal service state. Unexpected pending or
     * malformed values fail the smoke run immediately.
     * @param {object} readiness - Service startup result.
     * @returns {boolean} True when the supplied result was terminal and valid.
     */
    markServiceTerminal(readiness) {
        if (this.#settled) return false
        if (readiness?.status === 'ready' && typeof readiness.mode === 'string' && typeof readiness.hardwareReady === 'boolean') {
            this.#service = Object.freeze({
                status: 'ready',
                mode: readiness.mode,
                hardwareReady: readiness.hardwareReady
            })
        } else if (readiness?.status === 'unavailable' && typeof readiness.reason === 'string' && readiness.reason.length > 0) {
            this.#service = Object.freeze({
                status: 'unavailable',
                reason: readiness.reason
            })
        } else {
            this.#failWithCode('smoke-service-not-terminal')
            return false
        }
        this.#settle()
        return true
    }

    /**
     * Rejects the smoke run for a renderer lifecycle failure.
     * @param {'smoke-renderer-destroyed' | 'smoke-renderer-load-failed' | 'smoke-renderer-process-gone'} code - Stable lifecycle failure code.
     * @returns {boolean} True only when this call settled the gate.
     */
    fail(code) {
        if (!LIFECYCLE_FAILURE_CODES.has(code)) {
            throw new TypeError(`Unsupported smoke readiness failure: ${code}`)
        }
        return this.#failWithCode(code)
    }

    /**
     * Waits for renderer and terminal service evidence, starting the bounded
     * timeout on the first call.
     * @returns {Promise<{renderer: 'mounted', service: object}>} Frozen smoke evidence.
     */
    wait() {
        if (!this.#settled && this.#timer === null) {
            /** Rejects when the injected readiness bound expires. @returns {void} */
            const handleTimeout = () => this.#failWithCode('smoke-readiness-timeout')
            this.#timer = this.#scheduleTimeout(handleTimeout, this.#timeoutMs)
        }
        return this.promise
    }

    /**
     * Rejects pending readiness and releases timer resources when the owning
     * application stops.
     * @returns {void}
     */
    dispose() {
        this.#failWithCode('smoke-readiness-disposed')
    }

    /**
     * Resolves the shared promise once both startup facts are present.
     * @returns {void} Completes without effect while either fact is absent.
     */
    #settle() {
        if (this.#settled || !this.#rendererMounted || this.#service === null) return
        this.#settled = true
        this.#value = Object.freeze({ renderer: 'mounted', service: this.#service })
        this.#clearTimer()
        this.#resolve(this.#value)
    }

    /**
     * Rejects once with a stable readiness error and cancels the timeout.
     * @param {string} code - Stable failure code.
     * @returns {boolean} True only when this call settled the gate.
     */
    #failWithCode(code) {
        if (this.#settled) return false
        this.#settled = true
        this.#clearTimer()
        this.#reject(new SmokeReadinessError(code))
        return true
    }

    /**
     * Cancels and forgets the active timeout at most once.
     * @returns {void}
     */
    #clearTimer() {
        if (this.#timer === null) return
        this.#cancelTimeout(this.#timer)
        this.#timer = null
    }
}
