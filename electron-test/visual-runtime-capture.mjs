// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Enables DevTools exception reporting concurrently with the first renderer
 * navigation. Chromium does not resolve Runtime.enable for the initial blank
 * target until navigation starts, so awaiting it before load would deadlock.
 * @param {object} debuggerSession - Electron debugger session.
 * @param {Function} handleMessage - DevTools protocol event observer.
 * @param {() => Promise<void>} load - Renderer navigation operation.
 * @returns {Promise<void>} Resolves after both capture enablement and navigation.
 */
export async function loadWithPageErrorCapture(debuggerSession, handleMessage, load) {
    debuggerSession.attach('1.3')
    debuggerSession.on('message', handleMessage)
    const enablement = debuggerSession.sendCommand('Runtime.enable')
    const navigation = load()
    await Promise.all([enablement, navigation])
}

/**
 * Captures every error-stream offset before invoking a mount, load, or state
 * transition so errors produced by the operation cannot be hidden.
 * @template T
 * @param {import('./visual-error-tracker.mjs').VisualErrorTracker} errorTracker - Process-owned error streams.
 * @param {() => Promise<T>} operation - Visual operation to invoke after capture.
 * @returns {Promise<{cursor: Readonly<Record<string, number>>, value: T}>} Pre-operation cursor and operation result.
 */
export async function runWithVisualErrorCursor(errorTracker, operation) {
    const cursor = errorTracker.capture()
    const value = await operation()
    return { cursor, value }
}

/**
 * Captures a bounded sequence of compositor frames until screenshot-level
 * validation proves that the requested renderer state was actually painted.
 * @template TImage, TEvidence
 * @param {{capture: () => Promise<TImage>, prepare: (attempt: number) => Promise<void>, validate: (image: TImage) => TEvidence, maxAttempts?: number}} options - Capture, repaint, and fail-closed validation operations.
 * @returns {Promise<{image: TImage, evidence: TEvidence, attempts: number}>} First validated frame and evidence.
 * @throws {Error} When every bounded attempt remains stale or incomplete.
 */
export async function captureValidatedVisualImage(options) {
    const maxAttempts = options?.maxAttempts ?? 4
    if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || typeof options?.capture !== 'function' || typeof options?.prepare !== 'function' || typeof options?.validate !== 'function') {
        throw new TypeError('Validated visual capture options are incomplete')
    }
    let lastError = null
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
        await options.prepare(attempt)
        const image = await options.capture()
        try {
            return { image, evidence: options.validate(image), attempts: attempt }
        } catch (error) {
            lastError = error
        }
    }
    throw new Error(`Visual QA capture remained invalid after ${maxAttempts} attempts: ${lastError?.message ?? 'unknown raster validation failure'}`, { cause: lastError })
}
