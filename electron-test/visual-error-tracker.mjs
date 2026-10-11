// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

const STREAM_NAMES = Object.freeze(['consoleErrors', 'pageErrors', 'loadFailures', 'rendererCrashes'])

/**
 * Normalizes only error-level renderer console messages across Electron 44's
 * details-first event and the legacy positional signature. The owning listener
 * can retain arity one, avoiding Electron's deprecated positional API path.
 * @param {unknown} firstArgument - Current details object or legacy event object.
 * @param {ArrayLike<unknown>} legacyArguments - Complete callback arguments for legacy fallback.
 * @returns {{level: 'error', message: string}|null} Exact error evidence, otherwise null.
 */
export function normalizeConsoleMessage(firstArgument, legacyArguments) {
    if (typeof firstArgument === 'object' && firstArgument !== null && typeof firstArgument.level === 'string' && typeof firstArgument.message === 'string') {
        return firstArgument.level === 'error' && firstArgument.message.length > 0 ? { level: 'error', message: firstArgument.message } : null
    }
    if (legacyArguments?.[1] === 3 && typeof legacyArguments[2] === 'string' && legacyArguments[2].length > 0) {
        return { level: 'error', message: legacyArguments[2] }
    }
    return null
}

/**
 * Collects all Electron visual-QA error streams while allowing each operation
 * to assert only the errors emitted after its pre-operation cursor.
 */
export class VisualErrorTracker {
    #streams = Object.fromEntries(STREAM_NAMES.map((name) => [name, []]))

    /**
     * Appends one serializable error description to a known stream.
     * @param {'consoleErrors' | 'pageErrors' | 'loadFailures' | 'rendererCrashes'} streamName - Destination error stream.
     * @param {string} message - Human-readable error evidence.
     * @returns {void}
     * @throws {TypeError} Rejects unknown streams or empty messages.
     */
    record(streamName, message) {
        if (!STREAM_NAMES.includes(streamName) || typeof message !== 'string' || message.length === 0) {
            throw new TypeError('Visual error evidence requires a known stream and non-empty message')
        }
        this.#streams[streamName].push(message)
    }

    /**
     * Captures stream offsets immediately before a load, mount, or transition.
     * @returns {Readonly<Record<string, number>>} Frozen cursor for all streams.
     */
    capture() {
        return Object.freeze(Object.fromEntries(STREAM_NAMES.map((name) => [name, this.#streams[name].length])))
    }

    /**
     * Returns all evidence emitted after a previously captured cursor.
     * @param {Readonly<Record<string, number>>} cursor - Pre-operation stream offsets.
     * @returns {Readonly<Record<string, readonly string[]>>} Frozen per-stream deltas.
     * @throws {TypeError} Rejects incomplete or invalid cursors.
     */
    delta(cursor) {
        const result = {}
        for (const name of STREAM_NAMES) {
            if (!Number.isSafeInteger(cursor?.[name]) || cursor[name] < 0 || cursor[name] > this.#streams[name].length) {
                throw new TypeError(`Invalid visual error cursor for ${name}`)
            }
            result[name] = Object.freeze(this.#streams[name].slice(cursor[name]))
        }
        return Object.freeze(result)
    }

    /**
     * Fails when the selected operation emitted any console, page, load, or
     * renderer-process error.
     * @param {Readonly<Record<string, number>>} cursor - Cursor captured before the operation.
     * @param {string} context - Operation label included in failures.
     * @returns {void}
     * @throws {Error} Lists complete error deltas for the operation.
     */
    assertEmptySince(cursor, context) {
        this.#assertEmpty(this.delta(cursor), context)
    }

    /**
     * Fails when any error was observed anywhere in the complete QA run.
     * @returns {void}
     * @throws {Error} Lists all retained error evidence.
     */
    assertGloballyEmpty() {
        this.#assertEmpty(this.#streams, 'complete visual QA run')
    }

    /**
     * Formats non-empty streams into one stable assertion failure.
     * @param {Record<string, readonly string[]>} streams - Error evidence to inspect.
     * @param {string} context - Human-readable operation label.
     * @returns {void}
     * @throws {Error} Lists every non-empty stream.
     */
    #assertEmpty(streams, context) {
        const failures = []
        for (const name of STREAM_NAMES) {
            if (streams[name].length > 0) {
                failures.push(`${name}: ${streams[name].join(' | ')}`)
            }
        }
        if (failures.length > 0) {
            throw new Error(`Visual QA errors during ${context}: ${failures.join('; ')}`)
        }
    }
}
