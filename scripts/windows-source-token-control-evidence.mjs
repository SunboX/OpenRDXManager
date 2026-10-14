// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Fixed source-control observations never authorize the separate ordinary-child experiment. */
export const sourceControlRequirements = Object.freeze(Object.fromEntries(['source-open', 'source-query-ok', 'source-console-match', 'source-high-primary', 'fixture-protected', 'child-created', 'child-image-match', 'child-source-snapshot-match', 'console-revalidated', 'source-unchanged-after-create', 'source-unchanged-before-resume', 'child-resumed', 'child-exited', 'child-self-elevation-refused', 'source-unchanged-after-exit', 'source-unchanged-after-cleanup', 'owned-child-reaped', 'fixture-cleaned', ...['user', 'session', 'elevation', 'integrity', 'ui-access', 'sandbox-inert', 'type', 'elevation-type', 'groups', 'privileges'].map((property) => `child-${property}-match`), ...['after-create', 'before-resume', 'after-exit', 'after-cleanup'].map((phase) => `source-${phase}-query-ok`)].map((key) => [key, true])))

const phases = new Set(['source-open', 'source-query', 'console', 'fixture', 'create', 'source-after-create', 'proof', 'source-before-resume', 'resume', 'wait', 'source-after-exit', 'reap', 'cleanup', 'source-after-cleanup'])
const reasons = new Set(['UnsupportedPlatform', 'InvalidRequest', 'AccessDenied', 'Busy', 'ReadOnly', 'Cancelled', 'TimedOut', 'DeviceRemoved', 'NoMedia', 'EnumerationFailed', 'EvidenceIncomplete', 'ResourceLimit', 'Other'])
const exitCategories = new Set(['success', 'self-token-open', 'self-process-session', 'self-console-session', 'self-token-session', 'self-elevation', 'self-ui-access', 'self-sandbox-inert', 'self-primary', 'self-integrity', 'status-dll-not-found', 'status-dll-init-failed', 'status-invalid-image-format', 'unknown'])

/**
 * Reads only fixed source-control booleans/phases/categories from already bounded native lines.
 * Any failed transition stays fatal even if cleanup succeeds; malformed output never escapes.
 * @param {readonly string[]} nativeLines Captured, bounded, control-character-stripped lines.
 * @returns {object} Closed observations, exact facts and independent source-control verdict inputs.
 */
export function sourceControlEvidence(nativeLines) {
    const lines = []
    const seen = new Map()
    const stageSeen = new Map()
    let failure = false
    let exit = null
    let lastStatus = null
    /** @returns {object} Empty observations with a closed schema rejection. */
    const rejected = () => ({ lines: [], seen: new Map(), failure: true, exit: null, lastStatus: null, reason: 'source-control-schema' })
    for (const line of nativeLines) {
        if (line.startsWith('openrdx-token-source-control ')) {
            const pairs = []
            for (const pair of line.slice('openrdx-token-source-control '.length).split(' ')) {
                const match = /^([a-z-]+)=(true|false)$/u.exec(pair)
                if (match === null || !Object.hasOwn(sourceControlRequirements, match[1]) || seen.has(match[1])) return rejected()
                const value = match[2] === 'true'
                seen.set(match[1], value)
                if (!value) failure = true
                pairs.push(`${match[1]}=${match[2]}`)
            }
            lines.push(`openrdx-token-source-control ${pairs.join(' ')}`)
        } else if (line.startsWith('openrdx-token-source-control-stage ')) {
            const match = /^openrdx-token-source-control-stage phase=([a-z-]+) status=(begin|ok|failed)(?: reason=([A-Za-z]+))?$/u.exec(line)
            if (match === null || !phases.has(match[1]) || (match[2] === 'failed' ? !reasons.has(match[3]) : match[3] !== undefined)) return rejected()
            const prior = stageSeen.get(match[1])
            // A terminal must complete its matching begin; an orphan cannot prove execution.
            if (match[2] === 'begin' ? prior !== undefined : prior !== 'begin') return rejected()
            stageSeen.set(match[1], match[2])
            lastStatus = match[2]
            if (match[2] === 'failed') failure = true
            lines.push(`openrdx-token-source-control-stage phase=${match[1]} status=${match[2]}${match[3] === undefined ? '' : ` reason=${match[3]}`}`)
        } else if (line.startsWith('openrdx-token-source-control-exit ')) {
            const match = /^openrdx-token-source-control-exit category=([a-z-]+)$/u.exec(line)
            if (match === null || !exitCategories.has(match[1]) || exit !== null) return rejected()
            exit = match[1]
            if (exit !== 'self-elevation') failure = true
            lines.push(`openrdx-token-source-control-exit category=${exit}`)
        }
    }
    // A panic can leave a began operation unfinished even when cleanup later emits ok.
    if ([...stageSeen.values()].includes('begin')) failure = true
    return { lines, seen, failure, exit, lastStatus, reason: null }
}
