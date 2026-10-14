// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Fixed process-dacl-control observations never authorize the separate ordinary-child experiment. */
export const processControlRequirements = Object.freeze(
    Object.fromEntries(
        [
            'source-verified',
            'derived-verified',
            'source-default-dacl-unchanged',
            'source-snapshot-unchanged',
            'baseline-image-proved',
            'baseline-descriptors-valid',
            'baseline-dll-init-failed',
            'baseline-reaped',
            'process-descriptor-built',
            'treatment-image-proved',
            'treatment-process-dacl-exact',
            'treatment-other-components-unchanged',
            'treatment-thread-unchanged',
            'treatment-token-unchanged',
            'treatment-token-proved',
            'treatment-console-proved',
            'treatment-timeout-alive',
            'treatment-reaped',
            'positive-image-proved',
            'positive-descriptors-proved',
            'positive-token-proved',
            'positive-console-proved',
            'positive-exit-zero',
            'positive-reaped',
            'fixtures-cleaned',
            ...[
                'baseline-descriptors-query-ok',
                'treatment-descriptors-query-ok',
                'positive-descriptors-query-ok',
                'positive-process-dacl-exact',
                'owned-children-cleanup-ok',
                'positive-fixture-cleanup-ok',
                'wait-fixture-cleanup-ok',
                'source-snapshot-query-ok',
                'source-default-dacl-query-ok',
                'treatment-process-owner-preserved',
                'treatment-process-group-preserved',
                'treatment-process-label-preserved',
                'treatment-process-control-preserved',
                'positive-process-owner-preserved',
                'positive-process-group-preserved',
                'positive-process-label-preserved',
                'positive-process-control-preserved',
                'treatment-thread-components-exact',
                'treatment-token-components-exact',
                'positive-thread-components-exact',
                'positive-token-components-exact',
                'treatment-source-snapshot-query-ok',
                'treatment-source-snapshot-unchanged',
                'treatment-source-default-dacl-query-ok',
                'treatment-source-default-dacl-unchanged',
                'positive-source-snapshot-query-ok',
                'positive-source-snapshot-unchanged',
                'positive-source-default-dacl-query-ok',
                'positive-source-default-dacl-unchanged'
            ],
            ...['baseline-source-snapshot-query-ok', 'baseline-source-snapshot-unchanged', 'baseline-source-default-dacl-query-ok', 'baseline-source-default-dacl-unchanged']
        ].map((key) => [key, true])
    )
)

const phases = new Set(['setup', 'fixture', 'baseline-create', 'baseline-proof', 'baseline-resume', 'baseline-wait', 'baseline-reap', 'descriptor', 'treatment-create', 'treatment-proof', 'treatment-resume', 'treatment-wait', 'treatment-reap', 'positive-fixture', 'positive-create', 'positive-proof', 'positive-resume', 'positive-wait', 'positive-reap', 'child-cleanup', 'positive-fixture-cleanup', 'wait-fixture-cleanup', 'cleanup', 'source-check'])
const reasons = new Set(['UnsupportedPlatform', 'InvalidRequest', 'AccessDenied', 'Busy', 'ReadOnly', 'Cancelled', 'TimedOut', 'DeviceRemoved', 'NoMedia', 'EnumerationFailed', 'EvidenceIncomplete', 'ResourceLimit', 'Other'])
const exitCategories = new Set(['success', 'self-token-open', 'self-process-session', 'self-console-session', 'self-token-session', 'self-elevation', 'self-ui-access', 'self-sandbox-inert', 'self-primary', 'self-integrity', 'status-dll-not-found', 'status-dll-init-failed', 'status-invalid-image-format', 'unknown'])

/**
 * Reads only fixed process-dacl-control booleans/phases/categories from already bounded native lines.
 * Any failed transition stays fatal even if cleanup succeeds; malformed output never escapes.
 * @param {readonly string[]} nativeLines Captured, bounded, control-character-stripped lines.
 * @returns {object} Closed observations, exact facts and independent process-dacl-control verdict inputs.
 */
export function processControlEvidence(nativeLines) {
    const lines = []
    const seen = new Map()
    const stageSeen = new Map()
    let failure = false
    const exits = new Map()
    let lastStatus = null
    let active = null
    /** @returns {object} Empty observations with a closed schema rejection. */
    const rejected = () => ({ lines: [], seen: new Map(), failure: true, exits: new Map(), lastStatus: null, reason: 'process-dacl-control-schema' })
    for (const line of nativeLines) {
        if (line.startsWith('openrdx-token-process-dacl-control ')) {
            const pairs = []
            for (const pair of line.slice('openrdx-token-process-dacl-control '.length).split(' ')) {
                const match = /^([a-z-]+)=(true|false)$/u.exec(pair)
                if (match === null || !Object.hasOwn(processControlRequirements, match[1]) || seen.has(match[1])) return rejected()
                const value = match[2] === 'true'
                seen.set(match[1], value)
                if (!value) failure = true
                pairs.push(`${match[1]}=${match[2]}`)
            }
            lines.push(`openrdx-token-process-dacl-control ${pairs.join(' ')}`)
        } else if (line.startsWith('openrdx-token-process-dacl-control-stage ')) {
            const match = /^openrdx-token-process-dacl-control-stage phase=([a-z-]+) status=(begin|ok|failed)(?: reason=([A-Za-z]+))?$/u.exec(line)
            if (match === null || !phases.has(match[1]) || (match[2] === 'failed' ? !reasons.has(match[3]) : match[3] !== undefined)) return rejected()
            const prior = stageSeen.get(match[1])
            // A terminal must complete its matching begin; an orphan cannot prove execution.
            if (match[2] === 'begin' ? prior !== undefined || active !== null : prior !== 'begin' || active !== match[1]) return rejected()
            active = match[2] === 'begin' ? match[1] : null
            stageSeen.set(match[1], match[2])
            lastStatus = match[2]
            if (match[2] === 'failed') failure = true
            lines.push(`openrdx-token-process-dacl-control-stage phase=${match[1]} status=${match[2]}${match[3] === undefined ? '' : ` reason=${match[3]}`}`)
        } else if (line.startsWith('openrdx-token-process-dacl-control-exit ')) {
            const match = /^openrdx-token-process-dacl-control-exit phase=(baseline-wait|treatment-wait|positive-wait) category=([a-z-]+)$/u.exec(line)
            if (match === null || !exitCategories.has(match[2]) || exits.has(match[1]) || active !== match[1] || stageSeen.get(match[1]) !== 'begin') return rejected()
            exits.set(match[1], match[2])
            if (match[1] === 'treatment-wait' || match[2] !== (match[1] === 'baseline-wait' ? 'status-dll-init-failed' : 'success')) failure = true
            lines.push(`openrdx-token-process-dacl-control-exit phase=${match[1]} category=${match[2]}`)
        }
    }
    // A panic can leave a began operation unfinished even when cleanup later emits ok.
    if ([...phases].some((phase) => stageSeen.get(phase) !== 'ok')) failure = true
    return { lines, seen, failure, exits, lastStatus, reason: null }
}
