// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Fixed phase/key schema; booleans here describe synthetic evidence, not kernel authority. */
export const actualTokenSchema = Object.freeze({
    setup: ['verified'],
    derive: ['reduced-proved', 'source-handle-exact', 'source-minimal-rights'],
    fixtures: ['protected'],
    'baseline-create': ['created', 'creation-uncertain'],
    'baseline-proof': ['query-ok', 'image-proved', 'properties-equal', 'grant-absent', 'identity-known', 'actual-source-distinct', 'actual-derived-distinct', 'source-unchanged', 'derived-unchanged'],
    'baseline-resume': ['fresh-proof'],
    'baseline-wait': ['dll-init-failed'],
    'baseline-reap': ['verified'],
    'treatment-create': ['created', 'creation-uncertain'],
    'treatment-observe': ['fresh-proof', 'full-properties-known', 'full-properties-equal', 'identities-known', 'actual-source-distinct', 'actual-derived-distinct', 'write-handle-same-instance', 'prewrite-state-exact', 'source-unchanged', 'derived-unchanged'],
    'treatment-write': ['epoch-fresh', 'write-succeeded'],
    'treatment-readback': ['query-ok', 'token-dacl-exact', 'one-addition', 'old-aces-retained', 'denials-equal', 'owner-preserved', 'group-preserved', 'label-preserved', 'control-preserved', 'same-instance', 'full-properties-equal', 'default-dacl-equal', 'process-exact', 'thread-exact', 'source-unchanged', 'derived-unchanged'],
    'treatment-resume': ['fresh-proof', 'resumed'],
    'treatment-wait': ['timeout-alive'],
    'treatment-reap': ['verified'],
    'positive-create': ['created', 'creation-uncertain'],
    'positive-observe': ['fresh-proof', 'full-properties-known', 'full-properties-equal', 'identities-known', 'actual-source-distinct', 'actual-derived-distinct', 'write-handle-same-instance', 'prewrite-state-exact', 'source-unchanged', 'derived-unchanged'],
    'positive-write': ['epoch-fresh', 'write-succeeded'],
    'positive-readback': ['query-ok', 'token-dacl-exact', 'one-addition', 'old-aces-retained', 'denials-equal', 'owner-preserved', 'group-preserved', 'label-preserved', 'control-preserved', 'same-instance', 'full-properties-equal', 'default-dacl-equal', 'process-exact', 'thread-exact', 'source-unchanged', 'derived-unchanged'],
    'positive-resume': ['fresh-proof', 'resumed'],
    'positive-wait': ['exit-zero'],
    'positive-reap': ['verified'],
    'child-cleanup': ['verified', 'deferred'],
    'proof-cleanup': ['verified', 'deferred'],
    'wait-cleanup': ['verified', 'deferred'],
    'source-check': ['query-ok', 'properties-equal', 'default-dacl-equal', 'descriptor-equal', 'instance-known', 'instance-equal', 'logon-equal', 'modified-equal'],
    'derived-check': ['query-ok', 'properties-equal', 'default-dacl-equal', 'descriptor-equal', 'instance-known', 'instance-equal', 'logon-equal', 'modified-equal'],
    complete: ['experiment-complete', 'startup-proof']
})

const prefix = 'openrdx-token-actual-control'
const phases = Object.keys(actualTokenSchema)
const cleanupIndex = phases.indexOf('child-cleanup')
const reasons = new Set(['UnsupportedPlatform', 'InvalidRequest', 'AccessDenied', 'Busy', 'ReadOnly', 'Cancelled', 'TimedOut', 'DeviceRemoved', 'NoMedia', 'EnumerationFailed', 'EvidenceIncomplete', 'ResourceLimit', 'Other'])
const exits = new Set(['alive', 'success', 'self-token-open', 'self-process-session', 'self-console-session', 'self-token-session', 'self-elevation', 'self-ui-access', 'self-sandbox-inert', 'self-primary', 'self-integrity', 'status-dll-not-found', 'status-dll-init-failed', 'status-invalid-image-format', 'unknown'])

/**
 * Reconstructs fixed optional control evidence. Partial/unknown/malformed evidence has no authority.
 * @param {readonly string[]} input Bounded lines from fixed Cargo execution, never forwarded verbatim.
 * @returns {object} Closed facts/transitions, strict completion and independent startup proof.
 */
export function actualTokenControlEvidence(input) {
    const lines = [],
        stages = new Map(),
        facts = new Map(),
        observedExits = new Map()
    let active = null,
        next = 0,
        failure = false,
        terminalFailure = false,
        firstFailure = null
    /** @returns {object} Empty closed rejection without any captured string. */
    const reject = () => ({ lines: [], complete: false, startupProof: false, firstFailure: null, reason: 'actual-control-schema' })
    for (const line of input) {
        if (!line.startsWith(prefix)) continue
        const match = /^openrdx-token-actual-control(-stage|-exit)? phase=([a-z-]+) (.+)$/u.exec(line)
        if (match === null || !Object.hasOwn(actualTokenSchema, match[2])) return reject()
        const [, kind, phase, suffix] = match
        if (kind === '-stage') {
            const status = /^status=(begin|ok|failed)(?: reason=([A-Za-z]+))?$/u.exec(suffix)
            if (status === null || (status[1] === 'failed' ? !reasons.has(status[2]) : status[2] !== undefined)) return reject()
            if (status[1] === 'begin') {
                const index = phases.indexOf(phase)
                if (active !== null || stages.has(phase) || (index !== next && !(terminalFailure && index >= cleanupIndex && index >= next))) return reject()
                active = phase
                next = index + 1
                stages.set(phase, 'begin')
            } else {
                if (active !== phase || stages.get(phase) !== 'begin') return reject()
                active = null
                stages.set(phase, status[1])
                if (status[1] === 'failed') {
                    failure = true
                    terminalFailure = true
                    firstFailure ??= line
                }
            }
        } else if (kind === '-exit') {
            const exit = /^category=([a-z-]+)$/u.exec(suffix)
            if (active !== phase || !['baseline-wait', 'treatment-wait', 'positive-wait'].includes(phase) || observedExits.has(phase) || exit === null || !exits.has(exit[1])) return reject()
            observedExits.set(phase, exit[1])
            if (exit[1] !== { 'baseline-wait': 'status-dll-init-failed', 'treatment-wait': 'alive', 'positive-wait': 'success' }[phase]) failure = true
        } else {
            if (active !== phase) return reject()
            const seen = facts.get(phase) ?? new Map()
            for (const pair of suffix.split(' ')) {
                const fact = /^([a-z-]+)=(true|false)$/u.exec(pair)
                if (fact === null || !actualTokenSchema[phase].includes(fact[1]) || seen.has(fact[1])) return reject()
                const value = fact[2] === 'true'
                seen.set(fact[1], value)
                if (fact[1] !== 'modified-equal' && value !== (fact[1] !== 'deferred' && fact[1] !== 'creation-uncertain')) failure = true
            }
            facts.set(phase, seen)
        }
        lines.push(line)
    }
    for (const [phase, seen] of facts) {
        if (seen.get('creation-uncertain') === true && seen.get('created') === true) return reject()
        if (seen.get('deferred') === true && seen.get('verified') === true) return reject()
        if (seen.get('full-properties-equal') === true && seen.has('full-properties-known') && seen.get('full-properties-known') !== true) return reject()
        if (seen.get('instance-equal') === true && seen.get('instance-known') !== true) return reject()
        if (seen.get('one-addition') === true && ['old-aces-retained', 'denials-equal'].some((key) => seen.get(key) !== true)) return reject()
        if (seen.get('token-dacl-exact') === true && ['one-addition', 'old-aces-retained', 'denials-equal', 'owner-preserved', 'group-preserved', 'label-preserved', 'control-preserved'].some((key) => seen.get(key) !== true)) return reject()
        if (phase.endsWith('observe') && ['actual-source-distinct', 'actual-derived-distinct', 'write-handle-same-instance'].some((key) => seen.get(key) === true) && seen.get('identities-known') !== true) return reject()
    }
    const complete = !failure && active === null && next === phases.length && phases.every((phase) => stages.get(phase) === 'ok' && actualTokenSchema[phase].every((key) => facts.get(phase)?.has(key) && (key === 'modified-equal' || facts.get(phase)?.get(key) === (key !== 'deferred' && key !== 'creation-uncertain')))) && observedExits.get('baseline-wait') === 'status-dll-init-failed' && observedExits.get('treatment-wait') === 'alive' && observedExits.get('positive-wait') === 'success'
    return { lines, complete, startupProof: complete, firstFailure, reason: null }
}
