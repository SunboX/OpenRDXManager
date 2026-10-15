// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { ManagerSourceContextEvidence } from './windows-manager-source-context-evidence.mjs'

const proofKeys = ['query-ok', 'image', 'user-equal', 'session-equal', 'elevation-equal', 'integrity-equal', 'ui-access-equal', 'sandbox-inert-equal', 'primary-equal', 'elevation-type-equal', 'groups-equal', 'privileges-equal', 'default-dacl-equal', 'no-enabled-admins', 'donor-properties-equal', 'instance-known']
/** Exact compiled Task Two checkpoints; nested Task One phases remain separate. */
export const managerSourceSchema = Object.freeze({
    'donor-proof': ['available', 'enrolled', 'image', 'ordinary-medium', 'caller-user-equal', 'mapped-generation-known'],
    duplicate: ['copy-distinct'],
    'copy-proof': ['properties-equal', 'default-dacl-equal', 'descriptor-equal'],
    fixtures: ['protected', 'caller-owned'],
    'wait-create': ['created', 'creation-uncertain'],
    'wait-proof': proofKeys,
    'wait-resume': ['fresh'],
    'wait-observe': ['timeout-alive'],
    'wait-reap': ['verified', 'deferred'],
    'proof-create': ['created', 'creation-uncertain'],
    'proof-proof': proofKeys,
    'proof-resume': ['fresh'],
    'proof-exit': ['exit-zero'],
    'proof-reap': ['verified', 'deferred'],
    'child-cleanup': ['verified', 'deferred'],
    'wait-cleanup': ['verified', 'deferred'],
    'proof-cleanup': ['verified', 'deferred'],
    'caller-check': ['verified'],
    'donor-check': ['verified'],
    'copy-check': ['verified'],
    complete: ['experiment-complete', 'startup-proof']
})
const phases = Object.keys(managerSourceSchema)
const cleanupIndex = phases.indexOf('child-cleanup')
const reasons = new Set(['UnsupportedPlatform', 'InvalidRequest', 'AccessDenied', 'Busy', 'ReadOnly', 'Cancelled', 'TimedOut', 'DeviceRemoved', 'NoMedia', 'EnumerationFailed', 'EvidenceIncomplete', 'ResourceLimit', 'Other'])
const exits = new Set(['alive', 'success', 'self-token-open', 'self-process-session', 'self-console-session', 'self-token-session', 'self-elevation', 'self-ui-access', 'self-sandbox-inert', 'self-primary', 'self-integrity', 'status-dll-not-found', 'status-dll-init-failed', 'status-invalid-image-format', 'unknown'])

/**
 * Parses bounded native observations without forwarding captured strings or conferring production authority.
 * @param {readonly string[]} input Fixed execution's stdout lines.
 * @returns {object} Sanitized partial evidence and strict harmless-experiment completion.
 */
export function managerSourceEvidence(input) {
    const lines = [],
        stages = new Map(),
        facts = new Map(),
        observedExits = new Map()
    const nested = new ManagerSourceContextEvidence(reasons)
    let active = null,
        next = 0,
        failure = false,
        terminalFailure = false,
        firstFailure = null
    /** @returns {object} Closed rejection with no captured data. */
    const reject = () => ({ lines: [], complete: false, startupProof: false, firstFailure: null, reason: 'manager-source-schema' })
    const present = input.some((line) => line.includes('openrdx-manager-source'))
    if (present && input.some((line) => line.includes('openrdx-token-'))) return reject()
    for (const line of input) {
        if (!line.includes('openrdx-manager-source')) continue
        if (line.startsWith('openrdx-manager-source-task-one-')) {
            const safe = nested.consume(line, active)
            if (safe === null) return reject()
            lines.push(safe)
            continue
        }
        const match = /^openrdx-manager-source(-stage|-exit)? phase=([a-z-]+) (.+)$/u.exec(line)
        if (match === null || !Object.hasOwn(managerSourceSchema, match[2])) return reject()
        const [, kind, phase, suffix] = match
        if (kind === '-stage') {
            const status = /^status=(begin|ok|failed)(?: reason=([A-Za-z]+))?$/u.exec(suffix)
            if (status === null || (status[1] === 'failed' ? !reasons.has(status[2]) : status[2] !== undefined)) return reject()
            if (status[1] === 'begin') {
                const index = phases.indexOf(phase)
                if (active !== null || stages.has(phase) || (terminalFailure && index < cleanupIndex) || (index !== next && !(terminalFailure && index >= cleanupIndex && index >= next))) return reject()
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
                    firstFailure ??= `openrdx-manager-source-stage phase=${phase} status=failed reason=${status[2]}`
                }
                if (phase === 'donor-proof' && status[1] === 'ok' && !nested.acquired()) failure = true
                if (phase === 'duplicate' && status[1] === 'ok' && !nested.copied()) failure = true
            }
            lines.push(`openrdx-manager-source-stage phase=${phase} status=${status[1]}${status[2] === undefined ? '' : ` reason=${status[2]}`}`)
        } else if (kind === '-exit') {
            const exit = /^category=([a-z-]+)$/u.exec(suffix)
            if (active !== phase || !['wait-observe', 'proof-exit'].includes(phase) || observedExits.has(phase) || exit === null || !exits.has(exit[1])) return reject()
            observedExits.set(phase, exit[1])
            if (exit[1] !== (phase === 'wait-observe' ? 'alive' : 'success')) failure = true
            lines.push(`openrdx-manager-source-exit phase=${phase} category=${exit[1]}`)
        } else {
            if (active !== phase) return reject()
            const seen = facts.get(phase) ?? new Map(),
                safe = []
            for (const pair of suffix.split(' ')) {
                const fact = /^([a-z-]+)=(true|false)$/u.exec(pair)
                if (fact === null || !managerSourceSchema[phase].includes(fact[1]) || seen.has(fact[1])) return reject()
                const value = fact[2] === 'true'
                seen.set(fact[1], value)
                safe.push(`${fact[1]}=${value}`)
                if (fact[1] !== 'caller-user-equal' && value !== !['mapped-generation-known', 'creation-uncertain', 'deferred'].includes(fact[1])) failure = true
            }
            facts.set(phase, seen)
            lines.push(`openrdx-manager-source phase=${phase} ${safe.join(' ')}`)
        }
    }
    if (facts.get('donor-proof')?.has('caller-user-equal') && nested.callerEqual !== facts.get('donor-proof').get('caller-user-equal')) return reject()
    for (const seen of facts.values()) {
        if (seen.get('created') === true && seen.get('creation-uncertain') === true) return reject()
        if (seen.get('verified') === true && seen.get('deferred') === true) return reject()
    }
    const complete = !failure && nested.copied() && active === null && next === phases.length && phases.every((phase) => stages.get(phase) === 'ok' && managerSourceSchema[phase].every((key) => facts.get(phase)?.has(key))) && observedExits.get('wait-observe') === 'alive' && observedExits.get('proof-exit') === 'success'
    return { lines, complete, startupProof: complete, firstFailure, reason: null }
}
