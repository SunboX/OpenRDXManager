// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { TokenLineageEvidence } from './windows-token-lineage-evidence.mjs'

/** Compiled roles only; matrix completion never authorizes ordinary child admission. */
export const objectMatrixRows = Object.freeze(['baseline', 'process', 'thread', 'process-thread', 'token', 'process-token', 'thread-token', 'process-thread-token'])
const prefix = 'openrdx-token-object-dacl-matrix'
const ordinaryPhases = ['derive', 'reference-create', 'reference-read', 'reference-resume', 'reference-wait', 'reference-reap', 'intervention', 'create', 'read', 'resume', 'wait', 'reap']
const positivePhases = ['positive-create', 'positive-read', 'positive-resume', 'positive-wait', 'positive-reap']
const tailPhases = ['cleanup', 'source-check', 'complete']
const matrixPhases = ['setup', 'fixture', ...tailPhases]
const rowPhases = new Set([...ordinaryPhases, ...positivePhases, ...tailPhases])
const phases = new Set([...ordinaryPhases, ...positivePhases, ...matrixPhases])
const reasons = new Set(['UnsupportedPlatform', 'InvalidRequest', 'AccessDenied', 'Busy', 'ReadOnly', 'Cancelled', 'TimedOut', 'DeviceRemoved', 'NoMedia', 'EnumerationFailed', 'EvidenceIncomplete', 'ResourceLimit', 'Other'])
const exits = new Set(['alive', 'success', 'self-token-open', 'self-process-session', 'self-console-session', 'self-token-session', 'self-elevation', 'self-ui-access', 'self-sandbox-inert', 'self-primary', 'self-integrity', 'status-dll-not-found', 'status-dll-init-failed', 'status-invalid-image-format', 'unknown'])
const preserved = ['process', 'thread', 'token'].flatMap((object) => ['owner', 'group', 'label', 'control'].map((part) => `${object}-${part}-preserved`))
const sourcePreserved = ['source-properties-unchanged', 'source-default-dacl-unchanged', 'source-object-unchanged']
const schema = Object.freeze({
    setup: ['verified'],
    fixture: ['verified'],
    derive: ['query-ok', 'exact', 'source-observer-unchanged', 'source-rights-open', 'source-handle-exact', 'restricted-created', 'medium-set', 'reduced-proved'],
    'reference-read': ['query-ok', 'exact'],
    intervention: ['query-ok', 'exact', 'owner-preserved', 'group-preserved', 'label-preserved', 'control-preserved', 'properties-unchanged', 'default-dacl-unchanged'],
    read: ['query-ok', 'exact', 'token-propagated', 'process-exact', 'thread-exact', 'token-exact', ...preserved],
    'positive-read': ['query-ok', 'exact', 'token-propagated', 'process-exact', 'thread-exact', 'token-exact', ...preserved],
    'reference-resume': ['source-query-ok', 'source-unchanged', 'child-proof', ...sourcePreserved],
    resume: ['source-query-ok', 'source-unchanged', 'child-proof', ...sourcePreserved],
    'positive-resume': ['source-query-ok', 'source-unchanged', 'child-proof', ...sourcePreserved],
    'reference-reap': ['owned-cleanup'],
    reap: ['owned-cleanup'],
    'positive-reap': ['owned-cleanup'],
    cleanup: ['owned-cleanup'],
    'source-check': ['source-query-ok', 'source-unchanged', ...sourcePreserved],
    complete: ['experiment-complete', 'startup-proof', 'any-startup-proof']
})

/**
 * Reconstructs only fixed matrix facts and transitions, preserving the first failure.
 * Partial diagnostics cannot authorize completion; unknown/duplicate/private fields disappear.
 * @param {readonly string[]} input Bounded native lines, never forwarded verbatim.
 * @returns {object} Closed lines, experiment completion and independent startup observation.
 */
export function objectMatrixEvidence(input) {
    const lineage = new TokenLineageEvidence()
    const lines = [],
        facts = new Map(),
        stages = new Map(),
        observedExits = new Map(),
        order = []
    let active = null,
        failure = false,
        firstFailure = null
    /** @returns {object} Closed empty rejection, never captured native strings. */
    const reject = () => ({ lines: [], failure: true, complete: false, anyStartup: false, firstFailure: null, reason: 'object-dacl-matrix-schema' })
    for (const line of input) {
        if (line.startsWith('openrdx-token-object-lineage')) {
            const closed = lineage.accept(line, active)
            if (closed === null) return reject()
            lines.push(closed)
            continue
        }
        if (!line.startsWith(prefix)) continue
        const match = new RegExp(`^${prefix}(-stage|-exit)? row=([a-z-]+) phase=([a-z-]+) (.+)$`, 'u').exec(line)
        if (match === null) return reject()
        const [, kind, row, phase, suffix] = match
        if ((row !== 'matrix' && !objectMatrixRows.includes(row)) || !phases.has(phase) || (row === 'matrix' ? !matrixPhases.includes(phase) : !rowPhases.has(phase))) return reject()
        const key = `${row}/${phase}`
        if (kind === '-stage') {
            const status = /^status=(begin|ok|failed)(?: reason=([A-Za-z]+))?$/u.exec(suffix)
            if (status === null || (status[1] === 'failed' ? !reasons.has(status[2]) : status[2] !== undefined)) return reject()
            const prior = stages.get(key)
            if (status[1] === 'begin' ? active !== null || prior !== undefined : active !== key || prior !== 'begin') return reject()
            if (status[1] === 'begin') order.push(key)
            active = status[1] === 'begin' ? key : null
            stages.set(key, status[1])
            if (status[1] === 'failed') {
                failure = true
                firstFailure ??= line
            }
        } else if (kind === '-exit') {
            const exit = /^category=([a-z-]+)$/u.exec(suffix)
            if (exit === null || !exits.has(exit[1]) || !['reference-wait', 'wait', 'positive-wait'].includes(phase) || active !== key || observedExits.has(key)) return reject()
            observedExits.set(key, exit[1])
            if (exit[1] !== (phase === 'reference-wait' ? 'status-dll-init-failed' : phase === 'positive-wait' ? 'success' : 'alive') && !(phase === 'wait' && exit[1] === 'status-dll-init-failed')) failure = true
        } else {
            if (active !== key || !Object.hasOwn(schema, phase)) return reject()
            for (const pair of suffix.split(' ')) {
                const fact = /^([a-z-]+)=(true|false)$/u.exec(pair)
                if (fact === null || !schema[phase].includes(fact[1]) || facts.has(`${key}/${fact[1]}`) || (phase === 'complete' && fact[1] === (row === 'matrix' ? 'startup-proof' : 'any-startup-proof'))) return reject()
                facts.set(`${key}/${fact[1]}`, fact[2] === 'true')
                if (fact[2] === 'false' && !['startup-proof', 'any-startup-proof'].includes(fact[1])) failure = true
            }
        }
        lines.push(line)
    }
    if (!lineage.valid()) return reject()
    /** @param {string} row Fixed compiled row. @param {string} phase Fixed phase. @param {readonly string[]} keys Required true keys. @returns {boolean} Exact completed facts. */
    const proved = (row, phase, keys = schema[phase] ?? []) => stages.get(`${row}/${phase}`) === 'ok' && keys.every((key) => facts.get(`${row}/${phase}/${key}`) === true)
    const expected = ['matrix/setup', 'matrix/fixture']
    let anyStartup = false,
        complete = !failure && active === null
    for (const row of objectMatrixRows) {
        const startup = observedExits.get(`${row}/wait`) === 'alive'
        anyStartup ||= startup
        const rowPhases = [...ordinaryPhases, ...(startup ? positivePhases : []), ...tailPhases]
        expected.push(...rowPhases.map((phase) => `${row}/${phase}`))
        complete &&= rowPhases.every((phase) => proved(row, phase, phase === 'complete' ? ['experiment-complete'] : (schema[phase] ?? []))) && observedExits.get(`${row}/reference-wait`) === 'status-dll-init-failed' && ['alive', 'status-dll-init-failed'].includes(observedExits.get(`${row}/wait`)) && facts.get(`${row}/complete/startup-proof`) === startup && (!startup || observedExits.get(`${row}/positive-wait`) === 'success')
    }
    expected.push(...tailPhases.map((phase) => `matrix/${phase}`))
    complete &&= matrixPhases.every((phase) => proved('matrix', phase, phase === 'complete' ? ['experiment-complete'] : schema[phase])) && facts.get('matrix/complete/any-startup-proof') === anyStartup && expected.length === order.length && expected.every((key, index) => order[index] === key)
    return { lines, failure, complete, anyStartup: complete && anyStartup, firstFailure, reason: null }
}
