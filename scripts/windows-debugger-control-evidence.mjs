// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Fixed diagnostic-only schema; no successful debugger experiment is startup proof. */
export const debuggerSchema = Object.freeze({
    setup: ['verified', 'source-minimal', 'derived-medium'],
    fixture: ['protected'],
    'baseline-create': ['created', 'creation-uncertain'],
    'baseline-proof': ['image', 'properties', 'console', 'source-preserved', 'derived-preserved'],
    'baseline-resume': ['fresh'],
    'baseline-wait': ['dll-init-failed'],
    'baseline-reap': ['verified', 'deferred'],
    'debug-create': ['created', 'creation-uncertain'],
    'debug-proof': ['image', 'properties', 'console', 'source-preserved', 'derived-preserved'],
    'debug-resume': ['fresh'],
    'debug-events': ['event-protocol', 'exit-continued', 'held-exit-match', 'files-closed'],
    'debug-reap': ['verified', 'deferred'],
    'fixture-cleanup': ['verified', 'deferred'],
    'source-check': ['query-ok', 'properties', 'default-dacl', 'object-descriptor', 'instance-known', 'instance-equal'],
    'derived-check': ['query-ok', 'properties', 'default-dacl', 'object-descriptor', 'instance-known', 'instance-equal'],
    complete: ['experiment-complete', 'reproduced', 'debugger-changed-behavior', 'startup-proof']
})

const phases = Object.keys(debuggerSchema)
const reasons = new Set(['UnsupportedPlatform', 'InvalidRequest', 'AccessDenied', 'Busy', 'ReadOnly', 'Cancelled', 'TimedOut', 'DeviceRemoved', 'NoMedia', 'EnumerationFailed', 'EvidenceIncomplete', 'ResourceLimit', 'Other'])
const modules = new Set(['none', 'fixture', 'ntdll', 'kernel32', 'kernelbase', 'advapi32', 'ucrt', 'vcruntime', 'other', 'unknown'])
const exceptions = new Set(['none', 'breakpoint', 'access-denied', 'access-violation', 'in-page-error', 'dll-init-failed', 'other'])
const kinds = new Set(['create-process', 'create-thread', 'exit-thread', 'load', 'unload', 'exception', 'exit-process', 'debug-string', 'rip'])
const cleanup = new Set(['baseline-reap', 'debug-reap', 'fixture-cleanup', 'source-check', 'derived-check', 'complete'])
const falseKeys = new Set(['creation-uncertain', 'deferred', 'debugger-changed-behavior', 'startup-proof'])

/**
 * Reconstructs closed diagnostic rows. Matched failure is an observation only;
 * malformed or incomplete rows never establish ordinary startup authority.
 * @param {readonly string[]} input Bounded captured lines, never forwarded verbatim.
 * @returns {{lines:string[],complete:boolean,reproduced:boolean,changed:boolean,firstFailure:string|null,reason:string|null}} Closed observation and sticky failure.
 */
export function debuggerControlEvidence(input) {
    const lines = [],
        stages = new Map(),
        facts = new Map()
    let active = null,
        next = 0,
        failure = false,
        firstFailure = null,
        events = 0,
        exited = false
    /** @returns {object} Fixed rejection carrying no untrusted strings. */
    const reject = () => ({ lines: [], complete: false, reproduced: false, changed: false, firstFailure: null, reason: 'debugger-control-schema' })
    for (const line of input) {
        if (!line.startsWith('openrdx-token-')) continue
        if (!line.startsWith('openrdx-token-debugger')) {
            // An entirely absent debugger transcript belongs to an older mode.
            // Once this transcript is selected, other diagnostic schemas are orphaned.
            if (input.some((row) => row.startsWith('openrdx-token-debugger'))) return reject()
            continue
        }
        const event = /^openrdx-token-debugger-event slot=(e\d{3}) kind=([a-z-]+) module=([a-z0-9-]+) exception=([a-z-]+) first=(true|false) continued=(true|false)$/u.exec(line)
        if (event !== null) {
            const [, slot, kind, module, exception, first, continued] = event
            if (active !== 'debug-events' || events >= 128 || slot !== `e${String(events).padStart(3, '0')}` || !kinds.has(kind) || !modules.has(module) || !exceptions.has(exception) || exited) return reject()
            if ((events === 0) !== (kind === 'create-process')) return reject()
            if (kind === 'exception') {
                if (exception === 'none' || module === 'none') return reject()
            } else if (exception !== 'none' || first !== 'false' || (kind === 'load' ? module === 'none' : module !== 'none')) return reject()
            events += 1
            exited = kind === 'exit-process'
            // A RIP event is a native fatal observation even when continuation succeeds.
            if (continued !== 'true' || kind === 'rip') failure = true
            lines.push(`openrdx-token-debugger-event slot=${slot} kind=${kind} module=${module} exception=${exception} first=${first} continued=${continued}`)
            continue
        }
        const match = /^openrdx-token-debugger(-stage|-control) phase=([a-z-]+) (.+)$/u.exec(line)
        if (match === null || !Object.hasOwn(debuggerSchema, match[2])) return reject()
        const [, kind, phase, suffix] = match
        if (kind === '-stage') {
            const status = /^status=(begin|ok|failed)(?: reason=([A-Za-z]+))?$/u.exec(suffix)
            if (status === null || (status[1] === 'failed' ? !reasons.has(status[2]) : status[2] !== undefined)) return reject()
            if (status[1] === 'begin') {
                const index = phases.indexOf(phase)
                if (active !== null || stages.has(phase) || index < next || (failure ? !cleanup.has(phase) : index !== next)) return reject()
                active = phase
                next = index + 1
                stages.set(phase, 'begin')
            } else {
                if (active !== phase || stages.get(phase) !== 'begin') return reject()
                active = null
                stages.set(phase, status[1])
                if (status[1] === 'failed') {
                    failure = true
                    firstFailure ??= `openrdx-token-debugger-stage phase=${phase} status=failed reason=${status[2]}`
                } else if (debuggerSchema[phase].some((key) => !facts.get(phase)?.has(key))) return reject()
            }
            lines.push(`openrdx-token-debugger-stage phase=${phase} status=${status[1]}${status[2] === undefined ? '' : ` reason=${status[2]}`}`)
        } else {
            if (active !== phase) return reject()
            const seen = facts.get(phase) ?? new Map(),
                pairs = []
            for (const pair of suffix.split(' ')) {
                const fact = /^([a-z-]+)=(true|false)$/u.exec(pair)
                if (fact === null || !debuggerSchema[phase].includes(fact[1]) || seen.has(fact[1])) return reject()
                const value = fact[2] === 'true'
                seen.set(fact[1], value)
                if (value !== !falseKeys.has(fact[1])) failure = true
                pairs.push(`${fact[1]}=${fact[2]}`)
            }
            facts.set(phase, seen)
            lines.push(`openrdx-token-debugger-control phase=${phase} ${pairs.join(' ')}`)
        }
    }
    for (const seen of facts.values()) {
        if (seen.get('created') === true && seen.get('creation-uncertain') === true) return reject()
        if (seen.get('verified') === true && seen.get('deferred') === true) return reject()
        if (seen.get('instance-equal') === true && seen.get('instance-known') !== true) return reject()
    }
    const reproduced = facts.get('complete')?.get('reproduced') === true
    const changed = facts.get('complete')?.get('debugger-changed-behavior') === true
    if (reproduced && (changed || facts.get('baseline-wait')?.get('dll-init-failed') !== true || !exited || ['event-protocol', 'exit-continued', 'held-exit-match'].some((key) => facts.get('debug-events')?.get(key) !== true))) return reject()
    if (facts.get('complete')?.get('startup-proof') === true) return reject()
    const complete = !failure && active === null && events >= 2 && exited && next === phases.length && phases.every((phase) => stages.get(phase) === 'ok' && debuggerSchema[phase].every((key) => facts.get(phase)?.get(key) === !falseKeys.has(key)))
    return { lines, complete, reproduced: complete && reproduced, changed, firstFailure, reason: null }
}
