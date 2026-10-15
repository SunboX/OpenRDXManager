// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

const phases = ['caller', 'runtime', 'donor-discovery', 'donor-proof', 'caller-check', 'donor-check']
const keys = Object.freeze({
    caller: ['query-ok', 'elevated-admin', 'interactive-enabled', 'service-enabled', 'batch-enabled', 'active-console-session'],
    donor: ['query-ok', 'ordinary-medium', 'no-enabled-admins', 'caller-user-equal', 'mapped-generation-known'],
    preservation: ['query-ok', 'instance-known', 'instance-equal', 'logon-equal', 'modified-equal', 'properties-equal', 'default-dacl-equal', 'descriptor-equal'],
    copy: ['query-ok', 'instance-known', 'copy-distinct', 'logon-equal', 'modified-equal', 'properties-equal', 'default-dacl-equal']
})

/**
 * Validates the nested, bounded acquisition/copy transcript emitted by the existing native source lease.
 * It is an observation parser, never an independent acceptance or process authority.
 */
export class ManagerSourceContextEvidence {
    /** @param {ReadonlySet<string>} reasons Exact NativeError names. */
    constructor(reasons) {
        this.reasons = reasons
        this.active = null
        this.next = 0
        this.failed = false
        this.counts = new Map()
        this.copyBefore = 0
        this.copyAfter = 0
        this.copySeen = false
        this.duplicateStarted = false
        this.callerEqual = undefined
    }

    /**
     * Reconstructs one closed nested row in its owning outer phase.
     * @param {string} line Captured input, never returned without schema validation.
     * @param {string|null} outer Current outer checkpoint.
     * @returns {string|null} Canonical row or null on malformed/out-of-context input.
     */
    consume(line, outer) {
        const stage = /^openrdx-manager-source-task-one-stage phase=([a-z-]+) status=(begin|ok|failed)(?: reason=([A-Za-z]+))?$/u.exec(line)
        if (stage !== null) {
            const [, phase, status, reason] = stage
            const index = phases.indexOf(phase)
            if (outer !== 'donor-proof' || index < 0 || (status === 'failed' ? !this.reasons.has(reason) : reason !== undefined)) return null
            if (status === 'begin') {
                if (this.active !== null || index < this.next || (this.failed && index < 4) || (index !== this.next && !(this.failed && index >= 4))) return null
                this.active = phase
                this.next = index + 1
            } else {
                if (this.active !== phase) return null
                if (status === 'failed') this.failed = true
                if (status === 'ok' && !this.phaseComplete(phase)) this.failed = true
                this.active = null
            }
            return `openrdx-manager-source-task-one-stage phase=${phase} status=${status}${reason === undefined ? '' : ` reason=${reason}`}`
        }
        const match = /^openrdx-manager-source-task-one-(caller|donor|preservation|copy) (.+)$/u.exec(line)
        if (match === null) return null
        const [, kind, suffix] = match
        // Admission is checked once before copy observations; a later known false
        // preservation row remains reportable and can never restore completion.
        if (outer === 'duplicate' && !this.duplicateStarted) {
            if (!this.acquired()) return null
            this.duplicateStarted = true
        }
        const expected = keys[kind]
        const pairs = suffix.split(' ')
        if (pairs.length !== expected.length) return null
        const facts = new Map()
        for (const [index, pair] of pairs.entries()) {
            const field = /^([a-z-]+)=(true|false)$/u.exec(pair)
            if (field === null || field[1] !== expected[index]) return null
            const value = field[2] === 'true'
            facts.set(field[1], value)
            if (!['modified-equal', 'caller-user-equal'].includes(field[1]) && value !== !['service-enabled', 'batch-enabled', 'mapped-generation-known'].includes(field[1])) this.failed = true
        }
        if (outer === 'donor-proof') {
            if (!((kind === 'caller' && this.active === 'caller') || (kind === 'donor' && this.active === 'donor-proof') || (kind === 'preservation' && ['caller-check', 'donor-check'].includes(this.active)))) return null
            const limit = this.active === 'caller-check' ? 2 : this.active === 'donor-check' ? 4 : 1
            const count = (this.counts.get(this.active) ?? 0) + 1
            if (count > limit) return null
            this.counts.set(this.active, count)
            if (kind === 'donor') this.callerEqual = facts.get('caller-user-equal')
        } else if (outer === 'duplicate') {
            if (kind === 'copy') {
                if (this.copySeen || this.copyBefore !== 9) return null
                this.copySeen = true
            } else if (kind === 'preservation') {
                if (this.copySeen) {
                    if (++this.copyAfter > 4) return null
                } else if (++this.copyBefore > 9) return null
            } else return null
        } else return null
        return `openrdx-manager-source-task-one-${kind} ${expected.map((key) => `${key}=${facts.get(key)}`).join(' ')}`
    }

    /** @param {string} phase Fixed acquisition phase. @returns {boolean} Whether all actual nested rows were seen. */
    phaseComplete(phase) {
        const expected = { caller: 1, runtime: 0, 'donor-discovery': 0, 'donor-proof': 1, 'caller-check': 2, 'donor-check': 4 }[phase]
        return (this.counts.get(phase) ?? 0) === expected
    }

    /** @returns {boolean} Complete successful nested acquisition, never mapped-image proof. */
    acquired() {
        return !this.failed && this.active === null && this.next === phases.length && phases.every((phase) => this.phaseComplete(phase))
    }

    /** @returns {boolean} Exact successful duplicate observation sequence. */
    copied() {
        return this.acquired() && this.copySeen && this.copyBefore === 9 && this.copyAfter === 4
    }
}
