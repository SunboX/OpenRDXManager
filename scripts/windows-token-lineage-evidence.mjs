// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

const prefix = 'openrdx-token-object-lineage'
const roles = new Set(['token', 'process-token', 'thread-token', 'process-thread-token'])
const initial = ['source-initial-query-ok', 'source-initial-layout-valid']
const final = ['source-final-query-ok', 'source-final-layout-valid', 'source-stable-known', 'source-stable-id-equal', 'source-stable-logon-equal', 'source-stable-modified-equal']
const stats = ['source', 'derived', 'actual', 'source-initial', 'derived-initial'].flatMap((subject) => ['query-ok', 'layout-valid'].map((part) => `${subject}-${part}`))
const pairs = ['source-stable', 'derived-stable', 'source-derived', 'source-actual', 'derived-actual']
const profile = ['profile-valid', 'descriptor-query-ok', ...['baseline', 'expected', 'actual'].flatMap((object) => ['grant-absent', 'grant-single', 'grant-duplicate'].map((part) => `${object}-${part}`)), ...['baseline', 'expected'].flatMap((object) => ['acl-bytes-equal', 'ace-sequence-equal', 'header-equal', 'padding-equal'].map((part) => `${object}-${part}`)), 'old-aces-retained', 'denials-equal', 'one-addition', 'owner-preserved', 'group-preserved', 'label-preserved', 'control-preserved']
const read = new Set(['fresh-proof', 'actual-open-ok', 'full-properties-known', 'full-properties-equal', ...stats, ...pairs.flatMap((pair) => ['known', 'id-equal', 'logon-equal', 'modified-equal'].map((part) => `${pair}-${part}`)), ...profile])

/**
 * Captures closed optional lineage/profile facts only within matching live matrix phases.
 * Query/layout/comparison-known are separate; facts never authorize any ordinary child or setter.
 */
export class TokenLineageEvidence {
    #seen = new Map()
    /**
     * @param {string} line Bounded native line, never forwarded before reconstruction.
     * @param {string|null} active Exact active matrix row/phase.
     * @returns {string|null} Reconstructed line, null on unknown/duplicate/orphan/private data.
     */
    accept(line, active) {
        const match = /^openrdx-token-object-lineage row=([a-z-]+) phase=([a-z-]+) (.+)$/u.exec(line)
        if (match === null) return null
        const [, row, phase, suffix] = match
        const key = `${row}/${phase}`
        const keys = row === 'matrix' ? (phase === 'setup' ? initial : phase === 'source-check' ? final : null) : roles.has(row) && phase === 'read' ? read : null
        if (keys === null || active !== key) return null
        const seen = this.#seen.get(key) ?? new Map()
        const output = []
        for (const pair of suffix.split(' ')) {
            const value = /^([a-z-]+)=(true|false)$/u.exec(pair)
            if (value === null || (!keys.includes?.(value[1]) && !keys.has?.(value[1])) || seen.has(value[1])) return null
            seen.set(value[1], value[2] === 'true')
            output.push(`${value[1]}=${value[2]}`)
        }
        this.#seen.set(key, seen)
        return `${prefix} row=${row} phase=${phase} ${output.join(' ')}`
    }
    /** @returns {boolean} Mathematical/schema consistency only, never acceptance authority. */
    valid() {
        for (const [key, seen] of this.#seen) {
            for (const subject of ['source', 'derived', 'actual', 'source-initial', 'derived-initial', 'source-final']) if (seen.get(`${subject}-layout-valid`) === true && seen.get(`${subject}-query-ok`) !== true) return false
            if (seen.get('full-properties-equal') === true && seen.get('full-properties-known') !== true) return false
            if (key === 'matrix/source-check') {
                const known = seen.get('source-stable-known')
                const initial = this.#seen.get('matrix/setup')
                if (known !== undefined && known !== (initial?.get('source-initial-layout-valid') === true && seen.get('source-final-layout-valid') === true)) return false
                if (known === false && ['id-equal', 'logon-equal', 'modified-equal'].some((part) => seen.get(`source-stable-${part}`) === true)) return false
            }
            if (key.endsWith('/read')) {
                const interpreted = [...stats, ...profile, ...pairs.flatMap((pair) => ['known', 'id-equal', 'logon-equal', 'modified-equal'].map((part) => `${pair}-${part}`))].some((field) => seen.has(field))
                if (interpreted && ['fresh-proof', 'actual-open-ok', 'full-properties-known', 'full-properties-equal'].some((field) => seen.get(field) !== true)) return false
                for (const pair of pairs) {
                    const known = seen.get(`${pair}-known`)
                    if (known === false && ['id-equal', 'logon-equal', 'modified-equal'].some((part) => seen.get(`${pair}-${part}`) === true)) return false
                    if (known !== undefined) {
                        const [left, right] = pair === 'source-stable' ? ['source-initial', 'source'] : pair === 'derived-stable' ? ['derived-initial', 'derived'] : pair.split('-')
                        if (known !== (seen.get(`${left}-layout-valid`) === true && seen.get(`${right}-layout-valid`) === true)) return false
                    }
                }
                const known = ['source-derived', 'source-actual', 'derived-actual'].every((pair) => seen.get(`${pair}-known`) === true)
                if (known) for (const field of ['id-equal', 'logon-equal', 'modified-equal']) if (['source-derived', 'source-actual', 'derived-actual'].filter((pair) => seen.get(`${pair}-${field}`) === true).length === 2) return false
                if (profile.filter((field) => !['profile-valid', 'descriptor-query-ok'].includes(field)).some((field) => seen.has(field)) && seen.get('profile-valid') !== true) return false
                if (seen.get('profile-valid') === true) {
                    if (seen.get('descriptor-query-ok') !== true) return false
                    for (const object of ['baseline', 'expected', 'actual']) if (['grant-absent', 'grant-single', 'grant-duplicate'].filter((part) => seen.get(`${object}-${part}`) === true).length !== 1) return false
                    for (const object of ['baseline', 'expected']) {
                        // Exact bytes include the ACL header, used ACE sequence and padding. A missing comparison is unknown.
                        if (seen.get(`${object}-acl-bytes-equal`) === true && ['ace-sequence-equal', 'header-equal', 'padding-equal'].some((part) => seen.get(`${object}-${part}`) !== true)) return false
                        // Equal ACE sequences cannot disagree about this fixed grant's observed multiplicity.
                        if (seen.get(`${object}-ace-sequence-equal`) === true && ['grant-absent', 'grant-single', 'grant-duplicate'].some((part) => seen.get(`${object}-${part}`) !== seen.get(`actual-${part}`))) return false
                    }
                    if (seen.get('one-addition') === true && ['old-aces-retained', 'denials-equal'].some((field) => seen.get(field) !== true)) return false
                    if (seen.get('one-addition') === true && (((seen.get('baseline-grant-single') === true || seen.get('baseline-grant-duplicate') === true) && seen.get('actual-grant-duplicate') !== true) || (seen.get('baseline-grant-absent') === true && seen.get('actual-grant-single') !== true))) return false
                }
            }
        }
        return true
    }
}
