// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

export const managerSourceName = 'service_acl::windows_impl::restricted_token_probe::medium::child::manager_source_proof::native_authenticated_manager_source_proof'
export const managerSourceFields = Object.freeze({
    'donor-proof': ['available', 'enrolled', 'image', 'ordinary-medium', 'caller-user-equal', 'mapped-generation-known'],
    duplicate: ['copy-distinct'],
    'copy-proof': ['properties-equal', 'default-dacl-equal', 'descriptor-equal'],
    fixtures: ['protected', 'caller-owned'],
    'wait-create': ['created', 'creation-uncertain'],
    'wait-proof': ['query-ok', 'image', 'user-equal', 'session-equal', 'elevation-equal', 'integrity-equal', 'ui-access-equal', 'sandbox-inert-equal', 'primary-equal', 'elevation-type-equal', 'groups-equal', 'privileges-equal', 'default-dacl-equal', 'no-enabled-admins', 'donor-properties-equal', 'instance-known'],
    'wait-resume': ['fresh'],
    'wait-observe': ['timeout-alive'],
    'wait-reap': ['verified', 'deferred'],
    'proof-create': ['created', 'creation-uncertain'],
    'proof-proof': ['query-ok', 'image', 'user-equal', 'session-equal', 'elevation-equal', 'integrity-equal', 'ui-access-equal', 'sandbox-inert-equal', 'primary-equal', 'elevation-type-equal', 'groups-equal', 'privileges-equal', 'default-dacl-equal', 'no-enabled-admins', 'donor-properties-equal', 'instance-known'],
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

/** @returns {string} Synthetic private-state preservation observation, never runtime proof. */
export function preservation() {
    return 'openrdx-manager-source-task-one-preservation query-ok=true instance-known=true instance-equal=true logon-equal=true modified-equal=false properties-equal=true default-dacl-equal=true descriptor-equal=true'
}

/** @param {boolean} callerEqual Valid known same/different-account observation. @returns {string[]} Synthetic nested acquisition transcript. */
export function donorRows(callerEqual) {
    const lines = []
    for (const phase of ['caller', 'runtime', 'donor-discovery', 'donor-proof', 'caller-check', 'donor-check']) {
        lines.push(`openrdx-manager-source-task-one-stage phase=${phase} status=begin`)
        if (phase === 'caller') lines.push('openrdx-manager-source-task-one-caller query-ok=true elevated-admin=true interactive-enabled=true service-enabled=false batch-enabled=false active-console-session=true')
        if (phase === 'donor-proof') lines.push(`openrdx-manager-source-task-one-donor query-ok=true ordinary-medium=true no-enabled-admins=true caller-user-equal=${callerEqual} mapped-generation-known=false`)
        if (phase === 'caller-check' || phase === 'donor-check') lines.push(...Array.from({ length: phase === 'caller-check' ? 2 : 4 }, preservation))
        lines.push(`openrdx-manager-source-task-one-stage phase=${phase} status=ok`)
    }
    return lines
}

/** @returns {string[]} Synthetic nested copy observations with fixed pre/post preservation counts. */
export function copyRows() {
    return [...Array.from({ length: 9 }, preservation), 'openrdx-manager-source-task-one-copy query-ok=true instance-known=true copy-distinct=true logon-equal=true modified-equal=false properties-equal=true default-dacl-equal=true', ...Array.from({ length: 4 }, preservation)]
}

/** @param {boolean} [callerEqual] Known observational equality, never an authorization shortcut. @returns {string} Complete synthetic native transcript for deterministic gate tests. */
export function managerSourceOutput(callerEqual = false) {
    const lines = ['running 1 test']
    for (const [phase, keys] of Object.entries(managerSourceFields)) {
        lines.push(`openrdx-manager-source-stage phase=${phase} status=begin`)
        if (phase === 'donor-proof') lines.push(...donorRows(callerEqual))
        if (phase === 'duplicate') lines.push(...copyRows())
        if (phase === 'wait-observe' || phase === 'proof-exit') lines.push(`openrdx-manager-source-exit phase=${phase} category=${phase === 'wait-observe' ? 'alive' : 'success'}`)
        lines.push(`openrdx-manager-source phase=${phase} ${keys.map((key) => `${key}=${key === 'caller-user-equal' ? callerEqual : !['mapped-generation-known', 'creation-uncertain', 'deferred'].includes(key)}`).join(' ')}`)
        lines.push(`openrdx-manager-source-stage phase=${phase} status=ok`)
    }
    return `${lines.join('\n')}\ntest ${managerSourceName} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 150 filtered out; finished in 0.00s\n`
}
