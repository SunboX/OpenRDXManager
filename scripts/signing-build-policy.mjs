// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Keeps compile-time macOS client/helper team identities exact and consistent.
 * These build inputs cannot select runtime trust or authorize an IPC caller.
 * @param {NodeJS.ProcessEnv} environment - Validated build environment.
 * @returns {void}
 * @throws {TypeError} For malformed or disagreeing team identities.
 */
export function validateSigningBuildEnvironment(environment) {
    const canonical = environment.OPENRDX_MACOS_TEAM_ID
    const legacy = environment.OPENRDX_MANAGER_TEAM_ID
    for (const value of [canonical, legacy]) {
        if (value !== undefined && (typeof value !== 'string' || value.length !== 10 || !/^[A-Z0-9]{10}$/u.test(value))) throw new TypeError('native-service-signing-team-invalid')
    }
    if (canonical !== undefined && legacy !== undefined && canonical !== legacy) throw new TypeError('native-service-signing-team-mismatch')
}

/**
 * Selects the explicitly local installer build without altering the caller's
 * environment or inheriting a signed-only native helper requirement.
 * @param {NodeJS.ProcessEnv} source - Parent build environment.
 * @returns {NodeJS.ProcessEnv} Child-only environment with signing-team inputs removed.
 */
export function createLocalInstallerBuildEnvironment(source) {
    const environment = { ...source }
    delete environment.OPENRDX_MACOS_TEAM_ID
    delete environment.OPENRDX_MANAGER_TEAM_ID
    return environment
}
