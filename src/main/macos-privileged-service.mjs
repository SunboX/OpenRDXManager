// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

const LOCAL_STATES = new Set(['enabled', 'installer-required', 'repair-required'])

const NATIVE_STATES = new Set(['not-registered', 'enabled', 'requires-approval', 'not-found', 'invalid-signature', 'registration-failed'])

/**
 * Checks whether one value belongs to the closed ServiceManagement state vocabulary.
 * @param {unknown} value - Candidate native result.
 * @returns {value is string} True only for an approved state.
 */
function isNativeState(value) {
    return typeof value === 'string' && NATIVE_STATES.has(value)
}

/**
 * Creates the packaged-macOS-only privileged service controller.
 * @param {{addon?: object|null, localTrustAddon?: object|null, isPackaged: boolean, platform: string}} options - Runtime selector and fixed native adapter.
 * @returns {{getStatus: () => Promise<object>, register: () => Promise<object>, unregister: () => Promise<object>, openApprovalSettings: () => Promise<object>}} Frozen controller API.
 * @throws {TypeError} When an applicable runtime lacks the complete native adapter.
 */
export function createMacOsPrivilegedServiceController(options) {
    if (typeof options?.isPackaged !== 'boolean' || typeof options?.platform !== 'string') {
        throw new TypeError('macos-service-management-options-invalid')
    }
    const applicable = options.platform === 'darwin' && options.isPackaged
    const addon = options.addon
    if (applicable && (addon === null || typeof addon !== 'object' || ['installationMode', 'status', 'registerService', 'unregisterService', 'openApprovalSettings'].some((method) => typeof addon[method] !== 'function'))) {
        throw new TypeError('macos-service-management-addon-invalid')
    }

    /** @returns {'signed'|'local'|null} Installer-owned native mode; errors deny setup. */
    function getMode() {
        try {
            const mode = addon.installationMode()
            return mode === 'local' || mode === 'signed' ? mode : null
        } catch {
            return null
        }
    }

    /** @returns {Promise<object>} Verified local enrollment and retained native endpoint state. */
    async function getLocalStatus() {
        try {
            const state = await options.localTrustAddon?.localTrustStatus()
            return { state: LOCAL_STATES.has(state) ? state : 'repair-required' }
        } catch {
            return { state: 'repair-required' }
        }
    }

    /** @returns {Promise<object|null>} Installer guidance whenever signed registration is forbidden. */
    async function getInstallerActionFailure() {
        const mode = getMode()
        if (mode === 'signed') return null
        const state = mode === 'local' ? (await getLocalStatus()).state : 'repair-required'
        return { ok: false, reason: state === 'repair-required' ? state : 'installer-required' }
    }

    /** @returns {Promise<object>} Current closed service setup state. */
    async function getStatus() {
        if (!applicable) return { state: 'not-applicable' }
        const mode = getMode()
        if (mode === 'local') return getLocalStatus()
        if (mode !== 'signed') return { state: 'repair-required' }
        try {
            const state = addon.status()
            return isNativeState(state) ? { state } : { state: 'registration-failed', reason: 'invalid-native-response' }
        } catch {
            return { state: 'registration-failed', reason: 'native-service-management-failed' }
        }
    }

    /**
     * Executes one fixed zero-argument native action and maps its closed state.
     * @param {'registerService'|'unregisterService'} method - Fixed native method name.
     * @param {string} successfulState - State that represents success.
     * @returns {Promise<object>} Strict action result.
     */
    async function performStateAction(method, successfulState) {
        if (!applicable) return { ok: false, reason: 'not-applicable' }
        const guidance = await getInstallerActionFailure()
        if (guidance !== null) return guidance
        try {
            const state = addon[method]()
            if (!isNativeState(state)) return { ok: false, reason: 'invalid-native-response' }
            return state === successfulState ? { ok: true } : { ok: false, reason: state }
        } catch {
            return { ok: false, reason: 'native-service-management-failed' }
        }
    }

    /** @returns {Promise<object>} Registration result. */
    function register() {
        return performStateAction('registerService', 'enabled')
    }

    /** @returns {Promise<object>} Unregistration result. */
    async function unregister() {
        if (applicable && getMode() === 'local') return { ok: false, reason: 'installer-required' }
        return performStateAction('unregisterService', 'not-registered')
    }

    /** @returns {Promise<object>} Settings-navigation result. */
    async function openApprovalSettings() {
        if (!applicable) return { ok: false, reason: 'not-applicable' }
        if (getMode() === 'local') return { ok: false, reason: 'installer-required' }
        const guidance = await getInstallerActionFailure()
        if (guidance !== null) return guidance
        try {
            return addon.openApprovalSettings() === true ? { ok: true } : { ok: false, reason: 'invalid-native-response' }
        } catch {
            return { ok: false, reason: 'native-service-management-failed' }
        }
    }

    return Object.freeze({ getStatus, register, unregister, openApprovalSettings })
}
