// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Defines the closed readiness projections admitted by the real stdio test host.
 * Windows hosted runners may have administrator SPTI authority without any RDX
 * device. Transport authority never becomes physical hardware verification.
 * @param {string} platform - Actual host OS.
 * @param {boolean} privileged - Reported direct-process authority, validated below.
 * @returns {object} Exact expected host readiness fields.
 * @throws {TypeError} For an invalid privilege projection.
 */
export function nativeHostReadiness(platform, privileged) {
    if (typeof privileged !== 'boolean' || (privileged && platform !== 'win32')) throw new TypeError('invalid-native-host-privilege')
    const native = ['darwin', 'win32', 'linux'].includes(platform)
    const platformCapability = privileged ? { state: 'available' } : ['win32', 'linux'].includes(platform) ? { state: 'transport-unavailable', reason: 'raw-transport-unavailable' } : native ? { state: 'insufficient-permission', reason: 'privileged-service-unavailable' } : { state: 'transport-unavailable', reason: 'platform-adapter-not-implemented' }
    return { mode: native ? 'native' : 'no-device', privileged, hardwareReady: privileged, hardwareVerified: false, platformCapability }
}
