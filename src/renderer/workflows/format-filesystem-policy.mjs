// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

const DUAL_FILESYSTEM_POLICY = Object.freeze({
    defaultFilesystem: 'ntfs',
    filesystemChoices: Object.freeze(['ntfs', 'exfat']),
    toolingKey: 'utilities.format.tooling'
})
const LINUX_FILESYSTEM_POLICY = Object.freeze({
    defaultFilesystem: 'ext4',
    filesystemChoices: Object.freeze(['ext4', 'ext3', 'ext2', 'xfs', 'btrfs', 'f2fs', 'ntfs', 'exfat', 'fat16', 'fat32']),
    toolingKey: 'utilities.format.tooling.linux'
})
const MACOS_FILESYSTEM_POLICY = Object.freeze({
    defaultFilesystem: 'exfat',
    filesystemChoices: Object.freeze(['exfat', 'fat', 'fat12', 'fat16', 'fat32', 'hfs', 'hfs-case-sensitive', 'hfs-journaled', 'hfs-case-sensitive-journaled', 'apfs', 'apfs-case-sensitive', 'apfs-encrypted', 'apfs-case-sensitive-encrypted']),
    toolingKey: 'utilities.format.tooling.macos'
})
const UNAVAILABLE_FILESYSTEM_POLICY = Object.freeze({
    defaultFilesystem: null,
    filesystemChoices: Object.freeze([]),
    toolingKey: 'utilities.format.tooling.unavailable'
})

/**
 * Returns the renderer policy matching the exact native formatter implemented
 * for one host. Unknown hosts remain closed instead of inheriting a default.
 * @param {unknown} platform - Candidate Electron host platform.
 * @returns {{defaultFilesystem: string|null, filesystemChoices: readonly (string)[], toolingKey: string}} Frozen host filesystem policy.
 */
export function getFormatFilesystemPolicy(platform) {
    if (platform === 'darwin') return MACOS_FILESYSTEM_POLICY
    if (platform === 'linux') return LINUX_FILESYSTEM_POLICY
    if (platform === 'win32') return DUAL_FILESYSTEM_POLICY
    return UNAVAILABLE_FILESYSTEM_POLICY
}

/**
 * Resolves a requested format only when the host formatter supports it,
 * otherwise returning the host default or null for an unknown host.
 * @param {unknown} platform - Candidate Electron host platform.
 * @param {unknown} requestedFilesystem - Candidate control value.
 * @returns {string|null} Supported selection, supported default, or null.
 */
export function normalizeFormatFilesystem(platform, requestedFilesystem) {
    const policy = getFormatFilesystemPolicy(platform)
    return policy.filesystemChoices.includes(requestedFilesystem) ? requestedFilesystem : policy.defaultFilesystem
}

/**
 * Checks a format value against the exact native formatter for one host.
 * @param {unknown} platform - Candidate Electron host platform.
 * @param {unknown} filesystem - Candidate structured request value.
 * @returns {boolean} True only for a host-supported closed filesystem value.
 */
export function isFormatFilesystemSupported(platform, filesystem) {
    return getFormatFilesystemPolicy(platform).filesystemChoices.includes(filesystem)
}
