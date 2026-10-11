// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Concrete production coverage for the 25 numbered RDX Manager feature
 * documents. A mapping names only a surface that exists in the application;
 * unresolved native behavior is represented as an explicit state instead of
 * an operation.
 */
export const FEATURE_TARGET_REGISTRY = Object.freeze({
    route: Object.freeze({
        activity: targetDeclaration('support-overlay', '[data-action="open-event-log"]'),
        compatibility: targetDeclaration('support-overlay', '[data-action="open-compatibility"]'),
        status: targetDeclaration('device-area', '[data-area="status"]')
    }),
    'platform-state': Object.freeze({
        'localized-desktop-integration': targetDeclaration('implemented-platform-boundary', 'src/renderer/desktop-settings.mjs', 'createLiveTranslator'),
        'packaging-external': targetDeclaration('external-acceptance-required', 'docs/verification/platform-verification.md', 'Code signing, notarization, service installation, packaging'),
        'tray-lifecycle': targetDeclaration('implemented-platform-boundary', 'src/main/tray-controller.mjs', 'class TrayController'),
        'windows-drive-letter': targetDeclaration('implemented-platform-boundary', 'src/renderer/workflows/mode-workflow.mjs', 'drive-letter-windows-only')
    }),
    'evidence-state': Object.freeze({
        'access-security-write-unproven': targetDeclaration('evidence-incomplete', 'src/renderer/security-evidence-registry.mjs', 'selector-and-session-close-descriptor-semantics-unproven'),
        'aes-media-layout-and-security-write-unproven': targetDeclaration('evidence-incomplete', 'src/renderer/security-evidence-registry.mjs', 'compatible-aes-media-layout-and-security-write-unproven'),
        'automatic-auth-write-unproven': targetDeclaration('evidence-incomplete', 'src/renderer/security-evidence-registry.mjs', 'drive-generated-secret-selector-semantics-unproven'),
        'basic-protection-security-write-unproven': targetDeclaration('evidence-incomplete', 'src/renderer/security-evidence-registry.mjs', 'selector-flags-and-aggregate-semantics-unproven'),
        'credential-slot-write-unproven': targetDeclaration('evidence-incomplete', 'src/renderer/security-evidence-registry.mjs', 'temporary-slot-transaction-selectors-unproven'),
        'protection-removal-write-unproven': targetDeclaration('evidence-incomplete', 'src/renderer/security-evidence-registry.mjs', 'selector-and-remove-descriptor-semantics-unproven')
    })
})

export const FEATURE_MANIFEST = Object.freeze([
    feature(1, 'Drive discovery and Auto Scan', '01-drive-discovery-and-auto-scan.md', 'route', 'status'),
    feature(2, 'Drive and cartridge status', '02-drive-and-cartridge-status.md', 'route', 'status'),
    feature(3, 'Event logging', '03-event-logging.md', 'route', 'activity'),
    feature(4, 'RDX system summary', '04-system-summary.md', 'help', 'system-summary'),
    feature(5, 'Help, About and update checking', '05-help-and-update-checking.md', 'help', 'updates'),
    feature(6, 'Full-disk AES-256-XTS encryption', '06-full-disk-aes-256-xts-encryption.md', 'evidence-state', 'aes-media-layout-and-security-write-unproven'),
    feature(7, 'Basic password protection', '07-basic-password-protection.md', 'evidence-state', 'basic-protection-security-write-unproven'),
    feature(8, 'Disable and enable cartridge access', '08-disable-and-enable-cartridge-access.md', 'evidence-state', 'access-security-write-unproven'),
    feature(9, 'Change and remove protection', '09-change-and-remove-protection.md', 'evidence-state', 'protection-removal-write-unproven'),
    feature(10, 'Advanced passwords and permissions', '10-advanced-passwords-and-permissions.md', 'evidence-state', 'credential-slot-write-unproven'),
    feature(11, 'Automatic drive/media authentication', '11-automatic-drive-media-authentication.md', 'evidence-state', 'automatic-auth-write-unproven'),
    feature(12, 'Self Test', '12-self-test.md', 'operation', 'self-test'),
    feature(13, 'LED Test', '13-led-test.md', 'operation', 'led-test'),
    feature(14, 'Write/Read Test', '14-write-read-test.md', 'operation', 'write-read-test'),
    feature(15, 'Firmware update', '15-firmware-update.md', 'operation', 'firmware-update'),
    feature(16, 'Set and reset drive letter', '16-set-and-reset-drive-letter.md', 'platform-state', 'windows-drive-letter'),
    feature(17, 'Partition and format cartridge', '17-partition-and-format-cartridge.md', 'operation', 'format'),
    feature(18, 'Change Fixed/Removable mode', '18-change-drive-mode.md', 'operation', 'drive-mode-set'),
    feature(19, 'Change SATA III speed mode', '19-change-sata-iii-mode.md', 'operation', 'sata-mode-set'),
    feature(20, 'Eject cartridge and command-line eject', '20-eject-cartridge-and-command-line.md', 'operation', 'eject-safe'),
    feature(21, 'GUI language selection', '21-gui-language-selection.md', 'platform-state', 'localized-desktop-integration'),
    feature(22, 'Tray and background integration', '22-tray-and-background-integration.md', 'platform-state', 'tray-lifecycle'),
    feature(23, 'Installation, launch, Exit and uninstallation', '23-installation-launch-exit-and-uninstallation.md', 'platform-state', 'packaging-external'),
    feature(24, 'Platform, hardware and media compatibility', '24-platform-hardware-and-media-compatibility.md', 'route', 'compatibility'),
    feature(25, 'Support and troubleshooting', '25-support-troubleshooting-and-known-limitations.md', 'help', 'troubleshooting')
])

/**
 * Creates one frozen route selector or source-evidence declaration.
 * @param {string} state - Concrete production surface or bounded state.
 * @param {string} reference - DOM selector or repository-relative source.
 * @param {string} [anchor] - Exact source token proving the declared state.
 * @returns {object} Immutable target declaration.
 */
function targetDeclaration(state, reference, anchor) {
    return Object.freeze(anchor === undefined ? { selector: reference, surface: state } : { anchor, reference, state })
}

/**
 * Resolves a bounded non-operation feature target declaration.
 * @param {unknown} type - Candidate route or explicit-state mapping type.
 * @param {unknown} target - Candidate stable target identifier.
 * @returns {object|null} Frozen production declaration or null for arbitrary targets.
 */
export function resolveFeatureTarget(type, target) {
    if (typeof type !== 'string' || typeof target !== 'string' || !Object.hasOwn(FEATURE_TARGET_REGISTRY, type)) return null
    return Object.hasOwn(FEATURE_TARGET_REGISTRY[type], target) ? FEATURE_TARGET_REGISTRY[type][target] : null
}

/**
 * Builds and deeply freezes one manifest record.
 * @param {number} documentNumber - Numbered documentation group.
 * @param {string} title - Published feature title.
 * @param {string} source - Basename of the numbered source document.
 * @param {'route'|'operation'|'help'|'platform-state'|'evidence-state'} type - Honest production mapping class.
 * @param {string} target - Stable concrete route, operation, help, or state identifier.
 * @returns {object} Frozen feature coverage record.
 */
function feature(documentNumber, title, source, type, target) {
    if (Object.hasOwn(FEATURE_TARGET_REGISTRY, type) && resolveFeatureTarget(type, target) === null) {
        throw new TypeError(`Feature ${documentNumber} uses undeclared ${type} target: ${target}`)
    }
    return Object.freeze({ documentNumber, title, source, mapping: Object.freeze({ type, target }) })
}

/**
 * Returns a copy of one feature's concrete coverage mapping.
 * @param {unknown} documentNumber - Candidate numbered feature group.
 * @returns {{type: string, target: string}|null} Mapping copy or null when unknown.
 */
export function getFeatureCoverage(documentNumber) {
    for (const entry of FEATURE_MANIFEST) {
        if (entry.documentNumber === documentNumber) return { ...entry.mapping }
    }
    return null
}
