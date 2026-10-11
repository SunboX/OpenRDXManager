// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Returns filesystem label bounds without applying Linux limits to other formats.
 * @param {string|undefined} filesystem - Reported on-disk filesystem.
 * @returns {{maximum: number, bytes?: number}} UTF-16 input ceiling and optional UTF-8 byte limit.
 */
export function volumeLabelLimits(filesystem) {
    switch (filesystem?.toLowerCase()) {
        case 'exfat':
        case 'fat16':
        case 'fat32':
            return { maximum: 11 }
        case 'ext2':
        case 'ext3':
        case 'ext4':
            return { maximum: 16, bytes: 16 }
        case 'xfs':
            return { maximum: 12, bytes: 12 }
        default:
            return { maximum: 32 }
    }
}

/**
 * Captures a transient name draft bound to cartridge, filesystem and current label.
 * @param {HTMLElement} root - Application root.
 * @returns {object|null} Local draft; never sent to hardware without submission.
 */
export function captureVolumeLabelForm(root) {
    const input = root.querySelector('[data-utility-volume-label]')
    return input ? { binding: input.dataset.labelBinding, value: input.value } : null
}

/**
 * Restores only the same cartridge's draft and recomputes current readiness.
 * @param {HTMLElement} root - Application root.
 * @param {object|null} draft - Previously mounted local input.
 * @param {boolean} submitting - Whether the start request is still pending.
 * @returns {void} Updates the live field and button without moving focus.
 */
export function restoreVolumeLabelForm(root, draft, submitting = false) {
    const input = root.querySelector('[data-utility-volume-label]')
    if (!input) return
    const value = draft?.binding === input.dataset.labelBinding ? draft.value : input.dataset.currentValue
    // Assigning a different value moves the caret; leave a retained draft alone.
    if (input.value !== value) input.value = value
    updateVolumeLabelForm(input, submitting)
}

/**
 * Derives rename readiness from live input, capability and submission ownership.
 * @param {HTMLInputElement} input - Cartridge-name input.
 * @param {boolean} submitting - Whether the start request is still pending.
 * @returns {void} Updates the associated Save Name button.
 */
export function updateVolumeLabelForm(input, submitting = false) {
    const button = input.closest('[data-feature]')?.querySelector('[data-utility-operation="volume-label-set"]')
    if (!button) return
    button.disabled = submitting || input.disabled || input.dataset.labelAvailable !== 'true' || input.value === input.dataset.currentValue || input.value.length > input.maxLength || (input.dataset.labelByteLimit && new TextEncoder().encode(input.value).length > Number(input.dataset.labelByteLimit)) || !input.value.isWellFormed() || /[\u0000-\u001f\u007f-\u009f\\/:*?"<>|]/u.test(input.value)
    if (submitting) button.setAttribute('aria-busy', 'true')
    else button.removeAttribute('aria-busy')
}
