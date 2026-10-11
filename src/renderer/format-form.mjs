// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Captures transient format fields before a background render. They never enter
 * the renderer store, logs, or serialized markup.
 * @param {HTMLElement} root - Application root.
 * @returns {object|null} Draft bound to one exact dock and cartridge.
 */
export function captureFormatForm(root) {
    const card = root.querySelector('[data-feature="format"]')
    if (!card) return null
    return {
        target: card.dataset.formatTarget,
        identity: card.querySelector('[data-format-confirmation]')?.dataset.expectedIdentity,
        confirmation: card.querySelector('[data-format-confirmation]')?.value,
        filesystem: card.querySelector('[data-utility-filesystem]')?.value,
        passwords: [...card.querySelectorAll('[data-format-password]')].map((input) => input.value)
    }
}

/**
 * Restores only an unchanged cartridge's transient draft, then derives button
 * readiness from the current capability and visible controls.
 * @param {HTMLElement} root - Application root.
 * @param {object|null} draft - Previous live form fields.
 * @param {Function} translator - Active translator.
 * @returns {void} Updates controls without moving focus or scroll.
 */
export function restoreFormatForm(root, draft, translator) {
    const card = root.querySelector('[data-feature="format"]')
    if (!card) return
    const input = card.querySelector('[data-format-confirmation]')
    const sameTarget = draft?.target === card.dataset.formatTarget && draft?.identity === input?.dataset.expectedIdentity
    input.value = sameTarget ? (draft.confirmation ?? '') : ''
    const filesystem = card.querySelector('[data-utility-filesystem]')
    if (sameTarget && [...filesystem.options].some((option) => option.value === draft.filesystem)) filesystem.value = draft.filesystem
    for (const [index, password] of [...card.querySelectorAll('[data-format-password]')].entries()) password.value = sameTarget ? (draft.passwords[index] ?? '') : ''
    updateFormatForm(card, translator)
}

/**
 * Re-evaluates the actual form after input, selection, and hardware refresh.
 * @param {HTMLElement} card - Format card.
 * @param {Function} translator - Active translator.
 * @returns {void} Updates readiness and its visible, accessible explanation.
 */
export function updateFormatForm(card, translator) {
    const input = card.querySelector('[data-format-confirmation]')
    const button = card.querySelector('[data-action="start-format"]')
    const matched = Boolean(input.dataset.expectedIdentity) && input.value === input.dataset.expectedIdentity
    const filesystem = card.querySelector('[data-utility-filesystem]')
    const capacityReady = filesystem.selectedOptions[0]?.disabled === false
    const encrypted = filesystem.value.endsWith('-encrypted')
    const passwords = [...card.querySelectorAll('[data-format-password]')]
    for (const field of passwords) field.closest('label').hidden = !encrypted
    const passwordReady = !encrypted || (passwords[0]?.value.length >= 1 && new TextEncoder().encode(passwords[0].value).length <= 512 && passwords[0].value === passwords[1]?.value && !/[\r\n\0]/.test(passwords[0].value))
    button.disabled = !matched || !passwordReady || !capacityReady || button.dataset.readyWhenConfirmed !== 'true'
    const reason = !capacityReady ? translator('utilities.format.capacityUnsupported') : !matched ? translator('utilities.prerequisite.exactIdentity.required', { identity: input.dataset.expectedIdentity ?? '' }) : !passwordReady ? translator('utilities.format.passwordRequired') : button.dataset.readyWhenConfirmed !== 'true' ? button.dataset.unavailableReason : ''
    button.title = reason
    const hint = card.querySelector('[data-format-hint]')
    if (hint) {
        hint.textContent = reason
        hint.hidden = reason === ''
    }
}
