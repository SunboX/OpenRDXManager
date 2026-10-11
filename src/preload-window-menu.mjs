// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { WindowMenuChannel } from './shared/window-menu.mjs'

/**
 * Mounts the dark menu strip while keeping native popup access inside preload.
 * @param {{document: Document, transport: object}} dependencies - Isolated preload DOM and IPC.
 * @returns {Promise<void>} Completes after mounting the main-owned menu labels.
 */
export async function mountWindowMenu({ document, transport }) {
    const bar = document.querySelector('.window-menubar')
    if (!bar) return
    let entries
    try {
        entries = await transport.invoke(WindowMenuChannel.list)
    } catch {
        return
    }
    if (!Array.isArray(entries)) return
    const buttons = []
    for (const entry of entries) {
        if (!Number.isSafeInteger(entry.index) || typeof entry.label !== 'string') continue
        const button = document.createElement('button')
        button.type = 'button'
        button.textContent = entry.label
        button.setAttribute('role', 'menuitem')
        button.setAttribute('aria-haspopup', 'menu')
        button.setAttribute('aria-expanded', 'false')
        button.disabled = entry.enabled === false
        button.tabIndex = buttons.length === 0 ? 0 : -1
        /** @returns {Promise<void>} Opens only the matching main-owned native submenu. */
        async function openMenu() {
            if (button.getAttribute('aria-expanded') === 'true') return
            const rect = button.getBoundingClientRect()
            button.setAttribute('aria-expanded', 'true')
            try {
                await transport.invoke(WindowMenuChannel.open, { index: entry.index, x: Math.max(0, Math.round(rect.left)), y: Math.max(0, Math.round(rect.bottom)) })
            } catch {
                // A closing window or unavailable native menu must not produce a renderer error.
            } finally {
                button.setAttribute('aria-expanded', 'false')
            }
        }
        button.addEventListener('click', openMenu)
        buttons.push(button)
        bar.append(button)
    }
    /** @param {KeyboardEvent} event - Menu keyboard navigation. @returns {void} Moves focus without replacing native submenu behavior. */
    function navigate(event) {
        const current = buttons.indexOf(document.activeElement)
        if (current === -1) return
        let target
        if (event.key === 'ArrowRight') target = (current + 1) % buttons.length
        else if (event.key === 'ArrowLeft') target = (current + buttons.length - 1) % buttons.length
        else if (event.key === 'Home') target = 0
        else if (event.key === 'End') target = buttons.length - 1
        else if (event.key === 'ArrowDown') {
            event.preventDefault()
            buttons[current].click()
            return
        } else return
        event.preventDefault()
        for (const [index, button] of buttons.entries()) button.tabIndex = index === target ? 0 : -1
        buttons[target].focus()
    }
    /** @param {KeyboardEvent} event - Document keyboard event. @returns {void} Preserves conventional F10 menu access. */
    function focusMenu(event) {
        if (event.key === 'F10' && !event.shiftKey && buttons.length > 0) {
            event.preventDefault()
            buttons.find((button) => button.tabIndex === 0)?.focus()
        }
    }
    bar.addEventListener('keydown', navigate)
    document.addEventListener('keydown', focusMenu)
}
