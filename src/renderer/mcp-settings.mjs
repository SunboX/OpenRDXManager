// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { mcpStatusResponseSchema } from '../shared/mcp-schemas.mjs'

const mountedControllers = new WeakMap()

/**
 * Owns the native modal and its narrow MCP settings bridge independently of device renders.
 * Privileged clipboard work remains in main; this view only receives public status and action results.
 */
class McpSettingsView {
    #document
    #api
    #translate
    #dialog
    #controls
    #status = null
    #loaded = false
    #busy = false
    #feedback = null
    #generation = 0
    #pending = Promise.resolve()
    #opener = null

    /** @param {{document: Document, api?: object, translator: Function}} options - Browser document, narrow bridge, and live translator. */
    constructor({ document, api, translator }) {
        this.#document = document
        this.#api = api
        this.#translate = translator
        this.#dialog = document.createElement('dialog')
        this.#dialog.className = 'mcp-settings'
        this.#dialog.dataset.mcpSettings = ''
        this.#dialog.setAttribute('aria-labelledby', 'mcp-title')
        this.#dialog.setAttribute('aria-describedby', 'mcp-description')
        this.#dialog.innerHTML = `
            <header class="mcp-settings__header">
                <h1 id="mcp-title" data-mcp-label="mcp.title"></h1>
                <button class="icon-button" type="button" data-mcp-action="close" autofocus><i class="ph ph-x" aria-hidden="true"></i></button>
            </header>
            <form class="mcp-settings__body" novalidate>
                <p id="mcp-description" class="mcp-settings__description" data-mcp-label="mcp.description"></p>
                <label class="mcp-settings__toggle" for="mcp-enabled"><input id="mcp-enabled" type="checkbox" disabled /><span data-mcp-label="mcp.enable"></span></label>
                <div class="mcp-settings__port">
                    <label for="mcp-port" data-mcp-label="mcp.port"></label>
                    <input id="mcp-port" type="number" inputmode="numeric" min="1024" max="65535" step="1" required value="48170" aria-describedby="mcp-port-hint" disabled />
                    <p id="mcp-port-hint" data-mcp-label="mcp.portHint"></p>
                </div>
                <dl class="mcp-settings__connection">
                    <div><dt data-mcp-label="mcp.status.label"></dt><dd data-mcp-status></dd></div>
                    <div><dt data-mcp-label="mcp.endpoint"></dt><dd><code data-mcp-endpoint></code></dd></div>
                </dl>
                <p id="mcp-feedback" class="mcp-settings__feedback" data-mcp-feedback role="status" aria-live="polite" aria-atomic="true"></p>
                <div class="mcp-settings__actions">
                    <button class="button" type="button" data-mcp-action="copy" disabled><i class="ph ph-copy" aria-hidden="true"></i><span data-mcp-label="mcp.copy"></span></button>
                    <button class="button button--primary" type="submit" data-mcp-action="apply" disabled><span data-mcp-label="mcp.apply"></span></button>
                </div>
            </form>`
        this.#controls = {
            enabled: this.#dialog.querySelector('#mcp-enabled'),
            port: this.#dialog.querySelector('#mcp-port'),
            status: this.#dialog.querySelector('[data-mcp-status]'),
            endpoint: this.#dialog.querySelector('[data-mcp-endpoint]'),
            feedback: this.#dialog.querySelector('[data-mcp-feedback]'),
            apply: this.#dialog.querySelector('[data-mcp-action="apply"]'),
            copy: this.#dialog.querySelector('[data-mcp-action="copy"]'),
            close: this.#dialog.querySelector('[data-mcp-action="close"]')
        }
        document.body.append(this.#dialog)
        document.addEventListener('click', this.#handleDocumentClick.bind(this))
        this.#dialog.addEventListener('submit', this.#handleSubmit.bind(this))
        this.#dialog.addEventListener('cancel', this.#handleCancel.bind(this))
        this.#dialog.addEventListener('close', this.#handleClose.bind(this))
        this.#dialog.addEventListener('keydown', this.#handleKeyDown.bind(this))
        this.#controls.port.addEventListener('input', this.#handlePortInput.bind(this))
        this.refreshLanguage()
    }

    /** @returns {void} Updates translated text while preserving in-progress form input and focus. */
    refreshLanguage() {
        for (const element of this.#dialog.querySelectorAll('[data-mcp-label]')) element.textContent = this.#translate(element.dataset.mcpLabel)
        const closeLabel = this.#translate('mcp.close')
        this.#controls.close.setAttribute('aria-label', closeLabel)
        this.#controls.close.title = closeLabel
        this.#renderState()
    }

    /** @param {MouseEvent} event - Delegated document click. @returns {void} Opens settings or routes only this dialog's buttons. */
    #handleDocumentClick(event) {
        const opener = event.target?.closest?.('[data-action="open-mcp"]')
        if (opener && !opener.disabled) {
            this.#open(opener)
            return
        }
        const action = event.target?.closest?.('[data-mcp-action]')
        if (!action || !this.#dialog.contains(action) || action.disabled || !this.#dialog.open) return
        if (action.dataset.mcpAction === 'close') this.#dialog.close()
        if (action.dataset.mcpAction === 'copy' && !this.#busy) this.#pending = this.#copy()
    }

    /** @param {HTMLElement} opener - Current topbar control. @returns {void} Shows the modal immediately and refreshes status after any previous request. */
    #open(opener) {
        if (this.#dialog.open) return
        this.#opener = opener
        this.#status = null
        this.#loaded = false
        this.#busy = true
        this.#feedback = null
        this.#controls.enabled.checked = false
        this.#controls.port.value = '48170'
        this.#clearPortError()
        const generation = ++this.#generation
        const previous = this.#pending
        this.refreshLanguage()
        this.#dialog.showModal()
        // A close/reopen during Apply must read after that update has settled.
        this.#pending = this.#readStatus(previous, generation)
    }

    /** @param {Promise<unknown>} previous - Older in-flight request. @param {number} generation - Current modal lifetime. @returns {Promise<void>} Contains rejected or malformed IPC replies. */
    async #readStatus(previous, generation) {
        try {
            await previous
            if (generation !== this.#generation) return
            const response = await this.#api?.getStatus?.()
            if (generation !== this.#generation) return
            this.#acceptStatus(response)
        } catch {
            if (generation !== this.#generation) return
            this.#feedback = 'mcp.feedback.loadFailed'
        } finally {
            if (generation === this.#generation) {
                this.#busy = false
                this.#renderState()
            }
        }
    }

    /** @param {unknown} response - Main-owned public settings response. @returns {void} Hydrates only strict, non-secret state. @throws {Error} When the response is unsuccessful or malformed. */
    #acceptStatus(response) {
        const parsed = mcpStatusResponseSchema.safeParse(response)
        if (!parsed.success || !parsed.data.ok) throw new Error('Invalid MCP status')
        this.#status = parsed.data
        this.#loaded = true
        this.#controls.enabled.checked = parsed.data.enabled
        this.#controls.port.value = String(parsed.data.port)
        if (parsed.data.status === 'error') this.#feedback = parsed.data.reason === 'mcp-port-in-use' ? 'mcp.feedback.portInUse' : 'mcp.feedback.startFailed'
    }

    /** @param {SubmitEvent} event - Native form submission from Apply or Enter. @returns {void} Validates before starting a single update. */
    #handleSubmit(event) {
        event.preventDefault()
        if (this.#busy || !this.#loaded || !this.#dialog.open) return
        const text = this.#controls.port.value.trim()
        const port = Number(text)
        if (!/^\d+$/.test(text) || !Number.isInteger(port) || port < 1024 || port > 65535) {
            this.#feedback = 'mcp.feedback.invalidPort'
            this.#controls.port.setAttribute('aria-invalid', 'true')
            this.#controls.port.setAttribute('aria-errormessage', 'mcp-feedback')
            this.#renderState()
            this.#controls.port.focus()
            return
        }
        this.#clearPortError()
        this.#pending = this.#apply({ enabled: this.#controls.enabled.checked, port })
    }

    /** @param {{enabled: boolean, port: number}} request - Validated settings. @returns {Promise<void>} Applies once and displays fixed localized success or failure text. */
    async #apply(request) {
        const generation = this.#generation
        this.#busy = true
        this.#feedback = null
        this.#renderState()
        try {
            const response = await this.#api.update(request)
            if (generation !== this.#generation) return
            this.#acceptStatus(response)
            if (this.#status.status !== 'error') this.#feedback = 'mcp.feedback.applied'
        } catch {
            if (generation !== this.#generation) return
            this.#status = null
            this.#feedback = 'mcp.feedback.updateFailed'
        } finally {
            if (generation === this.#generation) {
                this.#busy = false
                this.#renderState()
            }
        }
    }

    /** @returns {Promise<void>} Requests main-owned clipboard writing without receiving or rendering configuration credentials. */
    async #copy() {
        if (this.#status?.status !== 'listening') return
        const generation = this.#generation
        this.#busy = true
        this.#feedback = null
        this.#renderState()
        try {
            const response = await this.#api.copyConfiguration()
            if (generation !== this.#generation) return
            this.#feedback = response?.ok === true ? 'mcp.feedback.copied' : 'mcp.feedback.copyFailed'
        } catch {
            if (generation !== this.#generation) return
            this.#feedback = 'mcp.feedback.copyFailed'
        } finally {
            if (generation === this.#generation) {
                this.#busy = false
                this.#renderState()
            }
        }
    }

    /** @param {Event} event - Native Escape cancellation. @returns {void} Closes through the same focus restoration path as the close button. */
    #handleCancel(event) {
        event.preventDefault()
        this.#dialog.close()
    }

    /** @returns {void} Invalidates stale async rendering and restores a connected topbar control after native close. */
    #handleClose() {
        if (this.#dialog.open) return
        this.#generation += 1
        this.#busy = false
        const opener = this.#opener?.isConnected ? this.#opener : this.#document.querySelector('[data-action="open-mcp"]')
        opener?.focus()
    }

    /** @param {KeyboardEvent} event - Modal keyboard event. @returns {void} Leaves native focus/Escape behavior intact while isolating application-level shortcuts. */
    #handleKeyDown(event) {
        event.stopPropagation()
        if (event.key === 'F1') event.preventDefault()
    }

    /** @returns {void} Removes a corrected port error without discarding other status feedback. */
    #handlePortInput() {
        if (this.#feedback !== 'mcp.feedback.invalidPort') return
        this.#feedback = null
        this.#clearPortError()
        this.#renderState()
    }

    /** @returns {void} Clears accessible field-error metadata before a new attempt. */
    #clearPortError() {
        this.#controls.port.removeAttribute('aria-invalid')
        this.#controls.port.removeAttribute('aria-errormessage')
    }

    /** @returns {void} Updates bounded status and action availability without replacing inputs or exposing main error details. */
    #renderState() {
        const unavailable = this.#busy || !this.#loaded
        this.#controls.enabled.disabled = unavailable
        this.#controls.port.disabled = unavailable
        this.#controls.apply.disabled = unavailable
        this.#controls.copy.disabled = this.#busy || this.#status?.status !== 'listening'
        this.#dialog.setAttribute('aria-busy', String(this.#busy))
        const status = this.#busy ? 'loading' : (this.#status?.status ?? 'error')
        this.#controls.status.textContent = this.#translate(`mcp.status.${status}`)
        this.#controls.status.dataset.state = status
        this.#controls.endpoint.textContent = this.#status?.endpoint ?? this.#translate('mcp.endpointUnavailable')
        this.#controls.feedback.textContent = this.#feedback ? this.#translate(this.#feedback) : ''
        this.#controls.feedback.dataset.tone = this.#feedback && !['mcp.feedback.applied', 'mcp.feedback.copied'].includes(this.#feedback) ? 'error' : 'success'
    }
}

/**
 * Mounts one MCP settings controller per document; it lives for the renderer document lifetime.
 * @param {{document: Document, api?: object, translator: Function}} options - Narrow settings dependencies.
 * @returns {{refreshLanguage: () => void}} Stable controller for language updates.
 */
export function mountMcpSettings(options) {
    let controller = mountedControllers.get(options.document)
    if (!controller) {
        controller = new McpSettingsView(options)
        mountedControllers.set(options.document, controller)
    }
    return controller
}
