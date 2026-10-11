// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { JSDOM } from 'jsdom'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createLiveTranslator } from '../src/renderer/desktop-settings.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createStore } from '../src/renderer/store.mjs'

const disabledStatus = { ok: true, enabled: false, port: 48170, status: 'disabled', endpoint: null }
const listeningStatus = { ok: true, enabled: true, port: 48171, status: 'listening', endpoint: 'http://127.0.0.1:48171/mcp' }

/** @returns {Promise<void>} Flushes bridge callbacks without timers or hardware. */
async function settle() {
    await new Promise((resolve) => setImmediate(resolve))
}

/** @returns {{promise: Promise<unknown>, resolve: Function}} Controlled pending IPC reply. */
function deferred() {
    let resolve
    const promise = new Promise((complete) => {
        resolve = complete
    })
    return { promise, resolve }
}

/**
 * Mounts the actual no-device application and settings controller with isolated IPC replies.
 * jsdom does not implement native dialog methods; only those browser APIs are supplied here.
 * @param {object} context - Node test lifecycle.
 * @param {object|undefined} api - Narrow MCP preload API.
 * @returns {Promise<object>} DOM controls and real renderer state.
 */
async function mountSettings(context, api = { getStatus: async () => disabledStatus }) {
    const dom = new JSDOM('<!doctype html><html><body><div id="app"></div></body></html>', { pretendToBeVisual: true, url: 'file:///openrdxmanager/src/index.html' })
    const { document, HTMLDialogElement, Event } = dom.window
    /** @returns {void} Models only native modal opening and initial focus absent from jsdom. */
    HTMLDialogElement.prototype.showModal = function () {
        this.open = true
        this.querySelector('[autofocus]')?.focus()
    }
    /** @returns {void} Models native close notification absent from jsdom. */
    HTMLDialogElement.prototype.close = function () {
        this.open = false
        this.dispatchEvent(new Event('close'))
    }
    const translator = createLiveTranslator('en')
    const store = createStore(createFixtureState({ mode: 'no-device' }))
    const application = mountApplication(document.querySelector('#app'), { store, translator: translator.translate })
    context.after(() => {
        application.destroy()
        dom.window.close()
    })
    const opener = document.querySelector('[data-action="open-mcp"]')
    assert.ok(opener, 'MCP settings must be reachable without a device')
    const { mountMcpSettings } = await import('../src/renderer/mcp-settings.mjs')
    const controller = mountMcpSettings({ document, api, translator: translator.translate })
    assert.equal(mountMcpSettings({ document, api, translator: translator.translate }), controller, 'repeated mounting must not add duplicate listeners')
    opener.focus()
    opener.click()
    await settle()
    return { dom, document, opener, store, controller, translator, dialog: document.querySelector('[data-mcp-settings]') }
}

/** @param {object} ui - Mounted DOM. @returns {void} Submits through the form event used by click and Enter. */
function submit(ui) {
    ui.dialog.querySelector('form').dispatchEvent(new ui.dom.window.Event('submit', { bubbles: true, cancelable: true }))
}

test('opens disabled MCP settings without hardware and preserves the dialog across app rerenders', async (context) => {
    let reads = 0
    const ui = await mountSettings(context, {
        getStatus: async () => {
            reads += 1
            return disabledStatus
        }
    })
    assert.equal(reads, 1)
    assert.equal(ui.opener.disabled, false)
    assert.equal(ui.dialog.open, true)
    assert.equal(ui.dialog.parentElement, ui.document.body)
    assert.equal(ui.document.querySelector('#mcp-enabled').checked, false)
    assert.equal(ui.document.querySelector('#mcp-port').value, '48170')
    assert.equal(ui.document.querySelector('[data-mcp-status]').textContent, 'Disabled')
    assert.equal(ui.document.querySelector('[data-mcp-action="copy"]').disabled, true)
    ui.document.querySelector('#mcp-port').value = '49200'
    ui.store.dispatch({ type: 'settings/changed', settings: { ...ui.store.getState().settings, autoScan: false } })
    assert.equal(ui.document.querySelector('[data-mcp-settings]'), ui.dialog)
    assert.equal(ui.document.querySelector('#mcp-port').value, '49200')
})

test('applies enabled state and an integer port then copies only through the main-owned clipboard action', async (context) => {
    const updates = []
    let copies = 0
    const ui = await mountSettings(context, {
        getStatus: async () => disabledStatus,
        update: async (request) => {
            updates.push(request)
            return listeningStatus
        },
        copyConfiguration: async () => {
            copies += 1
            return { ok: true }
        }
    })
    ui.document.querySelector('#mcp-enabled').checked = true
    ui.document.querySelector('#mcp-port').value = '48171'
    submit(ui)
    submit(ui)
    assert.equal(ui.document.querySelector('[data-mcp-action="apply"]').disabled, true)
    await settle()
    assert.deepEqual(updates, [{ enabled: true, port: 48171 }])
    assert.equal(ui.document.querySelector('[data-mcp-status]').textContent, 'Listening')
    assert.equal(ui.document.querySelector('[data-mcp-endpoint]').textContent, 'http://127.0.0.1:48171/mcp')
    assert.equal(ui.document.querySelector('[data-mcp-action="copy"]').disabled, false)
    ui.document.querySelector('[data-mcp-action="copy"]').click()
    await settle()
    assert.equal(copies, 1)
    assert.match(ui.document.querySelector('[data-mcp-feedback]').textContent, /copied/i)
    assert.doesNotMatch(ui.dialog.innerHTML, /OPENRDX_MCP_TOKEN|mcpServers|Bearer|tokenFile/)
})

test('rejects empty, fractional, non-decimal and out-of-range ports before IPC', async (context) => {
    const updates = []
    const ui = await mountSettings(context, {
        getStatus: async () => disabledStatus,
        update: async (request) => {
            updates.push(request)
            return disabledStatus
        }
    })
    for (const value of ['', '1023', '65536', '1024.5', '-4', '1e4']) {
        ui.document.querySelector('#mcp-port').value = value
        submit(ui)
        await settle()
        assert.equal(ui.document.querySelector('#mcp-port').getAttribute('aria-invalid'), 'true', `invalid port ${value}`)
        assert.match(ui.document.querySelector('[data-mcp-feedback]').textContent, /1024.*65535/)
    }
    assert.deepEqual(updates, [])
    for (const port of [1024, 65535]) {
        ui.document.querySelector('#mcp-port').value = String(port)
        submit(ui)
        await settle()
    }
    assert.deepEqual(updates, [
        { enabled: false, port: 1024 },
        { enabled: false, port: 65535 }
    ])
})

test('contains rejected reads and malformed status without exposing raw errors or enabling writes', async (context) => {
    for (const getStatus of [
        async () => {
            throw new Error('/private/secret/token')
        },
        async () => ({ ...listeningStatus, endpoint: 'https://outside.example/secret' }),
        async () => ({ ok: false, reason: 'private-secret' })
    ]) {
        const ui = await mountSettings(context, { getStatus })
        assert.equal(ui.document.querySelector('#mcp-enabled').disabled, true)
        assert.equal(ui.document.querySelector('[data-mcp-action="apply"]').disabled, true)
        assert.equal(ui.document.querySelector('[data-mcp-action="copy"]').disabled, true)
        assert.match(ui.document.querySelector('[data-mcp-feedback]').textContent, /could not.*load/i)
        assert.doesNotMatch(ui.dialog.innerHTML, /private|secret|outside\.example/)
    }
})

test('shows localized bind failure and allows retry without copying an inactive configuration', async (context) => {
    const ui = await mountSettings(context, { getStatus: async () => disabledStatus, update: async () => ({ ...listeningStatus, status: 'error', endpoint: null, reason: 'mcp-port-in-use' }) })
    ui.document.querySelector('#mcp-enabled').checked = true
    submit(ui)
    await settle()
    assert.equal(ui.document.querySelector('#mcp-enabled').checked, true)
    assert.equal(ui.document.querySelector('[data-mcp-status]').textContent, 'Connection error')
    assert.equal(ui.document.querySelector('[data-mcp-action="copy"]').disabled, true)
    assert.equal(ui.document.querySelector('[data-mcp-action="apply"]').disabled, false)
    assert.match(ui.document.querySelector('[data-mcp-feedback]').textContent, /port.*in use/i)
    assert.doesNotMatch(ui.dialog.innerHTML, /mcp-port-in-use/)
})

test('contains update and clipboard failures and keeps the dialog usable', async (context) => {
    const ui = await mountSettings(context, {
        getStatus: async () => listeningStatus,
        update: async () => {
            throw new Error('/private/update-secret')
        },
        copyConfiguration: async () => ({ ok: false, reason: 'copy-secret' })
    })
    ui.document.querySelector('[data-mcp-action="copy"]').click()
    await settle()
    assert.match(ui.document.querySelector('[data-mcp-feedback]').textContent, /could not.*copy/i)
    submit(ui)
    await settle()
    assert.match(ui.document.querySelector('[data-mcp-feedback]').textContent, /could not.*apply/i)
    assert.equal(ui.document.querySelector('[data-mcp-action="apply"]').disabled, false)
    assert.equal(ui.document.querySelector('[data-mcp-action="close"]').disabled, false)
    assert.doesNotMatch(ui.dialog.innerHTML, /private|secret/)
})

test('contains rejected clipboard promises as localized feedback', async (context) => {
    const ui = await mountSettings(context, {
        getStatus: async () => listeningStatus,
        copyConfiguration: async () => {
            throw new Error('clipboard-secret')
        }
    })
    ui.document.querySelector('[data-mcp-action="copy"]').click()
    await settle()
    assert.match(ui.document.querySelector('[data-mcp-feedback]').textContent, /could not.*copy/i)
    assert.equal(ui.document.querySelector('[data-mcp-action="copy"]').disabled, false)
    assert.doesNotMatch(ui.dialog.innerHTML, /clipboard-secret/)
})

test('closes with button and Escape and restores focus to a replaced opener', async (context) => {
    const ui = await mountSettings(context)
    ui.store.dispatch({ type: 'settings/changed', settings: { ...ui.store.getState().settings, autoScan: false } })
    ui.document.querySelector('[data-mcp-action="close"]').click()
    assert.equal(ui.dialog.open, false)
    assert.equal(ui.document.activeElement, ui.document.querySelector('[data-action="open-mcp"]'))
    ui.document.querySelector('[data-action="open-mcp"]').click()
    await settle()
    ui.dialog.dispatchEvent(new ui.dom.window.Event('cancel', { cancelable: true }))
    assert.equal(ui.dialog.open, false)
    assert.equal(ui.document.activeElement, ui.document.querySelector('[data-action="open-mcp"]'))
})

test('keeps application shortcuts from opening a second overlay behind the native modal', async (context) => {
    const ui = await mountSettings(context)
    ui.document.querySelector('[data-mcp-action="close"]').dispatchEvent(new ui.dom.window.KeyboardEvent('keydown', { key: 'F1', bubbles: true, cancelable: true }))
    assert.equal(ui.document.querySelector('[data-support-overlay]'), null)
    assert.equal(ui.dialog.open, true)
})

test('ignores a late closed-dialog response and refreshes the current settings after reopening', async (context) => {
    const first = deferred()
    let reads = 0
    const ui = await mountSettings(context, { getStatus: () => (++reads === 1 ? first.promise : Promise.resolve(listeningStatus)) })
    assert.equal(ui.document.querySelector('#mcp-enabled').disabled, true)
    ui.document.querySelector('[data-mcp-action="close"]').click()
    ui.opener.click()
    first.resolve(disabledStatus)
    await settle()
    assert.equal(ui.dialog.open, true)
    assert.equal(ui.document.querySelector('#mcp-enabled').checked, true)
    assert.equal(ui.document.querySelector('#mcp-port').value, '48171')
    assert.equal(reads, 2)
})

test('reopening during an update waits for the durable result before reading again', async (context) => {
    const update = deferred()
    let current = disabledStatus
    let reads = 0
    const ui = await mountSettings(context, {
        getStatus: async () => {
            reads += 1
            return current
        },
        update: async () => {
            await update.promise
            current = listeningStatus
            return current
        }
    })
    ui.document.querySelector('#mcp-enabled').checked = true
    ui.document.querySelector('#mcp-port').value = '48171'
    submit(ui)
    ui.document.querySelector('[data-mcp-action="close"]').click()
    ui.opener.click()
    await settle()
    assert.equal(reads, 1)
    assert.equal(ui.document.querySelector('[data-mcp-action="apply"]').disabled, true)
    update.resolve()
    await settle()
    assert.equal(reads, 2)
    assert.equal(ui.document.querySelector('#mcp-enabled').checked, true)
    assert.equal(ui.document.querySelector('[data-mcp-endpoint]').textContent, 'http://127.0.0.1:48171/mcp')
})

test('an unavailable bridge leaves settings readable as a localized failure with no enabled writes', async (context) => {
    const ui = await mountSettings(context, null)
    assert.equal(ui.dialog.open, true)
    assert.equal(ui.document.querySelector('[data-mcp-action="apply"]').disabled, true)
    assert.equal(ui.document.querySelector('[data-mcp-action="copy"]').disabled, true)
    assert.match(ui.document.querySelector('[data-mcp-feedback]').textContent, /could not.*load/i)
    ui.document.querySelector('[data-mcp-action="close"]').click()
    assert.equal(ui.dialog.open, false)
})

test('refreshes dialog labels in the current language without discarding unsaved input', async (context) => {
    const ui = await mountSettings(context)
    ui.document.querySelector('#mcp-port').value = '49200'
    ui.translator.setLanguage('de')
    ui.controller.refreshLanguage()
    assert.equal(ui.document.querySelector('#mcp-title').textContent, 'MCP-Agentenzugriff')
    assert.equal(ui.document.querySelector('[data-mcp-status]').textContent, 'Deaktiviert')
    assert.equal(ui.document.querySelector('#mcp-port').value, '49200')
    ui.document.querySelector('[data-mcp-action="close"]').click()
    ui.translator.setLanguage('ja')
    ui.opener.click()
    await settle()
    assert.equal(ui.document.querySelector('#mcp-title').textContent, 'MCP エージェントアクセス')
})
