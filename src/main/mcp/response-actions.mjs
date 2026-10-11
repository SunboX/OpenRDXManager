// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { AsyncLocalStorage } from 'node:async_hooks'

const responseActions = new AsyncLocalStorage()

/** @param {Function[]} actions - Request-owned deferred actions. @param {Function} callback - MCP request dispatch. @returns {*} Callback result with isolated response lifecycle context. */
export function runMcpResponseScope(actions, callback) {
    return responseActions.run(actions, callback)
}

/** @param {Function} action - Main-owned desktop action. @returns {boolean} Whether a current MCP response can safely defer this action. */
export function scheduleAfterMcpResponse(action) {
    const actions = responseActions.getStore()
    if (actions === undefined || typeof action !== 'function') return false
    actions.push(action)
    return true
}
