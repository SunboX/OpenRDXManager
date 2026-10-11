// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createAutomaticAuthOperation, transitionAutomaticAuthOperation } from './workflows/automatic-auth-workflow.mjs'
import { createPasswordOperation, transitionPasswordOperation } from './workflows/password-workflow.mjs'
import { createProtectionOperation, transitionProtectionOperation } from './workflows/protection-workflow.mjs'

const PASSWORD_OPERATIONS = new Set(['enable-access', 'disable-access', 'create-credential', 'change-credential', 'delete-credential'])
const PROTECTION_OPERATIONS = new Set(['configure-basic', 'configure-aes', 'remove-basic', 'remove-aes', 'reset-protection'])
const AUTOMATIC_OPERATIONS = new Set(['add-automatic-association', 'delete-automatic-association', 'delete-drive-automatic-credential'])

/**
 * Creates the exact guided state requested by one already-gated UI intent.
 * @param {object} intent - Structured non-secret Encryption action intent.
 * @param {object} model - Current strict security presentation model.
 * @returns {object} Initial immutable workflow state.
 * @throws {TypeError} For unknown operations or incomplete prerequisites.
 */
export function createSecurityWorkflow(intent, model) {
    if (PROTECTION_OPERATIONS.has(intent?.operation)) {
        return createProtectionOperation({
            access: model.access,
            currentMode: model.mode,
            device: model.device,
            mediaPresent: model.device?.media !== null && model.device?.media !== undefined,
            operation: intent.operation
        })
    }
    if (PASSWORD_OPERATIONS.has(intent?.operation)) {
        return createPasswordOperation({ device: model.device, operation: intent.operation, target: intent.credential })
    }
    if (AUTOMATIC_OPERATIONS.has(intent?.operation)) {
        return createAutomaticAuthOperation({ association: intent.association, device: model.device, operation: intent.operation })
    }
    throw new TypeError('Unknown security workflow operation')
}

/**
 * Applies one local workflow event through the operation-specific state machine.
 * @param {object} workflow - Current guided workflow.
 * @param {object} event - Submit, confirm, progress, finish, or cancel event.
 * @returns {object} Next immutable workflow state.
 * @throws {TypeError} For an unknown workflow operation.
 */
export function transitionSecurityWorkflow(workflow, event) {
    if (PROTECTION_OPERATIONS.has(workflow?.operation)) return transitionProtectionOperation(workflow, event)
    if (PASSWORD_OPERATIONS.has(workflow?.operation)) return transitionPasswordOperation(workflow, event)
    if (AUTOMATIC_OPERATIONS.has(workflow?.operation)) return transitionAutomaticAuthOperation(workflow, event)
    throw new TypeError('Unknown security workflow operation')
}
