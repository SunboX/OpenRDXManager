// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

const PROTOTYPE_CONTROL_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

/**
 * Inspects a structured value without reading accessors, rejecting any own
 * property that can control JavaScript prototype behavior. Inherited keys are
 * intentionally ignored so ordinary objects remain valid boundary values.
 * @param {unknown} value - Candidate structured boundary value.
 * @param {Set<object>} visited - Objects already inspected during recursion.
 * @returns {boolean} True when a prohibited own key or uninspectable object exists.
 */
function inspectPrototypeControlKeys(value, visited) {
    if ((typeof value !== 'object' && typeof value !== 'function') || value === null) {
        return false
    }
    if (visited.has(value)) {
        return false
    }
    visited.add(value)

    let descriptors
    try {
        descriptors = Object.getOwnPropertyDescriptors(value)
    } catch {
        // Proxy traps and other uninspectable objects fail closed at the boundary.
        return true
    }

    for (const key of Reflect.ownKeys(descriptors)) {
        if (typeof key === 'string' && PROTOTYPE_CONTROL_KEYS.has(key)) {
            return true
        }
        const descriptor = descriptors[key]
        if ('value' in descriptor && inspectPrototypeControlKeys(descriptor.value, visited)) {
            return true
        }
    }
    return false
}

/**
 * Detects prohibited own prototype-control keys recursively in structured
 * renderer/main boundary values. It never accepts a value it cannot inspect.
 * @param {unknown} value - Candidate structured request value.
 * @returns {boolean} True when the value must be rejected before schema parsing.
 */
export function hasOwnPrototypeControlKey(value) {
    return inspectPrototypeControlKeys(value, new Set())
}
