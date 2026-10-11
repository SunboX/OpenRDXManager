// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Returns a stable matching signature for one renderer-owned DOM node.
 * The signature is used only to retain existing nodes; it never becomes HTML.
 * @param {Node} node - Existing or desired DOM node.
 * @returns {string} Bounded structural signature.
 */
function getNodeSignature(node) {
    if (node.nodeType === 3) return '#text'
    if (node.nodeType !== 1) return `#node-${node.nodeType}`
    const key = node.id || node.dataset?.focusKey || node.dataset?.deviceId || node.dataset?.area || node.dataset?.operation || node.dataset?.feature || ''
    if (key !== '') return `${node.tagName}:${key}`
    const firstClass = typeof node.className === 'string' ? node.className.trim().split(/\s+/)[0] : ''
    return `${node.tagName}:${firstClass}`
}

/**
 * Synchronizes serialized attributes without replacing the live element.
 * @param {Element} current - Mounted element whose identity must remain stable.
 * @param {Element} desired - Detached element containing the next attributes.
 * @returns {void} Completes after only changed attributes are written.
 */
function reconcileAttributes(current, desired) {
    for (const attribute of [...current.attributes]) {
        if (!desired.hasAttribute(attribute.name)) current.removeAttribute(attribute.name)
    }
    for (const attribute of [...desired.attributes]) {
        if (current.getAttribute(attribute.name) !== attribute.value) current.setAttribute(attribute.name, attribute.value)
    }
}

/**
 * Finds one reusable child at or after the current insertion position.
 * @param {Node} parent - Mounted parent node.
 * @param {Node} desired - Detached child to match.
 * @param {number} startIndex - First mounted child eligible for reuse.
 * @returns {Node|null} Reusable live node, or null when a new clone is required.
 */
function findReusableChild(parent, desired, startIndex) {
    const signature = getNodeSignature(desired)
    for (let index = startIndex; index < parent.childNodes.length; index += 1) {
        const candidate = parent.childNodes[index]
        if (getNodeSignature(candidate) === signature) return candidate
    }
    return null
}

/**
 * Reconciles one mounted node with detached desired markup while retaining its
 * identity whenever its structural signature remains the same.
 * @param {Node} current - Mounted node.
 * @param {Node} desired - Detached desired node.
 * @returns {Node} Mounted node representing the desired content.
 */
function reconcileNode(current, desired) {
    if (current.nodeType !== desired.nodeType || getNodeSignature(current) !== getNodeSignature(desired)) {
        const replacement = desired.cloneNode(true)
        current.replaceWith(replacement)
        return replacement
    }
    if (current.nodeType === 3) {
        if (current.nodeValue !== desired.nodeValue) current.nodeValue = desired.nodeValue
        return current
    }
    if (current.nodeType !== 1) return current

    reconcileAttributes(current, desired)
    reconcileChildren(current, desired)
    if (current.tagName === 'INPUT' && ['checkbox', 'radio'].includes(current.type)) current.checked = desired.checked
    // Explicitly controlled confirmation fields must discard dirty DOM values
    // when their controller consumes an acknowledgement or changes targets.
    if (current.tagName === 'INPUT' && current.hasAttribute('data-controlled-value') && current.value !== desired.value) current.value = desired.value
    if (current.tagName === 'SELECT' && current.value !== desired.value) current.value = desired.value
    return current
}

/**
 * Reconciles a complete child list by moving reusable live nodes into desired
 * order and cloning only genuinely new structure.
 * @param {Node} currentParent - Mounted parent whose identity remains stable.
 * @param {Node} desiredParent - Detached desired parent or document fragment.
 * @returns {void} Completes after obsolete children are removed.
 */
function reconcileChildren(currentParent, desiredParent) {
    const desiredChildren = [...desiredParent.childNodes]
    for (let index = 0; index < desiredChildren.length; index += 1) {
        const desired = desiredChildren[index]
        let current = currentParent.childNodes[index]
        if (current === undefined || getNodeSignature(current) !== getNodeSignature(desired)) {
            const reusable = findReusableChild(currentParent, desired, index + 1)
            if (reusable !== null) {
                currentParent.insertBefore(reusable, current ?? null)
                current = reusable
            } else {
                current = desired.cloneNode(true)
                currentParent.insertBefore(current, currentParent.childNodes[index] ?? null)
            }
        }
        reconcileNode(current, desired)
    }
    while (currentParent.childNodes.length > desiredChildren.length) {
        currentParent.lastChild.remove()
    }
}

/**
 * Applies rendered markup incrementally so periodic hardware snapshots
 * do not destroy scroll, focus, or stable device-list element identities.
 * @param {HTMLElement} root - Mounted application root.
 * @param {string} html - Trusted renderer-owned next shell markup.
 * @returns {void} Completes after changed values and structure are reconciled.
 */
export function reconcileRenderedShell(root, html) {
    const template = root.ownerDocument.createElement('template')
    template.innerHTML = html
    reconcileChildren(root, template.content)
}
