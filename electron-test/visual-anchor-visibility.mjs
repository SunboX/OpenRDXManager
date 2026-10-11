// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Requires both the marker origin and text area to be visible through scroll
 * clipping/sticky overlays; viewport geometry alone cannot establish this.
 * @param {Element|null} element - Candidate structural anchor.
 * @param {Document} document - Renderer document supplying actual hit testing.
 * @returns {boolean} Whether both points resolve to this element or its children.
 */
export function isVisualAnchorUnoccluded(element, document) {
    if (!element) return false
    const rect = element.getBoundingClientRect()
    if (rect.width <= 0 || rect.height <= 0) return false
    const points = [
        [rect.left + Math.min(2, rect.width / 2), rect.top + Math.min(2, rect.height / 2)],
        [rect.left + rect.width / 2, rect.top + rect.height / 2]
    ]
    return points.every(([x, y]) => {
        const hit = document.elementFromPoint(x, y)
        return hit !== null && (hit === element || element.contains(hit))
    })
}
