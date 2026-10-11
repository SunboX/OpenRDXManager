// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

const SCENES = Object.freeze([
    Object.freeze({ state: 'no-device', surface: 'no-device' }),
    Object.freeze({ state: 'ready-no-media', surface: 'status' }),
    Object.freeze({ state: 'protected-locked', surface: 'encryption' }),
    Object.freeze({ state: 'protected-unlocked', surface: 'encryption' }),
    Object.freeze({ state: 'status', surface: 'status', keyboard: true }),
    Object.freeze({ state: 'encryption', surface: 'encryption' }),
    Object.freeze({ state: 'tests', surface: 'tests' }),
    Object.freeze({ state: 'utilities', surface: 'utilities' }),
    Object.freeze({ state: 'activity', surface: 'activity' }),
    Object.freeze({ state: 'help', surface: 'help' }),
    Object.freeze({ state: 'support', surface: 'support' }),
    Object.freeze({ state: 'compatibility', surface: 'compatibility' }),
    Object.freeze({ state: 'routine-active', surface: 'tests' }),
    Object.freeze({ state: 'critical-active', surface: 'utilities' }),
    Object.freeze({ state: 'destructive-preflight', surface: 'utilities' }),
    Object.freeze({ state: 'destructive-active', surface: 'utilities' }),
    Object.freeze({ state: 'disabled-reasons', surface: 'encryption' }),
    Object.freeze({ state: 'operation-success', surface: 'tests' }),
    Object.freeze({ state: 'operation-failure', surface: 'tests' }),
    Object.freeze({ state: 'service-unavailable', surface: 'service-unavailable' }),
    Object.freeze({ state: 'update-unavailable', surface: 'support' }),
    Object.freeze({ state: 'language-en', surface: 'status', language: 'en' }),
    Object.freeze({ state: 'language-zh', surface: 'status', language: 'zh' }),
    Object.freeze({ state: 'language-de', surface: 'status', language: 'de' }),
    Object.freeze({ state: 'language-fr', surface: 'status', language: 'fr' }),
    Object.freeze({ state: 'language-it', surface: 'status', language: 'it' }),
    Object.freeze({ state: 'language-pt', surface: 'status', language: 'pt' }),
    Object.freeze({ state: 'language-es', surface: 'status', language: 'es' }),
    Object.freeze({ state: 'language-ja', surface: 'status', language: 'ja' }),
    Object.freeze({ state: 'starting-runtime', surface: 'starting', fixture: false }),
    Object.freeze({ state: 'ready-no-device-runtime', surface: 'no-device', fixture: false })
])
const VIEWPORTS = Object.freeze([Object.freeze({ name: 'minimum', width: 1024, height: 768 }), Object.freeze({ name: 'expanded', width: 1440, height: 900 })])
const INTENTIONALLY_SCROLLED_STATES = new Set(['destructive-preflight', 'disabled-reasons', 'protected-locked', 'protected-unlocked', 'update-unavailable'])
const MAX_RASTER_NOISE_CHANNELS = 64
const MAX_RASTER_NOISE_DELTA = 3
const RASTER_ANCHOR_COLOR_TOLERANCE = 48
const MINIMUM_RASTER_ANCHOR_PIXELS = 8
const MINIMUM_RASTER_ANCHOR_COVERAGE = 0.004
const RASTER_FIDUCIAL_COLOR_TOLERANCE = 24
const MINIMUM_RASTER_FIDUCIAL_PIXELS = 8

/**
 * Reports whether an object owns a required evidence property.
 * @param {unknown} value - Candidate evidence container.
 * @param {string} property - Required property name.
 * @returns {boolean} True only for a directly owned property.
 */
function owns(value, property) {
    return typeof value === 'object' && value !== null && Object.hasOwn(value, property)
}

/**
 * Requires a complete array field and appends one fail-closed diagnostic.
 * @param {object} inspection - Candidate visual inspection.
 * @param {string} property - Required array property.
 * @param {string[]} failures - Mutable failure accumulator.
 * @returns {unknown[]} The supplied array or an empty array after recording failure.
 */
function requireArray(inspection, property, failures) {
    if (!owns(inspection, property) || !Array.isArray(inspection[property])) {
        failures.push(`missing ${property} evidence`)
        return []
    }
    return inspection[property]
}

/**
 * Requires a finite numeric field and appends one fail-closed diagnostic.
 * @param {object} value - Candidate numeric evidence container.
 * @param {string} property - Required numeric property.
 * @param {string[]} failures - Mutable failure accumulator.
 * @param {string} label - Human-readable evidence label.
 * @returns {number | null} Finite numeric value, otherwise null.
 */
function requireNumber(value, property, failures, label) {
    if (!owns(value, property) || !Number.isFinite(value[property])) {
        failures.push(`missing ${label}.${property} evidence`)
        return null
    }
    return value[property]
}

/**
 * Creates a deterministic non-secret identity for one rendered control.
 * Renderer-owned data identities take precedence over generic HTML values so
 * checkbox defaults such as `value="on"` cannot collapse distinct controls.
 * @param {object} element - DOM control or a compatible test double.
 * @param {number} index - Stable index within the rendered disabled controls.
 * @returns {string} Machine-readable control identity.
 */
export function createVisualControlKey(element, index) {
    const tag = typeof element?.tagName === 'string' ? element.tagName.toLowerCase() : 'control'
    const datasetEntries = Object.entries(element?.dataset ?? {}).sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    if (datasetEntries.length > 0) {
        const identity = datasetEntries.map(([property, value]) => `data-${property}=${value}`).join(';')
        if (element?.type === 'radio' && typeof element.value === 'string') return `${tag}:${identity};value=${element.value}`
        return `${tag}:${identity}`
    }
    const id = element?.getAttribute?.('id')
    if (typeof id === 'string' && id.length > 0) return `${tag}:id=${id}`
    const name = element?.getAttribute?.('name') ?? element?.name
    if (typeof name === 'string' && name.length > 0) return `${tag}:name=${name}`
    const type = typeof element?.type === 'string' && element.type.length > 0 ? element.type : 'control'
    return `${tag}:${type}:${index}`
}

/**
 * Collects only rendered, DOM-associated disabled-control explanations.
 * Tooltip-only titles and hidden described-by nodes are not visual evidence.
 * @param {object} element - Disabled DOM control.
 * @param {Document|object} document - Owning document or compatible test double.
 * @param {(candidate: object) => boolean} isRendered - Layout-visibility predicate.
 * @returns {string[]} Normalized visible rationale copy.
 */
export function collectVisualDisabledReasons(element, document, isRendered) {
    const reasons = []
    /**
     * Adds one bounded reason only when its associated node is rendered.
     * @param {object|null|undefined} candidate - Associated rationale node.
     * @returns {void}
     */
    const addReason = (candidate) => {
        if (candidate === null || candidate === undefined || !isRendered(candidate)) return
        const text = candidate.textContent?.trim()
        if (typeof text === 'string' && text.length > 0) reasons.push(text.replace(/\s+/g, ' ').slice(0, 240))
    }
    const ids = (element.getAttribute?.('aria-describedby') || '').split(/\s+/).filter(Boolean)
    for (const id of ids) addReason(document.getElementById(id))
    if (reasons.length === 0) {
        const owner = element.closest?.('[data-capability-card], [data-feature], [data-test-kind], .security-action, label')
        for (const candidate of owner?.querySelectorAll?.('[data-capability-reason], [data-action-reason], [data-row-action-reason], .capability-reason, .utility-action-readiness, small') ?? []) {
            addReason(candidate)
            if (reasons.length > 0) break
        }
    }
    return [...new Set(reasons)]
}

/**
 * Produces the complete deterministic feature/language state and size plan.
 * @returns {object[]} Frozen capture entries in stable review order.
 */
export function createVisualQaMatrix() {
    const entries = []
    for (const scene of SCENES) {
        for (const viewport of VIEWPORTS) {
            entries.push(
                Object.freeze({
                    fixture: scene.fixture !== false,
                    keyboard: scene.keyboard === true,
                    language: scene.language ?? 'en',
                    state: scene.state,
                    surface: scene.surface,
                    viewport,
                    screenshot: `${scene.state}-${viewport.name}-${viewport.width}x${viewport.height}.png`
                })
            )
        }
    }
    return Object.freeze(entries)
}

/**
 * Serializes visual QA evidence without volatile wall-clock metadata.
 * @param {object[]} results - Deterministic visual inspection results.
 * @returns {string} Pretty-printed JSON evidence with a trailing newline.
 */
export function serializeVisualQaManifest(results) {
    return `${JSON.stringify(
        {
            schemaVersion: 1,
            evidenceKind: 'deterministic-electron-visual-qa',
            harness: 'electron-test/visual-qa.mjs',
            productionFixtureActivation: false,
            physicalHardwareVerified: false,
            results
        },
        stableManifestReplacer,
        2
    )}\n`
}

/**
 * Excludes host-window activation and repaint retry counts from stable evidence,
 * and sorts resource identities independently of asynchronous completion order. The runtime
 * contract still requires the field so keyboard traversal records whether
 * macOS granted application focus, but that OS choice is not renderer state.
 * @param {string} key - Current JSON property name.
 * @param {unknown} value - Current JSON property value.
 * @returns {unknown} Stable serializable value or undefined for volatile run metrics.
 */
function stableManifestReplacer(key, value) {
    // Keep every observed URL (including duplicates and forbidden remote URLs).
    // The inspection validator checks the unsorted evidence before serialization.
    if (key === 'resourceUrls' && Array.isArray(value)) return [...value].sort()
    // The ring must validate at >=2px, but its host-dependent measured width
    // belongs in run metrics, not byte-stable post-blur screenshot evidence.
    if (key === 'keyboardEvidence' && value !== null && typeof value === 'object') {
        const { outlineWidth, ...stableFocusEvidence } = value
        return stableFocusEvidence
    }
    return key === 'windowFocusedAtTraversal' || key === 'captureAttempts' ? undefined : value
}

/** Preserves real bounded retry counts separately from deterministic screenshot evidence.
 * @param {object[]} results - Fully validated capture results.
 * @returns {string} Per-run metrics with every actual attempt count intact.
 */
export function serializeVisualQaCaptureMetrics(results) {
    const captures = results.map(({ screenshot, inspection }) => {
        const attempts = inspection.rasterEvidence.captureAttempts
        if (!Number.isSafeInteger(attempts) || attempts < 1 || attempts > 4) throw new TypeError('visual-capture-attempts-invalid')
        const keyboardEvidence = inspection.keyboardEvidence
        return { screenshot, attempts, ...(keyboardEvidence ? { keyboardOutlineWidth: keyboardEvidence.outlineWidth } : {}) }
    })
    return `${JSON.stringify({ schemaVersion: 1, evidenceKind: 'electron-visual-capture-metrics', physicalHardwareVerified: false, captures }, null, 2)}\n`
}

/**
 * Reports whether a fresh screenshot bitmap contains a meaningful change.
 * A bounded 64-channel, three-level compositor variation is retained as
 * Chromium raster noise; larger, wider, or dimension-changing drift is evidence.
 * @param {{width: number, height: number, bitmap: Uint8Array}} trackedRaster - Decoded tracked screenshot.
 * @param {{width: number, height: number, bitmap: Uint8Array}} freshRaster - Decoded freshly captured screenshot.
 * @returns {boolean} True when the tracked screenshot must be replaced.
 */
export function shouldReplaceVisualScreenshot(trackedRaster, freshRaster) {
    if (trackedRaster.width !== freshRaster.width || trackedRaster.height !== freshRaster.height) return true
    const expectedLength = trackedRaster.width * trackedRaster.height * 4
    if (!Number.isSafeInteger(trackedRaster.width) || trackedRaster.width <= 0 || !Number.isSafeInteger(trackedRaster.height) || trackedRaster.height <= 0 || trackedRaster.bitmap.length !== expectedLength || freshRaster.bitmap.length !== expectedLength) {
        return true
    }
    let noisyChannels = 0
    for (let index = 0; index < trackedRaster.bitmap.length; index += 1) {
        const difference = Math.abs(trackedRaster.bitmap[index] - freshRaster.bitmap[index])
        if (difference > MAX_RASTER_NOISE_DELTA) return true
        if (difference > 0 && (noisyChannels += 1) > MAX_RASTER_NOISE_CHANNELS) return true
    }
    return false
}

/**
 * Parses the renderer's computed sRGB color for screenshot comparison.
 * @param {string} color - Computed `rgb()` or `rgba()` color.
 * @returns {[number, number, number] | null} Red, green, and blue channels.
 */
function parseVisualRgbColor(color) {
    if (typeof color !== 'string' || !/^rgba?\(/.test(color)) return null
    const channels = color
        .match(/[\d.]+/g)
        ?.slice(0, 3)
        .map(Number)
    if (channels?.length !== 3 || channels.some((channel) => !Number.isFinite(channel) || channel < 0 || channel > 255)) return null
    return channels
}

/**
 * Measures one canonical RGBA bitmap pixel against an expected sRGB color.
 * @param {Uint8Array} bitmap - Physical four-channel screenshot bitmap.
 * @param {number} index - First channel for the candidate pixel.
 * @param {[number, number, number]} expected - Expected renderer RGB channels.
 * @returns {number} Smallest maximum channel delta across native arrangements.
 */
function visualAnchorColorDifference(bitmap, index, expected) {
    return Math.max(Math.abs(bitmap[index] - expected[0]), Math.abs(bitmap[index + 1] - expected[1]), Math.abs(bitmap[index + 2] - expected[2]))
}

/**
 * Reports whether one bitmap pixel approximates an expected sRGB color.
 * @param {Uint8Array} bitmap - Physical four-channel screenshot bitmap.
 * @param {number} index - First channel for the candidate pixel.
 * @param {[number, number, number]} expected - Expected renderer RGB channels.
 * @returns {boolean} True when the pixel is within the bounded color tolerance.
 */
function matchesVisualAnchorColor(bitmap, index, expected) {
    return visualAnchorColorDifference(bitmap, index, expected) <= RASTER_ANCHOR_COLOR_TOLERANCE
}

/**
 * Validates each renderer-declared structural anchor only inside its canonical
 * PNG screenshot crop. Canonical row and color order remove native bitmap
 * ambiguity and prevent unrelated page pixels from satisfying a missing or
 * shifted compositor layer.
 * @param {{name: string, color: string, fiducialColor: string, raster: {width: number, height: number, bitmap: Uint8Array}}[]} anchors - Decoded anchor crops, foreground colors, and unique test fiducials.
 * @returns {{anchorCount: number, paintedAnchors: {name: string, matchingPixels: number, minimumPixels: number, fiducialPixels: number}[]}} Serializable painted-anchor evidence.
 * @throws {Error} When a crop is incomplete or lacks enough foreground pixels.
 */
export function assertVisualRasterAnchorCrops(anchors) {
    if (!Array.isArray(anchors) || anchors.length < 2) throw new Error('Visual QA raster anchor evidence is incomplete')
    const missing = []
    const paintedAnchors = []
    for (const anchor of anchors) {
        const expected = parseVisualRgbColor(anchor?.color)
        const expectedFiducial = parseVisualRgbColor(anchor?.fiducialColor)
        const raster = anchor?.raster
        const expectedLength = raster?.width * raster?.height * 4
        if (typeof anchor?.name !== 'string' || anchor.name.length === 0 || expected === null || expectedFiducial === null || !Number.isSafeInteger(raster?.width) || raster.width <= 0 || !Number.isSafeInteger(raster?.height) || raster.height <= 0 || raster.bitmap?.length !== expectedLength) {
            missing.push(anchor?.name ?? 'invalid-anchor')
            continue
        }
        const minimumPixels = Math.max(MINIMUM_RASTER_ANCHOR_PIXELS, Math.ceil(raster.width * raster.height * MINIMUM_RASTER_ANCHOR_COVERAGE))
        let matchingPixels = 0
        let fiducialPixels = 0
        let closestDifference = Number.POSITIVE_INFINITY
        for (let index = 0; index < raster.bitmap.length; index += 4) {
            closestDifference = Math.min(closestDifference, visualAnchorColorDifference(raster.bitmap, index, expected))
            if (matchesVisualAnchorColor(raster.bitmap, index, expected)) matchingPixels += 1
            if (visualAnchorColorDifference(raster.bitmap, index, expectedFiducial) <= RASTER_FIDUCIAL_COLOR_TOLERANCE) fiducialPixels += 1
        }
        if (matchingPixels < minimumPixels || fiducialPixels < MINIMUM_RASTER_FIDUCIAL_PIXELS) missing.push(`${anchor.name}[pixels=${matchingPixels}/${minimumPixels};fiducial=${fiducialPixels}/${MINIMUM_RASTER_FIDUCIAL_PIXELS};closest=${closestDifference}]`)
        else paintedAnchors.push({ name: anchor.name, matchingPixels, minimumPixels, fiducialPixels })
    }
    if (missing.length > 0) throw new Error(`Visual QA raster anchors missing: ${missing.join(', ')}`)
    return { anchorCount: anchors.length, paintedAnchors }
}

/**
 * Rejects incomplete or contradictory visual evidence instead of allowing the
 * screenshot command to succeed merely because a PNG was written.
 * @param {object} inspection - Serializable renderer/runtime observations.
 * @param {object} expected - Exact matrix entry being inspected.
 * @returns {void} Completes when all fail-closed checks pass.
 * @throws {Error} Lists every failed visual/runtime contract.
 */
export function assertVisualSnapshot(inspection, expected) {
    const failures = []
    if (!owns(inspection, 'state') || inspection.state !== expected.state) {
        failures.push('state or viewport mismatch')
    }
    if (!owns(inspection, 'surface') || inspection.surface !== expected.surface) {
        failures.push('surface mismatch')
    }
    if (!owns(inspection, 'language') || inspection.language !== expected.language) {
        failures.push('language mismatch')
    }
    if (!owns(inspection, 'viewport') || typeof inspection.viewport !== 'object' || inspection.viewport === null) {
        failures.push('missing viewport evidence')
    }
    const viewportWidth = requireNumber(inspection?.viewport, 'width', failures, 'viewport')
    const viewportHeight = requireNumber(inspection?.viewport, 'height', failures, 'viewport')
    if (!owns(inspection?.viewport, 'name') || inspection.viewport.name !== expected.viewport.name || viewportWidth === null || viewportHeight === null || viewportWidth <= 0 || viewportHeight <= 0) {
        failures.push('state or viewport mismatch')
    }

    if (!owns(inspection, 'windowBounds') || typeof inspection.windowBounds !== 'object' || inspection.windowBounds === null) {
        failures.push('missing windowBounds evidence')
    }
    const windowX = requireNumber(inspection?.windowBounds, 'x', failures, 'windowBounds')
    const windowY = requireNumber(inspection?.windowBounds, 'y', failures, 'windowBounds')
    const windowWidth = requireNumber(inspection?.windowBounds, 'width', failures, 'windowBounds')
    const windowHeight = requireNumber(inspection?.windowBounds, 'height', failures, 'windowBounds')
    if (windowX !== null && !Number.isSafeInteger(windowX)) failures.push('window bounds are not integral')
    if (windowY !== null && !Number.isSafeInteger(windowY)) failures.push('window bounds are not integral')
    if (windowWidth !== expected.viewport.width || windowHeight !== expected.viewport.height) failures.push('window bounds mismatch')

    if (!owns(inspection, 'contentSize') || typeof inspection.contentSize !== 'object' || inspection.contentSize === null) {
        failures.push('missing contentSize evidence')
    }
    const contentWidth = requireNumber(inspection?.contentSize, 'width', failures, 'contentSize')
    const contentHeight = requireNumber(inspection?.contentSize, 'height', failures, 'contentSize')
    if (contentWidth === null || contentHeight === null || contentWidth <= 0 || contentHeight <= 0 || contentWidth > expected.viewport.width || contentHeight > expected.viewport.height) {
        failures.push('content size is outside window bounds')
    }
    if (viewportWidth !== contentWidth || viewportHeight !== contentHeight) failures.push('renderer viewport does not match content size')

    if (!owns(inspection, 'documentOverflowX') || !owns(inspection, 'bodyOverflowX') || inspection.documentOverflowX !== 0 || inspection.bodyOverflowX !== 0) {
        failures.push('horizontal overflow')
    }
    const clippedElements = requireArray(inspection, 'clippedElements', failures)
    if (clippedElements.length > 0) {
        failures.push(`clipped elements: ${clippedElements.join(', ')}`)
    }
    const horizontalScrollOffsets = requireArray(inspection, 'horizontalScrollOffsets', failures)
    if (horizontalScrollOffsets.length > 0) failures.push(`horizontal scroll offsets: ${horizontalScrollOffsets.join(', ')}`)
    const verticalScrollOffsets = requireArray(inspection, 'verticalScrollOffsets', failures)
    if (!INTENTIONALLY_SCROLLED_STATES.has(expected.state) && verticalScrollOffsets.length > 0) failures.push(`vertical scroll offsets: ${verticalScrollOffsets.join(', ')}`)
    if (!owns(inspection, 'topbarInViewport') || inspection.topbarInViewport !== true) failures.push('topbar is outside viewport')
    const rasterAnchors = requireArray(inspection, 'rasterAnchors', failures)
    const rasterAnchorNames = new Set()
    if (rasterAnchors.length < 2) failures.push('structural raster anchors are incomplete')
    for (const anchor of rasterAnchors) {
        const rect = anchor?.rect
        if (typeof anchor?.name !== 'string' || anchor.name.length === 0 || rasterAnchorNames.has(anchor.name) || parseVisualRgbColor(anchor?.color) === null || parseVisualRgbColor(anchor?.fiducialColor) === null || !Number.isFinite(rect?.left) || !Number.isFinite(rect?.top) || !Number.isFinite(rect?.right) || !Number.isFinite(rect?.bottom) || !Number.isFinite(rect?.width) || rect.width <= 0 || !Number.isFinite(rect?.height) || rect.height <= 0) {
            failures.push(`structural raster anchor is invalid: ${JSON.stringify(anchor)}`)
            break
        }
        rasterAnchorNames.add(anchor.name)
    }
    const unlabeledControls = requireArray(inspection, 'unlabeledControls', failures)
    if (unlabeledControls.length > 0) {
        failures.push(`unlabeled controls: ${unlabeledControls.join(', ')}`)
    }
    const disabledWithoutReason = requireArray(inspection, 'disabledWithoutReason', failures)
    if (disabledWithoutReason.length > 0) {
        failures.push(`disabled controls without reasons: ${disabledWithoutReason.join(', ')}`)
    }
    const disabledControls = requireArray(inspection, 'disabledControls', failures)
    const disabledControlCount = requireNumber(inspection, 'disabledControlCount', failures, 'inspection')
    if (disabledControlCount === null || !Number.isSafeInteger(disabledControlCount) || disabledControlCount < 0 || disabledControls.length !== disabledControlCount) {
        failures.push('disabled-control inventory is incomplete')
    }
    const disabledKeys = new Set()
    for (const control of disabledControls) {
        if (typeof control?.key !== 'string' || control.key.length === 0 || disabledKeys.has(control.key) || !Array.isArray(control?.reasons) || control.reasons.length === 0 || control.reasons.some((reason) => typeof reason !== 'string' || reason.trim().length === 0)) {
            failures.push(`disabled-control inventory is invalid: ${JSON.stringify(control)}`)
            break
        }
        disabledKeys.add(control.key)
    }
    if (!owns(inspection, 'destructivePreflightEvidence')) {
        failures.push('missing destructivePreflightEvidence evidence')
    } else if (expected.state === 'destructive-preflight') {
        const evidence = inspection.destructivePreflightEvidence
        if (evidence?.actionEnabled !== true || evidence?.exactIdentityEntered !== true || evidence?.noActiveOperation !== true || evidence?.targetInViewport !== true) {
            failures.push('destructive preflight evidence is incomplete')
        }
    } else if (inspection.destructivePreflightEvidence !== null) {
        failures.push('unexpected destructive preflight evidence')
    }
    if (!owns(inspection, 'disabledReasonEvidence')) {
        failures.push('missing disabledReasonEvidence evidence')
    } else if (expected.state === 'disabled-reasons') {
        const evidence = inspection.disabledReasonEvidence
        if (!Number.isSafeInteger(evidence?.reasonCount) || evidence.reasonCount < 1 || evidence?.targetInViewport !== true) {
            failures.push('disabled-reason scene evidence is incomplete')
        }
    } else if (inspection.disabledReasonEvidence !== null) {
        failures.push('unexpected disabled-reason scene evidence')
    }
    if (!owns(inspection, 'protectedAccessEvidence')) {
        failures.push('missing protectedAccessEvidence evidence')
    } else if (['protected-locked', 'protected-unlocked'].includes(expected.state)) {
        const evidence = inspection.protectedAccessEvidence
        const locked = expected.state === 'protected-locked'
        if (evidence?.reportedState !== (locked ? 'disabled' : 'enabled') || evidence?.enableAccessEnabled !== locked || evidence?.disableAccessEnabled === locked || evidence?.targetInViewport !== true) {
            failures.push('protected access evidence is incomplete')
        }
    } else if (inspection.protectedAccessEvidence !== null) {
        failures.push('unexpected protected access evidence')
    }
    if (!owns(inspection, 'updateUnavailableEvidence')) {
        failures.push('missing updateUnavailableEvidence evidence')
    } else if (expected.state === 'update-unavailable') {
        const evidence = inspection.updateUnavailableEvidence
        if (evidence?.checkEnabled !== true || evidence?.failureVisible !== true || evidence?.networkReasonVisible !== true || evidence?.targetInViewport !== true) {
            failures.push('update-unavailable evidence is incomplete')
        }
    } else if (inspection.updateUnavailableEvidence !== null) {
        failures.push('unexpected update-unavailable evidence')
    }
    const unexpectedEnabledControls = requireArray(inspection, 'unexpectedEnabledControls', failures)
    if (unexpectedEnabledControls.length > 0) {
        failures.push(`unexpected enabled controls: ${unexpectedEnabledControls.join(', ')}`)
    }
    const contradictoryCopy = requireArray(inspection, 'contradictoryCopy', failures)
    if (contradictoryCopy.length > 0) {
        failures.push(`contradictory provenance: ${contradictoryCopy.join(', ')}`)
    }
    const resourceUrls = requireArray(inspection, 'resourceUrls', failures)
    if (resourceUrls.length === 0 || resourceUrls.some((url) => typeof url !== 'string')) failures.push('local resource evidence missing')
    const remoteResources = resourceUrls.filter((url) => typeof url === 'string' && !url.startsWith('file:') && !url.startsWith('data:'))
    if (remoteResources.length > 0) {
        failures.push(`remote resource: ${remoteResources.join(', ')}`)
    }
    const fonts = requireArray(inspection, 'computedFonts', failures)
    if (!fonts.some((font) => font.includes('Inter')) || !fonts.some((font) => font.includes('Oxanium'))) {
        failures.push('local fonts missing')
    }
    if (!owns(inspection, 'iconGlyphCount') || !Number.isSafeInteger(inspection.iconGlyphCount) || inspection.iconGlyphCount < 1) {
        failures.push('icons missing')
    }
    if (!owns(inspection, 'csp') || typeof inspection.csp !== 'string' || !inspection.csp.includes("default-src 'self'") || !inspection.csp.includes("connect-src 'none'") || /https?:/.test(inspection.csp)) {
        failures.push('CSP is not local-only')
    }
    if (!owns(inspection, 'serviceStatusVisible') || inspection.serviceStatusVisible !== true) {
        failures.push('service status is not visibly truthful')
    }
    const consoleErrors = requireArray(inspection, 'consoleErrors', failures)
    if (consoleErrors.length > 0) {
        failures.push(`console errors: ${consoleErrors.join(', ')}`)
    }
    const pageErrors = requireArray(inspection, 'pageErrors', failures)
    if (pageErrors.length > 0) {
        failures.push(`page errors: ${pageErrors.join(', ')}`)
    }
    const loadFailures = requireArray(inspection, 'loadFailures', failures)
    if (loadFailures.length > 0) {
        failures.push(`load failures: ${loadFailures.join(', ')}`)
    }
    const rendererCrashes = requireArray(inspection, 'rendererCrashes', failures)
    if (rendererCrashes.length > 0) {
        failures.push(`renderer crashes: ${rendererCrashes.join(', ')}`)
    }
    if (!owns(inspection, 'keyboardEvidence')) {
        failures.push('missing keyboardEvidence evidence')
    }
    if (expected.keyboard === true && (typeof inspection.keyboardEvidence?.outlineWidth !== 'string' || !/^\d+(?:\.\d+)?px$/u.test(inspection.keyboardEvidence.outlineWidth) || parseFloat(inspection.keyboardEvidence.outlineWidth) < 2 || typeof inspection.keyboardEvidence?.outlineStyle !== 'string' || inspection.keyboardEvidence.outlineStyle === 'none' || inspection.keyboardEvidence.outlineStyle.length === 0)) {
        failures.push('keyboard focus evidence has an invalid measured outline')
    }
    // macOS may leave another host application OS-active during automation;
    // the rendered :focus-visible ring and traversal are the visual contract.
    if (expected.keyboard === true && (!owns(inspection?.keyboardEvidence, 'skipLinkFocused') || !owns(inspection.keyboardEvidence, 'visibleFocusRing') || !owns(inspection.keyboardEvidence, 'focusVisibleMatched') || !owns(inspection.keyboardEvidence, 'windowFocusedAtTraversal') || !owns(inspection.keyboardEvidence, 'shiftTabReturnedToSkipLink') || !owns(inspection.keyboardEvidence, 'endArea') || !owns(inspection.keyboardEvidence, 'homeArea') || inspection.keyboardEvidence.skipLinkFocused !== true || inspection.keyboardEvidence.visibleFocusRing !== true || inspection.keyboardEvidence.focusVisibleMatched !== true || inspection.keyboardEvidence.shiftTabReturnedToSkipLink !== true || inspection.keyboardEvidence.endArea !== 'utilities' || inspection.keyboardEvidence.homeArea !== 'status')) {
        failures.push(`keyboard focus evidence incomplete: ${JSON.stringify(inspection.keyboardEvidence)}`)
    } else if (expected.keyboard !== true && inspection.keyboardEvidence !== null) {
        failures.push('unexpected keyboard focus evidence')
    }
    if (failures.length > 0) {
        throw new Error(`Visual QA failed for ${expected.state}/${expected.viewport.name}: ${failures.join('; ')}`)
    }
}
