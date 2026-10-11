// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import * as visualQaContract from '../electron-test/visual-qa-contract.mjs'
import { normalizeConsoleMessage, VisualErrorTracker } from '../electron-test/visual-error-tracker.mjs'
import { captureValidatedVisualImage, loadWithPageErrorCapture, runWithVisualErrorCursor } from '../electron-test/visual-runtime-capture.mjs'

const { assertVisualRasterAnchorCrops, assertVisualSnapshot, createVisualQaMatrix } = visualQaContract

/**
 * Creates a hand-derived passing browser inspection result.
 * @param {object} entry - Capture-plan entry.
 * @returns {object} Complete controlled inspection input.
 */
function createPassingInspection(entry) {
    return {
        state: entry.state,
        viewport: { name: entry.viewport.name, width: entry.viewport.width, height: entry.viewport.height - 28 },
        windowBounds: { x: 40, y: 30, width: entry.viewport.width, height: entry.viewport.height },
        contentSize: { width: entry.viewport.width, height: entry.viewport.height - 28 },
        documentOverflowX: 0,
        bodyOverflowX: 0,
        clippedElements: [],
        unlabeledControls: [],
        disabledWithoutReason: [],
        disabledControlCount: 1,
        disabledControls: [{ key: 'fixture:disabled', reasons: ['Fixture reason'] }],
        destructivePreflightEvidence:
            entry.state === 'destructive-preflight'
                ? {
                      actionEnabled: true,
                      exactIdentityEntered: true,
                      noActiveOperation: true,
                      targetInViewport: true
                  }
                : null,
        disabledReasonEvidence: entry.state === 'disabled-reasons' ? { reasonCount: 1, targetInViewport: true } : null,
        protectedAccessEvidence: entry.state === 'protected-locked' ? { disableAccessEnabled: false, enableAccessEnabled: true, reportedState: 'disabled', targetInViewport: true } : entry.state === 'protected-unlocked' ? { disableAccessEnabled: true, enableAccessEnabled: false, reportedState: 'enabled', targetInViewport: true } : null,
        unexpectedEnabledControls: [],
        contradictoryCopy: [],
        resourceUrls: ['file:///app/src/index.html', 'file:///app/node_modules/@fontsource/inter/400.css'],
        computedFonts: ['Inter', 'Oxanium'],
        iconGlyphCount: 4,
        csp: "default-src 'self'; connect-src 'none'",
        serviceStatusVisible: true,
        consoleErrors: [],
        pageErrors: [],
        loadFailures: [],
        rendererCrashes: [],
        keyboardEvidence:
            entry.keyboard === true
                ? {
                      endArea: 'utilities',
                      focusVisibleMatched: true,
                      homeArea: 'status',
                      outlineStyle: 'solid',
                      outlineWidth: '2px',
                      shiftTabReturnedToSkipLink: true,
                      skipLinkFocused: true,
                      visibleFocusRing: true,
                      windowFocusedAtTraversal: true
                  }
                : null,
        language: entry.language,
        horizontalScrollOffsets: [],
        verticalScrollOffsets: [],
        topbarInViewport: true,
        rasterAnchors: [
            { name: 'brand', color: 'rgb(22, 230, 238)', fiducialColor: 'rgb(255, 0, 255)', rect: { left: 8, top: 8, right: 80, bottom: 32, width: 72, height: 24 } },
            { name: 'main-heading', color: 'rgb(233, 247, 255)', fiducialColor: 'rgb(255, 255, 0)', rect: { left: 120, top: 100, right: 260, bottom: 132, width: 140, height: 32 } }
        ],
        surface: entry.surface,
        updateUnavailableEvidence: entry.state === 'update-unavailable' ? { checkEnabled: true, failureVisible: true, networkReasonVisible: true, targetInViewport: true } : null
    }
}

test('visual QA matrix covers the complete feature, risk, recovery, and eight-language surfaces at both required sizes', () => {
    const matrix = createVisualQaMatrix()

    assert.equal(matrix.length, 62)
    assert.deepEqual([...new Set(matrix.map(({ state }) => state))], ['no-device', 'ready-no-media', 'protected-locked', 'protected-unlocked', 'status', 'encryption', 'tests', 'utilities', 'activity', 'help', 'support', 'compatibility', 'routine-active', 'critical-active', 'destructive-preflight', 'destructive-active', 'disabled-reasons', 'operation-success', 'operation-failure', 'service-unavailable', 'update-unavailable', 'language-en', 'language-zh', 'language-de', 'language-fr', 'language-it', 'language-pt', 'language-es', 'language-ja', 'starting-runtime', 'ready-no-device-runtime'])
    assert.deepEqual([...new Set(matrix.map(({ viewport }) => `${viewport.width}x${viewport.height}`))], ['1024x768', '1440x900'])
    assert.deepEqual([...new Set(matrix.filter(({ state }) => state.startsWith('language-')).map(({ language }) => language))], ['en', 'zh', 'de', 'fr', 'it', 'pt', 'es', 'ja'])
    assert.equal(new Set(matrix.map(({ screenshot }) => screenshot)).size, 62)
    assert.equal(matrix.every(Object.isFrozen), true)
})

test('identical visual inspections serialize to byte-identical deterministic manifests', () => {
    assert.equal(typeof visualQaContract.serializeVisualQaManifest, 'function')
    const entry = createVisualQaMatrix()[0]
    const results = [{ screenshot: entry.screenshot, inspection: createPassingInspection(entry) }]

    const first = visualQaContract.serializeVisualQaManifest(results)
    const second = visualQaContract.serializeVisualQaManifest(structuredClone(results))

    assert.equal(first, second)
    assert.doesNotMatch(first, /generatedAt/)
    assert.deepEqual(Object.keys(JSON.parse(first)), ['schemaVersion', 'evidenceKind', 'harness', 'productionFixtureActivation', 'physicalHardwareVerified', 'results'])
})

test('visual manifests keep successful repaint retry counts in separate run metrics', () => {
    const first = [{ screenshot: 'fixture.png', inspection: { rasterEvidence: { anchorCount: 4, captureAttempts: 1 } } }]
    const retried = structuredClone(first)
    retried[0].inspection.rasterEvidence.captureAttempts = 3
    assert.equal(visualQaContract.serializeVisualQaManifest(first), visualQaContract.serializeVisualQaManifest(retried))
    assert.deepEqual(JSON.parse(visualQaContract.serializeVisualQaCaptureMetrics(retried)).captures, [{ screenshot: 'fixture.png', attempts: 3 }])
    assert.equal(retried[0].inspection.rasterEvidence.captureAttempts, 3)
    retried[0].inspection.rasterEvidence.captureAttempts = 5
    assert.throws(() => visualQaContract.serializeVisualQaCaptureMetrics(retried), /attempts-invalid/u)
})

test('visual manifests exclude host-dependent window activation evidence', () => {
    const entry = createVisualQaMatrix().find(({ state }) => state === 'status')
    const focused = [{ screenshot: entry.screenshot, inspection: createPassingInspection(entry) }]
    const inactive = structuredClone(focused)
    inactive[0].inspection.keyboardEvidence.windowFocusedAtTraversal = false

    const focusedManifest = visualQaContract.serializeVisualQaManifest(focused)
    const inactiveManifest = visualQaContract.serializeVisualQaManifest(inactive)

    assert.equal(focusedManifest, inactiveManifest)
    assert.doesNotMatch(focusedManifest, /windowFocusedAtTraversal/)
})

test('visual manifests retain all resource identities without depending on load completion order', () => {
    const entry = createVisualQaMatrix()[0]
    const first = [{ screenshot: entry.screenshot, inspection: createPassingInspection(entry) }]
    first[0].inspection.resourceUrls.push('file:///app/src/renderer.mjs', 'file:///app/src/index.html')
    const reordered = structuredClone(first)
    reordered[0].inspection.resourceUrls.reverse()
    assertVisualSnapshot(first[0].inspection, entry)
    assertVisualSnapshot(reordered[0].inspection, entry)
    assert.equal(visualQaContract.serializeVisualQaManifest(first), visualQaContract.serializeVisualQaManifest(reordered))
    const serialized = JSON.parse(visualQaContract.serializeVisualQaManifest(first))
    assert.equal(serialized.results[0].inspection.resourceUrls.filter((url) => url === 'file:///app/src/index.html').length, 2)
    assert.notDeepEqual(first[0].inspection.resourceUrls, reordered[0].inspection.resourceUrls)
    reordered[0].inspection.resourceUrls.push('https://example.invalid/forbidden.js')
    assert.throws(() => assertVisualSnapshot(reordered[0].inspection, entry), /remote resource/)
    assert.match(visualQaContract.serializeVisualQaManifest(reordered), /https:\/\/example\.invalid\/forbidden\.js/)
})

test('host-dependent focus-ring widths remain validated and retained in run metrics', () => {
    const entry = createVisualQaMatrix().find(({ state }) => state === 'status')
    const first = [{ screenshot: entry.screenshot, inspection: createPassingInspection(entry) }]
    first[0].inspection.rasterEvidence = { captureAttempts: 1 }
    const wider = structuredClone(first)
    wider[0].inspection.keyboardEvidence.outlineWidth = '3px'
    assertVisualSnapshot(first[0].inspection, entry)
    assertVisualSnapshot(wider[0].inspection, entry)
    assert.equal(visualQaContract.serializeVisualQaManifest(first), visualQaContract.serializeVisualQaManifest(wider))
    assert.equal(JSON.parse(visualQaContract.serializeVisualQaCaptureMetrics(first)).captures[0].keyboardOutlineWidth, '2px')
    assert.equal(JSON.parse(visualQaContract.serializeVisualQaCaptureMetrics(wider)).captures[0].keyboardOutlineWidth, '3px')
    for (const width of ['1px', '0px', '2em', undefined]) {
        wider[0].inspection.keyboardEvidence.outlineWidth = width
        assert.throws(() => assertVisualSnapshot(wider[0].inspection, entry), /invalid measured outline/)
    }
})

test('visual screenshot evidence ignores bounded compositor noise but retains meaningful changes', () => {
    assert.equal(typeof visualQaContract.shouldReplaceVisualScreenshot, 'function')
    const tracked = { width: 2, height: 1, bitmap: Uint8Array.from([4, 12, 24, 255, 40, 52, 64, 255]) }

    assert.equal(visualQaContract.shouldReplaceVisualScreenshot(tracked, structuredClone(tracked)), false)
    assert.equal(visualQaContract.shouldReplaceVisualScreenshot(tracked, { ...tracked, bitmap: Uint8Array.from([4, 12, 25, 255, 40, 52, 64, 255]) }), false)
    assert.equal(visualQaContract.shouldReplaceVisualScreenshot(tracked, { ...tracked, bitmap: Uint8Array.from([4, 12, 26, 255, 40, 52, 64, 255]) }), false)
    assert.equal(visualQaContract.shouldReplaceVisualScreenshot(tracked, { ...tracked, bitmap: Uint8Array.from([4, 12, 28, 255, 40, 52, 64, 255]) }), true)
    assert.equal(visualQaContract.shouldReplaceVisualScreenshot(tracked, { width: 1, height: 1, bitmap: Uint8Array.from([4, 12, 24, 255]) }), true)

    const boundaryTracked = { width: 20, height: 1, bitmap: new Uint8Array(80).fill(100) }
    const boundedNoise = structuredClone(boundaryTracked)
    boundedNoise.bitmap.fill(103, 0, 64)
    assert.equal(visualQaContract.shouldReplaceVisualScreenshot(boundaryTracked, boundedNoise), false)
    boundedNoise.bitmap[64] = 101
    assert.equal(visualQaContract.shouldReplaceVisualScreenshot(boundaryTracked, boundedNoise), true)
})

test('visual screenshot evidence replaces equal-area rasters with different physical dimensions', () => {
    const bitmap = new Uint8Array(16).fill(24)

    assert.equal(visualQaContract.shouldReplaceVisualScreenshot({ width: 2, height: 2, bitmap }, { width: 1, height: 4, bitmap: structuredClone(bitmap) }), true)
})

test('raster anchors reject compositor-shifted pixels even when DOM geometry remains valid', () => {
    assert.equal(typeof assertVisualRasterAnchorCrops, 'function')
    const anchors = [
        { name: 'brand', color: 'rgb(22, 230, 238)', fiducialColor: 'rgb(255, 0, 255)' },
        { name: 'device-rail-heading', color: 'rgb(22, 230, 238)', fiducialColor: 'rgb(127, 255, 0)' },
        { name: 'main-heading', color: 'rgb(233, 247, 255)', fiducialColor: 'rgb(255, 255, 0)' },
        { name: 'command-rail-heading', color: 'rgb(22, 230, 238)', fiducialColor: 'rgb(255, 0, 127)' }
    ]

    for (const anchor of anchors) {
        anchor.raster = { width: 20, height: 8, bitmap: new Uint8Array(20 * 8 * 4).fill(8) }
        const red = Number(anchor.color.match(/\d+/g)[0])
        const green = Number(anchor.color.match(/\d+/g)[1])
        const blue = Number(anchor.color.match(/\d+/g)[2])
        const [fiducialRed, fiducialGreen, fiducialBlue] = anchor.fiducialColor.match(/\d+/g).map(Number)
        for (let offset = 0; offset < 12; offset += 1) {
            const index = (3 * anchor.raster.width + 3 + offset) * 4
            anchor.raster.bitmap.set([red, green, blue, 255], index)
        }
        for (let offset = 0; offset < 8; offset += 1) {
            anchor.raster.bitmap.set([fiducialRed, fiducialGreen, fiducialBlue, 255], offset * 4)
        }
    }

    assert.deepEqual(assertVisualRasterAnchorCrops(anchors), {
        anchorCount: 4,
        paintedAnchors: [
            { name: 'brand', matchingPixels: 12, minimumPixels: 8, fiducialPixels: 8 },
            { name: 'device-rail-heading', matchingPixels: 12, minimumPixels: 8, fiducialPixels: 8 },
            { name: 'main-heading', matchingPixels: 12, minimumPixels: 8, fiducialPixels: 8 },
            { name: 'command-rail-heading', matchingPixels: 12, minimumPixels: 8, fiducialPixels: 8 }
        ]
    })

    const shifted = structuredClone(anchors)
    for (const anchor of [shifted[0], shifted[1], shifted[3]]) {
        anchor.raster.bitmap.fill(8)
        const [red, green, blue] = anchor.color.match(/\d+/g).map(Number)
        for (let offset = 0; offset < 24; offset += 1) {
            anchor.raster.bitmap.set([red, green, blue, 255], offset * 4)
        }
    }

    assert.throws(() => assertVisualRasterAnchorCrops(shifted), /raster anchors missing.*brand.*device-rail-heading.*command-rail-heading/)
})

test('validated capture discards stale compositor frames and fails closed when none repaint', async () => {
    const frames = ['stale-overlay', 'complete-shell']
    const preparations = []
    const result = await captureValidatedVisualImage({
        /** @returns {Promise<string>} Next simulated compositor frame. */
        async capture() {
            return frames.shift()
        },
        /** @param {number} attempt - One-based capture attempt. @returns {Promise<void>} */
        async prepare(attempt) {
            preparations.push(attempt)
        },
        /** @param {string} frame - Candidate compositor frame. @returns {object} */
        validate(frame) {
            if (frame !== 'complete-shell') throw new Error('raster anchors missing: brand')
            return { anchorCount: 4 }
        }
    })

    assert.deepEqual(result, { image: 'complete-shell', evidence: { anchorCount: 4 }, attempts: 2 })
    assert.deepEqual(preparations, [1, 2])

    await assert.rejects(
        captureValidatedVisualImage({
            /** @returns {Promise<string>} Permanently stale simulated frame. */
            async capture() {
                return 'stale-overlay'
            },
            /** @returns {Promise<void>} No-op simulated repaint. */
            async prepare() {},
            /** @returns {never} Rejects the permanently stale frame. */
            validate() {
                throw new Error('raster anchors missing: command-rail-heading')
            },
            maxAttempts: 3
        }),
        /after 3 attempts.*command-rail-heading/
    )
})

test('disabled-control inventory keys distinguish checkbox data identities before their shared HTML value', () => {
    assert.equal(typeof visualQaContract.createVisualControlKey, 'function')
    const read = { dataset: { permissionInput: 'read' }, getAttribute: () => null, tagName: 'INPUT', type: 'checkbox', value: 'on' }
    const write = { dataset: { permissionInput: 'write' }, getAttribute: () => null, tagName: 'INPUT', type: 'checkbox', value: 'on' }

    assert.equal(visualQaContract.createVisualControlKey(read, 0), 'input:data-permissionInput=read')
    assert.equal(visualQaContract.createVisualControlKey(write, 1), 'input:data-permissionInput=write')
    assert.notEqual(visualQaContract.createVisualControlKey(read, 0), visualQaContract.createVisualControlKey(write, 1))

    const rowAction = { dataset: { action: 'change-credential', rowChange: '', slot: '0' }, getAttribute: () => null, tagName: 'BUTTON', type: 'submit', value: '' }
    const globalAction = { dataset: { action: 'change-credential' }, getAttribute: () => null, tagName: 'BUTTON', type: 'submit', value: '' }
    assert.notEqual(visualQaContract.createVisualControlKey(rowAction, 2), visualQaContract.createVisualControlKey(globalAction, 3))
})

test('disabled reasons accept rendered associated copy but reject hidden copy and title-only hints', () => {
    assert.equal(typeof visualQaContract.collectVisualDisabledReasons, 'function')
    const dom = new JSDOM('<button aria-describedby="reason" title="Tooltip only">Run</button><p id="reason" hidden>Visible prerequisite</p>')
    const button = dom.window.document.querySelector('button')
    const isRendered = (element) => element.hidden !== true

    assert.deepEqual(visualQaContract.collectVisualDisabledReasons(button, dom.window.document, isRendered), [])
    dom.window.document.querySelector('#reason').hidden = false
    assert.deepEqual(visualQaContract.collectVisualDisabledReasons(button, dom.window.document, isRendered), ['Visible prerequisite'])
})

test('visual snapshot contract accepts complete local, unclipped Electron evidence', () => {
    const entry = createVisualQaMatrix()[0]
    assert.doesNotThrow(() => assertVisualSnapshot(createPassingInspection(entry), entry))
})

test('visual snapshot contract rejects a disabled-control inventory that omits a rendered disabled control', () => {
    const entry = createVisualQaMatrix()[0]
    const inspection = createPassingInspection(entry)
    inspection.disabledControlCount = 2

    assert.throws(() => assertVisualSnapshot(inspection, entry), /disabled-control inventory is incomplete/)
})

test('destructive preflight cannot pass as an unconfirmed duplicate Utilities capture', () => {
    const entry = createVisualQaMatrix().find(({ state }) => state === 'destructive-preflight')
    const inspection = createPassingInspection(entry)
    inspection.destructivePreflightEvidence.exactIdentityEntered = false

    assert.throws(() => assertVisualSnapshot(inspection, entry), /destructive preflight evidence is incomplete/)

    inspection.destructivePreflightEvidence.exactIdentityEntered = true
    inspection.destructivePreflightEvidence.targetInViewport = false
    assert.throws(() => assertVisualSnapshot(inspection, entry), /destructive preflight evidence is incomplete/)
})

test('protected access and unavailable update scenes require state-specific visible evidence', () => {
    const lockedEntry = createVisualQaMatrix().find(({ state }) => state === 'protected-locked')
    const lockedInspection = createPassingInspection(lockedEntry)
    lockedInspection.protectedAccessEvidence.reportedState = 'enabled'
    assert.throws(() => assertVisualSnapshot(lockedInspection, lockedEntry), /protected access evidence is incomplete/)
    lockedInspection.protectedAccessEvidence.reportedState = 'disabled'
    lockedInspection.protectedAccessEvidence.targetInViewport = false
    assert.throws(() => assertVisualSnapshot(lockedInspection, lockedEntry), /protected access evidence is incomplete/)

    const updateEntry = createVisualQaMatrix().find(({ state }) => state === 'update-unavailable')
    const updateInspection = createPassingInspection(updateEntry)
    updateInspection.updateUnavailableEvidence.failureVisible = false
    assert.throws(() => assertVisualSnapshot(updateInspection, updateEntry), /update-unavailable evidence is incomplete/)
    updateInspection.updateUnavailableEvidence.failureVisible = true
    updateInspection.updateUnavailableEvidence.targetInViewport = false
    assert.throws(() => assertVisualSnapshot(updateInspection, updateEntry), /update-unavailable evidence is incomplete/)
})

test('keyboard evidence rejects a missing focus-visible ring even when traversal reaches every target', () => {
    const entry = createVisualQaMatrix().find(({ state }) => state === 'status')
    const inspection = createPassingInspection(entry)
    inspection.keyboardEvidence.windowFocusedAtTraversal = false
    assert.doesNotThrow(() => assertVisualSnapshot(inspection, entry))

    inspection.keyboardEvidence.focusVisibleMatched = false
    assert.throws(() => assertVisualSnapshot(inspection, entry), /keyboard focus evidence incomplete/)
})

test('capture layout rejects inherited scroll and an offscreen topbar on ordinary scenes', () => {
    const entry = createVisualQaMatrix().find(({ state }) => state === 'operation-failure')
    const inspection = createPassingInspection(entry)
    inspection.horizontalScrollOffsets = ['main-workspace:32']
    inspection.verticalScrollOffsets = ['window:120']
    inspection.topbarInViewport = false

    assert.throws(() => assertVisualSnapshot(inspection, entry), /horizontal scroll offsets.*vertical scroll offsets.*topbar is outside viewport/s)
})

test('disabled-reasons scene requires its associated rationale target inside the capture viewport', () => {
    const entry = createVisualQaMatrix().find(({ state }) => state === 'disabled-reasons')
    const inspection = createPassingInspection(entry)
    inspection.disabledReasonEvidence.targetInViewport = false

    assert.throws(() => assertVisualSnapshot(inspection, entry), /disabled-reason scene evidence is incomplete/)
})

test('visual snapshot contract rejects overflow, remote resources, missing assets, unlabeled gates, and runtime errors', () => {
    const entry = createVisualQaMatrix()[0]
    const failing = {
        ...createPassingInspection(entry),
        documentOverflowX: 2,
        clippedElements: ['button:Open support'],
        unlabeledControls: ['button:nth-of-type(2)'],
        disabledWithoutReason: ['Scan'],
        unexpectedEnabledControls: ['firmware-update'],
        contradictoryCopy: ['fixture-and-service-provenance'],
        resourceUrls: ['https://cdn.example.invalid/font.woff2'],
        computedFonts: ['Arial'],
        iconGlyphCount: 0,
        csp: 'default-src *',
        serviceStatusVisible: false,
        consoleErrors: ['Uncaught TypeError'],
        pageErrors: ['Unhandled rejection'],
        loadFailures: ['font failed'],
        rendererCrashes: ['crashed'],
        keyboardEvidence: {
            endArea: 'status',
            homeArea: 'utilities',
            shiftTabReturnedToSkipLink: false,
            skipLinkFocused: false,
            visibleFocusRing: false
        }
    }

    assert.throws(() => assertVisualSnapshot(failing, entry), /horizontal overflow.*clipped.*unlabeled.*disabled controls without reasons.*unexpected enabled controls.*contradictory provenance.*remote resource.*local fonts.*icons.*CSP.*service status.*console errors.*page errors.*load failures.*renderer crashes.*keyboard focus/s)
})

const requiredInspectionPaths = ['state', 'surface', 'language', 'viewport', 'viewport.name', 'viewport.width', 'viewport.height', 'windowBounds', 'windowBounds.x', 'windowBounds.y', 'windowBounds.width', 'windowBounds.height', 'contentSize', 'contentSize.width', 'contentSize.height', 'documentOverflowX', 'bodyOverflowX', 'clippedElements', 'horizontalScrollOffsets', 'verticalScrollOffsets', 'topbarInViewport', 'rasterAnchors', 'unlabeledControls', 'disabledControlCount', 'disabledControls', 'disabledWithoutReason', 'disabledReasonEvidence', 'destructivePreflightEvidence', 'protectedAccessEvidence', 'updateUnavailableEvidence', 'unexpectedEnabledControls', 'contradictoryCopy', 'resourceUrls', 'computedFonts', 'iconGlyphCount', 'csp', 'serviceStatusVisible', 'consoleErrors', 'pageErrors', 'loadFailures', 'rendererCrashes', 'keyboardEvidence']

/**
 * Deletes a nested property from a complete visual inspection clone.
 * @param {object} value - Complete inspection object.
 * @param {string} path - Dot-delimited property path to omit.
 * @returns {object} Cloned inspection with the selected property omitted.
 */
function omitInspectionPath(value, path) {
    const clone = structuredClone(value)
    const segments = path.split('.')
    const property = segments.pop()
    let parent = clone
    for (const segment of segments) {
        parent = parent[segment]
    }
    delete parent[property]
    return clone
}

test('visual snapshot contract fails closed when any required evidence field is omitted', () => {
    const entry = createVisualQaMatrix()[0]
    const inspection = createPassingInspection(entry)

    for (const path of requiredInspectionPaths) {
        assert.throws(() => assertVisualSnapshot(omitInspectionPath(inspection, path), entry), undefined, `omitting ${path} must fail`)
    }
})

test('visual error cursors expose injected mount and transition errors and global checks retain earlier errors', () => {
    const mountTracker = new VisualErrorTracker()
    const beforeMount = mountTracker.capture()
    mountTracker.record('pageErrors', 'injected mount error')
    assert.throws(() => mountTracker.assertEmptySince(beforeMount, 'mount'), /injected mount error/)

    const transitionTracker = new VisualErrorTracker()
    const beforeTransition = transitionTracker.capture()
    transitionTracker.record('consoleErrors', 'injected transition error')
    assert.throws(() => transitionTracker.assertEmptySince(beforeTransition, 'transition'), /injected transition error/)

    const lateCursor = transitionTracker.capture()
    assert.doesNotThrow(() => transitionTracker.assertEmptySince(lateCursor, 'late capture'))
    assert.throws(() => transitionTracker.assertGloballyEmpty(), /injected transition error/)
})

test('console message normalization accepts Electron 44 details first and legacy positional events', () => {
    assert.deepEqual(normalizeConsoleMessage({ level: 'error', message: 'current exact error', lineNumber: 7, sourceId: 'file:///app/renderer.mjs' }, []), {
        level: 'error',
        message: 'current exact error'
    })
    assert.deepEqual(normalizeConsoleMessage({ preventDefault() {} }, [{ preventDefault() {} }, 3, 'legacy exact error', 8, 'file:///app/renderer.mjs']), {
        level: 'error',
        message: 'legacy exact error'
    })
    assert.equal(normalizeConsoleMessage({ level: 'warning', message: 'expected warning' }, [{}, 3, 'deprecated shadow error']), null)
    assert.equal(normalizeConsoleMessage({ level: 'error', message: '' }, []), null)
})

test('page-error capture enables the DevTools runtime concurrently with the initial renderer load', async () => {
    let resolveEnablement
    let commandStarted = false
    let loadStarted = false
    const debuggerSession = {
        attach() {},
        on() {},
        sendCommand() {
            commandStarted = true
            return new Promise((resolve) => {
                resolveEnablement = resolve
            })
        }
    }
    /** Starts navigation and releases the simulated Runtime.enable command. @returns {Promise<void>} */
    async function load() {
        assert.equal(commandStarted, true)
        loadStarted = true
        resolveEnablement()
    }
    /** No-op debugger event observer. @returns {void} */
    function handleMessage() {}

    await loadWithPageErrorCapture(debuggerSession, handleMessage, load)
    assert.equal(loadStarted, true)
})

test('tracked mount and transition operations retain errors injected during the operation', async () => {
    for (const [context, stream] of [
        ['mount', 'pageErrors'],
        ['transition', 'consoleErrors']
    ]) {
        const tracker = new VisualErrorTracker()
        /** Injects one error at the operation boundary under test. @returns {Promise<void>} */
        async function injectOperationError() {
            tracker.record(stream, `injected ${context} error`)
        }
        const { cursor } = await runWithVisualErrorCursor(tracker, injectOperationError)
        assert.throws(() => tracker.assertEmptySince(cursor, context), new RegExp(`injected ${context} error`))
    }
})
