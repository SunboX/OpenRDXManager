// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { englishCatalog } from '../src/locales/en.mjs'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { renderStatusView } from '../src/renderer/views/status-view.mjs'

const englishTranslator = createTranslator(englishCatalog, englishCatalog)

/**
 * Mounts the renderer controller into an isolated status-test DOM.
 * @param {object} state - Renderer state to display.
 * @param {object} [options={}] - Additional controller dependencies.
 * @returns {{dom: JSDOM, controller: object}} Mounted DOM and controller.
 */
function createStatusDashboard(state, options = {}) {
    const dom = new JSDOM('<!doctype html><html><body><div id="app"></div></body></html>', {
        url: 'file:///openrdxmanager/src/index.html',
        pretendToBeVisual: true
    })
    const controller = mountApplication(dom.window.document.querySelector('#app'), { store: createStore(state), ...options })
    return { dom, controller }
}

/**
 * Reads one visible definition-list value by its exact label.
 * @param {Document} document - DOM containing the data rows.
 * @param {string} section - Section heading identifier.
 * @param {string} label - Visible row label.
 * @returns {string|undefined} Matching visible value.
 */
function valueFor(document, section, label) {
    const rows = [...document.querySelectorAll(`#${section} + dl .data-row`)]
    for (const row of rows) {
        if (row.querySelector('dt').textContent === label) return row.querySelector('dd').textContent
    }
    return undefined
}

/**
 * Verifies known native drive facts render once and unknown fields stay honest.
 * @returns {void} Throws when status evidence is lost or invented.
 */
function testRendersCompleteTruthfulStatusFields() {
    const fixture = createFixtureState({ mode: 'one-device' }).devices[0]
    const device = {
        ...fixture,
        drive: {
            ...fixture.drive,
            firmwareRevision: '0283',
            productType: 'USB 3 / SATA III',
            connectionType: 'USB 3',
            operationMode: 'Fixed disk',
            powerSource: 'Power adapter',
            details: {
                ...fixture.drive.details,
                firmwareRevision: { availability: 'reported', value: '0283' },
                productType: { availability: 'reported', value: 'USB 3 / SATA III' },
                connectionType: { availability: 'reported', value: 'USB 3' },
                operationMode: { availability: 'reported', value: 'Fixed disk' },
                powerSource: { availability: 'reported', value: 'Power adapter' }
            }
        },
        media: null,
        mediaState: 'no-media'
    }
    const dom = new JSDOM(renderStatusView(device, { translator: englishTranslator }))
    const document = dom.window.document

    assert.equal(valueFor(document, 'drive-data-heading', 'Firmware revision'), '2.83')
    assert.equal(valueFor(document, 'drive-data-heading', 'Product type'), 'USB 3 / SATA III')
    assert.equal(valueFor(document, 'drive-data-heading', 'Connection type'), undefined)
    assert.equal(valueFor(document, 'drive-data-heading', 'Operation mode'), undefined)
    assert.equal(valueFor(document, 'drive-data-heading', 'Power source'), 'Power adapter')
    assert.equal(valueFor(document, 'drive-data-heading', 'Drive status'), undefined)
    assert.equal(document.querySelectorAll('#cartridge-data-heading + dl .data-row').length, 1)
    assert.equal(valueFor(document, 'cartridge-data-heading', 'Status'), 'No media')
    dom.window.close()
}

/**
 * Verifies rejected candidates surface only stable aggregate details.
 * @returns {void} Throws when safe diagnostics are missing.
 */
function testRendersCandidateRejectionDiagnostics() {
    const fixture = createFixtureState({ mode: 'no-device' })
    const state = {
        ...fixture,
        discovery: { ...fixture.discovery, diagnostics: { candidateCount: 1, acceptedCount: 0, rejections: [{ reason: 'candidate-validation-failed', count: 1 }] } }
    }
    const dashboard = createStatusDashboard(state)
    const diagnostics = dashboard.dom.window.document.querySelector('[data-discovery-diagnostics]')
    assert.match(diagnostics.textContent, /1 candidate rejected/)
    assert.match(diagnostics.textContent, /candidate-validation-failed/)
    dashboard.controller.destroy()
    dashboard.dom.window.close()
}

/**
 * Verifies a path-free whole-pass failure remains visible with stale data.
 * @returns {void} Throws when failure evidence or the snapshot disappears.
 */
function testRendersPathFreeDiscoveryFailureWithStaleSnapshot() {
    const fixture = createFixtureState({ mode: 'one-device' })
    const state = { ...fixture, discovery: { ...fixture.discovery, scanStatus: 'idle', lastFailure: 'platform-access-denied' } }
    const dashboard = createStatusDashboard(state)
    assert.match(dashboard.dom.window.document.querySelector('[data-discovery-failure]').textContent, /platform-access-denied/)
    assert.match(dashboard.dom.window.document.body.textContent, /RDX QuikStor USB3\+ External/)
    dashboard.controller.destroy()
    dashboard.dom.window.close()
}

/**
 * Verifies absent optional media booleans use meaningful copy.
 * @returns {void} Throws when absence is misrepresented as false or a code.
 */
function testRendersAbsentMediaBooleansAsNotReported() {
    const fixture = createFixtureState({ mode: 'one-device' }).devices[0]
    const media = {
        ...fixture.media,
        details: {
            ...fixture.media.details,
            writeProtected: { availability: 'unavailable', reason: 'not-reported' },
            encrypted: { availability: 'unavailable', reason: 'not-reported' }
        }
    }
    delete media.writable
    delete media.encrypted
    const dom = new JSDOM(renderStatusView({ ...fixture, media }, { translator: englishTranslator }))
    assert.equal(valueFor(dom.window.document, 'cartridge-data-heading', 'Write protection'), undefined)
    assert.equal(valueFor(dom.window.document, 'cartridge-data-heading', 'Encryption state'), undefined)
    assert.match(dom.window.document.querySelector('.metric-card:last-child strong').textContent, /Not reported/)
    assert.doesNotMatch(dom.window.document.body.textContent, /not-reported/)
    dom.window.close()
}

/**
 * Verifies native reason and support tokens become useful user-facing text.
 * @returns {void} Throws when raw protocol tokens leak into the status page.
 */
function testRendersTypedUnavailableReasons() {
    const fixture = createFixtureState({ mode: 'one-device' }).devices[0]
    const device = {
        ...fixture,
        drive: {
            details: {
                firmwareRevision: { availability: 'reported', value: '0283' },
                status: { availability: 'unavailable', reason: 'field-decoder-unavailable' },
                operationMode: { availability: 'unavailable', reason: 'status-probe-unavailable' },
                policy: { availability: 'unavailable', reason: 'field-decoder-unavailable' },
                supportStatus: { availability: 'reported', value: 'drive-status-page-available' },
                senseSummary: { availability: 'unavailable', reason: 'no-safe-sense-available' }
            }
        },
        media: {
            ...fixture.media,
            details: {
                writeProtected: { availability: 'unavailable', reason: 'status-probe-unavailable' },
                encrypted: { availability: 'unavailable', reason: 'not-reported' },
                temperatureCelsius: { availability: 'reported', value: 28 },
                supportStatus: { availability: 'reported', value: 'cartridge-status-page-available' },
                senseSummary: { availability: 'unavailable', reason: 'no-safe-sense-available' }
            }
        }
    }
    const dom = new JSDOM(renderStatusView(device, { translator: englishTranslator }))
    const document = dom.window.document

    assert.equal(valueFor(document, 'drive-data-heading', 'Firmware revision'), '2.83')
    assert.equal(valueFor(document, 'drive-data-heading', 'Drive status'), undefined)
    assert.equal(valueFor(document, 'drive-data-heading', 'Operation mode'), undefined)
    assert.equal(valueFor(document, 'drive-data-heading', 'Drive policy'), 'Not available in OpenRDXManager')
    assert.equal(valueFor(document, 'drive-data-heading', 'Support status'), 'Drive status data available')
    assert.equal(valueFor(document, 'drive-data-heading', 'Sense summary'), 'No additional hardware diagnostics available')
    assert.equal(valueFor(document, 'cartridge-data-heading', 'Write protection'), undefined)
    assert.equal(valueFor(document, 'cartridge-data-heading', 'Encryption state'), undefined)
    assert.equal(valueFor(document, 'cartridge-data-heading', 'Temperature'), '28 °C')
    assert.equal(valueFor(document, 'cartridge-data-heading', 'Support status'), 'Cartridge status data available')
    assert.equal(valueFor(document, 'cartridge-data-heading', 'Sense summary'), 'No additional hardware diagnostics available')
    assert.doesNotMatch(document.querySelector('.device-identity').textContent, /Revision \d+/)
    assert.doesNotMatch(document.body.textContent, /not-reported|field-decoder-unavailable|status-probe-unavailable|page-available|no-safe-sense-available/)
    dom.window.close()
}

/**
 * Verifies summary cards use canonical typed media details even if a caller
 * bypasses schema validation with contradictory legacy duplicates.
 * @returns {void} Throws when legacy values can create contradictory UI.
 */
function testTypedMediaDetailsOwnSummaryTruth() {
    const fixture = createFixtureState({ mode: 'one-device' }).devices[0]
    const device = {
        ...fixture,
        media: {
            ...fixture.media,
            capacityBytes: 2000,
            usedBytes: 1800,
            writable: true,
            details: {
                ...fixture.media.details,
                capacityBytes: { availability: 'reported', value: 1000 },
                usedBytes: { availability: 'reported', value: 400 },
                freeBytes: { availability: 'reported', value: 600 },
                writeProtected: { availability: 'reported', value: true }
            }
        }
    }
    const dom = new JSDOM(renderStatusView(device, { translator: englishTranslator }))
    const document = dom.window.document

    assert.equal(document.querySelector('.metric-card--capacity progress').value, 40)
    assert.equal(document.querySelectorAll('.metric-card')[1].querySelector('small').textContent, 'Write protected')
    assert.equal(valueFor(document, 'cartridge-data-heading', 'Write protection'), undefined)
    dom.window.close()
}

/**
 * Verifies an unmounted cartridge never turns absent filesystem accounting
 * into a false completely-full capacity claim.
 * @returns {void} Throws when the transient unmounted state is misleading.
 */
function testUnmountedMediaDoesNotRenderAsFull() {
    const fixture = createFixtureState({ mode: 'one-device' }).devices[0]
    const device = {
        ...fixture,
        media: {
            ...fixture.media,
            filesystem: undefined,
            usedBytes: undefined,
            details: {
                ...fixture.media.details,
                mounted: { availability: 'reported', value: false },
                capacityBytes: { availability: 'reported', value: 320_000_000_000 },
                usedBytes: { availability: 'unavailable', reason: 'media-not-mounted' },
                freeBytes: { availability: 'unavailable', reason: 'media-not-mounted' }
            }
        }
    }
    const dom = new JSDOM(renderStatusView(device, { translator: englishTranslator }))
    const capacity = dom.window.document.querySelector('.metric-card--capacity')

    assert.match(capacity.textContent, /320 GB capacity/)
    assert.match(capacity.textContent, /Mount the cartridge to read used and free space/)
    assert.doesNotMatch(capacity.textContent, /320 GB used|0 B free/)
    assert.equal(capacity.querySelector('progress'), null)
    dom.window.close()
}

/**
 * Verifies the actionable privileged-service prerequisite replaces misleading
 * candidate validation diagnostics and keeps the badge aligned with the card.
 * @returns {void} Throws when setup state loses UI priority.
 */
function testRendersPrivilegedServiceSetupRecovery() {
    const fixture = createFixtureState({ mode: 'no-device' })
    const state = {
        ...fixture,
        provenance: 'service',
        privilegedServiceSetup: { state: 'requires-approval' },
        service: { status: 'ready', mode: 'native', privileged: false, hardwareReady: false, hardwareVerified: false, platformCapability: { state: 'insufficient-permission', reason: 'privileged-service-unavailable' } },
        discovery: { ...fixture.discovery, diagnostics: { candidateCount: 1, acceptedCount: 0, rejections: [{ reason: 'candidate-validation-failed', count: 1 }] } }
    }
    const dashboard = createStatusDashboard(state, { supportApi: { service: { openApprovalSettings: async () => ({ ok: true }) } } })
    const document = dashboard.dom.window.document

    assert.match(document.querySelector('#empty-state-title').textContent, /Allow OpenRDXManager in Login Items/)
    assert.match(document.querySelector('[data-service-status]').textContent, /Approval required/)
    assert.equal(document.querySelector('[data-action="open-hardware-approval"]')?.disabled, false)
    assert.equal(document.querySelector('[data-discovery-diagnostics]'), null)
    dashboard.controller.destroy()
    dashboard.dom.window.close()
}

/** @returns {void} Verifies mounted media gets exact guidance ahead of generic diagnostics. */
function testRendersMountedCandidateRecovery() {
    const fixture = createFixtureState({ mode: 'no-device' })
    const state = {
        ...fixture,
        provenance: 'service',
        privilegedServiceSetup: { state: 'enabled' },
        service: { status: 'ready', mode: 'native', privileged: true, hardwareReady: true, hardwareVerified: false, platformCapability: { state: 'available' } },
        discovery: { ...fixture.discovery, diagnostics: { candidateCount: 1, acceptedCount: 0, rejections: [{ reason: 'media-mounted', count: 1 }] } }
    }
    const dashboard = createStatusDashboard(state)
    const document = dashboard.dom.window.document
    assert.match(document.querySelector('#empty-state-title').textContent, /RDX cartridge is mounted by macOS/)
    assert.equal(document.querySelector('[data-discovery-diagnostics]'), null)
    dashboard.controller.destroy()
    dashboard.dom.window.close()
}

test('renders known native status fields once without inventing missing telemetry', testRendersCompleteTruthfulStatusFields)
test('renders path-free candidate rejection diagnostics', testRendersCandidateRejectionDiagnostics)
test('renders path-free discovery failures while preserving stale snapshots', testRendersPathFreeDiscoveryFailureWithStaleSnapshot)
test('renders absent optional media booleans with meaningful copy', testRendersAbsentMediaBooleansAsNotReported)
test('renders friendly status reasons, support text, and measurement units', testRendersTypedUnavailableReasons)
test('uses typed media details as the only summary truth', testTypedMediaDetailsOwnSummaryTruth)
test('does not render unmounted media as completely full', testUnmountedMediaDoesNotRenderAsFull)
test('prioritizes privileged service setup ahead of candidate diagnostics', testRendersPrivilegedServiceSetupRecovery)
test('prioritizes mounted cartridge guidance ahead of generic diagnostics', testRendersMountedCandidateRecovery)

/** @returns {void} Verifies only a reported healthy cartridge receives green styling. */
function testCartridgeHealthRequiresReportedGoodStatus() {
    for (const [status, healthy] of [
        [{ availability: 'reported', value: 'Good' }, true],
        [{ availability: 'reported', value: 'Cartridge error' }, false],
        [{ availability: 'unavailable', reason: 'field-decoder-unavailable' }, false],
        [{ availability: 'unavailable', reason: 'status-probe-unavailable' }, false]
    ]) {
        const device = structuredClone(createFixtureState({ mode: 'one-device' }).devices[0])
        device.media.details.status = status
        const dom = new JSDOM(renderStatusView(device, { translator: englishTranslator }))
        try {
            const card = dom.window.document.querySelectorAll('.metric-card')[1]
            assert.equal(card.classList.contains('metric-card--healthy'), healthy, JSON.stringify(status))
            if (status.reason === 'status-probe-unavailable') assert.match(card.textContent, /Could not read device status/)
            assert.doesNotMatch(card.textContent, /not supported/i)
        } finally {
            dom.window.close()
        }
    }
}

test('cartridge errors and unavailable readings are not presented as healthy', testCartridgeHealthRequiresReportedGoodStatus)
