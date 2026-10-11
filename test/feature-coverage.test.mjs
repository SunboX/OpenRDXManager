// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { HELP_TOPICS } from '../src/help/help-index.mjs'
import { englishCatalog } from '../src/locales/en.mjs'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { FEATURE_MANIFEST, FEATURE_TARGET_REGISTRY, getFeatureCoverage, resolveFeatureTarget } from '../src/renderer/feature-manifest.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { createCompatibilityModel, renderCompatibilityView } from '../src/renderer/views/compatibility-view.mjs'
import { OperationKind } from '../src/shared/schemas.mjs'

const EXPECTED_NUMBERS = Object.freeze(Array.from({ length: 25 }, (_, index) => index + 1))
const VALID_MAPPING_TYPES = new Set(['route', 'operation', 'help', 'platform-state', 'evidence-state'])
const englishTranslator = createTranslator(englishCatalog, englishCatalog)
const EXPECTED_DECLARED_TARGETS = Object.freeze({
    route: ['activity', 'compatibility', 'status'],
    'platform-state': ['localized-desktop-integration', 'packaging-external', 'tray-lifecycle', 'windows-drive-letter'],
    'evidence-state': ['access-security-write-unproven', 'aes-media-layout-and-security-write-unproven', 'automatic-auth-write-unproven', 'basic-protection-security-write-unproven', 'credential-slot-write-unproven', 'protection-removal-write-unproven']
})

test('every documented feature group has one concrete current production mapping', () => {
    const covered = FEATURE_MANIFEST.map((entry) => entry.documentNumber).sort((left, right) => left - right)

    assert.deepEqual(covered, EXPECTED_NUMBERS)
    assert.equal(new Set(covered).size, 25)
    for (const entry of FEATURE_MANIFEST) {
        assert.match(entry.source, new RegExp(`^${String(entry.documentNumber).padStart(2, '0')}-[a-z0-9-]+\\.md$`))
        assert.ok(existsSync(resolve('docs/protocols/features', entry.source)), `feature ${entry.documentNumber} has an existing source document`)
        assert.equal(VALID_MAPPING_TYPES.has(entry.mapping.type), true, `feature ${entry.documentNumber} has a known mapping type`)
        assert.match(entry.mapping.target, /^[a-z0-9][a-z0-9:./-]*$/)
        assert.notEqual(entry.mapping.target, 'planned')
        assert.notEqual(entry.mapping.target, 'unwired')
        if (entry.mapping.type === 'operation') assert.equal(Object.values(OperationKind).includes(entry.mapping.target), true)
        if (entry.mapping.type === 'help')
            assert.equal(
                HELP_TOPICS.some((topic) => topic.id === entry.mapping.target),
                true
            )
    }
})

test('current coverage distinguishes production surfaces from evidence and platform boundaries', () => {
    assert.deepEqual(getFeatureCoverage(1), { type: 'route', target: 'status' })
    assert.deepEqual(getFeatureCoverage(6), { type: 'evidence-state', target: 'aes-media-layout-and-security-write-unproven' })
    assert.deepEqual(getFeatureCoverage(16), { type: 'platform-state', target: 'windows-drive-letter' })
    assert.deepEqual(getFeatureCoverage(23), { type: 'platform-state', target: 'packaging-external' })
    assert.deepEqual(getFeatureCoverage(25), { type: 'help', target: 'troubleshooting' })
    assert.equal(getFeatureCoverage(26), null)
})

test('unproven security groups remain explicit evidence states instead of operations', () => {
    for (const documentNumber of [6, 7, 8, 9, 10, 11]) {
        const coverage = getFeatureCoverage(documentNumber)
        assert.equal(coverage.type, 'evidence-state')
        assert.match(coverage.target, /unproven$/)
    }
})

test('route, platform, and evidence targets resolve to bounded production declarations', () => {
    const dom = new JSDOM('<!doctype html><body><div id="app"></div></body>', { pretendToBeVisual: true })
    const root = dom.window.document.querySelector('#app')
    const controller = mountApplication(root, {
        platform: 'darwin',
        store: createStore(createFixtureState({ mode: 'one-device' })),
        translator: englishTranslator
    })

    for (const [type, expectedTargets] of Object.entries(EXPECTED_DECLARED_TARGETS)) {
        assert.deepEqual(Object.keys(FEATURE_TARGET_REGISTRY[type]).sort(), expectedTargets)
        for (const entry of FEATURE_MANIFEST.filter((candidate) => candidate.mapping.type === type)) {
            assert.equal(Object.hasOwn(FEATURE_TARGET_REGISTRY[type], entry.mapping.target), true)
        }
    }
    for (const type of Object.keys(EXPECTED_DECLARED_TARGETS)) {
        assert.equal(resolveFeatureTarget(type, 'arbitrary-unwired-target'), null)
    }
    for (const declaration of Object.values(FEATURE_TARGET_REGISTRY.route)) {
        assert.notEqual(root.querySelector(declaration.selector), null, declaration.selector)
    }
    for (const type of ['platform-state', 'evidence-state']) {
        for (const declaration of Object.values(FEATURE_TARGET_REGISTRY[type])) {
            const reference = resolve(declaration.reference)
            assert.equal(existsSync(reference), true, declaration.reference)
            assert.match(readFileSync(reference, 'utf8'), new RegExp(declaration.anchor.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&')))
        }
    }

    controller.destroy()
    dom.window.close()
})

test('hardware acceptance records runtime evidence and the current legacy firmware boundary', () => {
    const applicationChecks = readFileSync(resolve('docs/verification/application-checks.md'), 'utf8')
    const acceptance = readFileSync(resolve('docs/verification/hardware-acceptance.md'), 'utf8')

    assert.match(applicationChecks, /USB2\/SATA1[\s\S]{0,160}`\.BIP`[\s\S]{0,160}`legacy-bip-format-unproven`/)
    assert.match(applicationChecks, /USB3\/SATA3[\s\S]{0,160}`\.BIN`/)
    assert.match(applicationChecks, /current Mac has validated the\s+attached dock through the development application/)
    assert.match(applicationChecks, /cartridge-state and broader\s+physical operation acceptance remain pending/)
    assert.match(acceptance, /exact host, OS\/runtime, dock, firmware,\s+media, command/)
    assert.match(acceptance, /\| Date \| Host \| OS \/ runtime \| Dock \/ model \|/)
    assert.match(acceptance, /Evidence fields[^\n]*OS\/runtime/)
    const checklistRows = acceptance.split('\n').filter((line) => /^\|\s+\d+\s+\|/.test(line))
    assert.equal(checklistRows.length, 22)
    for (const row of checklistRows) {
        const cells = row
            .split('|')
            .slice(1, -1)
            .map((cell) => cell.trim())
        assert.equal(cells.length, 13)
        assert.deepEqual(cells.slice(5), Array(8).fill(''))
    }
})

test('compatibility view separates live capability evidence from historical vendor qualification', () => {
    const dom = new JSDOM('<!doctype html><body></body>')
    const view = renderCompatibilityView(
        {
            host: { platform: 'darwin', hardwareReady: false, hardwareVerified: false, privilege: 'unavailable' },
            device: null
        },
        { document: dom.window.document, translator: englishTranslator }
    )

    const live = view.querySelector('[data-compatibility-section="live"]')
    const historical = view.querySelector('[data-compatibility-section="historical"]')
    assert.match(live.textContent, /No validated RDX dock is selected/)
    assert.match(live.textContent, /Hardware access unavailable/)
    assert.match(live.textContent, /Physical hardware not yet verified/)
    assert.match(historical.textContent, /Historical vendor qualification/)
    assert.match(historical.textContent, /Windows 7/)
    assert.match(historical.textContent, /Server 2008/)
    assert.match(historical.textContent, /OS X 10\.11/)
    assert.match(historical.textContent, /Persistent Set Drive Letter/)
    assert.match(historical.textContent, /Windows quick format/)
    assert.match(historical.textContent, /do(?:es)? not certify this host/i)
})

test('compatibility view exposes ordered troubleshooting and honest feature states', () => {
    const dom = new JSDOM('<!doctype html><body></body>')
    const view = renderCompatibilityView(
        {
            host: { platform: 'win32', hardwareReady: true, hardwareVerified: false, privilege: 'ready' },
            device: {
                id: 'rdx:validated-example',
                product: 'RDX QuikStor',
                firmware: '0283',
                connectionType: 'usb3',
                capabilities: {
                    diagnostics: { state: 'available' },
                    firmware: { state: 'wrong-media-state', reason: 'cartridge-present' },
                    security: { state: 'evidence-incomplete', reason: 'security-write-unproven' }
                }
            }
        },
        { document: dom.window.document, translator: englishTranslator }
    )

    const diagnosticSteps = [...view.querySelectorAll('[data-diagnostic-step]')].map((node) => Number(node.dataset.diagnosticStep))
    assert.deepEqual(diagnosticSteps, [1, 2, 3, 4, 5])
    const troubleshooting = view.querySelector('[data-compatibility-section="troubleshooting"]').textContent
    assert.match(troubleshooting, /physical write-protect tab/i)
    assert.match(troubleshooting, /Standard SATA AHCI Controller/)
    assert.match(troubleshooting, /Do not power off/i)
    assert.match(view.querySelector('[data-live-capability="diagnostics"]').textContent, /Available/)
    assert.match(view.querySelector('[data-live-capability="firmware"]').textContent, /Cartridge present/)
    assert.match(view.querySelector('[data-live-capability="security"]').textContent, /Evidence incomplete/)
    assert.match(view.querySelector('[data-compatibility-section="limits"]').textContent, /SATA driver/i)
    assert.match(view.querySelector('[data-compatibility-section="limits"]').textContent, /safe eject/i)
    assert.match(view.querySelector('[data-compatibility-section="history"]').textContent, /24\.8 days/)
    assert.match(view.querySelector('[data-compatibility-section="history"]').textContent, /Disk Not Ejected Properly/)
})

test('compatibility view resolves user-facing copy through the active translator', () => {
    const dom = new JSDOM('<!doctype html><body></body>')
    const translator = createTranslator({ ...englishCatalog, 'compatibility.title': 'Lokalisierter Kompatibilitätstitel', 'compatibility.live.title': 'Aktuelle Funktionslage' }, englishCatalog)
    const view = renderCompatibilityView({ host: { platform: 'linux', hardwareReady: false, hardwareVerified: false, privilege: 'not-reported' }, device: null }, { document: dom.window.document, translator })

    assert.equal(view.querySelector('h1').textContent, 'Lokalisierter Kompatibilitätstitel')
    assert.equal(view.querySelector('[data-compatibility-section="live"] h2').textContent, 'Aktuelle Funktionslage')
})

test('compatibility opens as a local overlay without changing the four device areas', () => {
    const dom = new JSDOM('<!doctype html><body><div id="app"></div></body>', {
        pretendToBeVisual: true,
        url: 'file:///openrdxmanager/src/index.html'
    })
    const root = dom.window.document.querySelector('#app')
    const controller = mountApplication(root, {
        platform: 'darwin',
        store: createStore(createFixtureState({ mode: 'one-device' })),
        translator: englishTranslator
    })

    assert.equal(root.querySelectorAll('[role="tab"][data-area]').length, 4)
    const opener = root.querySelector('[data-action="open-compatibility"]')
    assert.notEqual(opener, null)
    opener.click()
    const overlay = root.querySelector('[data-support-overlay]')
    assert.notEqual(overlay.querySelector('[data-compatibility-view]'), null)
    assert.equal(overlay.getAttribute('aria-labelledby'), 'compatibility-title')
    assert.equal(dom.window.document.activeElement, overlay.querySelector('h1'))
    assert.equal(root.querySelectorAll('[role="tab"][data-area]').length, 4)
    overlay.querySelector('[data-action="close-support-panel"]').click()
    assert.equal(root.querySelector('[data-support-overlay]'), null)
    assert.equal(dom.window.document.activeElement?.dataset.action, 'open-compatibility')

    controller.destroy()
    dom.window.close()
})

test('compatibility model derives only current renderer-safe device and service evidence', () => {
    const state = createFixtureState({ mode: 'one-device' })
    const model = createCompatibilityModel(state, 'darwin')

    assert.equal(model.host.platform, 'darwin')
    assert.equal(model.host.hardwareReady, false)
    assert.equal(model.host.hardwareVerified, false)
    assert.equal(model.host.managementPrerequisite, 'macos-unmount-volume')
    assert.equal(model.device.id, 'rdx:7810544062')
    assert.equal(model.device.product, 'RDX QuikStor USB3+ External')
    assert.equal(model.device.firmware, 'fixture-not-reported')
    assert.equal(model.device.connectionType, 'fixture-not-reported')
    assert.equal(model.device.capabilities['self-test'].state, 'available')
})
