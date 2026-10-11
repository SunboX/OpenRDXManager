// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { renderUtilitiesView } from '../src/renderer/views/utilities-view.mjs'
import { createUtilityOperationController } from '../src/renderer/workflows/utility-operation-controller.mjs'
import { createFirmwareWorkflow } from '../src/renderer/workflows/firmware-workflow.mjs'
import { createFormatWorkflow } from '../src/renderer/workflows/format-workflow.mjs'
import { createDriveLetterWorkflow, createDriveModeWorkflow, createSataModeWorkflow } from '../src/renderer/workflows/mode-workflow.mjs'
import { createEjectWorkflow } from '../src/renderer/workflows/eject-workflow.mjs'
import { completeDeviceSnapshot } from './helpers/device-snapshot.mjs'

/** @returns {{dom: JSDOM, document: Document}} Isolated utility DOM. */
function createDom() {
    const dom = new JSDOM('<!doctype html><html><head></head><body><div id="app"></div></body></html>', {
        pretendToBeVisual: true,
        url: 'file:///openrdxmanager/src/index.html'
    })
    return { dom, document: dom.window.document }
}

/**
 * Creates one complete device with deliberately selectable product/media facts.
 * @param {{availableDriveLetters?: string[], connectionType?: string, media?: object|null, capabilities?: object, operationMode?: string, product?: string}} [overrides={}] - Fixture overrides.
 * @returns {object} Complete renderer-safe device.
 */
function utilityDevice(overrides = {}) {
    return completeDeviceSnapshot({
        capabilities: {
            'drive-letter-reset': { state: 'available' },
            'drive-letter-set': { state: 'available' },
            'drive-mode-set': { state: 'available' },
            'eject-force': { state: 'available' },
            'eject-safe': { state: 'available' },
            'firmware-update': { state: 'available' },
            format: { state: 'available' },
            'sata-mode-set': { state: 'available' },
            ...overrides.capabilities
        },
        drive: {
            ...(overrides.availableDriveLetters === undefined ? {} : { availableDriveLetters: overrides.availableDriveLetters }),
            connectionType: overrides.connectionType ?? 'USB 3',
            firmwareRevision: '0283',
            operationMode: overrides.operationMode ?? 'Removable Disk',
            productType: overrides.connectionType === 'Legacy USB 2 / SATA I' ? 'USB 2 / SATA I' : 'USB 3 / SATA III',
            powerSource: 'external'
        },
        id: 'rdx:utility-ui',
        media:
            overrides.media === undefined
                ? {
                      capacityBytes: 1_000_000_000,
                      encrypted: false,
                      filesystem: 'exfat',
                      id: 'media:utility-ui',
                      label: 'Disposable RDX',
                      serial: 'MEDIA-UTILITY-01',
                      status: 'ready',
                      usedBytes: 250_000_000,
                      writable: true
                  }
                : overrides.media,
        product: overrides.product ?? 'RDX QuikStor USB3+ External',
        revision: 12,
        serial: 'DOCK-UTILITY-01',
        vendor: 'TANDBERG'
    })
}

/** @returns {void} Verifies product and media mismatch block firmware before file selection. */
function testFirmwarePreflight() {
    const { dom, document } = createDom()
    const device = utilityDevice()
    const view = renderUtilitiesView(device, { document, operationIntentAvailable: true })
    const firmware = view.querySelector('[data-feature="firmware"]')
    const workflow = createFirmwareWorkflow(device)

    assert.match(firmware.textContent, /Eject the cartridge/i)
    assert.match(firmware.textContent, /\.BIN/)
    assert.match(firmware.textContent, /selected product/i)
    assert.match(firmware.textContent, /checks the firmware authentication result for the selected installation route/i)
    assert.match(firmware.textContent, /Keep the dock powered and OpenRDXManager open/i)
    assert.match(firmware.textContent, /Disconnect USB only when the app explicitly requests a power cycle/i)
    assert.match(firmware.textContent, /do not put the computer to sleep/i)
    const action = firmware.querySelector('[data-action="start-firmware"]')
    assert.equal(action.disabled, true)
    assert.equal(firmware.querySelector(`#${action.getAttribute('aria-describedby')}`) !== null, true)
    assert.equal(workflow.image.extension, '.BIN')
    assert.equal(workflow.capability.state, 'wrong-media-state')

    dom.window.close()
}

/** @returns {void} Verifies the legacy family receives only its documented image extension. */
function testLegacyFirmwareFamily() {
    const device = utilityDevice({ connectionType: 'Legacy USB 2 / SATA I', media: null, product: 'RDX QuikStor USB 2 External' })
    const workflow = createFirmwareWorkflow(device)

    assert.equal(workflow.image.extension, '.BIP')
    assert.match(workflow.image.family, /USB 2.*SATA I/i)
}

/** @returns {void} Verifies SATA III is not misclassified as the SATA I legacy family. */
function testModernSataFirmwareFamily() {
    const device = utilityDevice({ connectionType: 'SATA III', media: null, product: 'RDX QuikStor SATA III' })
    const workflow = createFirmwareWorkflow(device)

    assert.equal(workflow.image.extension, '.BIN')
    assert.match(workflow.image.family, /USB 3.*SATA III/i)
}

/** @returns {void} Verifies reported product identity can classify a family when connection type is unavailable. */
function testFirmwareFamilyProductFallback() {
    const device = createFixtureState({ mode: 'one-device' }).devices[0]
    const workflow = createFirmwareWorkflow(device)

    assert.equal(workflow.image.extension, '.BIN')
    assert.match(workflow.image.family, /USB 3.*SATA III/i)
}

/** @returns {void} Verifies USB products cannot expose a usable SATA link setter. */
function testUsbSataGate() {
    const { dom, document } = createDom()
    const view = renderUtilitiesView(utilityDevice({ media: null }), {
        currentSataMode: '1.5g-3g',
        document,
        operationIntentAvailable: true
    })
    const sata = view.querySelector('[data-feature="sata-mode"]')

    assert.match(sata.textContent, /SATA III docks only/i)
    assert.equal(sata.querySelector('[data-action="set-sata-mode"]').disabled, true)
    dom.window.close()
}

/** @returns {void} Verifies the SATA default, SSD warning, and no-op decision. */
function testSataModeRules() {
    const device = utilityDevice({ connectionType: 'SATA III', media: null, product: 'RDX QuikStor SATA III' })
    const workflow = createSataModeWorkflow(device, { currentMode: '1.5g-3g', selectedMode: '1.5g-3g' })

    assert.equal(workflow.recommendedMode, '1.5g-3g')
    assert.equal(workflow.noOp, true)
    assert.equal(workflow.capability.state, 'available')
    assert.equal(workflow.guidanceKey, 'utilities.sataMode.guidance')
    assert.deepEqual(
        workflow.stages.map((stage) => stage.id),
        ['device-configuring', 'device-reconnecting', 'device-readback']
    )
}

/** @returns {void} Verifies the global operation lock cannot be bypassed by host-mode readiness. */
function testModeGlobalLock() {
    const sataDevice = utilityDevice({ connectionType: 'SATA III', media: null, product: 'RDX QuikStor SATA III' })
    const driveLetterDevice = utilityDevice({ media: null })
    const sata = createSataModeWorkflow(sataDevice, { currentMode: '1.5g-3g', locked: true, selectedMode: '3g-6g' })
    const driveLetter = createDriveLetterWorkflow(driveLetterDevice, { availableLetters: ['R'], locked: true, platform: 'win32' })

    assert.deepEqual(sata.capability, { reason: 'operation-in-progress', state: 'busy' })
    assert.deepEqual(driveLetter.setCapability, { reason: 'operation-in-progress', state: 'busy' })
    assert.deepEqual(driveLetter.resetCapability, { reason: 'operation-in-progress', state: 'busy' })
}

/** @returns {void} Verifies mode setters require no media and suppress current-value writes. */
function testDriveModeNoOp() {
    const device = utilityDevice({ media: null, operationMode: 'Fixed Disk' })
    const workflow = createDriveModeWorkflow(device, { selectedMode: 'fixed' })

    assert.equal(workflow.currentMode, 'fixed')
    assert.equal(workflow.noOp, true)
    assert.equal(workflow.capability.state, 'available')
    assert.equal(workflow.guidanceKey, 'utilities.driveMode.noOpGuidance')
}

/** @returns {void} Verifies only reported available Windows letters are offered. */
function testDriveLetterAvailability() {
    const device = utilityDevice({ media: null })
    const supported = createDriveLetterWorkflow(device, { availableLetters: ['R', 'T'], platform: 'win32', selectedLetter: 'R' })
    const missing = createDriveLetterWorkflow(device, { availableLetters: [], platform: 'win32' })
    const otherPlatform = createDriveLetterWorkflow(device, { availableLetters: ['R'], platform: 'linux' })

    assert.deepEqual(supported.availableLetters, ['R', 'T'])
    assert.equal(supported.setCapability.state, 'available')
    assert.equal(supported.resetCapability.state, 'available')
    assert.equal(missing.setCapability.state, 'host-dependency-missing')
    assert.equal(missing.resetCapability.state, 'available')
    assert.equal(otherPlatform.setCapability.state, 'unsupported-platform')
    assert.equal(otherPlatform.resetCapability.state, 'unsupported-platform')
}

/** @returns {void} Verifies a production-shaped device snapshot drives Set while global lock still wins. */
function testDriveLetterSnapshotAvailability() {
    const { dom, document } = createDom()
    const device = utilityDevice({ availableDriveLetters: ['R', 'T'], media: null })
    const ready = renderUtilitiesView(device, { document, operationIntentAvailable: true, platform: 'win32' })
    const readyCard = ready.querySelector('[data-feature="drive-letter"]')

    assert.deepEqual(
        [...readyCard.querySelector('[data-utility-drive-letter]').options].map((option) => option.value),
        ['R', 'T']
    )
    assert.equal(readyCard.querySelector('[data-action="set-drive-letter"]').disabled, false)
    assert.equal(readyCard.querySelector('[data-action="reset-drive-letter"]').disabled, false)

    const busy = renderUtilitiesView(device, { document, locked: true, operationIntentAvailable: true, platform: 'win32' })
    const busyCard = busy.querySelector('[data-feature="drive-letter"]')
    assert.equal(busyCard.querySelector('[data-action="set-drive-letter"]').disabled, true)
    assert.equal(busyCard.querySelector('[data-action="reset-drive-letter"]').disabled, true)
    assert.match(busyCard.textContent, /Another operation is in progress/i)
    dom.window.close()
}

/** @returns {void} Verifies format is writable-media-only and exact-identity destructive. */
function testFormatConfirmation() {
    const device = utilityDevice()
    const workflow = createFormatWorkflow(device, { confirmationValue: 'DOCK-UTILITY-01', filesystem: 'exfat', platform: 'win32' })
    const confirmed = createFormatWorkflow(device, { confirmationValue: workflow.expectedIdentity, filesystem: 'exfat', platform: 'win32' })

    assert.equal(workflow.filesystem, 'exfat')
    assert.equal(workflow.defaultFilesystem, 'ntfs')
    assert.equal(workflow.confirmed, false)
    assert.equal(workflow.capability.state, 'wrong-media-state')
    assert.equal(confirmed.confirmed, true)
    assert.equal(confirmed.capability.state, 'available')
    assert.equal(workflow.consequenceKey, 'utilities.format.consequence')

    const unavailableSerial = { availability: 'unavailable', reason: 'not-reported' }
    const mediaIdOnly = utilityDevice({ media: { ...device.media, details: { ...device.media.details, serialNumber: unavailableSerial }, id: 'media:exact-fallback', serial: undefined } })
    const idOnlyWorkflow = createFormatWorkflow(mediaIdOnly, { platform: 'win32' })
    assert.equal(idOnlyWorkflow.expectedIdentity, 'DOCK-UTILITY-01 / media:exact-fallback')
    assert.doesNotMatch(idOnlyWorkflow.expectedIdentity, /NO-MEDIA/)

    const unidentifiedMedia = { ...device, media: { ...device.media, details: { ...device.media.details, serialNumber: unavailableSerial }, id: undefined, serial: undefined } }
    const unidentifiedWorkflow = createFormatWorkflow(unidentifiedMedia, { confirmationValue: 'DOCK-UTILITY-01 / NO-MEDIA', platform: 'win32' })
    assert.equal(unidentifiedWorkflow.expectedIdentity, null)
    assert.equal(unidentifiedWorkflow.confirmed, false)
    assert.notEqual(unidentifiedWorkflow.capability.state, 'available')
}

/** @returns {void} Verifies format choices and defaults never exceed the native host formatter. */
function testFormatPlatformPolicy() {
    const device = utilityDevice()
    const cases = [
        { platform: 'darwin', choices: ['exfat', 'fat', 'fat12', 'fat16', 'fat32', 'hfs', 'hfs-case-sensitive', 'hfs-journaled', 'hfs-case-sensitive-journaled', 'apfs', 'apfs-case-sensitive', 'apfs-encrypted', 'apfs-case-sensitive-encrypted'], defaultFilesystem: 'exfat', toolingKey: 'utilities.format.tooling.macos' },
        { platform: 'win32', choices: ['ntfs', 'exfat'], defaultFilesystem: 'ntfs', toolingKey: 'utilities.format.tooling' },
        { platform: 'linux', choices: ['ext4', 'ext3', 'ext2', 'xfs', 'btrfs', 'f2fs', 'ntfs', 'exfat', 'fat16', 'fat32'], defaultFilesystem: 'ext4', toolingKey: 'utilities.format.tooling.linux' },
        { platform: 'unknown', choices: [], defaultFilesystem: null, toolingKey: 'utilities.format.tooling.unavailable' }
    ]

    for (const expected of cases) {
        const workflow = createFormatWorkflow(device, { filesystem: 'unsupported', platform: expected.platform })
        assert.deepEqual(workflow.filesystemChoices, expected.choices, expected.platform)
        assert.equal(workflow.defaultFilesystem, expected.defaultFilesystem, expected.platform)
        assert.equal(workflow.filesystem, expected.defaultFilesystem, expected.platform)
        assert.equal(workflow.toolingKey, expected.toolingKey, expected.platform)
    }
}

/** @returns {void} Verifies an unknown host cannot become format-ready after exact confirmation. */
function testUnknownFormatPlatformGate() {
    const device = utilityDevice()
    const initial = createFormatWorkflow(device, { platform: 'unknown' })
    const confirmed = createFormatWorkflow(device, { confirmationValue: initial.expectedIdentity, platform: 'unknown' })

    assert.deepEqual(confirmed.capability, { reason: 'format-host-filesystem-unavailable', state: 'host-dependency-missing' })
}

/** @returns {void} Verifies macOS presents native macOS formatters with an explicit rationale. */
function testMacosFormatPresentation() {
    const { dom, document } = createDom()
    const view = renderUtilitiesView(utilityDevice(), { document, operationIntentAvailable: true, platform: 'darwin' })
    const card = view.querySelector('[data-feature="format"]')
    const filesystem = card.querySelector('[data-utility-filesystem]')

    assert.deepEqual(
        [...filesystem.options].map((option) => option.value),
        ['exfat', 'fat', 'fat12', 'fat16', 'fat32', 'hfs', 'hfs-case-sensitive', 'hfs-journaled', 'hfs-case-sensitive-journaled', 'apfs', 'apfs-case-sensitive', 'apfs-encrypted', 'apfs-case-sensitive-encrypted']
    )
    assert.equal(filesystem.value, 'exfat')
    assert.match(card.textContent, /exFAT.*macOS.*NTFS/is)
    dom.window.close()
}

/** @returns {void} Verifies safe and force eject preserve distinct risk boundaries. */
function testEjectBoundaries() {
    const device = utilityDevice()
    const safe = createEjectWorkflow(device, 'safe')
    const forced = createEjectWorkflow(device, 'force', { riskAccepted: false })

    assert.equal(safe.risk, 'routine')
    assert.equal(safe.guidanceKey, 'utilities.eject.safeGuidance')
    assert.deepEqual(
        safe.stages.map((stage) => stage.id),
        ['host-unmounting', 'host-ejecting', 'eject-readback']
    )
    assert.equal(forced.risk, 'critical')
    assert.equal(forced.capability.state, 'wrong-media-state')
    assert.equal(forced.guidanceKey, 'utilities.eject.forceGuidance')
    assert.deepEqual(
        forced.stages.map((stage) => stage.id),
        ['host-ejecting', 'eject-readback']
    )
}

/** @returns {Promise<void>} Verifies the exact preload sequence for file tokens and confirmations. */
async function testOperationController() {
    const calls = []
    const api = {
        files: {
            /** @returns {Promise<object>} Returns one opaque main-owned token. */
            async chooseFirmware() {
                calls.push({ method: 'choose-firmware', request: {} })
                return { ok: true, fileToken: 'firmware:utility-selection' }
            }
        },
        operations: {
            /** @param {object} request - Exact confirmation binding. @returns {Promise<object>} Service-issued token. */
            async confirm(request) {
                calls.push({ method: 'confirm', request })
                return { ok: true, confirmationToken: 'confirm:utility-selection' }
            },
            /** @param {object} request - Strict operation request. @returns {Promise<object>} Accepted operation. */
            async start(request) {
                calls.push({ method: 'start', request })
                return { ok: true, operationId: 'op:utility-selection' }
            }
        }
    }
    const controller = createUtilityOperationController(api)

    assert.deepEqual(await controller.start({ kind: 'firmware-update', deviceId: 'rdx:utility-ui', deviceRevision: 12 }), { ok: true, operationId: 'op:utility-selection' })
    assert.deepEqual(await controller.start({ kind: 'format', deviceId: 'rdx:utility-ui', deviceRevision: 12, filesystem: 'exfat' }), { ok: true, operationId: 'op:utility-selection' })
    assert.deepEqual(calls, [
        { method: 'choose-firmware', request: {} },
        { method: 'start', request: { kind: 'firmware-update', deviceId: 'rdx:utility-ui', deviceRevision: 12, firmwareFileToken: 'firmware:utility-selection' } },
        { method: 'confirm', request: { kind: 'format', deviceId: 'rdx:utility-ui', deviceRevision: 12, filesystem: 'exfat' } },
        { method: 'start', request: { kind: 'format', deviceId: 'rdx:utility-ui', deviceRevision: 12, filesystem: 'exfat', confirmationToken: 'confirm:utility-selection' } }
    ])
}

/** @returns {Promise<void>} Verifies the real shell emits a structured utility request through its dedicated boundary. */
async function testShellIntegration() {
    const { dom, document } = createDom()
    const device = utilityDevice()
    const requests = []
    const utilityController = {
        /** @returns {boolean} Reports every utility action available in this fixture. */
        isAvailable() {
            return true
        },
        /** @param {object} request - Structured utility operation. @returns {Promise<object>} Accepted start. */
        async start(request) {
            requests.push(request)
            return { ok: true, operationId: 'op:shell-utility' }
        }
    }
    const store = createStore({
        activeArea: 'utilities',
        activeOperation: null,
        activity: [],
        authenticationSessions: {},
        devices: [device],
        discovery: { diagnostics: { acceptedCount: 1, candidateCount: 1, rejections: [] }, epoch: 1, listRevision: 1, scanStatus: 'idle', selectionInitialized: true, tombstones: {} },
        lastOperation: null,
        provenance: 'fixture',
        selectedDeviceId: device.id,
        service: { status: 'ready' },
        settings: { autoScan: true }
    })
    const controller = mountApplication(document.querySelector('#app'), { platform: 'win32', store, utilityController })
    const input = document.querySelector('[data-format-confirmation]')
    const button = document.querySelector('[data-action="start-format"]')

    assert.equal(document.querySelector('[data-utilities-view]') !== null, true)
    assert.equal(button.disabled, true)
    assert.equal(
        button
            .getAttribute('aria-describedby')
            .split(/\s+/)
            .every((id) => document.getElementById(id) !== null),
        true
    )
    input.value = input.dataset.expectedIdentity
    input.dispatchEvent(new dom.window.Event('input', { bubbles: true }))
    assert.equal(button.disabled, false)
    const filesystem = document.querySelector('[data-utility-filesystem]')
    filesystem.value = 'exfat'
    filesystem.dispatchEvent(new dom.window.Event('change', { bubbles: true }))
    store.dispatch({ type: 'device/list-replaced', epoch: 1, listRevision: 2, devices: [{ ...device, revision: 13 }] })
    assert.equal(input.value, input.dataset.expectedIdentity)
    assert.equal(button.disabled, false, 'background refresh must preserve confirmed format readiness')
    assert.equal(filesystem.value, 'exfat', 'background refresh must preserve the chosen filesystem')
    button.click()
    await new Promise((resolve) => setTimeout(resolve, 0))
    assert.deepEqual(requests, [{ kind: 'format', deviceId: 'rdx:utility-ui', deviceRevision: 13, filesystem: 'exfat' }])

    controller.destroy()
    dom.window.close()
}

/** @returns {Promise<void>} Verifies a tampered macOS control cannot submit unsupported NTFS. */
async function testMacosFormatSubmissionGate() {
    const { dom, document } = createDom()
    const device = utilityDevice()
    const requests = []
    const utilityController = {
        /** @returns {boolean} Reports the utility bridge available. */
        isAvailable() {
            return true
        },
        /** @param {object} request - Candidate structured utility operation. @returns {Promise<object>} Accepted start. */
        async start(request) {
            requests.push(request)
            return { ok: true, operationId: 'op:unsupported-format' }
        }
    }
    const store = createStore({
        activeArea: 'utilities',
        activeOperation: null,
        activity: [],
        authenticationSessions: {},
        devices: [device],
        discovery: { diagnostics: { acceptedCount: 1, candidateCount: 1, rejections: [] }, epoch: 1, listRevision: 1, scanStatus: 'idle', selectionInitialized: true, tombstones: {} },
        lastOperation: null,
        provenance: 'fixture',
        selectedDeviceId: device.id,
        service: { status: 'ready' },
        settings: { autoScan: true }
    })
    const controller = mountApplication(document.querySelector('#app'), { platform: 'darwin', store, utilityController })
    const filesystem = document.querySelector('[data-utility-filesystem]')
    const injectedOption = document.createElement('option')
    injectedOption.value = 'ntfs'
    injectedOption.textContent = 'Injected unsupported NTFS'
    filesystem.append(injectedOption)
    filesystem.value = 'ntfs'
    const input = document.querySelector('[data-format-confirmation]')
    const button = document.querySelector('[data-action="start-format"]')
    input.value = input.dataset.expectedIdentity
    input.dispatchEvent(new dom.window.Event('input', { bubbles: true }))
    assert.equal(button.disabled, false)
    button.click()
    await new Promise((resolve) => setTimeout(resolve, 0))

    assert.deepEqual(requests, [])
    controller.destroy()
    dom.window.close()
}

/** @returns {Promise<void>} Verifies the utility stylesheet preserves a dense responsive dark grid. */
async function testUtilityStyles() {
    const { dom, document } = createDom()
    const style = document.createElement('style')
    style.textContent = `${await readFile(new URL('../src/styles/tokens.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/base.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/operation-components.css', import.meta.url), 'utf8')}\n${await readFile(new URL('../src/styles/utility-workflows.css', import.meta.url), 'utf8')}`
    document.head.append(style)
    const view = renderUtilitiesView(utilityDevice(), { document, operationIntentAvailable: true })
    document.body.append(view)

    assert.equal(document.defaultView.getComputedStyle(view).display, 'grid')
    assert.match(document.defaultView.getComputedStyle(view.querySelector('.utility-card')).backgroundImage, /linear-gradient/)
    assert.equal(view.querySelectorAll('i[class*="ph-"]').length >= 12, true)
    dom.window.close()
}

test('firmware preflight rejects media and a mismatched image before transfer', testFirmwarePreflight)
test('legacy firmware flow accepts only the documented BIP family', testLegacyFirmwareFamily)
test('SATA III firmware flow is not confused with the SATA I legacy family', testModernSataFirmwareFamily)
test('firmware family uses reported product identity when connection type is unavailable', testFirmwareFamilyProductFallback)
test('USB dock never offers SATA link setter', testUsbSataGate)
test('SATA workflow retains the recommended default and suppresses current-mode writes', testSataModeRules)
test('SATA and drive-letter readiness preserve the global operation lock', testModeGlobalLock)
test('Fixed and Removable workflow suppresses current-mode writes', testDriveModeNoOp)
test('drive-letter workflow lists only host-reported available letters', testDriveLetterAvailability)
test('production snapshot enables Windows Set and preserves the global busy lock', testDriveLetterSnapshotAvailability)
test('format requires writable media and exact destructive identity', testFormatConfirmation)
test('format choices and defaults follow the native host formatter', testFormatPlatformPolicy)
test('unknown host platform keeps format fail-closed after exact confirmation', testUnknownFormatPlatformGate)
test('macOS format card offers all native filesystems with a visible native-host rationale', testMacosFormatPresentation)
test('safe and force eject keep flush and cached-data risk separate', testEjectBoundaries)
test('utility operation controller obtains opaque file and confirmation tokens', testOperationController)
test('Utilities tab integrates exact structured actions and confirmation input', testShellIntegration)
test('macOS structured format boundary rejects an injected NTFS selection', testMacosFormatSubmissionGate)
test('Utilities workspace uses bundled icons and responsive cyberpunk styling', testUtilityStyles)

test('rejected macOS format requests retain their reason across background renders without starting an erase', async () => {
    const { dom, document } = createDom()
    const device = utilityDevice()
    const pending = Promise.withResolvers()
    let starts = 0
    const api = {
        operations: {
            /** @returns {Promise<object>} Deferred read-only confirmation rejection. */
            async confirm() {
                return await pending.promise
            },
            /** @returns {Promise<object>} Tracks any accidental erase admission. */
            async start() {
                starts += 1
                return { ok: true, operationId: 'op:unexpected' }
            }
        }
    }
    const base = createFixtureState({ mode: 'one-device' })
    const store = createStore({ ...base, activeArea: 'utilities', devices: [device], selectedDeviceId: device.id, discovery: { ...base.discovery, epoch: 1, listRevision: 1 } })
    const controller = mountApplication(document.querySelector('#app'), { platform: 'darwin', store, utilityController: createUtilityOperationController(api) })
    try {
        const filesystem = document.querySelector('[data-utility-filesystem]')
        filesystem.value = 'hfs'
        filesystem.dispatchEvent(new dom.window.Event('change', { bubbles: true }))
        const input = document.querySelector('[data-format-confirmation]')
        input.value = input.dataset.expectedIdentity
        input.dispatchEvent(new dom.window.Event('input', { bubbles: true }))
        document.querySelector('[data-action="start-format"]').click()
        store.dispatch({ type: 'device/list-replaced', epoch: 1, listRevision: 2, devices: [{ ...device, revision: 13 }] })
        assert.match(document.querySelector('[data-utility-feedback]').textContent, /Submitting/)
        pending.resolve({ ok: false, reason: 'stale-device-revision' })
        await new Promise((resolve) => setImmediate(resolve))
        assert.match(document.querySelector('[data-utility-feedback]').textContent, /stale-device-revision/)
        store.dispatch({ type: 'device/list-replaced', epoch: 1, listRevision: 3, devices: [{ ...device, revision: 14 }] })
        assert.match(document.querySelector('[data-utility-feedback]').textContent, /stale-device-revision/)
        assert.equal(starts, 0, 'confirmation rejection never reaches the erase API')
        store.dispatch({ type: 'device/list-replaced', epoch: 1, listRevision: 4, devices: [] })
        store.dispatch({ type: 'device/list-replaced', epoch: 1, listRevision: 5, devices: [{ ...device, revision: 15 }] })
        store.dispatch({ type: 'device/select', deviceId: device.id })
        assert.equal(document.querySelector('[role="tab"][aria-selected="true"]').dataset.area, 'status')
        document.querySelector('[role="tab"][data-area="utilities"]').click()
        assert.doesNotMatch(document.querySelector('[data-utility-feedback]').textContent, /stale-device-revision/, 'old feedback is cleared after the target disappears')
    } finally {
        pending.resolve({ ok: false, reason: 'stale-device-revision' })
        controller.destroy()
        dom.window.close()
    }
})
