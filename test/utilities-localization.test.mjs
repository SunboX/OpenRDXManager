// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { renderUtilitiesView } from '../src/renderer/views/utilities-view.mjs'
import { createEjectWorkflow } from '../src/renderer/workflows/eject-workflow.mjs'
import { createFirmwareWorkflow } from '../src/renderer/workflows/firmware-workflow.mjs'
import { createFormatWorkflow } from '../src/renderer/workflows/format-workflow.mjs'
import { createDriveLetterWorkflow, createDriveModeWorkflow, createSataModeWorkflow } from '../src/renderer/workflows/mode-workflow.mjs'
import { completeDeviceSnapshot } from './helpers/device-snapshot.mjs'

/**
 * Returns a conspicuous translator that exposes every requested key and bounded
 * parameter at the visible presentation boundary.
 * @param {string} key - Requested bundled message key.
 * @param {object} [params={}] - Bounded interpolation parameters.
 * @returns {string} Sentinel translation.
 */
function sentinelTranslator(key, params = {}) {
    const entries = Object.entries(params).sort(([left], [right]) => left.localeCompare(right))
    const suffix = entries.length === 0 ? '' : `:${entries.map(([name, value]) => `${name}=${value}`).join(',')}`
    return `§${key}${suffix}§`
}

/** @returns {{dom: JSDOM, document: Document}} Isolated Utilities DOM. */
function createDom() {
    const dom = new JSDOM('<!doctype html><html><body></body></html>', {
        pretendToBeVisual: true,
        url: 'file:///openrdxmanager/src/index.html'
    })
    return { dom, document: dom.window.document }
}

/** @returns {object} Complete device with raw identity and one untrusted reason. */
function localizedDevice() {
    return completeDeviceSnapshot({
        capabilities: {
            'drive-letter-reset': { state: 'available' },
            'drive-letter-set': { state: 'available' },
            'drive-mode-set': { state: 'available' },
            'eject-force': { state: 'available' },
            'eject-safe': { state: 'available' },
            'firmware-update': { reason: 'device-injected-catalog-key', state: 'unsupported-product' },
            format: { state: 'available' },
            'sata-mode-set': { state: 'available' }
        },
        drive: {
            connectionType: 'USB 3',
            firmwareRevision: '0283',
            operationMode: 'Removable Disk',
            productType: 'USB 3 / SATA III',
            powerSource: 'external'
        },
        id: 'rdx:utility-localization',
        media: {
            capacityBytes: 1_000_000_000,
            encrypted: false,
            filesystem: 'exfat',
            id: 'media:raw-localization',
            label: 'Disposable RDX',
            serial: 'RAW-MEDIA-LOCALIZED-01',
            status: 'ready',
            usedBytes: 250_000_000,
            writable: true
        },
        product: 'RAW RDX Product Name',
        revision: 22,
        serial: 'RAW-DOCK-LOCALIZED-01',
        vendor: 'TANDBERG'
    })
}

test('Utilities view translates app copy, preserves raw identities, and allowlists device reason tokens', () => {
    const { dom, document } = createDom()
    const device = localizedDevice()
    const view = renderUtilitiesView(device, {
        availableDriveLetters: ['R'],
        document,
        lastOperation: {
            deviceId: device.id,
            deviceRevision: device.revision,
            error: { code: 'format-failed', stage: 'format-writing', supportCorrelationId: 'RAW-SUPPORT-42' },
            kind: 'format',
            stage: 'format-writing',
            status: 'failed'
        },
        operationIntentAvailable: true,
        platform: 'win32',
        provenance: 'fixture',
        translator: sentinelTranslator
    })
    const copy = view.textContent

    for (const key of ['utilities.eyebrow', 'utilities.title', 'utilities.description', 'utilities.firmware.title', 'utilities.firmware.warning.power', 'utilities.eject.title', 'utilities.eject.forceAcknowledgement', 'utilities.driveMode.title', 'utilities.sataMode.title', 'utilities.driveLetter.title', 'utilities.format.title', 'utilities.preflight', 'utilities.capability.title', 'utilities.result.failedTitle', 'reason.generic', 'utilities.fixtureNote']) {
        assert.match(copy, new RegExp(`§${key}(?::|\\§)`))
    }
    for (const untranslated of ['GUIDED HARDWARE OPERATIONS', 'Update Firmware', 'Eject Cartridge', 'Requested drive mode', 'Partition & Format Cartridge', 'No success is claimed']) {
        assert.doesNotMatch(copy, new RegExp(untranslated.replaceAll(/[.*+?^${}()|[\]\\]/g, '\\$&')))
    }
    assert.doesNotMatch(copy, /device-injected-catalog-key/)
    assert.match(copy, /RAW RDX Product Name/)
    assert.match(copy, /RAW-DOCK-LOCALIZED-01/)
    assert.match(copy, /RAW-SUPPORT-42/)
    assert.match(copy, /\.BIN/)
    assert.match(copy, /USB 3/)

    dom.window.close()
})

test('Utilities workflow models carry keys while protocol values and capability reasons remain stable', () => {
    const inserted = localizedDevice()
    const ejected = { ...inserted, media: null }
    const firmware = createFirmwareWorkflow(inserted)
    const eject = createEjectWorkflow(inserted, 'safe')
    const format = createFormatWorkflow(inserted, { platform: 'win32' })
    const driveMode = createDriveModeWorkflow(ejected)
    const sataMode = createSataModeWorkflow({ ...ejected, drive: { ...ejected.drive, connectionType: 'SATA III', productType: 'SATA III' }, product: 'RDX QuikStor SATA III' }, { currentMode: '1.5g-3g' })
    const driveLetter = createDriveLetterWorkflow(ejected, { availableLetters: ['R'], platform: 'win32' })

    assert.equal(firmware.stages[0].labelKey, 'utilities.stage.firmwareValidating')
    assert.equal(firmware.prerequisites[0].labelKey, 'utilities.prerequisite.mediaEjected.label')
    assert.equal(firmware.warnings[0], 'utilities.firmware.warning.power')
    assert.equal(firmware.image.extension, '.BIN')
    assert.equal(firmware.image.family, 'USB 3 / SATA III')
    assert.equal(firmware.capability.reason, 'device-injected-catalog-key')
    assert.equal(eject.guidanceKey, 'utilities.eject.safeGuidance')
    assert.equal(format.consequenceKey, 'utilities.format.consequence')
    assert.equal(format.defaultFilesystem, 'ntfs')
    assert.equal(format.filesystem, 'ntfs')
    assert.equal(driveMode.guidanceKey, 'utilities.driveMode.noOpGuidance')
    assert.equal(sataMode.guidanceKey, 'utilities.sataMode.guidance')
    assert.equal(driveLetter.guidanceKey, 'utilities.driveLetter.guidance')
    assert.equal(Object.hasOwn(format, 'consequence'), false)
    assert.equal(Object.hasOwn(driveMode, 'guidance'), false)
})

test('Utilities view localizes an unavailable support ID instead of exposing its internal token', () => {
    const { dom, document } = createDom()
    const device = localizedDevice()
    const view = renderUtilitiesView(device, {
        document,
        lastOperation: {
            deviceId: device.id,
            deviceRevision: device.revision,
            error: { code: 'format-failed', stage: 'format-writing' },
            kind: 'format',
            stage: 'format-writing',
            status: 'failed'
        },
        operationIntentAvailable: true,
        platform: 'linux',
        provenance: 'fixture',
        translator: sentinelTranslator
    })
    const result = view.querySelector('[data-result-status="failed"]').textContent

    assert.match(result, /§state\.notReported§/)
    assert.doesNotMatch(result, /not-reported/)
    dom.window.close()
})
