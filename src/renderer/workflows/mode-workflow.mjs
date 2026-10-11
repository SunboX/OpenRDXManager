// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { OperationKind } from '../../shared/contracts.mjs'
import { reportedUtilityConnectionIdentity, reportedUtilityValue, resolveUtilityCapability, utilityPrerequisite, utilityStages } from './utility-workflow-helpers.mjs'

const CONFIGURATION_STAGES = utilityStages([
    ['device-configuring', 'utilities.stage.deviceConfiguring'],
    ['device-reconnecting', 'utilities.stage.deviceReconnecting'],
    ['device-readback', 'utilities.stage.deviceReadback']
])
const DRIVE_LETTER_STAGES = utilityStages([
    ['host-volume-changing', 'utilities.stage.hostVolumeChanging'],
    ['host-volume-readback', 'utilities.stage.hostVolumeReadback']
])

/**
 * Normalizes the reported Fixed/Removable label to the public setter value.
 * @param {unknown} value - Reported operation-mode text.
 * @returns {'fixed'|'removable'|null} Known current choice or null.
 */
function normalizeDriveMode(value) {
    if (typeof value !== 'string') return null
    const normalized = value.toLowerCase()
    if (normalized.includes('fixed')) return 'fixed'
    if (normalized.includes('removable') || normalized.includes('standard')) return 'removable'
    return null
}

/**
 * Builds the Fixed/Removable mode workflow with no-media and no-op rules.
 * @param {object} device - Selected renderer-safe RDX device.
 * @param {{selectedMode?: 'fixed'|'removable', locked?: boolean, operationIntentAvailable?: boolean}} [options={}] - User selection and shell gates.
 * @returns {object} Frozen drive-mode workflow.
 */
export function createDriveModeWorkflow(device, options = {}) {
    const currentMode = normalizeDriveMode(reportedUtilityValue(device?.drive?.details?.operationMode) ?? device?.drive?.operationMode)
    const selectedMode = options.selectedMode === 'fixed' ? 'fixed' : 'removable'
    const mediaEjected = device?.media === null
    const currentReported = currentMode !== null
    const noOp = currentReported && currentMode === selectedMode
    const prerequisites = Object.freeze([utilityPrerequisite('media-ejected', 'utilities.prerequisite.mediaEjected.label', mediaEjected, mediaEjected ? 'utilities.prerequisite.mediaEjected.met' : 'utilities.prerequisite.mediaEjected.driveMode'), utilityPrerequisite('current-mode', 'utilities.prerequisite.currentDriveMode.label', currentReported, currentReported ? 'utilities.prerequisite.currentDriveMode.reported' : 'utilities.prerequisite.currentDriveMode.unreported', currentReported ? { mode: currentMode } : {})])
    return Object.freeze({
        capability: resolveUtilityCapability(device, OperationKind.DRIVE_MODE_SET, prerequisites, { ...options, unmetReason: currentReported ? 'media-must-be-ejected' : 'current-drive-mode-unavailable', unmetState: currentReported ? 'wrong-media-state' : 'evidence-incomplete' }),
        currentMode,
        guidanceKey: noOp ? 'utilities.driveMode.noOpGuidance' : 'utilities.driveMode.changeGuidance',
        kind: OperationKind.DRIVE_MODE_SET,
        noOp,
        prerequisites,
        risk: 'configuration',
        selectedMode,
        stages: CONFIGURATION_STAGES
    })
}

/**
 * Builds the SATA III link-mode workflow with product, media, readback, and no-op gates.
 * @param {object} device - Selected renderer-safe RDX device.
 * @param {{currentMode?: '1.5g-3g'|'3g-6g', selectedMode?: '1.5g-3g'|'3g-6g', locked?: boolean, operationIntentAvailable?: boolean}} [options={}] - Current/selected mode and shell gates.
 * @returns {object} Frozen SATA-mode workflow.
 */
export function createSataModeWorkflow(device, options = {}) {
    const connectionIdentity = reportedUtilityConnectionIdentity(device).toUpperCase()
    const sata3 = /SATA\s*(?:III|3)/.test(connectionIdentity)
    const reportedMode = reportedUtilityValue(device?.drive?.details?.sataMode) ?? device?.drive?.sataMode ?? options.currentMode
    const currentMode = ['1.5g-3g', '3g-6g'].includes(reportedMode) ? reportedMode : null
    const selectedMode = options.selectedMode === '3g-6g' ? '3g-6g' : '1.5g-3g'
    const mediaEjected = device?.media === null
    const noOp = currentMode !== null && currentMode === selectedMode
    const prerequisites = Object.freeze([utilityPrerequisite('sata-iii-product', 'utilities.prerequisite.sataProduct.label', sata3, sata3 ? 'utilities.prerequisite.sataProduct.met' : 'utilities.prerequisite.sataProduct.unmet'), utilityPrerequisite('media-ejected', 'utilities.prerequisite.mediaEjected.label', mediaEjected, mediaEjected ? 'utilities.prerequisite.mediaEjected.met' : 'utilities.prerequisite.mediaEjected.sataMode'), utilityPrerequisite('current-sata-mode', 'utilities.prerequisite.currentSataMode.label', currentMode !== null, currentMode === null ? 'utilities.prerequisite.currentSataMode.unreported' : 'utilities.prerequisite.currentSataMode.reported', currentMode === null ? {} : { mode: currentMode })])
    const capability = resolveUtilityCapability(device, OperationKind.SATA_MODE_SET, prerequisites, { ...options, unmetReason: !sata3 ? 'sata-iii-product-required' : !mediaEjected ? 'media-must-be-ejected' : 'current-sata-mode-unavailable', unmetState: !sata3 ? 'unsupported-product' : !mediaEjected ? 'wrong-media-state' : 'evidence-incomplete' })
    return Object.freeze({
        capability,
        currentMode,
        guidanceKey: 'utilities.sataMode.guidance',
        kind: OperationKind.SATA_MODE_SET,
        noOp,
        prerequisites,
        recommendedMode: '1.5g-3g',
        risk: 'configuration',
        selectedMode,
        stages: CONFIGURATION_STAGES
    })
}

/**
 * Sanitizes and de-duplicates host-reported available drive letters.
 * @param {unknown} values - Candidate available-letter list.
 * @returns {string[]} Frozen uppercase available letters.
 */
function normalizeAvailableLetters(values) {
    if (!Array.isArray(values)) return Object.freeze([])
    const letters = []
    for (const value of values) {
        if (typeof value === 'string' && /^[D-Z]$/i.test(value)) {
            const letter = value.toUpperCase()
            if (!letters.includes(letter)) letters.push(letter)
        }
    }
    return Object.freeze(letters.sort())
}

/**
 * Builds the Windows USB3 serial-specific drive-letter workflow.
 * @param {object} device - Selected renderer-safe RDX device.
 * @param {{availableLetters?: string[], platform?: string, selectedLetter?: string, locked?: boolean, operationIntentAvailable?: boolean}} [options={}] - Host facts and shell gates.
 * @returns {object} Frozen drive-letter workflow.
 */
export function createDriveLetterWorkflow(device, options = {}) {
    const availableLetters = normalizeAvailableLetters(options.availableLetters)
    const connectionIdentity = reportedUtilityConnectionIdentity(device).toUpperCase()
    const windows = options.platform === 'win32'
    const usb3 = /USB\s*3/.test(connectionIdentity)
    const mediaEjected = device?.media === null
    const selectedLetter = availableLetters.includes(options.selectedLetter?.toUpperCase()) ? options.selectedLetter.toUpperCase() : (availableLetters[0] ?? null)
    const sharedPrerequisites = [utilityPrerequisite('windows-host', 'utilities.prerequisite.windowsHost.label', windows, windows ? 'utilities.prerequisite.windowsHost.met' : 'utilities.prerequisite.windowsHost.unmet'), utilityPrerequisite('usb3-product', 'utilities.prerequisite.usb3Product.label', usb3, usb3 ? 'utilities.prerequisite.usb3Product.met' : 'utilities.prerequisite.usb3Product.unmet'), utilityPrerequisite('media-ejected', 'utilities.prerequisite.mediaEjected.label', mediaEjected, mediaEjected ? 'utilities.prerequisite.mediaEjected.met' : 'utilities.prerequisite.mediaEjected.driveLetter')]
    const resetPrerequisites = Object.freeze(sharedPrerequisites)
    const prerequisites = Object.freeze([...sharedPrerequisites, utilityPrerequisite('available-letter', 'utilities.prerequisite.availableLetter.label', selectedLetter !== null, selectedLetter === null ? 'utilities.prerequisite.availableLetter.unreported' : 'utilities.prerequisite.availableLetter.reported', selectedLetter === null ? {} : { letter: `${selectedLetter}:` })])
    const setCapability = resolveUtilityCapability(device, OperationKind.DRIVE_LETTER_SET, prerequisites, { ...options, unmetReason: !windows ? 'drive-letter-windows-only' : availableLetters.length === 0 ? 'available-drive-letters-unreported' : 'drive-letter-prerequisites-not-met', unmetState: !windows ? 'unsupported-platform' : availableLetters.length === 0 ? 'host-dependency-missing' : 'wrong-media-state' })
    const resetCapability = resolveUtilityCapability(device, OperationKind.DRIVE_LETTER_RESET, resetPrerequisites, { ...options, unmetReason: !windows ? 'drive-letter-windows-only' : 'drive-letter-prerequisites-not-met', unmetState: !windows ? 'unsupported-platform' : 'wrong-media-state' })
    return Object.freeze({
        availableLetters,
        capability: setCapability,
        guidanceKey: 'utilities.driveLetter.guidance',
        kind: OperationKind.DRIVE_LETTER_SET,
        prerequisites,
        resetKind: OperationKind.DRIVE_LETTER_RESET,
        resetCapability,
        resetPrerequisites,
        risk: 'configuration',
        selectedLetter,
        setCapability,
        stages: DRIVE_LETTER_STAGES
    })
}
