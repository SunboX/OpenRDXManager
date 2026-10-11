// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { writeFile } from 'node:fs/promises'
import { arch, platform, release } from 'node:os'

import { englishCatalog } from '../locales/en.mjs'
import { SupportSummaryService } from './support-summary-service.mjs'
import { UpdateService } from './update-service.mjs'

/** @param {string} filePath - Main-selected destination. @param {string} text - Sanitized UTF-8 content. @param {{exclusive?: boolean}} [options={}] - Exclusive creation policy for automatic exports. @returns {Promise<void>} Saves the local artifact. */
async function writeUtf8(filePath, text, options = {}) {
    await writeFile(filePath, text, { encoding: 'utf8', flag: options.exclusive === true ? 'wx' : 'w', mode: 0o600 })
}

/** @returns {string} Current host architecture. */
function currentArchitecture() {
    return arch()
}

/** @returns {string} Current Node platform identifier. */
function currentPlatform() {
    return platform()
}

/** @returns {string} Current operating-system release. */
function currentRelease() {
    return release()
}

/**
 * Runs the configured non-blocking startup check without exposing any device action.
 * @param {{enabled: boolean, services: {updates?: {checkStartup?: () => Promise<object>}}}} options - Persisted preference and main-owned services.
 * @returns {Promise<object>} Read-only availability or one stable contained failure.
 */
export async function runStartupUpdateCheck(options) {
    if (options?.enabled !== true) return { ok: false, reason: 'update-check-disabled' }
    if (typeof options?.services?.updates?.checkStartup !== 'function') return { ok: false, reason: 'update-service-unavailable' }
    try {
        return await options.services.updates.checkStartup()
    } catch {
        return { ok: false, reason: 'update-network-failure' }
    }
}

/**
 * Wires summary, activity export, and update checking to the current runtime.
 * @param {{application: {getName: () => string, getVersion: () => string}, chooseDestination: (options: object) => Promise<object>, runtime: {client: {list: () => Promise<object>}, getReadiness: () => object, logger: object}, exportDirectory?: string, randomUUID?: () => string, translate?: (key: string) => string, setLoggingEnabled?: (request: object) => Promise<object>, host?: {architecture: () => string, platform: () => string, release: () => string}, writeText?: (path: string, text: string, options?: {exclusive?: boolean}) => Promise<void>, updateEndpoint?: string, updatePublicKey?: unknown, fetch?: Function, now?: () => Date}} options - Main-owned dependencies and explicit update trust configuration.
 * @returns {{automationSupport: object, logs: object, support: object, updates: object}} Frozen main service groups.
 * @throws {TypeError} When required main-owned dependencies are absent.
 */
export function createSupportRuntimeServices(options) {
    if (typeof options?.application?.getName !== 'function' || typeof options?.application?.getVersion !== 'function' || typeof options?.chooseDestination !== 'function' || typeof options?.runtime?.client?.list !== 'function' || typeof options?.runtime?.getReadiness !== 'function' || typeof options?.runtime?.logger?.list !== 'function' || typeof options?.runtime?.logger?.setEnabled !== 'function') {
        throw new TypeError('Support runtime services require application, dialog, runtime, and logger boundaries')
    }
    const host = options.host ?? { architecture: currentArchitecture, platform: currentPlatform, release: currentRelease }
    const writeText = options.writeText ?? writeUtf8
    const translate = typeof options.translate === 'function' ? options.translate : (key) => englishCatalog[key] ?? key

    /** @returns {Promise<object[]>} Snapshots only the current renderer-safe discovered devices. */
    async function listDevices() {
        try {
            const result = await options.runtime.client.list()
            return result?.ok === true && Array.isArray(result.devices) ? result.devices.slice(0, 128) : []
        } catch {
            return []
        }
    }

    /** @returns {Promise<object>} Collects allowlisted application, host, service, and device facts. */
    async function collectSummary() {
        const readiness = options.runtime.getReadiness()
        return {
            application: { name: options.application.getName(), version: options.application.getVersion() },
            devices: await listDevices(),
            generatedAt: new Date().toISOString(),
            host: { architecture: host.architecture(), platform: host.platform(), release: host.release() },
            service: {
                hardwareReady: readiness?.hardwareReady === true,
                hardwareVerified: readiness?.hardwareVerified === true,
                mode: readiness?.mode,
                status: readiness?.status
            }
        }
    }

    /** @param {string} defaultName - Fixed local artifact filename. @returns {Promise<object>} Main-selected destination. */
    function chooseArtifactDestination(defaultName) {
        const titleKey = defaultName === 'RDXManagerActivity.txt' ? 'filePicker.activityExport.title' : 'filePicker.supportSummary.title'
        return options.chooseDestination({ buttonLabel: translate('filePicker.save'), defaultPath: defaultName, title: translate(titleKey) })
    }

    const summaryService = new SupportSummaryService({ chooseDestination: chooseArtifactDestination, collect: collectSummary, exportDirectory: options.exportDirectory, randomUUID: options.randomUUID, writeText })
    const updateService = new UpdateService({ currentVersion: options.application.getVersion(), devices: listDevices, endpoint: options.updateEndpoint, fetch: options.fetch, now: options.now, publicKey: options.updatePublicKey })
    const logger = options.runtime.logger
    const setLoggingEnabled = typeof options.setLoggingEnabled === 'function' ? options.setLoggingEnabled : logger.setEnabled.bind(logger)
    let startupCheckConsumed = false
    let startupCheckPromise = null

    const logs = Object.freeze({
        /** @returns {Promise<object>} Lists bounded renderer-safe activity. */
        list() {
            return logger.list()
        },
        /** @param {object} request - Exact logging toggle. @returns {Promise<object>} Durable toggle result. */
        setEnabled(request) {
            return setLoggingEnabled(request)
        },
        /** @returns {Promise<object>} Saves already-redacted activity through a main chooser. */
        export() {
            return summaryService.exportActivity(logger)
        }
    })
    const support = Object.freeze({
        /** @returns {Promise<object>} Saves a fresh sanitized local summary. */
        generateSummary() {
            return summaryService.generateSummary()
        }
    })
    const automationSupport = Object.freeze({
        /** @returns {Promise<object>} Returns a fresh sanitized summary without opening a chooser. */
        readSummary() {
            return summaryService.readSummary()
        },
        /** @returns {Promise<object>} Returns redacted local activity without opening a chooser. */
        readActivity() {
            return summaryService.readActivity(logger)
        },
        /** @returns {Promise<object>} Exclusively creates a generated summary in the configured export directory. */
        exportSummary() {
            return summaryService.exportSummaryAutomatically()
        },
        /** @returns {Promise<object>} Exclusively creates generated redacted activity in the configured export directory. */
        exportActivity() {
            return summaryService.exportActivityAutomatically(logger)
        }
    })
    const updates = Object.freeze({
        /** @returns {Promise<object>} Starts and retains exactly one main-owned silent metadata check for the renderer. */
        checkStartup() {
            startupCheckPromise ??= updateService.check({ silent: true })
            return startupCheckPromise
        },
        /** @param {object} request - Exact explicit/silent check mode. @returns {Promise<object>} Read-only availability. */
        async check(request) {
            if (request?.silent === true && startupCheckPromise !== null && !startupCheckConsumed) {
                startupCheckConsumed = true
                return startupCheckPromise
            }
            return updateService.check(request)
        }
    })
    return Object.freeze({ automationSupport, logs, support, updates })
}
