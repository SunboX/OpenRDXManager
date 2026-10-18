// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { OperationContinuationService } from './operation-continuation-service.mjs'
import { MigrationRecoveryService } from './migration-recovery-service.mjs'
import { ManufacturingService } from './manufacturing-service.mjs'
import { ManufacturingFolderService } from './manufacturing-folder-service.mjs'
import { windowsManufacturingDirectory } from './windows-manufacturing-directory.mjs'
import { join } from 'node:path'

import { DeviceServiceClient, createDeviceServiceTransportFactory, resolveDeviceServiceExecutable } from './device-service-client.mjs'
import { EventLogger } from './event-logger.mjs'
import { WindowsLogSecurityAdapter } from './windows-log-security-adapter.mjs'
import { OperationCoordinator } from './operation-coordinator.mjs'
import { SptiDiagnosticLog } from './spti-diagnostics.mjs'

// The native transport proves the installed helper before becoming ready. Its
// service then completes fresh runtime and peer checks before replying.
const MACOS_INSTALLED_HANDSHAKE_TIMEOUT_MS = 10_000

/**
 * Registers and dispatches one firmware operation without exposing local paths.
 * @param {{client: {registerFirmwareImage: Function, startOperation: Function}, firmwareFileService?: {claimFirmwareFile: Function}, operation: object}} options - Main-owned firmware boundaries.
 * @returns {Promise<object>} Strict registration or operation result.
 */
export async function dispatchRegisteredFirmwareOperation(options) {
    if (options?.operation?.request?.kind !== 'firmware-update') {
        return options.client.startOperation(options.operation)
    }
    if (typeof options?.firmwareFileService?.claimFirmwareFile !== 'function') {
        return { ok: false, reason: 'firmware-selection-unavailable' }
    }
    const token = options.operation.request.firmwareFileToken
    const claimed = await options.firmwareFileService.claimFirmwareFile(token)
    if (claimed?.ok === false) return claimed
    if (claimed?.extension !== '.BIN' || !Buffer.isBuffer(claimed?.bytes) || claimed.bytes.length !== claimed.size) {
        claimed?.bytes?.fill?.(0)
        return { ok: false, reason: claimed?.extension === '.BIP' ? 'legacy-bip-format-unproven' : 'firmware-file-invalid' }
    }
    try {
        const registered = await options.client.registerFirmwareImage({ bytes: claimed.bytes, extension: claimed.extension, fileToken: token, ...(claimed.openRdx === undefined ? {} : { openRdx: claimed.openRdx }) })
        if (registered.ok !== true) return registered
        return options.client.startOperation(options.operation)
    } finally {
        claimed.bytes.fill(0)
    }
}

/**
 * Creates and wires the concrete Phase 2 main-process services behind the
 * Task 6 injectable IPC boundary.
 * The optional `sptiDiagnostics: true` setting opens a separate header-only log
 * only in Windows development; it cannot enable a packaged capture or device action.
 * @param {{appPath: string, resourcesPath: string, isPackaged: boolean, platform: 'darwin'|'win32'|'linux', elevateDevelopmentService?: boolean, logDirectory: string, manufacturingFolder?: {directory: string, openPath: Function}, services: object, ipcController: {publishDeviceEvent: Function, publishOperationEvent: Function}, eventLoggerOptions?: object, firmwareFileService?: {claimFirmwareFile: Function}, transportFactory?: Function, windowsSecurityAdapter?: object}} options - Main-owned runtime roots and injection surfaces.
 * @returns {{start: () => Promise<object>, stop: () => Promise<object>, getReadiness: () => object, client: DeviceServiceClient, coordinator: OperationCoordinator, logger: EventLogger}} Frozen runtime API.
 * @throws {TypeError} When the Task 6 injection surface is incomplete.
 */
export function createApplicationServiceRuntime(options) {
    if (options?.services === null || typeof options?.services !== 'object' || typeof options?.ipcController?.publishDeviceEvent !== 'function' || typeof options?.ipcController?.publishOperationEvent !== 'function') {
        throw new TypeError('Application service runtime requires IPC injection services')
    }
    if (options.eventLoggerOptions !== undefined && (options.eventLoggerOptions === null || typeof options.eventLoggerOptions !== 'object')) {
        throw new TypeError('Application service runtime logger injection is invalid')
    }

    let client = null
    let loggerHealthFailed = false
    let stopPromise = null
    let recovery = null
    let manufacturing = null
    const pendingConfirmations = new Map()
    const confirmationLifetimeMs = 60_000

    /**
     * Converts any internal logger reason into one fixed runtime health failure.
     * The client latches synchronously, then contains failure outside the logger
     * callback stack so admission failure cannot recursively log lifecycle state.
     * @returns {void} Completes after latching at most one fatal containment.
     */
    function handleLoggerFailure() {
        if (loggerHealthFailed) {
            return
        }
        loggerHealthFailed = true
        const generation = client?.getGeneration() ?? 0
        if (client?.faultEventLog(generation) !== true) {
            options.ipcController.publishDeviceEvent({ type: 'service', status: 'unavailable', reason: 'event-log-unavailable' })
        }
    }

    const windowsClientAddonPath = options.platform === 'win32' ? join(options.isPackaged ? options.resourcesPath : options.appPath, options.isPackaged ? 'native' : 'out/native', 'windows', 'openrdx-windows-client.node') : undefined
    const macosClientAddonPath = options.platform === 'darwin' ? join(options.isPackaged ? options.resourcesPath : options.appPath, options.isPackaged ? 'native' : 'out/native', 'macos', 'openrdx-macos-client.node') : undefined
    const windowsSecurityAdapter = options.windowsSecurityAdapter !== undefined ? options.windowsSecurityAdapter : options.platform === 'win32' ? new WindowsLogSecurityAdapter({ directory: options.logDirectory, addonPath: windowsClientAddonPath }) : undefined
    const logger = new EventLogger({ ...options.eventLoggerOptions, directory: options.logDirectory, onFailure: handleLoggerFailure, platform: options.platform, windowsSecurityAdapter })
    const sptiEnabled = options.sptiDiagnostics === true && options.isPackaged === false && options.platform === 'win32'
    const sptiDirectory = join(options.logDirectory, 'spti')
    const sptiLog = sptiEnabled ? new SptiDiagnosticLog({ directory: sptiDirectory, platform: 'win32', windowsSecurityAdapter: new WindowsLogSecurityAdapter({ directory: sptiDirectory, addonPath: windowsClientAddonPath }) }) : null
    const executable = resolveDeviceServiceExecutable({
        appPath: options.appPath,
        resourcesPath: options.resourcesPath,
        isPackaged: options.isPackaged,
        platform: options.platform
    })
    // Tests may inject an explicit fake. Packaged production connects only to
    // the privileged endpoint; a missing endpoint never falls back to a child.
    const transportFactory = typeof options.transportFactory === 'function' ? options.transportFactory : createDeviceServiceTransportFactory({ elevateDevelopmentService: options.elevateDevelopmentService, isPackaged: options.isPackaged, platform: options.platform, windowsClientAddonPath, macosClientAddonPath, sptiDiagnostics: sptiEnabled, onSptiDiagnostic: sptiLog?.record.bind(sptiLog) })
    client = new DeviceServiceClient({ executable, logger, emitHandshakeDiagnostics: options.isPackaged === true && options.platform === 'darwin', platform: options.platform, transportFactory, handshakeTimeoutMs: options.isPackaged === true && options.platform === 'darwin' ? MACOS_INSTALLED_HANDSHAKE_TIMEOUT_MS : undefined })

    /**
     * Sends one coordinator-owned operation through the supervised client.
     * @param {object} operation - Exact operation identity and request.
     * @returns {Promise<object>} Strict action result.
     */
    async function dispatchOperation(operation) {
        return dispatchRegisteredFirmwareOperation({ client, firmwareFileService: options.firmwareFileService, operation })
    }

    /**
     * Sends one coordinator-approved cancellation through the supervised client.
     * @param {object} request - Exact cancellation identity.
     * @returns {Promise<object>} Strict action result.
     */
    async function cancelOperation(request) {
        return client.cancelOperation(request)
    }

    /** @param {object} request - Strict scan request. @returns {Promise<object>} Service scan result. */
    async function dispatchScan(request) {
        return client.scan(request)
    }

    /**
     * Resolves one current service-owned device snapshot.
     * @param {string} deviceId - Opaque device identity.
     * @returns {object|null} Current strict device or null.
     */
    function getDevice(deviceId) {
        return client.getDevice(deviceId)
    }

    /**
     * Returns the current handshaken platform capability.
     * @returns {object} Strict platform capability.
     */
    function getPlatformCapability() {
        return client.getPlatformCapability()
    }

    /** @returns {string|null} Fatal logger health reason or null. */
    function getServiceFailure() {
        return loggerHealthFailed ? 'event-log-unavailable' : null
    }

    /**
     * Reports the current handshaken service privilege state.
     * @returns {boolean} True only after a privileged current handshake.
     */
    function hasPrivilege() {
        return client.hasPrivilege()
    }

    /** @returns {number} Current supervised service generation. */
    function getGeneration() {
        return client.getGeneration()
    }

    /**
     * Starts bounded teardown for one exact coordinator-owned service generation.
     * @param {number} generation - Exact generation reporting a protocol contradiction.
     * @returns {boolean} True only when the current generation entered recovery.
     */
    function faultGeneration(generation) {
        return client.faultGeneration(generation)
    }

    /** @returns {string|null} Current reconciled service mode. */
    function getServiceMode() {
        return client.getServiceMode()
    }

    /** @returns {boolean} True only for current native hardware readiness. */
    function isHardwareReady() {
        return client.isHardwareReady()
    }

    /**
     * Issues one token through the native service and retains its exact main-owned binding.
     * @param {object} request - Strict destructive action without a token.
     * @returns {Promise<object>} Opaque token response or bounded failure.
     */
    async function issueConfirmation(request) {
        const result = await client.issueConfirmation(request)
        if (result.ok !== true) {
            return result
        }
        pendingConfirmations.set(result.confirmationToken, {
            request: JSON.stringify(request),
            generation: client.getGeneration(),
            expiresAt: Date.now() + confirmationLifetimeMs
        })
        return result
    }

    /**
     * Converts a confirmed host operation into its token-free exact action binding.
     * @param {object} request - Strict operation request.
     * @returns {object|null} Exact confirmable action or null.
     */
    function confirmationBinding(request) {
        if (request?.kind === 'format') {
            return { kind: request.kind, deviceId: request.deviceId, deviceRevision: request.deviceRevision, filesystem: request.filesystem }
        }
        if (request?.kind === 'eject-force') {
            return { kind: request.kind, deviceId: request.deviceId, deviceRevision: request.deviceRevision }
        }
        return null
    }

    /**
     * Atomically consumes a main-observed service token before operation dispatch.
     * @param {object} request - Strict operation request carrying the token.
     * @returns {boolean} True only for the exact current action, generation, and lifetime.
     */
    function validateConfirmation(request) {
        return matchConfirmation(request, true)
    }

    /**
     * Checks a pending token for the IPC preflight without consuming it before
     * the coordinator's atomic reservation boundary.
     * @param {object} request - Strict operation request carrying the token.
     * @returns {boolean} True only for the exact current binding.
     */
    function peekConfirmation(request) {
        return matchConfirmation(request, false)
    }

    /**
     * Matches one main-observed service token and optionally consumes it first.
     * @param {object} request - Strict operation request carrying the token.
     * @param {boolean} consume - Whether to delete before returning a decision.
     * @returns {boolean} True only for the exact current action, generation, and lifetime.
     */
    function matchConfirmation(request, consume) {
        const token = request?.confirmationToken
        if (typeof token !== 'string') {
            return false
        }
        const record = pendingConfirmations.get(token)
        if (consume) {
            pendingConfirmations.delete(token)
        }
        const binding = confirmationBinding(request)
        return record !== undefined && binding !== null && record.generation === client.getGeneration() && Date.now() < record.expiresAt && record.request === JSON.stringify(binding)
    }

    /**
     * Creates the one redacted operation lifecycle record used on both sides of
     * the terminal persistence barrier.
     * @param {object} event - Strict coordinator-owned lifecycle event.
     * @returns {object} Logger-safe operation metadata.
     */
    function createOperationLogRecord(event) {
        return {
            event: 'operation-lifecycle',
            messageKey: 'activity.operation',
            severity: event.state === 'failed' ? 'error' : 'info',
            operationId: event.operationId,
            kind: event.kind,
            deviceId: event.deviceId,
            deviceRevision: event.deviceRevision,
            state: event.state,
            stage: event.stage,
            supportCorrelationId: event.state === 'failed' ? event.error.supportCorrelationId : undefined
        }
    }

    /**
     * Persists one terminal before the coordinator can release or publish it.
     * @param {object} event - Strict terminal operation event.
     * @returns {Promise<boolean>} True only after bounded durable persistence.
     */
    async function persistOperationTerminal(event) {
        if (loggerHealthFailed) return false
        let persisted = false
        try {
            persisted = (await logger.writeCritical(createOperationLogRecord(event))) === true
        } catch {
            persisted = false
        }
        if (!persisted) handleLoggerFailure()
        return persisted && !loggerHealthFailed
    }

    const coordinator = new OperationCoordinator({
        getRecoveryOwner: () => manufacturing?.getActiveOperation() ?? recovery?.getActiveOperation() ?? null,
        cancelDispatch: cancelOperation,
        dispatch: dispatchOperation,
        faultGeneration,
        getDevice,
        getGeneration,
        getPlatformCapability,
        getServiceFailure,
        getServiceMode,
        hasPrivilege,
        isHardwareReady,
        peekConfirmation,
        scanDispatch: dispatchScan,
        terminalBarrier: persistOperationTerminal,
        validateConfirmation
    })
    recovery = new MigrationRecoveryService({ wire: client.recovery, getActiveOperation: () => coordinator.getActiveOperation() ?? manufacturing?.getActiveOperation() ?? null, getGeneration: client.getGeneration.bind(client), isReady: client.hasPrivilege.bind(client), getAdmissionFailure: () => (coordinator.isShuttingDown() ? 'application-shutting-down' : null) })
    manufacturing = new ManufacturingService({ wire: client.manufacturing, getActiveOperation: () => coordinator.getActiveOperation() ?? recovery?.getActiveOperation() ?? null, getGeneration: client.getGeneration.bind(client), isReady: client.hasPrivilege.bind(client), getAdmissionFailure: () => (coordinator.isShuttingDown() ? 'application-shutting-down' : null) })

    /**
     * Maps supervised service lifecycle into strict renderer state and lock failure.
     * @param {object} state - Frozen service lifecycle state.
     * @returns {void} Completes after safe publication.
     */
    function handleLifecycle(state) {
        if (state.status !== 'ready' || state.epoch !== client.getGeneration()) {
            pendingConfirmations.clear()
        }
        if (state.status === 'ready') {
            options.ipcController.publishDeviceEvent({ type: 'service', status: 'ready', epoch: state.epoch, listRevision: state.listRevision, mode: state.mode, privileged: state.privileged === true, hardwareReady: state.hardwareReady, hardwareVerified: state.hardwareVerified === true, platformCapability: state.platformCapability })
            return
        }
        if (['restarting', 'unavailable'].includes(state.status) && Number.isSafeInteger(state.terminatedGeneration)) {
            // The logger's own fatal transition cannot recursively manufacture a
            // terminal record; exact generation loss reconciles it without IPC.
            coordinator.handleGenerationLoss(state.terminatedGeneration, state.reason, state.reason !== 'event-log-unavailable')
        }
        if (['teardown-unconfirmed', 'unavailable'].includes(state.status)) {
            options.ipcController.publishDeviceEvent({ type: 'service', status: 'unavailable', reason: state.reason })
            return
        }
        if (['starting', 'restarting', 'recovering', 'reconciling'].includes(state.status)) {
            options.ipcController.publishDeviceEvent({ type: 'service', status: state.status })
        }
    }

    /**
     * Maps strict client events to either discovery publication or operation ownership.
     * @param {{channel: 'device'|'operation', event: object}} envelope - Safe client event envelope.
     * @returns {boolean|Promise<boolean>} Exact downstream protocol acceptance.
     */
    function handleClientEvent(envelope) {
        if (envelope.channel === 'device') {
            options.ipcController.publishDeviceEvent(envelope.event)
            return true
        } else if (envelope.channel === 'operation') {
            return coordinator.handleServiceEvent(envelope.event, envelope.publicationSequence)
        }
        return false
    }

    /**
     * Publishes and logs only safe coordinator-owned operation metadata.
     * @param {object} event - Strict operation lifecycle event.
     * @returns {boolean} True after public delivery; terminals were already persisted.
     */
    function handleOperationEvent(event) {
        options.ipcController.publishOperationEvent(event)
        if (['succeeded', 'failed', 'cancelled'].includes(event.state)) return true
        void logger.write(createOperationLogRecord(event))
        return true
    }

    const unsubscribeLifecycle = client.subscribeLifecycle(handleLifecycle)
    const unsubscribeClientEvents = client.subscribeEvents(handleClientEvent)
    const unsubscribeOperationEvents = coordinator.subscribe(handleOperationEvent)
    options.services.devices = Object.freeze({ list: client.list.bind(client), scan: coordinator.scan.bind(coordinator) })
    options.services.recovery = Object.freeze({ list: recovery.list.bind(recovery), status: recovery.status.bind(recovery), start: recovery.start.bind(recovery), continue: recovery.continue.bind(recovery) })
    /** Resolves only the native known-folder path after the service has prepared it. */
    function windowsBackupDirectory() {
        return windowsManufacturingDirectory(windowsClientAddonPath)
    }
    const manufacturingFolder = new ManufacturingFolderService({ ...options.manufacturingFolder, ...(options.platform === 'win32' ? { directory: windowsBackupDirectory, createDirectory: false } : {}), prepare: client.manufacturing.prepareFolder.bind(client.manufacturing) })
    options.services.manufacturing = Object.freeze({ list: manufacturing.list.bind(manufacturing), backup: manufacturing.backup.bind(manufacturing), restore: manufacturing.restore.bind(manufacturing), openFolder: manufacturingFolder.open.bind(manufacturingFolder) })
    const continuationService = new OperationContinuationService({ getActiveOperation: coordinator.getActiveOperation.bind(coordinator), dispatch: client.continueOperation.bind(client) })
    options.services.operations = Object.freeze({
        continue: continuationService.continue.bind(continuationService),
        cancel: coordinator.cancel.bind(coordinator),
        confirm: issueConfirmation,
        getContext: coordinator.getContext.bind(coordinator),
        waitForScan: coordinator.waitForScan.bind(coordinator),
        start: coordinator.start.bind(coordinator)
    })
    options.services.logs = logger
    /**
     * Starts supervision and returns the first ready or terminal unavailable state.
     * @returns {Promise<object>} Frozen service readiness state.
     */
    async function start() {
        if (stopPromise !== null) {
            return client.getState()
        }
        if (loggerHealthFailed) {
            return getReadiness()
        }
        return client.start()
    }

    /**
     * Stops supervision and detaches all internal event mapping callbacks.
     * @returns {Promise<object>} Resolves with the bounded sanitized log-close result.
     */
    function stop() {
        if (stopPromise !== null) return stopPromise

        /** @returns {Promise<object>} Performs the one owned teardown sequence. */
        async function performStop() {
            await client.stop()
            await sptiLog?.close()
            const loggerResult = await logger.close()
            unsubscribeLifecycle()
            unsubscribeClientEvents()
            unsubscribeOperationEvents()
            return loggerResult
        }
        stopPromise = performStop()
        return stopPromise
    }

    /**
     * Returns current service readiness without starting or mutating runtime state.
     * @returns {object} Frozen service state.
     */
    function getReadiness() {
        if (loggerHealthFailed && !['unavailable', 'teardown-unconfirmed', 'stopped'].includes(client.getState().status)) {
            return Object.freeze({ status: 'unavailable', reason: 'event-log-unavailable', restartCount: client.getState().restartCount ?? 0 })
        }
        return client.getState()
    }

    return Object.freeze({ client, coordinator, recovery, logger, start, stop, getReadiness })
}
