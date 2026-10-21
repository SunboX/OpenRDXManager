// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync } from 'node:fs'
import { waitForInstallerResult } from './main/installer-startup.mjs'
import { join } from 'node:path'
import { createRequire } from 'node:module'
import { pathToFileURL, fileURLToPath } from 'node:url'
import { app, BrowserWindow, clipboard, dialog, ipcMain, Menu, nativeImage, nativeTheme, powerMonitor, shell, Tray } from 'electron/main'

import { getAppIconPath, linuxDesktopEntryId } from './app-icon.mjs'
import { applicationMetadata } from './main/application-metadata.mjs'
import { englishCatalog } from './locales/en.mjs'
import { getCatalog } from './locales/catalogs.mjs'
import { showFirmwareOpenDialog } from './main/firmware-dialog.mjs'
import { registerWindowMenu } from './main/window-menu.mjs'
import { WindowFrameController } from './main/window-frame-controller.mjs'
import { FirmwareFileSelectionService } from './main/firmware-file-selection-service.mjs'
import { isTrustedApplicationSender, registerIpcHandlers, trustApplicationWindow } from './main/ipc-controller.mjs'
import { createMacOsPrivilegedServiceController } from './main/macos-privileged-service.mjs'
import { createApplicationServiceRuntime } from './main/service-runtime.mjs'
import { McpHttpServer } from './main/mcp/server.mjs'
import { resolveMcpBridgePath } from './main/mcp/bridge-path.mjs'
import { McpSettingsController } from './main/mcp/settings-controller.mjs'
import { McpOperationStore } from './main/mcp/operation-store.mjs'
import { createMcpToolRegistry } from './main/mcp/tool-registry.mjs'
import { createMcpEventPublisher } from './main/mcp/application-integration.mjs'
import { scheduleAfterMcpResponse } from './main/mcp/response-actions.mjs'
import { resolveStartupLanguage, SettingsService } from './main/settings-service.mjs'
import { ShutdownController } from './main/shutdown-controller.mjs'
import { StartupFailureExitController } from './main/startup-failure-exit.mjs'
import { containBrokenConsolePipes } from './main/process-output.mjs'
import { assertAuthenticatedServiceReadiness, attachSmokeReadinessListeners, getServiceReadinessFailureReason, resolveSmokeReadinessTimeout, SmokeReadinessError, SmokeReadinessGate } from './main/smoke-readiness.mjs'
import { assertInstalledDeviceDiscovery } from './main/installed-device-verification.mjs'
import { createSupportRuntimeServices, runStartupUpdateCheck } from './main/support-runtime.mjs'
import { AutoScanController, DesktopLifecycleController, TrayController } from './main/tray-controller.mjs'
import { createTranslator } from './renderer/i18n.mjs'
import { IpcChannel } from './shared/ipc-contract.mjs'
import { windowOptions } from './window-options.mjs'

const htmlPath = fileURLToPath(new URL('./index.html', import.meta.url))
// Match Chromium menus, dialogs, and native decorations to the dark dashboard.
nativeTheme.themeSource = 'dark'
containBrokenConsolePipes()
const require = createRequire(import.meta.url)
const htmlUrl = pathToFileURL(htmlPath).href
// A renamed development executable still runs the default app with an explicit
// source directory. Actual packaged launches do not carry process.defaultApp.
const isPackagedRuntime = app.isPackaged && process.defaultApp !== true
const isServiceScanTest = process.argv.includes('--service-scan-test')
const isServiceAuthenticationTest = process.argv.includes('--service-auth-test') || isServiceScanTest
const isSmokeTest = process.argv.includes('--smoke-test') || isServiceAuthenticationTest
const trustedWebContents = new Set()
let serviceRuntime = null
let mcpController = null
const mcpOperationStore = new McpOperationStore()
let shutdownController = null
let settingsService = null
let autoScanController = null
let desktopLifecycle = null
let trayController = null
let traySelectedDeviceId = null
let privilegedServiceController = null
const startupFailureExit = new StartupFailureExitController({
    app,
    /** @returns {object} Current ownership guard, including unresolved runtime recovery. */
    getShutdownPolicy() {
        return serviceRuntime === null ? { allowed: true } : serviceRuntime.coordinator.getShutdownPolicy()
    }
})
let desktopTranslator = createTranslator(englishCatalog, englishCatalog)
const smokeReadiness = isSmokeTest ? new SmokeReadinessGate({ timeoutMs: resolveSmokeReadinessTimeout({ platform: process.platform, isPackaged: isPackagedRuntime, serviceAuthentication: isServiceAuthenticationTest }) }) : null
let smokeWebContents = null

if (process.platform === 'win32') app.setAppUserModelId('OpenRDX.OpenRDXManager')
if (process.platform === 'linux') app.setDesktopName(linuxDesktopEntryId)

/**
 * Loads the dock artwork through Node's Unicode-safe filesystem boundary.
 * Electron's direct path loader can reject decomposed non-ASCII app paths.
 * @returns {void} Completes after the dock receives a validated native image.
 */
function setMacOsDockIcon() {
    const icon = nativeImage.createFromBuffer(readFileSync(getAppIconPath('linux')))
    if (icon.isEmpty()) throw new Error('app-icon-unavailable')
    app.dock.setIcon(icon)
}

const services = {
    /**
     * Accepts IPC only from an application window currently owned by main and
     * loaded from the exact local renderer document.
     * @param {object} event - Electron invoke event.
     * @returns {boolean} True only for the local application renderer.
     */
    isTrustedSender(event) {
        return isTrustedApplicationSender({ event, rendererUrl: htmlUrl, trustedWebContents })
    },
    /**
     * Returns current application-owned renderer targets for validated events.
     * @returns {object[]} Trusted Electron web contents.
     */
    getTrustedWebContents() {
        const targets = []
        for (const webContents of trustedWebContents) {
            if (webContents.isDestroyed() === false && webContents.getURL() === htmlUrl) {
                targets.push(webContents)
            }
        }
        return targets
    },
    app: {
        /**
         * Returns bounded, non-sensitive application metadata.
         * @returns {Promise<object>} Renderer-safe application information.
         */
        async getInfo() {
            return {
                ok: true,
                app: {
                    ...applicationMetadata,
                    platform: process.platform
                }
            }
        },
        /** @param {{deviceId: string|null}} request - Validated renderer selection. @returns {Promise<object>} Stable action response. */
        async setTraySelection(request) {
            traySelectedDeviceId = request.deviceId
            await refreshTrayDevices()
            return { ok: true }
        }
    }
}

const ipcController = registerIpcHandlers({ ipcMain, services })
registerWindowMenu({ ipcMain, Menu, BrowserWindow, isTrustedSender: services.isTrustedSender })
const eventPublisher = createMcpEventPublisher({ ipcController, operationStore: mcpOperationStore, getController: () => mcpController })

/**
 * Loads the fixed packaged macOS ServiceManagement addon from application
 * resources. Non-applicable platforms never load native code.
 * @returns {object|null} Native addon only for packaged macOS.
 */
function loadMacOsServiceManagementAddon() {
    if (process.platform !== 'darwin' || isPackagedRuntime !== true) return null
    return require(join(process.resourcesPath, 'native', 'macos', 'openrdx-service-management.node'))
}

/**
 * Loads only the fixed packaged read-only macOS local trust verifier. Missing
 * native verification leaves setup disabled and directs the user to repair.
 * @returns {object|null} Native verifier for packaged macOS, otherwise null.
 */
function loadMacOsLocalTrustAddon() {
    if (process.platform !== 'darwin' || isPackagedRuntime !== true) return null
    try {
        return require(join(process.resourcesPath, 'native', 'macos', 'openrdx-macos-client.node'))
    } catch {
        return null
    }
}

/** @returns {Promise<object>} Refreshes ServiceManagement status through the strict IPC shape. */
async function getPrivilegedServiceSetup() {
    const status = await privilegedServiceController.getStatus()
    return { ok: true, ...status }
}

/**
 * Registers the fixed embedded daemon and retries the existing production
 * socket runtime only after ServiceManagement reports it enabled.
 * @returns {Promise<object>} Strict action result.
 */
async function registerPrivilegedService() {
    const result = await privilegedServiceController.register()
    if (result.ok === true && serviceRuntime !== null) {
        await serviceRuntime.start()
        await refreshTrayDevices()
    }
    return result
}

/**
 * Retries the existing runtime transport and refreshes discovery after recovery.
 * Development stays on its source-built stdio helper; this action never registers
 * or falls back to an installed privileged service.
 * @returns {Promise<object>} Strict action result.
 */
async function retryHardwareService() {
    if (serviceRuntime === null || autoScanController === null) {
        return { ok: false, reason: 'service-unavailable' }
    }
    const readiness = await serviceRuntime.start()
    if (readiness.status !== 'ready') {
        return { ok: false, reason: readiness.reason ?? 'service-unavailable' }
    }
    await autoScanController.scanNow()
    return { ok: true }
}

/**
 * Accepts the internal mounted signal only from the exact smoke-test window.
 * @param {object} event - Electron IPC event from preload.
 * @returns {void} Completes after recording trusted renderer evidence.
 */
function handleRendererMounted(event) {
    if (smokeReadiness !== null && event.sender === smokeWebContents && services.isTrustedSender(event)) {
        smokeReadiness.markRendererMounted()
    }
}

ipcMain.on(IpcChannel.APP_RENDERER_MOUNTED, handleRendererMounted)

/**
 * Creates and loads one secure local application window.
 * @returns {Promise<BrowserWindow>} Loaded application window.
 */
async function createWindow() {
    const savedBounds = settingsService?.getDesktopState().windowBounds ?? null
    const window = new BrowserWindow(savedBounds === null ? windowOptions : { ...windowOptions, ...savedBounds })
    // The renderer strip uses native submenus; a second system strip would duplicate it.
    if (process.platform !== 'darwin') window.setMenuBarVisibility(false)
    trustApplicationWindow(window, trustedWebContents)
    new WindowFrameController(window)
    if (isSmokeTest && smokeWebContents === null) {
        smokeWebContents = window.webContents
        attachSmokeReadinessListeners(window.webContents, smokeReadiness)
    }

    if (shutdownController !== null && desktopLifecycle !== null) {
        /** @param {object} event - Electron close event. @returns {void} Applies the operation guard and records safe bounds. */
        function handleWindowClose(event) {
            if (!desktopLifecycle.handleWindowClose(event)) return
            void saveWindowBounds(window)
            shutdownController.handleWindowClose(event)
        }
        window.on('close', handleWindowClose)
    }
    await window.loadFile(htmlPath)
    // A hidden Windows launcher can suppress the constructor's initial show.
    // Explicitly expose the loaded local window rather than leaving a tray-only app.
    window.show()
    return window
}

/** @param {BrowserWindow} window - Closing native window. @returns {Promise<void>} Saves bounds while containing native or persistence failures at the synchronous close boundary. */
async function saveWindowBounds(window) {
    try {
        await settingsService.updateDesktopState({ windowBounds: window.getBounds() })
    } catch {
        // Closing a destroyed native window must not weaken shutdown policy.
    }
}

/** @returns {object} Small bundled tray image without a remote or filesystem dependency. */
function createTrayImage() {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 18 18"><rect x="1" y="2" width="16" height="14" rx="3" fill="none" stroke="#32f3c7" stroke-width="1.5"/><path d="M5 6h8M5 9h5" stroke="#32f3c7" stroke-width="1.5" stroke-linecap="round"/><circle cx="13" cy="12" r="1.5" fill="#ff3ea5"/></svg>'
    return nativeImage.createFromDataURL(`data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`)
}

/** @returns {Promise<void>} Refreshes bounded tray state from the current strict service list. */
async function refreshTrayDevices() {
    let response
    try {
        response = await services.devices.list({})
    } catch {
        response = { ok: false, reason: 'service-failure' }
    }
    if (response?.ok !== true) {
        trayController?.update({ devices: [], selectedDeviceId: null, serviceStatus: 'unavailable', loggingEnabled: settingsService.getDesktopState().eventLogging })
        return
    }
    const selectedDeviceId = response.devices.some((device) => device.id === traySelectedDeviceId) ? traySelectedDeviceId : null
    trayController?.update({ devices: response.devices, selectedDeviceId, serviceStatus: response.status, loggingEnabled: settingsService.getDesktopState().eventLogging })
}

/** @returns {Promise<void>} Re-publishes readiness and performs one wake refresh. */
async function refreshAfterResume() {
    const readiness = serviceRuntime.getReadiness()
    if (readiness.status === 'ready') {
        ipcController.publishDeviceEvent({ type: 'service', status: 'ready', epoch: readiness.epoch, listRevision: readiness.listRevision, mode: readiness.mode, privileged: readiness.privileged === true, hardwareReady: readiness.hardwareReady, hardwareVerified: readiness.hardwareVerified === true, platformCapability: readiness.platformCapability })
    }
    await autoScanController.scanNow()
}

/** @returns {Promise<void>} Displays the single non-sensitive unsafe-close warning. */
async function warnUnsafeClose() {
    await dialog.showMessageBox({ type: 'warning', title: desktopTranslator('unsafeClose.title'), message: desktopTranslator('unsafeClose.message'), detail: desktopTranslator('unsafeClose.detail'), buttons: [desktopTranslator('unsafeClose.keepRunning')], defaultId: 0, noLink: true })
}

/** @returns {Promise<void>} Brings an existing local window forward or creates one. */
async function openApplicationWindow() {
    const [window] = BrowserWindow.getAllWindows()
    if (window === undefined) {
        await createWindow()
        return
    }
    if (window.isMinimized()) window.restore()
    window.show()
    window.focus()
}

/** @param {boolean} enabled - Requested persisted logging state. @returns {Promise<object>} Stable action result. */
async function setEventLogging(enabled) {
    const result = await updateRendererSettings({ eventLogging: enabled })
    return result.ok === true ? { ok: true } : result
}

/** @param {object} request - Strict public settings update. @returns {Promise<object>} Persisted renderer-safe settings response. */
async function updateRendererSettings(request) {
    const prior = settingsService.getDesktopState()
    const saved = await settingsService.update(request)
    if (saved.ok !== true) return saved
    const next = settingsService.getDesktopState()
    if (next.eventLogging !== prior.eventLogging && serviceRuntime !== null) {
        const changed = await serviceRuntime.logger.setEnabled({ enabled: next.eventLogging })
        if (changed.ok !== true) {
            await settingsService.update({ eventLogging: prior.eventLogging })
            return changed
        }
    }
    if (next.language !== prior.language) {
        desktopTranslator = createTranslator(getCatalog(next.language), englishCatalog)
        trayController?.setTranslator(desktopTranslator)
    }
    if (autoScanController !== null && next.autoScan !== prior.autoScan) {
        if (next.autoScan) autoScanController.start()
        else {
            /** @returns {Promise<void>} Observes admitted scan cleanup without delaying this settings publication. */
            async function stopPolling() {
                try {
                    await autoScanController.stop()
                } catch {
                    console.error('Failed to stop OpenRDXManager device polling')
                }
            }
            // stop() disables polling synchronously. Waiting for its scan drain
            // here would let a later enable publish before this disable.
            void stopPolling()
        }
    }
    eventPublisher.publishSettingsEvent(saved.settings)
    await refreshTrayDevices()
    return saved
}

/**
 * Adapts the strict renderer logging request to the shared durable setting flow.
 * @param {{enabled: boolean}} request - Validated event-logging request.
 * @returns {Promise<object>} Persisted toggle result.
 */
function setEventLoggingFromRenderer(request) {
    return setEventLogging(request.enabled)
}

/**
 * Opens the main-owned save chooser at the user's desktop with a fixed artifact name.
 * @param {{buttonLabel: string, defaultPath: string, title: string}} options - Internal support artifact dialog options.
 * @returns {Promise<object>} Electron save-dialog selection.
 */
function chooseSupportDestination(options) {
    return dialog.showSaveDialog({ ...options, defaultPath: join(app.getPath('desktop'), options.defaultPath) })
}

/** @param {string} key - Bundled main-process message key. @param {object} [params={}] - Bounded interpolation values. @returns {string} Current desktop-language message. */
function translateDesktopMessage(key, params = {}) {
    return desktopTranslator(key, params)
}

/** @returns {void} Clears renderer authentication state without issuing a device action. */
function invalidateRendererSessions() {
    traySelectedDeviceId = null
    ipcController.publishDeviceEvent({ type: 'service', status: 'recovering' })
    trayController?.update({ devices: [], selectedDeviceId: null, serviceStatus: 'suspended', loggingEnabled: settingsService.getDesktopState().eventLogging })
}

/**
 * Waits for Electron readiness, creates the first window, and installs the
 * platform-standard activate behavior.
 * @returns {Promise<void>} Resolves after startup registration completes.
 */
async function start() {
    const smokeCompletion = smokeReadiness?.wait() ?? null
    if (smokeCompletion !== null) {
        /** @returns {Promise<void>} Observes early rejection until startup reaches its explicit readiness await. */
        async function observeEarlySmokeFailure() {
            try {
                await smokeCompletion
            } catch {
                // The awaited smoke result below remains the startup authority.
            }
        }
        void observeEarlySmokeFailure()
    }
    await app.whenReady()
    if (process.platform === 'win32' && isPackagedRuntime) {
        const resultFile = process.argv.find((argument) => argument.startsWith('--installer-result-file='))?.slice('--installer-result-file='.length)
        if (resultFile !== undefined) await waitForInstallerResult(resultFile)
    }
    // Hidden title bars need an explicit native menu in non-default-app launches.
    if (Menu.getApplicationMenu() === null) {
        Menu.setApplicationMenu(Menu.buildFromTemplate([...(process.platform === 'darwin' ? [{ role: 'appMenu' }] : []), { role: 'fileMenu' }, { role: 'editMenu' }, { role: 'viewMenu' }, { role: 'windowMenu' }]))
    }
    if (process.platform === 'darwin') setMacOsDockIcon()
    const firmwareFileService = new FirmwareFileSelectionService({
        /** @param {object} options - Firmware chooser options. @returns {Promise<object>} Window-owned native selection. */
        showOpenDialog: (options) => showFirmwareOpenDialog({ BrowserWindow, dialog }, options),
        translate: translateDesktopMessage
    })
    settingsService = new SettingsService({ filePath: join(app.getPath('userData'), 'settings.json') })
    await settingsService.load()
    const startupLanguage = resolveStartupLanguage({ argv: process.argv, persistedLanguage: settingsService.getDesktopState().language, warn: console.warn })
    settingsService.setSessionLanguage(startupLanguage.language)
    desktopTranslator = createTranslator(getCatalog(startupLanguage.language), englishCatalog)
    privilegedServiceController = createMacOsPrivilegedServiceController({ addon: loadMacOsServiceManagementAddon(), localTrustAddon: loadMacOsLocalTrustAddon(), isPackaged: isPackagedRuntime, platform: process.platform })
    services.service = Object.freeze({
        getSetup: getPrivilegedServiceSetup,
        openApprovalSettings: privilegedServiceController.openApprovalSettings,
        retry: retryHardwareService,
        register: registerPrivilegedService
    })
    services.settings = Object.freeze({ get: settingsService.get.bind(settingsService), update: updateRendererSettings })
    services.files = Object.freeze({ chooseFirmware: firmwareFileService.chooseFirmware.bind(firmwareFileService) })
    serviceRuntime = createApplicationServiceRuntime({
        appPath: app.getAppPath(),
        resourcesPath: process.resourcesPath,
        isPackaged: isPackagedRuntime,
        elevateDevelopmentService: isPackagedRuntime === false && ['darwin', 'linux'].includes(process.platform),
        platform: process.platform,
        logDirectory: join(app.getPath('userData'), 'logs'),
        sptiDiagnostics: isPackagedRuntime === false && process.platform === 'win32' && process.env.OPENRDX_SPTI_DIAGNOSTICS === '1',
        manufacturingFolder: { directory: join(app.getPath('appData'), 'OpenRDXManager', 'manufacturing-backups'), openPath: shell.openPath.bind(shell) },
        eventLoggerOptions: { enabled: settingsService.getDesktopState().eventLogging },
        firmwareFileService,
        services,
        ipcController: eventPublisher
    })
    Object.assign(
        services,
        createSupportRuntimeServices({
            application: app,
            chooseDestination: chooseSupportDestination,
            runtime: serviceRuntime,
            exportDirectory: join(app.getPath('userData'), 'exports'),
            setLoggingEnabled: setEventLoggingFromRenderer,
            translate: translateDesktopMessage,
            updateEndpoint: process.env.OPENRDX_UPDATE_MANIFEST_URL,
            updatePublicKey: process.env.OPENRDX_UPDATE_PUBLIC_KEY
        })
    )
    const mcpTools = createMcpToolRegistry({
        services,
        operationStore: mcpOperationStore,
        firmwareFiles: firmwareFileService,
        support: services.automationSupport,
        getReadiness: serviceRuntime.getReadiness,
        getActiveOperation: serviceRuntime.coordinator.getActiveOperation.bind(serviceRuntime.coordinator),
        desktop: {
            /** @returns {Promise<object>} Opens the normal application window. */
            async show() {
                await openApplicationWindow()
                return { ok: true }
            },
            /** @returns {object} Defers a guarded quit until its MCP response completes. */
            exit() {
                if (serviceRuntime.coordinator.getShutdownPolicy().allowed !== true) return { ok: false, reason: 'operation-in-progress' }
                return scheduleAfterMcpResponse(() => app.quit()) ? { ok: true } : { ok: false, reason: 'response-context-unavailable' }
            }
        }
    })
    mcpController = new McpSettingsController({ directory: join(app.getPath('userData'), 'mcp'), bridgePath: resolveMcpBridgePath(app.getAppPath()), copyText: clipboard.writeText.bind(clipboard), createServer: ({ token }) => new McpHttpServer({ token, tools: mcpTools }) })
    services.mcp = Object.freeze({ getStatus: mcpController.getStatus.bind(mcpController), update: mcpController.update.bind(mcpController), copyConfiguration: mcpController.copyConfiguration.bind(mcpController) })
    shutdownController = new ShutdownController({ app, coordinator: serviceRuntime.coordinator, runtime: { stop: stopApplicationRuntime } })
    autoScanController = new AutoScanController({ afterScan: refreshTrayDevices, scan: () => services.devices.scan({ kind: 'scan' }) })
    desktopLifecycle = new DesktopLifecycleController({
        getShutdownPolicy: serviceRuntime.coordinator.getShutdownPolicy.bind(serviceRuntime.coordinator),
        invalidateSessions: invalidateRendererSessions,
        refresh: refreshAfterResume,
        requestQuit: app.quit.bind(app),
        scanner: autoScanController,
        warnUnsafeClose
    })
    trayController = new TrayController({
        Menu,
        Tray,
        actions: {
            exit: desktopLifecycle.requestExit.bind(desktopLifecycle),
            open: openApplicationWindow,
            scan: autoScanController.scanNow.bind(autoScanController),
            setLogging: setEventLogging,
            startOperation: serviceRuntime.coordinator.start.bind(serviceRuntime.coordinator)
        },
        icon: createTrayImage(),
        translate: desktopTranslator
    })
    const serviceReadiness = await serviceRuntime.start()
    void runStartupUpdateCheck({ enabled: settingsService.getDesktopState().updateChecks, services })
    smokeReadiness?.markServiceTerminal(serviceReadiness)
    console.log(`OpenRDXManager service readiness: ${serviceReadiness.status} ${serviceReadiness.mode ?? 'none'} hardware=${serviceReadiness.hardwareReady === true} capability=${serviceReadiness.platformCapability?.reason ?? serviceReadiness.platformCapability?.state ?? 'none'} reason=${getServiceReadinessFailureReason(serviceReadiness)}`)
    // Populate the first authoritative inventory even when periodic Auto Scan
    // is disabled; the renderer must never open on the helper's empty cache.
    await autoScanController.scanNow()
    await mcpController.load()
    await createWindow()

    if (isSmokeTest) {
        const readiness = await smokeCompletion
        if (isServiceAuthenticationTest) assertAuthenticatedServiceReadiness(readiness.service)
        if (isServiceScanTest) {
            const expectedId = process.argv.find((argument) => argument.startsWith('--expected-device-id='))?.slice('--expected-device-id='.length)
            const expectedFirmware = process.argv.find((argument) => argument.startsWith('--expected-firmware-revision='))?.slice('--expected-firmware-revision='.length)
            const inventory = await services.devices.list()
            console.log(`OpenRDXManager installed discovery diagnostics: ${JSON.stringify(inventory.diagnostics ?? null)}`)
            const count = assertInstalledDeviceDiscovery(readiness.service, inventory, expectedId, expectedFirmware)
            console.log(`OpenRDXManager installed device discovery passed: count=${count} selected=${expectedId === undefined ? 'any' : 'matched'} media=${inventory.devices.filter((device) => device.media != null).length}`)
            if (expectedFirmware !== undefined) console.log(`OpenRDXManager installed firmware verification passed: revision=${expectedFirmware}`)
        }
        await autoScanController.stop()
        trayController.destroy()
        await stopApplicationRuntime()
        smokeReadiness.dispose()
        console.log(`OpenRDXManager smoke test passed: renderer=${readiness.renderer} service=${readiness.service.status} mode=${readiness.service.mode ?? 'none'} hardware=${readiness.service.hardwareReady === true} capability=${readiness.service.platformCapability?.reason ?? readiness.service.platformCapability?.state ?? 'none'} reason=${getServiceReadinessFailureReason(readiness.service)}`)
        if (isServiceAuthenticationTest) console.log(`OpenRDXManager installed service authentication passed: platform=${process.platform}`)
        app.quit()
        return
    }

    if (settingsService.getDesktopState().autoScan) autoScanController.start()

    /** @returns {Promise<void>} Applies the bounded suspend policy and contains errors from the native event listener. */
    async function handleSuspend() {
        try {
            await desktopLifecycle.onSuspend()
        } catch {
            console.error('Failed to suspend OpenRDXManager device polling')
        }
    }

    /** @returns {Promise<void>} Applies the bounded resume policy and contains errors from the native event listener. */
    async function handleResume() {
        try {
            await desktopLifecycle.onResume()
        } catch {
            console.error('Failed to resume OpenRDXManager device polling')
        }
    }

    /**
     * Recreates the application window after dock activation on macOS.
     * @returns {Promise<void>} Resolves after any missing window is recreated.
     */
    async function handleActivate() {
        try {
            if (BrowserWindow.getAllWindows().length === 0) {
                await createWindow()
            }
        } catch {
            console.error('Failed to open OpenRDXManager window')
        }
    }

    app.on('activate', handleActivate)
    powerMonitor.on('suspend', handleSuspend)
    powerMonitor.on('resume', handleResume)
}

/**
 * Quits on Windows/Linux while preserving normal macOS application lifetime.
 * @returns {void} Completes after any platform-appropriate quit request.
 */
function handleAllWindowsClosed() {
    if (process.platform !== 'darwin') {
        app.quit()
    }
}

app.on('window-all-closed', handleAllWindowsClosed)

/**
 * Stops native-service supervision when Electron begins application shutdown.
 * @returns {void} Completes after scheduling idempotent runtime cleanup.
 */
function handleBeforeQuit(event) {
    if (serviceRuntime !== null && serviceRuntime.coordinator.getShutdownPolicy().allowed !== true) {
        event.preventDefault()
        desktopLifecycle?.requestExit()
        return
    }
    autoScanController?.stop()
    trayController?.destroy()
    shutdownController?.handleBeforeQuit(event)
}

app.on('before-quit', handleBeforeQuit)

/** @param {object} event - Final Electron quit event. @returns {void} Preserves failed startup status after approved teardown. */
function handleWillQuit(event) {
    startupFailureExit.handleWillQuit(event)
}

app.on('will-quit', handleWillQuit)

/** @returns {Promise<void>} Closes MCP protocol access before the owned native runtime during approved shutdown. */
async function stopApplicationRuntime() {
    try {
        await mcpController?.stop()
    } finally {
        await serviceRuntime?.stop()
    }
}

/**
 * Reports a sanitized startup failure and terminates the Electron lifecycle.
 * @param {unknown} _error - Startup error whose details stay in main.
 * @returns {Promise<void>} Completes after setting failure status and requesting quit, even if teardown fails.
 */
async function handleStartupFailure(_error) {
    smokeReadiness?.dispose()
    try {
        await autoScanController?.stop()
        trayController?.destroy()
    } catch {
        // Failed desktop cleanup must not prevent native runtime shutdown.
    }
    try {
        if (serviceRuntime !== null) await stopApplicationRuntime()
    } catch {
        // Preserve the sanitized startup diagnostic after best-effort teardown.
    }
    const reason = _error instanceof SmokeReadinessError ? `: ${_error.code}` : ''
    console.error(`Failed to start OpenRDXManager${reason}`)
    startupFailureExit.requestFailure()
}

/** @returns {Promise<void>} Owns the detached Electron startup task and awaits its failure cleanup. */
async function runApplication() {
    try {
        await start()
    } catch (error) {
        await handleStartupFailure(error)
    }
}

void runApplication()
