// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

/** Returns whether a selected device is currently safe-eject ready. @param {object} device - Strict device snapshot. @returns {boolean} True only for ready media and available capability. */
function canSafelyEject(device) {
    const status = device?.media?.details?.status
    const ready = device?.media !== null && (device?.media?.status === 'ready' || (status?.availability === 'reported' && status.value === 'ready'))
    return ready && device?.capabilities?.['eject-safe']?.state === 'available'
}

/** Owns one coalesced non-overlapping main-process scan scheduler. */
export class AutoScanController {
    #afterScan
    #enabled = false
    #epoch = 0
    #inFlight = null
    #intervalMs
    #scan
    #timer = null
    #timers

    /** @param {{scan: () => Promise<object>, afterScan?: (result: object) => Promise<void>|void, intervalMs?: number, timers?: {setTimeout: Function, clearTimeout: Function}}} options - Scan action and timer surface. */
    constructor(options) {
        const intervalMs = options?.intervalMs ?? 1_000
        const timers = options?.timers ?? { setTimeout: globalThis.setTimeout, clearTimeout: globalThis.clearTimeout }
        if (typeof options?.scan !== 'function' || !Number.isInteger(intervalMs) || intervalMs < 250 || intervalMs > 60_000 || typeof timers.setTimeout !== 'function' || typeof timers.clearTimeout !== 'function') throw new TypeError('AutoScanController configuration is invalid')
        this.#scan = options.scan
        this.#afterScan = options.afterScan ?? (() => {})
        this.#intervalMs = intervalMs
        this.#timers = timers
    }

    /** @returns {void} Starts the one-second scheduler idempotently. */
    start() {
        this.#enabled = true
        this.#schedule()
    }

    /** @returns {boolean} True only when future automatic scan ticks are enabled. */
    isRunning() {
        return this.#enabled
    }

    /** @returns {Promise<void>} Stops polling, invalidates publication, and settles after admitted work. */
    async stop() {
        this.#enabled = false
        this.#epoch += 1
        if (this.#timer !== null) {
            this.#timers.clearTimeout(this.#timer)
            this.#timer = null
        }
        await this.#inFlight?.promise
    }

    /** @returns {Promise<object>} Shared current scan result. */
    scanNow() {
        if (this.#inFlight !== null) return this.#inFlight.promise
        const epoch = this.#epoch
        const record = { epoch, promise: null }

        /** @returns {Promise<object>} Contains the named scan and rearms after settlement. */
        async function perform() {
            try {
                const result = await this.#scan()
                if (record.epoch !== this.#epoch) return { ok: false, reason: 'scan-invalidated' }
                const normalized = result?.ok === true ? { ok: true } : { ok: false, reason: typeof result?.reason === 'string' ? result.reason : 'service-failure' }
                await this.#afterScan(normalized)
                return normalized
            } catch {
                return record.epoch === this.#epoch ? { ok: false, reason: 'service-failure' } : { ok: false, reason: 'scan-invalidated' }
            } finally {
                if (this.#inFlight === record) this.#inFlight = null
                this.#schedule()
            }
        }
        record.promise = perform.call(this)
        this.#inFlight = record
        return record.promise
    }

    /** @returns {void} Arms one timer only after prior work has settled. */
    #schedule() {
        if (!this.#enabled || this.#timer !== null || this.#inFlight !== null) return

        /** @returns {void} Starts one due scan. */
        const handleTimer = () => {
            this.#timer = null
            void this.scanNow()
        }
        this.#timer = this.#timers.setTimeout(handleTimer, this.#intervalMs)
    }
}

/** Owns application tray presentation and named main-process actions. */
export class TrayController {
    #Menu
    #actions
    #destroyed = false
    #state = { devices: [], loggingEnabled: true, selectedDeviceId: null, serviceStatus: 'starting' }
    #tray
    #translate

    /** @param {{Tray: Function, Menu: {buildFromTemplate: Function}, icon: unknown, actions: {open: Function, scan: Function, startOperation: Function, setLogging: Function, exit: Function}, translate?: (key: string, params?: object) => string}} options - Electron tray types and bounded actions. */
    constructor(options) {
        const actions = options?.actions
        if (typeof options?.Tray !== 'function' || typeof options?.Menu?.buildFromTemplate !== 'function' || ['open', 'scan', 'startOperation', 'setLogging', 'exit'].some((name) => typeof actions?.[name] !== 'function')) throw new TypeError('TrayController configuration is invalid')
        this.#Menu = options.Menu
        this.#actions = actions
        this.#translate = options.translate ?? ((key) => key)
        this.#tray = new options.Tray(options.icon)
        this.#render()
    }

    /** @param {{devices: object[], selectedDeviceId: string|null, serviceStatus: string, loggingEnabled: boolean}} state - Complete current safe tray state. @returns {void} Rebuilds native menu. */
    update(state) {
        if (!Array.isArray(state?.devices) || !(state.selectedDeviceId === null || typeof state.selectedDeviceId === 'string') || typeof state.serviceStatus !== 'string' || typeof state.loggingEnabled !== 'boolean') return
        this.#state = { devices: [...state.devices], loggingEnabled: state.loggingEnabled, selectedDeviceId: state.selectedDeviceId, serviceStatus: state.serviceStatus }
        this.#render()
    }

    /** @param {(key: string, params?: object) => string} translate - Active locale translator. @returns {boolean} Whether the menu was rebuilt. */
    setTranslator(translate) {
        if (typeof translate !== 'function') return false
        this.#translate = translate
        this.#render()
        return true
    }

    /** @returns {void} Releases the native tray resource. */
    destroy() {
        if (this.#destroyed) return
        this.#destroyed = true
        this.#tray.destroy()
    }

    /** @returns {object|null} Exact selected device only when selection is unambiguous. */
    #selectedDevice() {
        if (this.#state.selectedDeviceId === null) return null
        const selected = this.#state.devices.filter((device) => device?.id === this.#state.selectedDeviceId)
        return selected.length === 1 ? selected[0] : null
    }

    /** @param {string} name - Fixed native menu action name. @param {...unknown} args - Action-specific arguments. @returns {Promise<unknown>} Action result or a stable failure; Electron does not observe rejected menu promises. */
    async #runAction(name, ...args) {
        try {
            return await this.#actions[name](...args)
        } catch {
            return { ok: false, reason: 'service-failure' }
        }
    }

    /** @returns {void} Rebuilds the bounded menu from current state. */
    #render() {
        if (this.#destroyed) return
        const device = this.#selectedDevice()
        const t = this.#translate
        const statusKey = this.#state.serviceStatus === 'suspended' ? 'tray.status.suspended' : `service.${this.#state.serviceStatus}`
        const translatedStatus = t(statusKey)
        const localizedStatus = translatedStatus === `[${statusKey}]` ? this.#state.serviceStatus : translatedStatus
        const summary = t('tray.summary', { count: this.#state.devices.length, status: localizedStatus })

        /** @returns {Promise<object>} Starts exact safe eject for the captured ready identity. */
        const eject = async () => (device === null ? { ok: false, reason: 'device-not-selected' } : this.#runAction('startOperation', { kind: 'eject-safe', deviceId: device.id, deviceRevision: device.revision }))

        /** @returns {Promise<object>} Toggles logging through the persisted main-owned action. */
        const toggleLogging = async () => this.#runAction('setLogging', !this.#state.loggingEnabled)

        const template = [{ id: 'summary', label: summary, enabled: false }, { id: 'open', label: t('tray.open'), click: this.#runAction.bind(this, 'open') }, { id: 'scan', label: t('tray.scan'), click: this.#runAction.bind(this, 'scan') }, { id: 'safe-eject', label: t('tray.safeEject', { device: device?.product ?? t('devices.noneSelected') }), enabled: device !== null && canSafelyEject(device), click: eject }, { type: 'separator' }, { id: 'logging', label: t('tray.logging'), type: 'checkbox', checked: this.#state.loggingEnabled, click: toggleLogging }, { type: 'separator' }, { id: 'exit', label: t('tray.exit'), click: this.#runAction.bind(this, 'exit') }]
        this.#tray.setToolTip(summary)
        this.#tray.setContextMenu(this.#Menu.buildFromTemplate(template))
    }
}

/** Coordinates suspend/resume invalidation and operation-safe window close. */
export class DesktopLifecycleController {
    #getShutdownPolicy
    #invalidateSessions
    #refresh
    #requestQuit
    #scanner
    #resumePolling = true
    #suspendBarrier = Promise.resolve()
    #warnUnsafeClose
    #warningPromise = null

    /** @param {{scanner: {start: Function, stop: Function}, invalidateSessions: Function, refresh: Function, getShutdownPolicy?: Function, requestQuit?: Function, warnUnsafeClose?: Function}} options - Owned lifecycle dependencies. */
    constructor(options) {
        if (typeof options?.scanner?.start !== 'function' || typeof options?.scanner?.stop !== 'function' || typeof options?.invalidateSessions !== 'function' || typeof options?.refresh !== 'function') throw new TypeError('DesktopLifecycleController configuration is invalid')
        this.#scanner = options.scanner
        this.#invalidateSessions = options.invalidateSessions
        this.#refresh = options.refresh
        this.#getShutdownPolicy = options.getShutdownPolicy ?? (() => ({ allowed: true }))
        this.#requestQuit = options.requestQuit ?? (() => {})
        this.#warnUnsafeClose = options.warnUnsafeClose ?? (async () => {})
    }

    /** @returns {Promise<void>} Stops polling and invalidates stale UI sessions without ejecting. */
    async onSuspend() {
        this.#resumePolling = typeof this.#scanner.isRunning === 'function' ? this.#scanner.isRunning() : true
        this.#suspendBarrier = (async () => {
            await this.#scanner.stop()
            await this.#invalidateSessions()
        })()
        await this.#suspendBarrier
    }

    /** @returns {Promise<void>} Restarts polling and immediately refreshes current state. */
    async onResume() {
        await this.#suspendBarrier
        if (this.#resumePolling) this.#scanner.start()
        await this.#refresh()
    }

    /** @param {{preventDefault: Function}} event - Electron close event. @returns {boolean} True only when close is currently safe. */
    handleWindowClose(event) {
        let allowed = false
        try {
            allowed = this.#getShutdownPolicy().allowed === true
        } catch {
            allowed = false
        }
        if (allowed) return true
        event.preventDefault()
        if (this.#warningPromise === null) {
            this.#warningPromise = this.#showWarning()
        }
        return false
    }

    /** @returns {boolean} Requests application exit only when no unsafe operation owns the coordinator. */
    requestExit() {
        let allowed = false
        try {
            allowed = this.#getShutdownPolicy().allowed === true
        } catch {
            allowed = false
        }
        if (allowed) {
            this.#requestQuit()
            return true
        }
        if (this.#warningPromise === null) {
            this.#warningPromise = this.#showWarning()
        }
        return false
    }

    /** @returns {Promise<void>} Resolves after any currently displayed warning. */
    async waitForWarning() {
        await this.#warningPromise
    }

    /** @returns {Promise<void>} Contains dialog failures and releases the single warning owner for the next close attempt. */
    async #showWarning() {
        // Publish the warning owner before invoking a synchronous or reentrant dialog.
        await Promise.resolve()
        try {
            await this.#warnUnsafeClose()
        } catch {
            // The synchronous close guard still protects the active operation.
        } finally {
            this.#warningPromise = null
        }
    }
}
