// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { manufacturingResponseSchema } from '../shared/manufacturing-schemas.mjs'

const UNCERTAIN_REASONS = new Set(['service-unavailable', 'service-request-timeout', 'service-response-timeout', 'operation-outcome-unknown', 'manufacturing-outcome-unknown', 'invalid-service-response'])

/** Owns one manufacturing submission and target-bound, path-free backup selections. */
export class ManufacturingController {
    #api
    #store
    #render
    #destroyed = false
    #generation = 0
    #context = null
    #targetContext = null
    #acceptedGeneration = -1
    #refreshNeeded = false
    #listGeneration = null
    #listPending = false
    #requestedRefresh = null
    #queuedBackup = null
    #pending = false
    #uncertain = false
    #openingFolder = false
    #folderError = null
    #view

    /** @param {object|undefined} api - Closed preload manufacturing methods. @param {object} store - Renderer state and operation locks. @param {Function} render - Refreshes the current shell. */
    constructor(api, store, render) {
        this.#api = api
        this.#store = store
        this.#render = render
        this.#view = { available: ['list', 'backup', 'restore'].every((method) => typeof api?.[method] === 'function'), hydrated: false, loading: false, page: 0, hasMore: false, backups: [], backupId: '', confirmationSerial: '', acknowledged: false, allowIdentityChange: false, supportKnown: false, backupSupported: false, restoreSupported: false, reason: null, result: null }
    }

    /** @returns {object|null} Current selected, validated renderer snapshot. */
    #device() {
        const state = this.#store.getState()
        return state.devices.find((device) => device.id === state.selectedDeviceId) ?? null
    }

    /** @param {boolean} [editing=false] - Local form editing may continue during discovery; device requests must wait. @returns {boolean} Admission state excluding this controller's own mutation lock. */
    #ready(editing = false) {
        const state = this.#store.getState()
        return state.service.status === 'ready' && state.activeOperation === null && state.recoveryLocked !== true && (editing || state.discovery?.scanStatus !== 'scanning') && this.#device() !== null
    }

    /** @returns {object} Safe form state plus current admission decisions; never includes record bytes or paths. */
    getView() {
        const device = this.#device()
        const selected = this.#view.backups.find((backup) => backup.backupId === this.#view.backupId && backup.state === 'valid')
        const locked = this.#pending || this.#uncertain || this.#queuedBackup !== null
        // Disabling a live select closes its native popup. Discovery only blocks
        // device commands; changed device revisions still consume confirmations.
        const editable = this.#ready(true) && !locked && !this.#view.loading && this.#view.hydrated && device?.mediaState === 'no-media'
        const ready = editable && this.#ready() && this.#acceptedGeneration === this.#generation && this.#listGeneration === null
        const identityChangeRequired = selected !== undefined && (selected.deviceId !== device?.id || selected.serial !== device?.serial)
        // Backup clicks can wait for discovery and support revalidation. Restore
        // retains its strict fresh-generation gate and explicit confirmation.
        return { ...this.#view, locked, pending: this.#pending || this.#queuedBackup !== null, uncertain: this.#uncertain, device, identityChangeRequired, restoreSerial: selected?.serial ?? '', openingFolder: this.#openingFolder, folderError: this.#folderError, openFolderDisabled: this.#openingFolder || typeof this.#api?.openFolder !== 'function', formDisabled: !editable, refreshDisabled: !this.#ready(true) || this.#pending || this.#queuedBackup !== null || this.#requestedRefresh !== null || !this.#view.hydrated, canBackup: editable && this.#view.backupSupported, canRestore: ready && this.#view.restoreSupported && selected !== undefined && typeof selected.serial === 'string' && selected.serial === this.#view.confirmationSerial && this.#view.acknowledged && (!identityChangeRequired || this.#view.allowIdentityChange) }
    }

    /** @returns {Promise<void>} Opens the backup directory without taking a hardware lock or changing restore consent. */
    async openFolder() {
        if (this.#destroyed || this.getView().openFolderDisabled) return
        this.#openingFolder = true
        this.#folderError = null
        this.#changed()
        try {
            const result = await this.#api.openFolder()
            if (result?.ok !== true) this.#folderError = 'open'
        } catch {
            this.#folderError = 'open'
        } finally {
            this.#openingFolder = false
            this.#changed()
        }
    }

    /** @returns {void} Publishes only this controller's independent lock marker. */
    #changed() {
        if (this.#destroyed) return
        const locked = this.#pending || this.#uncertain || this.#queuedBackup !== null
        if (this.#store.getState().manufacturingLocked !== locked) this.#store.dispatch({ type: 'manufacturing/lock', locked })
        else this.#render()
    }

    /** @returns {void} Consumes all prior target confirmations after target, backup, or operation changes. */
    #clearConfirmation() {
        this.#view.backupId = ''
        this.#view.confirmationSerial = ''
        this.#view.acknowledged = false
        this.#view.allowIdentityChange = false
    }

    /** @returns {string} Binds a queued read-only backup to one unchanged empty receiver. */
    #backupBinding() {
        const state = this.#store.getState()
        const device = this.#device()
        return JSON.stringify([device?.id, device?.vendor, device?.product, device?.serial, device?.mediaState, device?.media === null, device?.drive?.details?.firmwareRevision, device?.drive?.firmwareRevision, state.service.status, state.discovery?.epoch])
    }

    /** @returns {void} Releases an unsubmitted backup ticket after its target changes. */
    #cancelQueuedBackup() {
        this.#queuedBackup?.resolve()
        this.#queuedBackup = null
    }

    /** @param {object} state - Current renderer state. @returns {void} Invalidates late replies and confirms each newly selected device generation independently. */
    observe(state) {
        if (this.#destroyed || !this.#view.available) return
        const device = state.devices.find((candidate) => candidate.id === state.selectedDeviceId)
        const context = JSON.stringify([device?.id, device?.revision, state.service.status, state.discovery?.epoch])
        if (context === this.#context) {
            // A snapshot may arrive before discovery releases its scan lease.
            // Revalidate once it finishes instead of waiting for another revision.
            this.#startRefresh()
            return
        }
        const targetContext = JSON.stringify([device?.id, device?.serial, state.service.status, state.discovery?.epoch])
        const targetChanged = targetContext !== this.#targetContext
        if (this.#queuedBackup !== null && this.#queuedBackup.binding !== this.#backupBinding()) this.#cancelQueuedBackup()
        if (targetChanged) this.#cancelRefresh()
        this.#targetContext = targetContext
        this.#context = context
        this.#generation += 1
        this.#refreshNeeded = true
        this.#listGeneration = null
        this.#clearConfirmation()
        // Numeric revisions include routine status changes. Keep settled content
        // for the same dock, but never let its cached support authorize a write.
        if (targetChanged) Object.assign(this.#view, { hydrated: false, loading: false, page: 0, hasMore: false, backups: [], supportKnown: false, backupSupported: false, restoreSupported: false, reason: null, result: null })
        else Object.assign(this.#view, { loading: this.#requestedRefresh !== null })
        // A revision/connection change cannot release ownership of a submitted
        // native call. Only its reply or a later service list can reconcile it.
        this.#startRefresh()
        this.#changed()
    }

    /** @param {object} response - Schema-validated inventory. @param {number} requestedPage - Explicit list page, defaulting to the newest page for mutation replies. @returns {void} Accepts metadata without choosing a backup on the operator's behalf. */
    #accept(response, requestedPage = 0) {
        this.#view.page = response.page ?? requestedPage
        this.#view.hasMore = response.hasMore === true
        this.#view.backups = [...response.backups].sort((left, right) => right.createdAt - left.createdAt).slice(0, 128)
        this.#view.backupSupported = response.backupSupported
        this.#view.restoreSupported = response.restoreSupported
        this.#view.supportKnown = true
        this.#acceptedGeneration = this.#generation
        this.#view.hydrated = true
        this.#view.reason = null
        this.#clearConfirmation()
    }

    /** @returns {void} Resolves an abandoned explicit request when its target changes or presentation closes. */
    #cancelRefresh() {
        this.#requestedRefresh?.resolve()
        this.#requestedRefresh = null
    }

    /** @returns {void} Starts one admitted read, giving the operator's queued request priority over automatic revalidation. */
    #startRefresh() {
        if (this.#destroyed || this.#listPending || this.#pending || !this.#ready()) return
        if (this.#requestedRefresh !== null || this.#refreshNeeded) void this.#readInventory(this.#requestedRefresh)
        else if (this.#queuedBackup !== null) void this.#completeQueuedBackup()
    }

    /** @returns {Promise<void>} Submits a queued backup once fresh inventory and discovery settle. */
    async #completeQueuedBackup() {
        const ticket = this.#queuedBackup
        if (ticket === null) return
        this.#queuedBackup = null
        try {
            if (ticket.binding !== this.#backupBinding() || this.#acceptedGeneration !== this.#generation || !this.#view.backupSupported) return
            await this.#performSubmit('backup')
        } finally {
            ticket.resolve()
            this.#changed()
        }
    }

    /** @param {number} page - Bounded explicit page, defaulting to the visible page. @returns {Promise<void>} Queues one explicit refresh until discovery and any prior inventory release their leases. */
    async refresh(page = this.#view.page) {
        if (this.#destroyed || !this.#view.available || this.getView().refreshDisabled || !Number.isInteger(page) || page < 0 || page > 31 || (this.#uncertain && page !== this.#view.page)) return
        const request = { ...Promise.withResolvers(), page }
        // Latch before rendering or awaiting: repeated clicks cannot enqueue
        // duplicate native reads, even while automatic discovery owns the dock.
        this.#requestedRefresh = request
        this.#view.loading = true
        this.#clearConfirmation()
        this.#changed()
        this.#startRefresh()
        await request.promise
    }

    /** @param {object|null} request - Explicit refresh ticket, or null for automatic revalidation. @returns {Promise<void>} Serializes native reads and accepts only replies for the current device generation. */
    async #readInventory(request) {
        const page = request?.page ?? this.#view.page
        const device = this.#device()
        const generation = this.#generation
        this.#listPending = true
        this.#listGeneration = generation
        this.#refreshNeeded = false
        this.#acceptedGeneration = -1
        this.#view.loading = request !== null || !this.#view.hydrated
        this.#clearConfirmation()
        this.#changed()
        try {
            const parsed = manufacturingResponseSchema.safeParse(await this.#api.list({ deviceId: device.id, deviceRevision: device.revision, ...(page === 0 ? {} : { page }) }))
            if (this.#destroyed || generation !== this.#generation) return
            if (parsed.success && parsed.data.ok) {
                this.#accept(parsed.data, page)
                this.#uncertain = false
            } else {
                Object.assign(this.#view, { supportKnown: false, backupSupported: false, restoreSupported: false })
                this.#view.reason = parsed.success ? parsed.data.reason : 'invalid-service-response'
                // A new renderer must recover a native mutation's existing
                // ownership even when it never observed the original submit.
                this.#uncertain ||= ['manufacturing-outcome-unknown', 'operation-outcome-unknown'].includes(this.#view.reason)
            }
        } catch {
            if (generation === this.#generation) Object.assign(this.#view, { reason: 'service-unavailable', supportKnown: false, backupSupported: false, restoreSupported: false })
        } finally {
            // Revision invalidation does not release a still-running native
            // read. Its completion alone makes room for the queued request.
            this.#listPending = false
            if (generation === this.#generation) {
                this.#listGeneration = null
                if (request !== null && this.#requestedRefresh === request) this.#cancelRefresh()
                this.#view.loading = this.#requestedRefresh !== null
                this.#view.hydrated = true
            }
            this.#startRefresh()
            this.#changed()
        }
    }

    /** @param {'previous'|'next'} direction - Explicit page action. @returns {Promise<void>} Reads another bounded page and consumes every confirmation. */
    async navigate(direction) {
        const view = this.getView()
        if (view.locked || view.refreshDisabled) return
        if (direction === 'previous' && view.page > 0) await this.refresh(view.page - 1)
        else if (direction === 'next' && view.hasMore && view.page < 31) await this.refresh(view.page + 1)
    }

    /** @param {string} field - Closed manufacturing field. @param {string|boolean} value - Explicit local form input. @returns {void} Retains only valid metadata selections and bounded confirmation text. */
    select(field, value) {
        if (this.#destroyed || this.getView().formDisabled) return
        if (field === 'backup') {
            this.#clearConfirmation()
            if (this.#view.backups.some((backup) => backup.backupId === value && backup.state === 'valid' && typeof backup.serial === 'string')) this.#view.backupId = value
        } else if (field === 'confirmationSerial' && typeof value === 'string') this.#view.confirmationSerial = value.slice(0, 64)
        else if (field === 'acknowledged' && typeof value === 'boolean') this.#view.acknowledged = value
        else if (field === 'allowIdentityChange' && typeof value === 'boolean' && this.getView().identityChangeRequired) this.#view.allowIdentityChange = value
        else return
        this.#view.result = null
        this.#changed()
    }

    /** @param {'backup'|'restore'} action - Explicit operator action. @returns {Promise<void>} Queues read-only backup through background discovery; restores still require immediate fresh consent. */
    async submit(action) {
        if (action !== 'backup') return this.#performSubmit(action)
        if (this.#destroyed || !this.getView().canBackup) return
        const ticket = { ...Promise.withResolvers(), binding: this.#backupBinding() }
        this.#queuedBackup = ticket
        this.#view.result = null
        this.#view.reason = null
        this.#clearConfirmation()
        this.#changed()
        this.#startRefresh()
        await ticket.promise
    }

    /** @param {'backup'|'restore'} action - Admitted explicit action. @returns {Promise<void>} Sends one exact request and retains uncertainty after transport failure or revision drift. */
    async #performSubmit(action) {
        const view = this.getView()
        if (this.#destroyed || !view.available || !((action === 'backup' && view.canBackup) || (action === 'restore' && view.canRestore))) return
        const device = this.#device()
        const generation = this.#generation
        const request = { deviceId: device.id, deviceRevision: device.revision, ...(action === 'restore' ? { backupId: view.backupId, confirmationSerial: view.confirmationSerial, acknowledged: true, ...(view.identityChangeRequired && view.allowIdentityChange ? { allowIdentityChange: true } : {}) } : {}) }
        this.#pending = true
        this.#view.result = null
        this.#view.reason = null
        this.#clearConfirmation()
        this.#changed()
        try {
            const parsed = manufacturingResponseSchema.safeParse(await this.#api[action](request))
            if (this.#destroyed) return
            if (generation !== this.#generation) {
                this.#uncertain = true
                return
            }
            if (parsed.success && parsed.data.ok) {
                this.#accept(parsed.data)
                this.#view.result = action
            } else {
                this.#view.reason = parsed.success ? parsed.data.reason : 'invalid-service-response'
                this.#uncertain = !parsed.success || UNCERTAIN_REASONS.has(parsed.data.reason)
            }
        } catch {
            this.#uncertain = true
            if (generation === this.#generation) this.#view.reason = 'service-unavailable'
        } finally {
            this.#pending = false
            this.#changed()
        }
    }

    /** @returns {void} Detaches presentation without cancelling a native operation or clearing its global lock. */
    destroy() {
        this.#destroyed = true
        this.#cancelRefresh()
        this.#cancelQueuedBackup()
    }
}
