// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { recoveryListResponseSchema, recoveryStatusResponseSchema } from '../shared/recovery-schemas.mjs'

/** Keeps recovery presentation and the global renderer lock aligned with native snapshots. */
export class RecoveryController {
    #api
    #store
    #render
    #timers
    #timer = null
    #destroyed = false
    #service = null
    #epoch = null
    #scanState = null
    #listPending = false
    #statusPending = false
    #uncertain = false
    #generation = 0
    #acceptedGeneration = -1
    #consumedContinuation = null
    #view = { available: false, hydrated: false, loading: false, pending: false, targets: [], bundles: [], bundleId: '', targetToken: '', acknowledged: false, status: { state: 'idle', revision: 0 }, reason: null }

    /** @param {object|undefined} api - Closed preload methods. @param {object} store - Global renderer state. @param {Function} render - Refreshes presentation. @param {object} timers - Injectable bounded poll scheduler. */
    constructor(api, store, render, timers = globalThis) {
        this.#api = api
        this.#store = store
        this.#render = render
        this.#timers = timers
        this.#view.available = ['list', 'status', 'start', 'continue'].every((method) => typeof api?.[method] === 'function')
    }

    /** @returns {object} Presentation state; tokens are submitted only through exact named actions. */
    getView() {
        return { ...this.#view, visible: this.#view.targets.length > 0 || this.#view.status.state !== 'idle' || this.#view.pending || this.#uncertain, locked: this.#locked(), continuationConsumed: this.#consumedContinuation === this.#view.status.attemptId, operationBusy: this.#store.getState().activeOperation !== null || this.#store.getState().manufacturingLocked === true }
    }

    /** @param {object} state - Current main-service projection. @returns {void} Hydrates on startup and each newly ready service generation. */
    observe(state) {
        const newlyReady = state.service.status === 'ready' && (this.#service !== 'ready' || this.#epoch !== state.discovery?.epoch)
        const scanCompleted = this.#scanState === 'scanning' && state.discovery?.scanStatus === 'idle'
        this.#service = state.service.status
        this.#epoch = state.discovery?.epoch
        this.#scanState = state.discovery?.scanStatus
        if (this.#view.available && newlyReady) {
            this.#generation += 1
            this.#listPending = false
            this.#statusPending = false
            this.#uncertain ||= this.#view.pending
            this.#view.pending = false
            void this.refresh()
        } else if (this.#view.available && state.service.status === 'ready' && scanCompleted && !this.#locked() && !this.#view.bundleId && !this.#view.targetToken && !this.#view.acknowledged && state.activeOperation === null) {
            // Normal Scan discovers newly connected ROM loaders, but never rotates
            // an inventory token while the operator is associating a saved profile.
            void this.refresh()
        }
    }

    /** @returns {boolean} Only known or uncertain mutation ownership locks ordinary operations. */
    #locked() {
        return this.#view.available && (this.#view.pending || this.#uncertain || this.#view.status.state === 'running')
    }

    /** @returns {void} Publishes only the global lock marker; native status remains authoritative. */
    #changed() {
        if (this.#destroyed) return
        const locked = this.#locked()
        if (this.#store.getState().recoveryLocked !== locked) this.#store.dispatch({ type: 'recovery/lock', locked })
        else this.#render()
    }

    /** @param {object} status - Strict native snapshot. @param {number} generation - Request's service epoch. @returns {boolean} Rejects stale replies and revisions without reopening consumed gates. */
    #acceptStatus(status, generation) {
        if (generation !== this.#generation) return false
        const previous = this.#view.status
        if (this.#acceptedGeneration === generation) {
            if (previous.attemptId === status.attemptId && status.revision < previous.revision) return false
            if (previous.state === 'running' && status.state === 'idle') return false
        }
        if (this.#acceptedGeneration !== generation || previous.attemptId !== status.attemptId) this.#consumedContinuation = null
        this.#acceptedGeneration = generation
        if (['succeeded', 'failed'].includes(status.state) && (previous.state === 'running' || this.#view.pending)) {
            this.#view.bundleId = ''
            this.#view.targetToken = ''
            this.#view.acknowledged = false
        }
        this.#view.status = status
        this.#view.hydrated = true
        this.#uncertain = false
        this.#view.reason = null
        return true
    }

    /** @returns {void} Arms only a status read, never inventory refresh or a mutation retry. */
    #schedule() {
        if (this.#destroyed || this.#timer !== null || !this.#locked()) return
        this.#timer = this.#timers.setTimeout(async () => {
            this.#timer = null
            await this.poll()
        }, 1000)
    }

    /** @returns {Promise<void>} Refreshes explicit selections and saved data, without selecting either automatically. */
    async refresh() {
        if (this.#destroyed || !this.#view.available || this.#listPending || this.#view.pending) return
        this.#listPending = true
        const generation = this.#generation
        this.#view.loading = true
        this.#changed()
        try {
            const parsed = recoveryListResponseSchema.safeParse(await this.#api.list({}))
            if (this.#destroyed || generation !== this.#generation) return
            if (!parsed.success || !parsed.data.ok) {
                this.#view.reason = parsed.success ? parsed.data.reason : 'invalid-service-response'
                this.#view.hydrated = true
                return
            }
            this.#view.targets = parsed.data.targets
            this.#view.bundles = parsed.data.bundles
            this.#view.targetToken = ''
            this.#view.bundleId = ''
            this.#view.acknowledged = false
            this.#acceptStatus(parsed.data.status, generation)
        } catch {
            if (generation === this.#generation) {
                this.#view.reason = 'service-unavailable'
                this.#view.hydrated = true
            }
        } finally {
            if (generation === this.#generation) {
                this.#listPending = false
                this.#view.loading = false
                this.#changed()
                this.#schedule()
            }
        }
    }

    /** @returns {Promise<void>} Restores progress and consumed acknowledgement after reload, without refreshing tokens. */
    async poll() {
        if (this.#destroyed || !this.#view.available || this.#statusPending) return
        this.#statusPending = true
        const generation = this.#generation
        try {
            const parsed = recoveryStatusResponseSchema.safeParse(await this.#api.status({}))
            if (this.#destroyed || generation !== this.#generation) return
            if (parsed.success && parsed.data.ok) this.#acceptStatus(parsed.data.status, generation)
            else this.#view.reason = parsed.success ? parsed.data.reason : 'invalid-service-response'
        } catch {
            if (generation === this.#generation) this.#view.reason = 'service-unavailable'
        } finally {
            if (generation === this.#generation) {
                this.#statusPending = false
                this.#changed()
                this.#schedule()
            }
        }
    }

    /** @param {string} field - Closed form field. @param {string|boolean} value - Explicit operator selection. @returns {void} Changes only local form state. */
    select(field, value) {
        if (this.#locked() || this.#view.loading || this.#destroyed) return
        if (field === 'bundle' && this.#view.bundles.some((bundle) => bundle.bundleId === value)) this.#view.bundleId = value
        else if (field === 'target' && this.#view.targets.some((target) => target.token === value)) this.#view.targetToken = value
        else if (field === 'acknowledged' && typeof value === 'boolean') this.#view.acknowledged = value
        else return
        if (field !== 'acknowledged') this.#view.acknowledged = false
        this.#changed()
    }

    /** @param {'start'|'continue'} action - Explicit operator button. @returns {Promise<void>} Submits once and reconciles uncertainty only through status. */
    async submit(action) {
        if (this.#destroyed || !this.#view.available || this.#view.pending || !this.#view.hydrated || this.#uncertain) return
        let request
        if (action === 'start') {
            if (this.#locked() || this.#view.loading || this.#store.getState().activeOperation !== null || this.#store.getState().manufacturingLocked === true || !this.#view.acknowledged || !this.#view.bundles.some((bundle) => bundle.bundleId === this.#view.bundleId) || !this.#view.targets.some((target) => target.token === this.#view.targetToken)) return
            request = { bundleId: this.#view.bundleId, targetToken: this.#view.targetToken, acknowledged: true }
        } else if (action === 'continue') {
            const status = this.#view.status
            if (status.state !== 'running' || status.stage !== 'recovery-awaiting-power-cycle' || !status.awaitingAcknowledgment || this.#consumedContinuation === status.attemptId) return
            request = { attemptId: status.attemptId, stage: status.stage, acknowledged: true }
            this.#consumedContinuation = status.attemptId
        } else return
        this.#view.pending = true
        const generation = this.#generation
        this.#changed()
        try {
            const parsed = recoveryStatusResponseSchema.safeParse(await this.#api[action](request))
            if (this.#destroyed || generation !== this.#generation) return
            if (parsed.success && parsed.data.ok) this.#acceptStatus(parsed.data.status, generation)
            else {
                this.#view.reason = parsed.success ? parsed.data.reason : 'invalid-service-response'
                this.#uncertain = !parsed.success || ['recovery-outcome-unknown', 'operation-outcome-unknown', 'service-unavailable', 'service-request-timeout'].includes(parsed.data.reason)
                if (!this.#uncertain && action === 'continue') this.#consumedContinuation = null
            }
        } catch {
            if (generation === this.#generation) {
                this.#view.reason = 'service-unavailable'
                this.#uncertain = true
            }
        } finally {
            if (generation === this.#generation) {
                this.#view.pending = false
                this.#changed()
                this.#schedule()
            }
        }
    }

    /** @returns {void} Stops renderer polling without cancelling or releasing native recovery. */
    destroy() {
        this.#destroyed = true
        if (this.#timer !== null) this.#timers.clearTimeout(this.#timer)
        this.#timer = null
    }
}
