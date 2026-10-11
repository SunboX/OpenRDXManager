// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { deviceEventSchema, deviceListResponseSchema, operationEventSchema, privilegedServiceSetupResponseSchema, settingsResponseSchema, settingsSchema } from '../shared/schemas.mjs'

/**
 * Creates the non-fixture renderer state used by the real Electron runtime.
 * It begins with no claimed service or hardware readiness.
 * @returns {object} Serializable empty runtime state.
 */
export function createRuntimeState() {
    return Object.freeze({
        provenance: 'service',
        service: Object.freeze({ status: 'starting' }),
        privilegedServiceSetup: Object.freeze({ state: 'not-applicable' }),
        discovery: Object.freeze({ epoch: 0, listRevision: -1, tombstones: Object.freeze({}), diagnostics: Object.freeze({ candidateCount: 0, acceptedCount: 0, rejections: Object.freeze([]) }), scanStatus: 'idle' }),
        devices: Object.freeze([]),
        selectedDeviceId: null,
        activeArea: 'status',
        settings: Object.freeze({ autoScan: true, eventLogging: true, language: 'en', lastSafeView: 'status', updateChecks: true }),
        activeOperation: null,
        authenticationSessions: Object.freeze({}),
        lastOperation: null,
        activity: Object.freeze([])
    })
}

/**
 * Maps one strict service/discovery event to a renderer store action.
 * @param {object} store - Renderer state store.
 * @param {unknown} event - Candidate device/service event.
 * @returns {boolean} True when a strict event was dispatched.
 */
function dispatchDeviceEvent(store, event) {
    const parsedEvent = deviceEventSchema.safeParse(event)
    if (!parsedEvent.success) {
        return false
    }
    const safeEvent = parsedEvent.data
    switch (safeEvent.type) {
        case 'service':
            if (safeEvent.status === 'ready') {
                store.dispatch({ type: 'service/ready', epoch: safeEvent.epoch, hardwareReady: safeEvent.hardwareReady, hardwareVerified: safeEvent.hardwareVerified, listRevision: safeEvent.listRevision, mode: safeEvent.mode, platformCapability: safeEvent.platformCapability, privileged: safeEvent.privileged })
            } else if (safeEvent.status === 'unavailable') {
                store.dispatch({ type: 'service/unavailable', reason: safeEvent.reason })
            } else {
                store.dispatch({ type: 'service/status', status: safeEvent.status })
            }
            break
        case 'list':
            store.dispatch({ type: 'device/list-replaced', devices: safeEvent.devices, ...(safeEvent.diagnostics === undefined ? {} : { diagnostics: safeEvent.diagnostics }), epoch: safeEvent.epoch, listRevision: safeEvent.listRevision })
            break
        case 'snapshot':
            store.dispatch({ type: 'device/snapshot', device: safeEvent.device, epoch: safeEvent.epoch, listRevision: safeEvent.listRevision })
            break
        case 'removed':
            store.dispatch({ type: 'device/removed', deviceId: safeEvent.deviceId, deviceRevision: safeEvent.deviceRevision, epoch: safeEvent.epoch, listRevision: safeEvent.listRevision })
            break
    }
    return true
}

/**
 * Maps one strict operation event through the store's identity/revision guard.
 * @param {object} store - Renderer state store.
 * @param {unknown} event - Candidate operation event.
 * @returns {boolean} True when a strict event was dispatched.
 */
function dispatchOperationEvent(store, event) {
    const parsedEvent = operationEventSchema.safeParse(event)
    if (!parsedEvent.success) {
        return false
    }
    store.dispatch({ type: 'operation/event', event: parsedEvent.data })
    return true
}

/**
 * Connects the frozen named preload subscriptions and initial device list to
 * the real renderer store without introducing fixture or hardware claims.
 * @param {unknown} api - Candidate frozen `window.openRdx` API.
 * @param {{dispatch: Function}} store - Renderer state store.
 * @returns {{ready: Promise<void>, destroy: () => void}} Binding readiness and cleanup.
 */
export function bindOpenRdxStore(api, store) {
    if (typeof store?.dispatch !== 'function') {
        throw new TypeError('Service binding requires a renderer store')
    }
    const unsubscribers = []
    let destroyed = false
    let subscriptionsReady = true

    /** @param {unknown} settings - Candidate pushed settings snapshot. @returns {boolean} Whether strict settings were applied. */
    function handleSettingsEvent(settings) {
        const parsed = settingsSchema.safeParse(settings)
        if (!parsed.success || destroyed) return false
        store.dispatch({ type: 'settings/changed', settings: parsed.data })
        return true
    }

    /**
     * Receives one already preload-validated device/service event.
     * @param {object} event - Renderer-safe event.
     * @returns {void} Completes after guarded dispatch.
     */
    function handleDeviceEvent(event) {
        if (!destroyed && subscriptionsReady) {
            dispatchDeviceEvent(store, event)
        }
    }

    /**
     * Receives one already preload-validated operation event.
     * @param {object} event - Renderer-safe event.
     * @returns {void} Completes after guarded dispatch.
     */
    function handleOperationEvent(event) {
        if (!destroyed && subscriptionsReady) {
            dispatchOperationEvent(store, event)
        }
    }

    try {
        if (typeof api?.devices?.subscribe === 'function') {
            const unsubscribe = api.devices.subscribe(handleDeviceEvent)
            if (typeof unsubscribe === 'function') {
                unsubscribers.push(unsubscribe)
            } else {
                subscriptionsReady = false
            }
        } else subscriptionsReady = false
        if (typeof api?.operations?.subscribe === 'function') {
            const unsubscribe = api.operations.subscribe(handleOperationEvent)
            if (typeof unsubscribe === 'function') {
                unsubscribers.push(unsubscribe)
            } else {
                subscriptionsReady = false
            }
        } else subscriptionsReady = false
        if (typeof api?.settings?.subscribe === 'function') {
            const unsubscribe = api.settings.subscribe(handleSettingsEvent)
            if (typeof unsubscribe === 'function') unsubscribers.push(unsubscribe)
        }
    } catch {
        subscriptionsReady = false
        store.dispatch({ type: 'service/unavailable', reason: 'service-unavailable' })
    }

    /**
     * Loads the initial strict device list and establishes ready versus unavailable state.
     * @returns {Promise<void>} Resolves after the initial state is truthful.
     */
    async function loadInitialDevices() {
        if (!subscriptionsReady) {
            store.dispatch({ type: 'service/unavailable', reason: 'service-unavailable' })
            return
        }
        if (typeof api?.devices?.list !== 'function') {
            store.dispatch({ type: 'service/unavailable', reason: 'service-unavailable' })
            return
        }
        let response
        try {
            response = await api.devices.list({})
        } catch {
            response = { ok: false, reason: 'service-unavailable' }
        }
        if (destroyed) {
            return
        }
        const parsedResponse = deviceListResponseSchema.safeParse(response)
        if (!parsedResponse.success || parsedResponse.data.ok === false) {
            const reason = parsedResponse.success ? parsedResponse.data.reason : 'invalid-service-response'
            store.dispatch({ type: 'service/unavailable', reason })
            return
        }
        store.dispatch({ type: 'service/ready', epoch: parsedResponse.data.epoch, hardwareReady: parsedResponse.data.hardwareReady, hardwareVerified: parsedResponse.data.hardwareVerified, listRevision: parsedResponse.data.listRevision, mode: parsedResponse.data.mode, platformCapability: parsedResponse.data.platformCapability, privileged: parsedResponse.data.privileged })
        store.dispatch({ type: 'device/list-replaced', devices: parsedResponse.data.devices, ...(parsedResponse.data.diagnostics === undefined ? {} : { diagnostics: parsedResponse.data.diagnostics }), epoch: parsedResponse.data.epoch, listRevision: parsedResponse.data.listRevision })
    }

    /** @returns {Promise<void>} Hydrates persisted settings through the strict preload response. */
    async function loadInitialSettings() {
        if (typeof api?.settings?.get !== 'function') return
        let response
        try {
            response = await api.settings.get({})
        } catch {
            return
        }
        if (destroyed) return
        const parsed = settingsResponseSchema.safeParse(response)
        if (parsed.success && parsed.data.ok === true) store.dispatch({ type: 'settings/changed', settings: parsed.data.settings })
    }

    /** @returns {Promise<void>} Hydrates the closed privileged-service setup state. */
    async function loadPrivilegedServiceSetup() {
        if (typeof api?.service?.getSetup !== 'function') return
        let response
        try {
            response = await api.service.getSetup({})
        } catch {
            return
        }
        if (destroyed) return
        const parsed = privilegedServiceSetupResponseSchema.safeParse(response)
        if (parsed.success && parsed.data.ok === true) store.dispatch({ type: 'service/setup', setup: { state: parsed.data.state, ...(parsed.data.reason === undefined ? {} : { reason: parsed.data.reason }) } })
    }

    /** @returns {Promise<void>} Resolves when all independent initial snapshots have settled. */
    async function loadInitialState() {
        await Promise.all([loadInitialDevices(), loadInitialSettings(), loadPrivilegedServiceSetup()])
    }
    const ready = loadInitialState()

    /**
     * Detaches every preload listener without mutating renderer state.
     * @returns {void} Completes after idempotent cleanup.
     */
    function destroy() {
        if (destroyed) {
            return
        }
        destroyed = true
        for (const unsubscribe of unsubscribers) {
            try {
                unsubscribe()
            } catch {
                // A broken isolated-world callback cannot block remaining cleanup.
            }
        }
        unsubscribers.length = 0
    }

    return Object.freeze({ ready, destroy })
}
