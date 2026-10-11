// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { OperationKind } from '../shared/contracts.mjs'
import { deviceEventSchema, deviceSnapshotSchema, operationEventSchema, platformCapabilitySchema, privilegedServiceSetupStateSchema, settingsSchema } from '../shared/schemas.mjs'

/**
 * Recursively freezes a renderer-state tree after each transition.
 * @template T
 * @param {T} value - Serializable renderer state to freeze.
 * @returns {T} The deeply frozen state value.
 */
function deepFreeze(value) {
    if (value === null || typeof value !== 'object' || Object.isFrozen(value)) {
        return value
    }

    for (const nestedValue of Object.values(value)) {
        deepFreeze(nestedValue)
    }

    return Object.freeze(value)
}

/**
 * Checks whether a value is a plain object record without a custom prototype.
 * @param {unknown} value - Candidate record value.
 * @returns {boolean} True when the value is a plain object or null-prototype record.
 */
function isPlainRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        return false
    }

    const prototype = Object.getPrototypeOf(value)
    return prototype === Object.prototype || prototype === null
}

/**
 * Verifies that a value can retain its exact renderer meaning across the JSON
 * state boundary. Only null, finite numbers, strings, booleans, dense arrays,
 * and plain data records are accepted; functions, custom objects, accessors,
 * symbols, non-enumerable properties, and circular references are rejected.
 * @param {unknown} value - Candidate data-only value.
 * @param {Set<object>} ancestors - Objects currently traversed for cycle detection.
 * @returns {void} Completes when value is JSON-safe data.
 * @throws {TypeError} When value cannot be represented safely in renderer state.
 */
function assertJsonSafeData(value, ancestors = new Set()) {
    if (value === null || typeof value === 'string' || typeof value === 'boolean') {
        return
    }

    if (typeof value === 'number') {
        if (Number.isFinite(value)) {
            return
        }
        throw new TypeError('Renderer state must contain only JSON-safe data')
    }

    if (typeof value !== 'object' || ancestors.has(value)) {
        throw new TypeError('Renderer state must contain only JSON-safe data')
    }

    if (!Array.isArray(value) && !isPlainRecord(value)) {
        throw new TypeError('Renderer state must contain only JSON-safe data')
    }

    if (Object.getOwnPropertySymbols(value).length > 0) {
        throw new TypeError('Renderer state must contain only JSON-safe data')
    }

    ancestors.add(value)
    try {
        const descriptors = Object.getOwnPropertyDescriptors(value)
        for (const [key, descriptor] of Object.entries(descriptors)) {
            if (Array.isArray(value) && key === 'length') {
                continue
            }

            if (!descriptor.enumerable || !('value' in descriptor)) {
                throw new TypeError('Renderer state must contain only JSON-safe data')
            }

            if (Array.isArray(value) && (!/^(0|[1-9]\d*)$/.test(key) || Number(key) >= value.length)) {
                throw new TypeError('Renderer state must contain only JSON-safe data')
            }

            assertJsonSafeData(descriptor.value, ancestors)
        }

        if (Array.isArray(value) && Object.keys(value).length !== value.length) {
            throw new TypeError('Renderer state must contain only JSON-safe data')
        }
    } finally {
        ancestors.delete(value)
    }
}

/**
 * Checks data-only values without exposing validator exceptions to reducer
 * callers. Invalid actions are rejected as no-op transitions.
 * @param {unknown} value - Candidate action or payload.
 * @returns {boolean} True when the value is JSON-safe data.
 */
function isJsonSafeData(value) {
    try {
        assertJsonSafeData(value)
        return true
    } catch (error) {
        return false
    }
}

/**
 * Creates a detached JSON-equivalent copy for a renderer state boundary.
 * @param {object} state - Initial or transitioned renderer state.
 * @returns {object} A mutable plain-data copy suitable for freezing.
 * @throws {TypeError} When state cannot cross the JSON-safe renderer boundary.
 */
function cloneJsonSafeState(state) {
    if (!isPlainRecord(state)) {
        throw new TypeError('Renderer state must contain only JSON-safe data')
    }

    assertJsonSafeData(state)
    return JSON.parse(JSON.stringify(state))
}

/**
 * Finds a device in current state by its opaque renderer-visible identifier.
 * @param {object} state - Current renderer state.
 * @param {unknown} deviceId - Candidate opaque device identifier.
 * @returns {object|null} Matching device snapshot, or null when absent.
 */
function findDevice(state, deviceId) {
    if (typeof deviceId !== 'string') {
        return null
    }

    for (const device of state.devices) {
        if (device.id === deviceId) {
            return device
        }
    }

    return null
}

/** @param {object} state - Current renderer state. @param {number} epoch - Event epoch. @param {number} listRevision - Event list revision. @returns {boolean} True for a strictly newer event in the current epoch. */
function isNewDiscoveryEvent(state, epoch, listRevision) {
    return state.service.status === 'ready' && Number.isSafeInteger(epoch) && Number.isSafeInteger(listRevision) && epoch === state.discovery.epoch && listRevision > state.discovery.listRevision
}

/** @param {object} tombstones - Existing revision tombstones. @param {string} deviceId - Device ID. @param {number} revision - Removed revision. @returns {object} Updated detached tombstones. */
function withTombstone(tombstones, deviceId, revision) {
    return { ...tombstones, [deviceId]: Math.max(tombstones[deviceId] ?? -1, revision) }
}

/** @param {object[]} devices - Current full device snapshots. @returns {object} Complete default accounting when a legacy event has no diagnostics. */
function defaultDiscoveryDiagnostics(devices) {
    return { candidateCount: devices.length, acceptedCount: devices.length, rejections: [] }
}

/** @param {object} state - Current state. @param {object[]} devices - Replacement devices. @returns {object} Sessions still bound to the exact same identity revision. */
function retainCurrentAuthenticationSessions(state, devices) {
    const sessions = {}
    const currentSessions = state.authenticationSessions ?? {}
    for (const device of devices) {
        const session = currentSessions[device.id]
        if (session?.deviceRevision === device.revision) sessions[device.id] = session
    }
    return sessions
}

/** @param {object} discovery - Current discovery state. @param {string} [failure] - Optional latest safe failure. @returns {object} Idle state without undefined JSON properties. */
function finishDiscoveryScan(discovery, failure = undefined) {
    const { trigger: _trigger, lastFailure: _lastFailure, ...stable } = discovery
    return { ...stable, scanStatus: 'idle', ...(failure === undefined ? {} : { lastFailure: failure }) }
}

/**
 * Checks whether a value is a public high-level operation kind.
 * @param {unknown} kind - Candidate operation kind.
 * @returns {boolean} True when the kind is published by the shared contract.
 */
function isKnownOperationKind(kind) {
    return typeof kind === 'string' && Object.values(OperationKind).includes(kind)
}

/**
 * Checks the bounded opaque identifier shape shared with the Electron contract.
 * @param {unknown} value - Candidate operation identifier.
 * @returns {boolean} True when value is a bounded opaque identifier.
 */
function isBoundedIdentifier(value) {
    return typeof value === 'string' && /^[a-z][a-z0-9:-]*$/i.test(value) && value.length <= 64
}

/**
 * Checks that an operation event belongs to the exact active identity owner.
 * @param {object} activeOperation - Current renderer lock.
 * @param {object} event - Strict operation event.
 * @returns {boolean} True only when ID, kind, device, and revision all match.
 */
function operationEventMatches(activeOperation, event) {
    return activeOperation !== null && event.operationId === activeOperation.id && event.kind === activeOperation.kind && event.deviceId === activeOperation.deviceId && event.deviceRevision === activeOperation.deviceRevision
}

/**
 * Converts a strict operation event into the renderer's compact lock model.
 * @param {object} event - Strict queued or started operation event.
 * @returns {object} Renderer active-operation record.
 */
function createActiveOperation(event) {
    return {
        id: event.operationId,
        kind: event.kind,
        deviceId: event.deviceId,
        deviceRevision: event.deviceRevision,
        status: event.state,
        stage: event.stage
    }
}

/**
 * Applies a single immutable renderer-state transition. Invalid, stale, or
 * unsafe actions are ignored so renderer events cannot violate the operation
 * lock or inject unmodelled state.
 * @param {object} state - Current frozen renderer state.
 * @param {object} action - Data-only transition request.
 * @returns {object} The next state, or the current state when rejected.
 */
function reduceState(state, action) {
    if (!isPlainRecord(action) || !isJsonSafeData(action)) {
        return state
    }

    switch (action.type) {
        case 'manufacturing/lock':
            return typeof action.locked === 'boolean' ? { ...state, manufacturingLocked: action.locked } : state
        case 'recovery/lock':
            return typeof action.locked === 'boolean' ? { ...state, recoveryLocked: action.locked } : state
        case 'service/setup': {
            if (!isPlainRecord(action.setup)) return state
            const parsedState = privilegedServiceSetupStateSchema.safeParse(action.setup.state)
            if (!parsedState.success || (action.setup.reason !== undefined && (typeof action.setup.reason !== 'string' || !/^[a-z][a-z0-9-]{0,127}$/.test(action.setup.reason))) || !['state', ...(action.setup.reason === undefined ? [] : ['reason'])].every((key) => Object.hasOwn(action.setup, key)) || Object.keys(action.setup).length > (action.setup.reason === undefined ? 1 : 2)) return state
            return { ...state, privilegedServiceSetup: { state: parsedState.data, ...(action.setup.reason === undefined ? {} : { reason: action.setup.reason }) } }
        }
        case 'service/ready':
            if (!Number.isSafeInteger(action.epoch) || action.epoch <= 0 || !Number.isSafeInteger(action.listRevision) || action.listRevision < 0 || !['native', 'no-device'].includes(action.mode) || typeof action.privileged !== 'boolean' || typeof action.hardwareReady !== 'boolean' || typeof action.hardwareVerified !== 'boolean') {
                return state
            }
            const parsedCapability = platformCapabilitySchema.safeParse(action.platformCapability)
            if (!parsedCapability.success) return state
            if (action.epoch < state.discovery.epoch) {
                return state
            }
            return {
                ...state,
                service: { status: 'ready', mode: action.mode, privileged: action.privileged, hardwareReady: action.hardwareReady, hardwareVerified: action.hardwareVerified, platformCapability: parsedCapability.data },
                discovery: action.epoch === state.discovery.epoch ? state.discovery : { epoch: action.epoch, listRevision: -1, tombstones: {}, diagnostics: defaultDiscoveryDiagnostics([]), scanStatus: 'idle', selectionInitialized: false },
                ...(action.epoch === state.discovery.epoch ? {} : { devices: [], selectedDeviceId: null, authenticationSessions: {} })
            }
        case 'service/status':
            if (!['starting', 'restarting', 'recovering', 'reconciling'].includes(action.status)) {
                return state
            }
            return { ...state, service: { status: action.status }, devices: [], selectedDeviceId: null, authenticationSessions: {}, discovery: { ...state.discovery, scanStatus: 'idle' } }
        case 'service/unavailable':
            if (typeof action.reason !== 'string' || !/^[a-z][a-z0-9-]{0,127}$/.test(action.reason)) {
                return state
            }
            return { ...state, service: { status: 'unavailable', reason: action.reason }, devices: [], selectedDeviceId: null, authenticationSessions: {}, discovery: { ...state.discovery, scanStatus: 'idle' } }
        case 'device/list-replaced': {
            const parsedEvent = deviceEventSchema.safeParse({ type: 'list', devices: action.devices, epoch: action.epoch, listRevision: action.listRevision, ...(action.diagnostics === undefined ? {} : { diagnostics: action.diagnostics }) })
            if (!parsedEvent.success || !isNewDiscoveryEvent(state, parsedEvent.data.epoch, parsedEvent.data.listRevision)) {
                return state
            }
            const devices = parsedEvent.data.devices
            let tombstones = { ...state.discovery.tombstones }
            const incomingIds = new Set()
            for (const device of devices) {
                incomingIds.add(device.id)
            }
            for (const current of state.devices) {
                if (!incomingIds.has(current.id)) {
                    tombstones = withTombstone(tombstones, current.id, current.revision)
                }
            }
            for (const device of devices) {
                const current = findDevice(state, device.id)
                if ((current !== null && device.revision < current.revision) || device.revision <= (tombstones[device.id] ?? -1)) {
                    return state
                }
            }
            const selectedExists = findDevice({ ...state, devices }, state.selectedDeviceId) !== null
            const selectedDeviceId = selectedExists ? state.selectedDeviceId : state.selectedDeviceId === null && state.discovery.selectionInitialized !== true ? (devices[0]?.id ?? null) : null
            return {
                ...state,
                devices,
                selectedDeviceId,
                authenticationSessions: retainCurrentAuthenticationSessions(state, devices),
                discovery: { ...state.discovery, epoch: parsedEvent.data.epoch, listRevision: parsedEvent.data.listRevision, tombstones, diagnostics: parsedEvent.data.diagnostics ?? defaultDiscoveryDiagnostics(devices), selectionInitialized: state.discovery.selectionInitialized === true || devices.length > 0 }
            }
        }
        case 'device/snapshot': {
            const parsedEvent = deviceEventSchema.safeParse({ type: 'snapshot', device: action.device, epoch: action.epoch, listRevision: action.listRevision })
            if (!parsedEvent.success || !isNewDiscoveryEvent(state, parsedEvent.data.epoch, parsedEvent.data.listRevision)) {
                return state
            }
            const currentDevice = findDevice(state, parsedEvent.data.device.id)
            if ((currentDevice !== null && parsedEvent.data.device.revision < currentDevice.revision) || parsedEvent.data.device.revision <= (state.discovery.tombstones[parsedEvent.data.device.id] ?? -1)) {
                return state
            }
            const devices = []
            if (currentDevice === null) {
                devices.push(...state.devices, parsedEvent.data.device)
            } else {
                for (const device of state.devices) {
                    devices.push(device.id === parsedEvent.data.device.id ? parsedEvent.data.device : device)
                }
            }
            const selectedDeviceId = state.selectedDeviceId ?? (state.discovery.selectionInitialized === true ? null : parsedEvent.data.device.id)
            return { ...state, devices, selectedDeviceId, authenticationSessions: retainCurrentAuthenticationSessions(state, devices), discovery: { ...state.discovery, listRevision: parsedEvent.data.listRevision, selectionInitialized: true } }
        }
        case 'device/removed': {
            const parsedEvent = deviceEventSchema.safeParse({ type: 'removed', deviceId: action.deviceId, deviceRevision: action.deviceRevision, epoch: action.epoch, listRevision: action.listRevision })
            if (!parsedEvent.success || !isNewDiscoveryEvent(state, parsedEvent.data.epoch, parsedEvent.data.listRevision)) {
                return state
            }
            const currentDevice = findDevice(state, parsedEvent.data.deviceId)
            if ((currentDevice !== null && parsedEvent.data.deviceRevision < currentDevice.revision) || parsedEvent.data.deviceRevision < (state.discovery.tombstones[parsedEvent.data.deviceId] ?? -1)) {
                return state
            }
            const devices = []
            for (const device of state.devices) {
                if (device.id !== parsedEvent.data.deviceId) {
                    devices.push(device)
                }
            }
            const selectedDeviceId = state.selectedDeviceId === parsedEvent.data.deviceId ? null : state.selectedDeviceId
            return {
                ...state,
                devices,
                selectedDeviceId,
                authenticationSessions: retainCurrentAuthenticationSessions(state, devices),
                discovery: {
                    ...state.discovery,
                    listRevision: parsedEvent.data.listRevision,
                    tombstones: withTombstone(state.discovery.tombstones, parsedEvent.data.deviceId, parsedEvent.data.deviceRevision),
                    selectionInitialized: state.discovery.selectionInitialized === true || state.selectedDeviceId === parsedEvent.data.deviceId
                }
            }
        }
        case 'discovery/scan-started': {
            if (state.service.status !== 'ready' || state.activeOperation !== null || state.manufacturingLocked === true || !['auto', 'manual'].includes(action.trigger) || state.discovery.scanStatus === 'scanning') return state
            const { lastFailure: _lastFailure, ...discovery } = state.discovery
            return { ...state, discovery: { ...discovery, scanStatus: 'scanning', trigger: action.trigger } }
        }
        case 'discovery/scan-completed':
            if (state.discovery.scanStatus !== 'scanning' || action.trigger !== state.discovery.trigger) return state
            return { ...state, discovery: finishDiscoveryScan(state.discovery) }
        case 'discovery/scan-failed':
            if (state.discovery.scanStatus !== 'scanning' || action.trigger !== state.discovery.trigger || typeof action.reason !== 'string' || !/^[a-z][a-z0-9-]{0,127}$/.test(action.reason)) return state
            return { ...state, discovery: finishDiscoveryScan(state.discovery, action.reason) }
        case 'authentication/session-established': {
            const device = findDevice(state, action.deviceId)
            if (device === null || device.revision !== action.deviceRevision || !isBoundedIdentifier(action.sessionId)) return state
            return { ...state, authenticationSessions: { ...(state.authenticationSessions ?? {}), [device.id]: { sessionId: action.sessionId, deviceRevision: device.revision } } }
        }
        case 'operation/event': {
            const parsedEvent = operationEventSchema.safeParse(action.event)
            if (!parsedEvent.success) {
                return state
            }
            const event = parsedEvent.data
            if (event.state === 'queued' || event.state === 'started') {
                const device = findDevice(state, event.deviceId)
                if (device === null || device.revision !== event.deviceRevision) {
                    return state
                }
                if (state.activeOperation !== null && !operationEventMatches(state.activeOperation, event)) {
                    return state
                }
                return { ...state, activeOperation: createActiveOperation(event), lastOperation: null }
            }
            if (!operationEventMatches(state.activeOperation, event)) {
                return state
            }
            if (event.state === 'progress') {
                return {
                    ...state,
                    activeOperation: { ...state.activeOperation, status: 'progress', stage: event.stage, progress: event.progress, cancellationState: event.cancellationState }
                }
            }
            if (event.state === 'failed') {
                return {
                    ...state,
                    activeOperation: null,
                    lastOperation: { ...state.activeOperation, status: 'failed', error: event.error }
                }
            }
            return {
                ...state,
                activeOperation: null,
                lastOperation: { ...state.activeOperation, status: event.state, stage: event.stage, ...(event.reason === undefined ? {} : { reason: event.reason }) }
            }
        }
        case 'setting/auto-scan-changed':
            if (state.activeOperation !== null || state.manufacturingLocked === true || typeof action.enabled !== 'boolean') {
                return state
            }
            return { ...state, settings: { ...state.settings, autoScan: action.enabled } }
        case 'settings/changed': {
            const parsedSettings = settingsSchema.safeParse(action.settings)
            if (!parsedSettings.success) return state
            return { ...state, settings: parsedSettings.data }
        }
        case 'device/refreshed': {
            const parsedDevice = deviceSnapshotSchema.safeParse(action.device)
            if (!parsedDevice.success) {
                return state
            }

            const currentDevice = findDevice(state, parsedDevice.data.id)
            if (currentDevice === null || parsedDevice.data.revision < currentDevice.revision) {
                return state
            }

            const devices = []
            for (const device of state.devices) {
                devices.push(device.id === parsedDevice.data.id ? parsedDevice.data : device)
            }
            return { ...state, devices }
        }
        case 'device/select':
            // A selection is part of an operation's identity and stays fixed
            // until the active operation reaches a terminal state.
            if (state.activeOperation !== null || state.manufacturingLocked === true || findDevice(state, action.deviceId) === null) {
                return state
            }
            return { ...state, selectedDeviceId: action.deviceId, discovery: { ...state.discovery, selectionInitialized: true } }
        case 'operation/started': {
            const selectedDevice = findDevice(state, state.selectedDeviceId)
            if (state.activeOperation !== null || state.manufacturingLocked === true || selectedDevice === null || !isBoundedIdentifier(action.operationId) || !isKnownOperationKind(action.kind)) {
                return state
            }
            return {
                ...state,
                activeOperation: {
                    id: action.operationId,
                    kind: action.kind,
                    deviceId: selectedDevice.id,
                    deviceRevision: selectedDevice.revision,
                    status: 'started'
                },
                lastOperation: null
            }
        }
        case 'operation/succeeded':
            if (state.activeOperation === null || !isBoundedIdentifier(action.operationId) || action.operationId !== state.activeOperation.id) {
                return state
            }
            return {
                ...state,
                activeOperation: null,
                lastOperation: { ...state.activeOperation, status: 'succeeded' }
            }
        case 'operation/progress':
            if (state.activeOperation === null || !isBoundedIdentifier(action.operationId) || action.operationId !== state.activeOperation.id || !isBoundedIdentifier(action.stage) || typeof action.progress !== 'number' || !Number.isFinite(action.progress) || action.progress < 0 || action.progress > 1 || !['cancellable', 'requested', 'closed'].includes(action.cancellationState)) {
                return state
            }
            return {
                ...state,
                activeOperation: {
                    ...state.activeOperation,
                    status: 'progress',
                    stage: action.stage,
                    progress: action.progress,
                    cancellationState: action.cancellationState
                }
            }
        default:
            return state
    }
}

/**
 * Creates the renderer's small immutable state store. Subscription callbacks
 * receive only frozen snapshots after accepted state transitions.
 * @param {object} initialState - Serializable initial renderer state.
 * @returns {{getState: () => object, dispatch: (action: object) => object, subscribe: (listener: (state: object) => void) => () => void}} Store API.
 */
export function createStore(initialState) {
    let state = deepFreeze(cloneJsonSafeState(initialState))
    const listeners = new Set()

    /**
     * Reads the current immutable renderer state.
     * @returns {object} Current frozen state snapshot.
     */
    function getState() {
        return state
    }

    /**
     * Applies an action and synchronously informs subscribers on accepted
     * transitions only.
     * @param {object} action - Data-only state transition request.
     * @returns {object} The resulting frozen state snapshot.
     */
    function dispatch(action) {
        const nextState = reduceState(state, action)
        if (nextState === state) {
            return state
        }

        state = deepFreeze(cloneJsonSafeState(nextState))
        for (const listener of listeners) {
            listener(state)
        }
        return state
    }

    /**
     * Registers a synchronous listener for accepted store transitions.
     * @param {(state: object) => void} listener - State observer callback.
     * @returns {() => void} Removes this listener; repeated calls are safe.
     * @throws {TypeError} When listener is not callable.
     */
    function subscribe(listener) {
        if (typeof listener !== 'function') {
            throw new TypeError('Store listener must be a function')
        }

        listeners.add(listener)
        let subscribed = true

        /**
         * Removes this callback from the store without changing application
         * state. Calling it more than once has no additional effect.
         * @returns {void} Completes after the callback is removed.
         */
        function unsubscribe() {
            if (subscribed) {
                listeners.delete(listener)
                subscribed = false
            }
        }

        return unsubscribe
    }

    return Object.freeze({ getState, dispatch, subscribe })
}
