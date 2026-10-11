// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

const defaultDiscoveryTimers = Object.freeze({ setTimeout, clearTimeout })

/**
 * Creates the renderer-owned discovery scheduler around the narrow named Scan
 * method. The scheduler never accepts a path or scan parameter.
 * @param {{service: {scan: (request?: object) => Promise<object>}, store?: {dispatch: (action: object) => object}, intervalMs?: number, manualDebounceMs?: number, timers?: {setTimeout: Function, clearTimeout: Function}}} options - Scan boundary and deterministic scheduling dependencies.
 * @returns {{isAvailable: () => boolean, startAutoScan: () => void, stopAutoScan: () => void, requestManualScan: () => Promise<object>, refreshForOperation: () => Promise<object>, destroy: () => void}} Frozen discovery controller.
 * @throws {TypeError} When the scan or timer contract is unavailable.
 */
export function createDeviceController(options) {
    const service = options?.service
    const store = options?.store ?? null
    const timers = options?.timers ?? defaultDiscoveryTimers
    const intervalMs = options?.intervalMs ?? 1_000
    const manualDebounceMs = options?.manualDebounceMs ?? 250
    if (typeof service?.scan !== 'function' || (store !== null && typeof store?.dispatch !== 'function') || typeof timers?.setTimeout !== 'function' || typeof timers?.clearTimeout !== 'function' || !Number.isInteger(intervalMs) || intervalMs < 1 || intervalMs > 60_000 || !Number.isInteger(manualDebounceMs) || manualDebounceMs < 0 || manualDebounceMs > 5_000) {
        throw new TypeError('Device discovery controller configuration is invalid')
    }

    let autoScanEnabled = false
    let autoTimer = null
    let destroyed = false
    let manualTimer = null
    let pendingManualResolvers = []
    let scanPromise = null

    /** @param {object} action - Bounded renderer discovery action. @returns {void} Dispatches only while active. */
    function publish(action) {
        if (!destroyed) store?.dispatch(action)
    }

    /** @param {unknown} result - Candidate bridge result. @returns {object} Stable safe scan outcome. */
    function normalizeResult(result) {
        return result?.ok === true ? { ok: true } : { ok: false, reason: typeof result?.reason === 'string' && /^[a-z][a-z0-9-]{0,127}$/.test(result.reason) ? result.reason : 'service-failure' }
    }

    /** @param {'auto'|'manual'} trigger - Scan origin. @returns {Promise<object>} Shared in-flight result. */
    function performScan(trigger) {
        if (destroyed) return Promise.resolve({ ok: false, reason: 'service-unavailable' })
        if (store?.getState?.().recoveryLocked === true || store?.getState?.().manufacturingLocked === true) return Promise.resolve({ ok: false, reason: 'operation-in-progress' })
        if (scanPromise !== null) return scanPromise
        publish({ type: 'discovery/scan-started', trigger })

        /** @returns {Promise<object>} Executes and contains the one named bridge call. */
        async function executeScan() {
            let result
            try {
                result = normalizeResult(await service.scan({}))
            } catch {
                result = { ok: false, reason: 'service-failure' }
            }
            if (result.ok) publish({ type: 'discovery/scan-completed', trigger })
            else publish({ type: 'discovery/scan-failed', trigger, reason: result.reason })
            scanPromise = null
            return result
        }

        scanPromise = executeScan()
        return scanPromise
    }

    /** @returns {void} Arms exactly one future automatic scan. */
    function scheduleAutoScan() {
        if (!autoScanEnabled || destroyed || autoTimer !== null) return

        /** @returns {Promise<void>} Runs one timer tick and rearms after completion. */
        async function handleAutoTimer() {
            autoTimer = null
            if (!autoScanEnabled || destroyed) return
            await performScan('auto')
            scheduleAutoScan()
        }

        autoTimer = timers.setTimeout(handleAutoTimer, intervalMs)
    }

    /** @returns {boolean} True while the fixed named Scan method is usable. */
    function isAvailable() {
        return !destroyed
    }

    /** @returns {void} Enables the one-second non-overlapping scheduler idempotently. */
    function startAutoScan() {
        if (destroyed) return
        autoScanEnabled = true
        scheduleAutoScan()
    }

    /** @returns {void} Disables automatic scans without cancelling an admitted scan. */
    function stopAutoScan() {
        autoScanEnabled = false
        if (autoTimer !== null) {
            timers.clearTimeout(autoTimer)
            autoTimer = null
        }
    }

    /** @param {object} result - Shared contained result. @returns {void} Settles every coalesced manual caller. */
    function settleManual(result) {
        const resolvers = pendingManualResolvers
        pendingManualResolvers = []
        for (const resolve of resolvers) resolve(result)
    }

    /** @returns {Promise<object>} Debounces rapid manual requests into one scan. */
    function requestManualScan() {
        if (destroyed) return Promise.resolve({ ok: false, reason: 'service-unavailable' })
        if (manualTimer !== null) timers.clearTimeout(manualTimer)

        /** @param {Function} resolve - Promise resolver retained until the shared scan settles. @returns {void} Stores and rearms the debounce. */
        function queueManual(resolve) {
            pendingManualResolvers.push(resolve)

            /** @returns {Promise<void>} Dispatches the one coalesced manual scan. */
            async function handleManualTimer() {
                manualTimer = null
                settleManual(await performScan('manual'))
            }

            manualTimer = timers.setTimeout(handleManualTimer, manualDebounceMs)
        }

        return new Promise(queueManual)
    }

    /**
     * Settles any scan already in flight, or performs one fresh scan, before a
     * hardware operation reads the selected device revision. The automatic
     * timer is paused across this boundary so it cannot immediately supersede
     * the revision that the operation is about to submit.
     * @returns {Promise<object>} Safe result for the coalesced preflight scan.
     */
    async function refreshForOperation() {
        if (destroyed) return { ok: false, reason: 'service-unavailable' }
        const resumeAutoScan = autoScanEnabled
        stopAutoScan()
        if (manualTimer !== null) {
            timers.clearTimeout(manualTimer)
            manualTimer = null
        }
        const result = await performScan('manual')
        settleManual(result)
        if (resumeAutoScan && !destroyed) startAutoScan()
        return result
    }

    /** @returns {void} Stops timers and settles queued callers without mutating hardware. */
    function destroy() {
        if (destroyed) return
        stopAutoScan()
        destroyed = true
        if (manualTimer !== null) {
            timers.clearTimeout(manualTimer)
            manualTimer = null
        }
        settleManual({ ok: false, reason: 'service-unavailable' })
    }

    return Object.freeze({ isAvailable, startAutoScan, stopAutoScan, requestManualScan, refreshForOperation, destroy })
}
