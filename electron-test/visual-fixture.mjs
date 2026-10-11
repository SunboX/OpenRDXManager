// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { getCatalog } from '../src/locales/catalogs.mjs'
import { englishCatalog } from '../src/locales/en.mjs'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'
import { createRendererIntentAdapter, RendererIntentType } from '../src/renderer/intent-adapter.mjs'
import { createStore } from '../src/renderer/store.mjs'

/** Every bounded renderer intent exercised by the visual-only fixture app. */
const supportedIntents = Object.freeze(Object.values(RendererIntentType))

/** @param {string} state - Visual scene ID. @returns {string} Scene language or English. */
function languageForState(state) {
    const language = state.startsWith('language-') ? state.slice('language-'.length) : 'en'
    return Object.hasOwn({ de: true, en: true, es: true, fr: true, it: true, ja: true, pt: true, zh: true }, language) ? language : 'en'
}

/** @param {object} device - Base screenshot device. @returns {object} Detached no-media snapshot. */
function withoutMedia(device) {
    return { ...device, media: null, mediaState: 'no-media' }
}

/** @param {object} device - Base screenshot device. @returns {object} Detached AES-protected snapshot. */
function protectedDevice(device) {
    return {
        ...device,
        media: {
            ...device.media,
            encrypted: true,
            details: {
                ...device.media.details,
                encrypted: { availability: 'reported', value: true }
            }
        }
    }
}

/**
 * Creates the deterministic state for one feature, risk, locale, or recovery
 * scene. These are renderer fixtures and cannot claim device execution.
 * @param {string} scene - Published visual scene ID.
 * @returns {object} Complete JSON-safe renderer state.
 */
function createSceneState(scene) {
    if (scene === 'no-device') return createFixtureState({ mode: 'no-device' })
    if (scene === 'service-unavailable') return createFixtureState({ mode: 'service-unavailable' })

    const base = createFixtureState({ mode: 'one-device' })
    const language = languageForState(scene)
    const device = ['protected-locked', 'protected-unlocked'].includes(scene) ? protectedDevice(base.devices[0]) : scene === 'ready-no-media' ? withoutMedia(base.devices[0]) : base.devices[0]
    const areaByScene = {
        'critical-active': 'utilities',
        'destructive-active': 'utilities',
        'destructive-preflight': 'utilities',
        'disabled-reasons': 'encryption',
        encryption: 'encryption',
        'operation-failure': 'tests',
        'firmware-power-cycle': 'utilities',
        'operation-success': 'tests',
        'protected-locked': 'encryption',
        'protected-unlocked': 'encryption',
        'routine-active': 'tests',
        tests: 'tests',
        utilities: 'utilities'
    }
    const state = {
        ...base,
        activeArea: areaByScene[scene] ?? 'status',
        devices: [device],
        selectedDeviceId: device.id,
        settings: { ...base.settings, language, updateChecks: false }
    }

    if (scene === 'routine-active') {
        state.activeOperation = {
            cancellationState: 'closed',
            deviceId: device.id,
            deviceRevision: device.revision,
            id: 'op:visual-routine',
            kind: 'self-test',
            progress: 0.5,
            stage: 'diagnostic-running',
            status: 'progress'
        }
    } else if (scene === 'critical-active') {
        state.activeOperation = {
            cancellationState: 'closed',
            deviceId: device.id,
            deviceRevision: device.revision,
            id: 'op:visual-critical',
            kind: 'firmware-update',
            progress: 0.42,
            stage: 'firmware-writing',
            status: 'progress'
        }
    } else if (scene === 'destructive-active') {
        state.activeOperation = {
            cancellationState: 'closed',
            deviceId: device.id,
            deviceRevision: device.revision,
            id: 'op:visual-destructive',
            kind: 'format',
            progress: 0.64,
            stage: 'format-writing',
            status: 'progress'
        }
    } else if (scene === 'operation-success') {
        state.lastOperation = {
            deviceId: device.id,
            deviceRevision: device.revision,
            id: 'op:visual-success',
            kind: 'self-test',
            stage: 'complete',
            status: 'succeeded'
        }
    } else if (scene === 'firmware-power-cycle') {
        state.devices = [withoutMedia(device)]
        state.lastOperation = {
            deviceId: device.id,
            deviceRevision: device.revision,
            error: { category: 'preflight', code: 'firmware-power-cycle-required', messageKey: 'errors.operation.failed', retryable: false, stage: 'firmware-validating', supportCorrelationId: 'support:visual-interlock' },
            id: 'op:visual-interlock',
            kind: 'firmware-update',
            status: 'failed'
        }
    } else if (scene === 'operation-failure') {
        state.lastOperation = {
            deviceId: device.id,
            deviceRevision: device.revision,
            error: {
                category: 'transport',
                code: 'transport-timeout',
                messageKey: 'errors.transport.timeout',
                retryable: true,
                stage: 'diagnostic-running',
                supportCorrelationId: 'support-visual-01'
            },
            id: 'op:visual-failure',
            kind: 'self-test',
            status: 'failed'
        }
    }
    return state
}

/**
 * Creates a protected-media model for the two explicit lock states and lets
 * production projection handle every other scene.
 * @param {string} scene - Published visual scene ID.
 * @returns {object|null} Optional security state provider.
 */
function createSecurityStateProvider(scene) {
    if (!['protected-locked', 'protected-unlocked'].includes(scene)) return null
    return {
        /** @param {object} _state - Renderer state. @param {object} device - Selected device. @param {object|null} workflow - Local workflow. @returns {object} Protected fixture model. */
        getModel(_state, device, workflow) {
            return {
                access: scene === 'protected-unlocked' ? 'enabled' : 'disabled',
                automaticAuthentication: {},
                credentials: [{ name: 'Fixture master', permissions: { manage: true, read: true, write: true }, role: 'master', slot: 0 }],
                device: { drive: device.drive, id: device.id, label: `${device.product} · ${device.media.serial}`, media: device.media, revision: device.revision },
                evidence: { 'disable-access': { state: 'available' }, 'enable-access': { state: 'available' } },
                mode: 'aes',
                resetWithoutPassword: false,
                workflow
            }
        }
    }
}

/** @returns {Promise<void>} Resolves after renderer-owned support promises settle. */
async function waitForFixtureTurn() {
    await Promise.resolve()
    /** @param {() => void} resolve - Turn resolver. @returns {void} Schedules one zero-delay turn. */
    function schedule(resolve) {
        setTimeout(resolve, 0)
    }
    await new Promise(schedule)
}

/** @param {object} appInfo - Settled metadata from the real preload boundary. @returns {object} Deterministic local support API with no file, network, or hardware effects. */
function createSupportApi(appInfo) {
    return {
        app: {
            /** @returns {Promise<object>} Returns bounded fixture metadata. */
            async getInfo() {
                return appInfo
            }
        },
        logs: {
            /** @returns {Promise<object>} Returns one redacted fixture entry. */
            async list() {
                return { entries: [{ id: 'activity:visual', messageKey: 'activity.failure', occurredAt: '2026-08-29T08:30:00.000Z', severity: 'error', supportCorrelationId: 'support:visual' }], ok: true }
            },
            /** @returns {Promise<object>} Refuses test-only export. */
            async export() {
                return { ok: false, reason: 'log-export-unavailable' }
            },
            /** @returns {Promise<object>} Refuses test-only setting changes. */
            async setEnabled() {
                return { ok: false, reason: 'event-log-unavailable' }
            }
        },
        support: {
            /** @returns {Promise<object>} Refuses test-only file creation. */
            async generateSummary() {
                return { ok: false, reason: 'support-service-unavailable' }
            }
        },
        updates: {
            /** @returns {Promise<object>} Returns the explicit offline/unavailable boundary. */
            async check() {
                return { ok: false, reason: 'update-network-failure' }
            }
        }
    }
}

/**
 * Opens the requested local feature surface after the fixture is mounted.
 * @param {string} scene - Published visual scene ID.
 * @returns {Promise<void>} Resolves after asynchronous local panel work settles.
 */
async function openSceneSurface(scene) {
    const actionByScene = { activity: 'open-event-log', compatibility: 'open-compatibility', help: 'open-help', support: 'open-support', 'update-unavailable': 'open-support' }
    const action = actionByScene[scene]
    if (action !== undefined) {
        document.querySelector(`[data-action="${action}"]`).click()
        await waitForFixtureTurn()
    }
    if (scene === 'update-unavailable') {
        document.querySelector('[data-action="check-updates"]').click()
        await waitForFixtureTurn()
    }
    if (scene === 'destructive-preflight') {
        const confirmation = document.querySelector('[data-format-confirmation]')
        confirmation.value = confirmation.dataset.expectedIdentity
        confirmation.dispatchEvent(new InputEvent('input', { bubbles: true }))
        await waitForFixtureTurn()
    }
}

/**
 * Replaces the default service-bound renderer with one deterministic complete
 * feature fixture. This module is imported only by the separate Electron QA
 * entrypoint and is unreachable from production main/preload entrypoints.
 * @param {string} scene - Exact visual scene ID.
 * @returns {Promise<void>} Resolves after the surface is mounted and settled.
 */
export async function mountVisualFixture(scene) {
    // Resolve the real read-only metadata boundary before mounting. Startup and
    // support reads then share settled package metadata rather than racing IPC
    // completions that can reconcile a dialog during an otherwise stable paint.
    const appInfo = (await globalThis.openRdx?.app?.getInfo({})) ?? { ok: false, reason: 'service-unavailable' }
    globalThis.__openRdxVisualFixture?.controller?.destroy()
    const currentRoot = document.querySelector('#app')
    const root = currentRoot.cloneNode(false)
    const calls = []

    /** @param {object} intent - Bounded renderer intent. @returns {boolean} Records the fixture intent. */
    function invoke(intent) {
        calls.push(intent)
        return true
    }

    const language = languageForState(scene)
    const state = createSceneState(scene)
    const utilityController = {
        /** @returns {boolean} Exposes the existing structured fixture boundary. */
        isAvailable() {
            return true
        },
        /** @returns {Promise<object>} Refuses every fixture hardware mutation. */
        async start() {
            return { ok: false, reason: 'hardware-unavailable' }
        }
    }
    currentRoot.replaceWith(root)
    const controller = mountApplication(root, {
        intentAdapter: createRendererIntentAdapter({ supportedIntents, invoke }),
        platform: 'darwin',
        securityStateProvider: createSecurityStateProvider(scene),
        store: createStore(state),
        supportApi: createSupportApi(appInfo),
        translator: createTranslator(getCatalog(language), englishCatalog),
        utilityController
    })
    globalThis.__openRdxVisualFixture = { calls, controller, language, scene }
    await openSceneSurface(scene)
}
