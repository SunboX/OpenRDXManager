// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import test from 'node:test'

import { JSDOM } from 'jsdom'

import { HELP_TOPICS, findHelpTopic } from '../src/help/help-index.mjs'
import { registerIpcHandlers } from '../src/main/ipc-controller.mjs'
import { createSupportRuntimeServices } from '../src/main/support-runtime.mjs'
import * as supportRuntimeModule from '../src/main/support-runtime.mjs'
import { SupportSummaryService } from '../src/main/support-summary-service.mjs'
import { UpdateService, serializeUpdatePayload } from '../src/main/update-service.mjs'
import { createPreloadApi } from '../src/preload-api.mjs'
import { mountApplication } from '../src/renderer/app-controller.mjs'
import { createFixtureState } from '../src/renderer/fixture-state.mjs'
import { createTranslator } from '../src/renderer/i18n.mjs'
import { createStore } from '../src/renderer/store.mjs'
import { renderActivityView } from '../src/renderer/views/activity-view.mjs'
import { renderHelpView } from '../src/renderer/views/help-view.mjs'
import { englishCatalog } from '../src/locales/en.mjs'

const translateEnglish = createTranslator(englishCatalog, englishCatalog)

/** @returns {{dom: JSDOM, document: Document}} Isolated local renderer document. */
function createDom() {
    const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'file:///openrdxmanager/src/index.html' })
    return { dom, document: dom.window.document }
}

/** @returns {object} Device fixture containing supported fields plus forbidden secrets. */
function summaryFixtureWithSecrets() {
    return {
        application: { name: 'OpenRDXManager', version: '1.4.0' },
        generatedAt: '2026-08-28T08:30:00.000Z',
        host: { architecture: 'arm64', platform: 'darwin', release: '25.6.0' },
        service: { hardwareReady: false, mode: 'no-device', status: 'ready' },
        devices: [
            {
                id: 'rdx:summary-one',
                password: 'do-not-render',
                derivedKey: '00ff',
                authorizationBlob: [1, 2, 3],
                product: 'RDX QuikStor USB3+ External',
                revision: 4,
                serial: '7810544062',
                vendor: 'TANDBERG',
                drive: {
                    firmwareRevision: '0283',
                    connectionType: 'USB 3',
                    operationMode: 'Removable Disk'
                },
                media: {
                    capacityBytes: 1_000_000_000,
                    encrypted: true,
                    filesystem: 'exfat',
                    label: 'RDX Cartridge',
                    status: 'ready',
                    writable: true
                }
            }
        ]
    }
}

/** @param {object} payload - Unsigned manifest payload. @param {import('node:crypto').KeyObject} privateKey - Test-only signing key. @returns {string} Signed manifest JSON. */
function signedManifest(payload, privateKey) {
    const signature = sign(null, Buffer.from(serializeUpdatePayload(payload), 'utf8'), privateKey).toString('base64')
    return JSON.stringify({ ...payload, signature })
}

/** @returns {Promise<void>} Lets renderer-owned promise handlers settle. */
async function settleRenderer() {
    await new Promise((resolve) => setTimeout(resolve, 0))
}

test('support summary omits secrets and preserves documented device fields', async () => {
    const service = new SupportSummaryService()
    const text = await service.generate(summaryFixtureWithSecrets())

    assert.doesNotMatch(text, /password|derivedKey|authorizationBlob|do-not-render|00ff/i)
    assert.match(text, /Firmware revision: 0283/)
    assert.match(text, /Connection type: USB 3/)
    assert.match(text, /Protection state: Encrypted/)
    assert.match(text, /Devices discovered: 1/)
})

test('summary save uses the documented filename and returns the selected destination', async () => {
    const writes = []
    const service = new SupportSummaryService({
        /** @returns {Promise<object>} Supplies current main-owned summary inputs. */
        async collect() {
            return summaryFixtureWithSecrets()
        },
        /** @param {string} defaultName - Requested documented filename. @returns {Promise<object>} Controlled save choice. */
        async chooseDestination(defaultName) {
            assert.equal(defaultName, 'RdxSystemSummary.txt')
            return { canceled: false, filePath: '/safe/RdxSystemSummary.txt' }
        },
        /** @param {string} filePath - Main-owned destination. @param {string} text - Sanitized summary. @returns {Promise<void>} Records the write. */
        async writeText(filePath, text) {
            writes.push({ filePath, text })
        }
    })

    const result = await service.generateSummary()

    assert.deepEqual(result, { ok: true, savedPath: '/safe/RdxSystemSummary.txt', deviceCount: 1 })
    assert.equal(writes.length, 1)
    assert.doesNotMatch(writes[0].text, /do-not-render/)
})

test('activity export saves only bounded redacted fields under the documented local name', async () => {
    const writes = []
    const service = new SupportSummaryService({
        /** @param {string} defaultName - Requested activity filename. @returns {Promise<object>} Controlled destination. */
        async chooseDestination(defaultName) {
            assert.equal(defaultName, 'RDXManagerActivity.txt')
            return { canceled: false, filePath: '/safe/RDXManagerActivity.txt' }
        },
        /** @param {string} filePath - Main-owned path. @param {string} text - Safe export. @returns {Promise<void>} Records it. */
        async writeText(filePath, text) {
            writes.push({ filePath, text })
        }
    })
    const logger = {
        /** @returns {Promise<object>} Mirrors EventLogger renderer-safe list output. */
        async list() {
            return { ok: true, entries: [{ id: 'activity:1', occurredAt: '2026-08-28T08:00:00.000Z', severity: 'error', messageKey: 'activity.failure', supportCorrelationId: 'support:22' }] }
        }
    }

    assert.deepEqual(await service.exportActivity(logger), { ok: true, savedPath: '/safe/RDXManagerActivity.txt' })
    assert.match(writes[0].text, /activity\.failure.*support:22/)
    assert.doesNotMatch(writes[0].text, /password|token|path/i)
})

test('support runtime aggregates the current service snapshot and exposes no upload method', async () => {
    const writes = []
    const destinations = []
    const logger = {
        /** @returns {Promise<object>} Returns renderer-safe local activity. */
        async list() {
            return { ok: true, entries: [] }
        },
        /** @returns {Promise<object>} Accepts a bounded logging state. */
        async setEnabled() {
            return { ok: true }
        }
    }
    const runtime = {
        client: {
            /** @returns {Promise<object>} Returns the current discovered devices. */
            async list() {
                return { ok: true, devices: summaryFixtureWithSecrets().devices }
            }
        },
        /** @returns {object} Returns current service state. */
        getReadiness() {
            return { hardwareReady: false, hardwareVerified: false, mode: 'no-device', status: 'ready' }
        },
        logger
    }
    const services = createSupportRuntimeServices({
        application: { getName: () => 'OpenRDXManager', getVersion: () => '1.4.0' },
        /** @param {object} options - Main-owned save dialog options. @returns {Promise<object>} Controlled choice. */
        async chooseDestination(options) {
            destinations.push(options)
            return { canceled: false, filePath: `/safe/${options.defaultPath}` }
        },
        host: { architecture: () => 'arm64', platform: () => 'darwin', release: () => '25.6.0' },
        runtime,
        translate: (key) => `localized:${key}`,
        /** @param {string} filePath - Chosen path. @param {string} text - Sanitized content. @returns {Promise<void>} Records it. */
        async writeText(filePath, text) {
            writes.push({ filePath, text })
        }
    })

    const result = await services.support.generateSummary({})

    assert.equal(result.ok, true)
    assert.equal(result.deviceCount, 1)
    assert.match(writes[0].text, /Firmware revision: 0283/)
    assert.deepEqual(await services.logs.export(), { ok: true, savedPath: '/safe/RDXManagerActivity.txt' })
    assert.deepEqual(destinations, [
        {
            buttonLabel: 'localized:filePicker.save',
            defaultPath: 'RdxSystemSummary.txt',
            title: 'localized:filePicker.supportSummary.title'
        },
        {
            buttonLabel: 'localized:filePicker.save',
            defaultPath: 'RDXManagerActivity.txt',
            title: 'localized:filePicker.activityExport.title'
        }
    ])
    assert.deepEqual(Object.keys(services).sort(), ['automationSupport', 'logs', 'support', 'updates'])
    assert.equal('upload' in services.support, false)
})

test('support runtime delegates logging changes through the durable desktop setting boundary', async () => {
    const calls = []
    const runtime = {
        client: {
            /** @returns {Promise<object>} Returns an empty current snapshot. */
            async list() {
                return { ok: true, devices: [] }
            }
        },
        /** @returns {object} Returns current service state. */
        getReadiness() {
            return { hardwareReady: false, hardwareVerified: false, mode: 'no-device', status: 'ready' }
        },
        logger: {
            /** @returns {Promise<object>} Returns redacted local activity. */
            async list() {
                return { ok: true, entries: [] }
            },
            /** @returns {Promise<object>} Must not be called when a durable delegate exists. */
            async setEnabled() {
                calls.push('logger-direct')
                return { ok: true }
            }
        }
    }
    const services = createSupportRuntimeServices({
        application: { getName: () => 'OpenRDXManager', getVersion: () => '1.4.0' },
        /** @returns {Promise<object>} Controlled unused destination. */
        async chooseDestination() {
            return { canceled: true }
        },
        runtime,
        /** @param {object} request - Strict logging request. @returns {Promise<object>} Records durable delegation. */
        async setLoggingEnabled(request) {
            calls.push(request)
            return { ok: false, reason: 'settings-write-failed' }
        }
    })

    assert.deepEqual(await services.logs.setEnabled({ enabled: false }), { ok: false, reason: 'settings-write-failed' })
    assert.deepEqual(calls, [{ enabled: false }])
})

test('startup update checking sends one silent request only when the persisted preference is enabled', async () => {
    const requests = []
    const services = {
        updates: {
            /** @returns {Promise<object>} Starts the retained main-owned silent check. */
            async checkStartup() {
                requests.push({ silent: true })
                return { ok: true, silent: true, manager: { status: 'current', currentVersion: '1.4.0' }, firmware: { status: 'not-applicable', updates: [] } }
            }
        }
    }

    assert.deepEqual(await supportRuntimeModule.runStartupUpdateCheck({ enabled: true, services }), {
        ok: true,
        silent: true,
        manager: { status: 'current', currentVersion: '1.4.0' },
        firmware: { status: 'not-applicable', updates: [] }
    })
    assert.deepEqual(requests, [{ silent: true }])
})

test('startup update checking stays offline when the persisted preference is disabled', async () => {
    let checked = false
    const services = {
        updates: {
            /** @returns {Promise<object>} Must remain unused while disabled. */
            async checkStartup() {
                checked = true
                return { ok: false, reason: 'unexpected-check' }
            }
        }
    }

    assert.deepEqual(await supportRuntimeModule.runStartupUpdateCheck({ enabled: false, services }), { ok: false, reason: 'update-check-disabled' })
    assert.equal(checked, false)
})

test('startup update failure is contained without invoking a device mutation service', async () => {
    const mutations = []
    const services = {
        operations: {
            /** @returns {Promise<object>} Records any forbidden device mutation. */
            async start() {
                mutations.push('start')
                return { ok: true }
            }
        },
        updates: {
            /** @returns {Promise<object>} Simulates a rejected network operation. */
            async checkStartup() {
                throw new Error('network detail must stay in main')
            }
        }
    }

    assert.deepEqual(await supportRuntimeModule.runStartupUpdateCheck({ enabled: true, services }), { ok: false, reason: 'update-network-failure' })
    assert.deepEqual(mutations, [])
})

test('support runtime retains one verified available startup result for the later renderer read', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const payload = {
        expiresAt: '2026-09-30T00:00:00.000Z',
        firmware: [{ product: 'RDX QuikStor USB3+ External', revision: '0284', url: 'https://updates.example.test/rdx-0284.bin' }],
        issuedAt: '2026-08-28T00:00:00.000Z',
        manager: { url: 'https://updates.example.test/manager', version: '1.5.0' },
        schemaVersion: 1
    }
    const body = signedManifest(payload, privateKey)
    let fetchCount = 0
    const mutations = []
    const services = createSupportRuntimeServices({
        application: { getName: () => 'OpenRDXManager', getVersion: () => '1.4.0' },
        /** @returns {Promise<object>} Controlled unused destination. */
        async chooseDestination() {
            return { canceled: true }
        },
        /** @returns {Promise<object>} Returns one signed authoritative manifest. */
        async fetch() {
            fetchCount += 1
            return { ok: true, status: 200, url: 'https://updates.example.test/openrdx.json', text: async () => body }
        },
        now: () => new Date('2026-08-28T09:00:00.000Z'),
        runtime: {
            client: {
                /** @returns {Promise<object>} Returns a currently applicable dock without mutating it. */
                async list() {
                    return { ok: true, devices: [{ product: 'RDX QuikStor USB3+ External', drive: { firmwareRevision: '0283' } }] }
                },
                /** @returns {Promise<object>} Records any forbidden device operation. */
                async start() {
                    mutations.push('start')
                    return { ok: true }
                }
            },
            /** @returns {object} Returns stable no-hardware readiness. */
            getReadiness() {
                return { hardwareReady: false, hardwareVerified: false, mode: 'no-device', status: 'ready' }
            },
            logger: {
                /** @returns {Promise<object>} Returns empty renderer-safe activity. */
                async list() {
                    return { ok: true, entries: [] }
                },
                /** @returns {Promise<object>} Accepts a bounded local toggle. */
                async setEnabled() {
                    return { ok: true }
                }
            }
        },
        updateEndpoint: 'https://updates.example.test/openrdx.json',
        updatePublicKey: publicKey
    })

    const startupResult = await services.updates.checkStartup()
    const rendererResult = await services.updates.check({ silent: true })

    assert.equal(fetchCount, 1)
    assert.deepEqual(rendererResult, startupResult)
    assert.equal(rendererResult.manager.status, 'available')
    assert.equal(rendererResult.firmware.status, 'available')
    assert.equal('apply' in rendererResult, false)
    assert.equal('install' in rendererResult, false)
    assert.deepEqual(mutations, [])
})

test('invalid or unsigned update metadata cannot offer an update action', async () => {
    const { publicKey } = generateKeyPairSync('ed25519')
    const service = new UpdateService({ currentVersion: '1.0.0', endpoint: 'https://updates.example.test/openrdx.json', publicKey })

    await assert.rejects(service.parse('{"version":"2.0.0"}'), /unsigned-or-invalid-manifest/)
})

test('signed metadata distinguishes Manager and applicable firmware without applying either', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const payload = {
        expiresAt: '2026-09-30T00:00:00.000Z',
        firmware: [
            { product: 'RDX QuikStor USB3+ External', revision: '0284', url: 'https://updates.example.test/rdx-0284.bin' },
            { product: 'RDX QuikStor SATA III', revision: '0190', url: 'https://updates.example.test/rdx-sata.bin' }
        ],
        issuedAt: '2026-08-28T00:00:00.000Z',
        manager: { url: 'https://updates.example.test/manager', version: '1.5.0' },
        schemaVersion: 1
    }
    const body = signedManifest(payload, privateKey)
    let fetchCount = 0
    const service = new UpdateService({
        currentVersion: '1.4.0',
        endpoint: 'https://updates.example.test/openrdx.json',
        /** @returns {Promise<object>} Returns one exact authoritative response. */
        async fetch() {
            fetchCount += 1
            return { ok: true, status: 200, url: 'https://updates.example.test/openrdx.json', text: async () => body }
        },
        now: () => new Date('2026-08-28T09:00:00.000Z'),
        publicKey,
        /** @returns {Promise<object[]>} Supplies current devices for local applicability only. */
        async devices() {
            return [{ product: 'RDX QuikStor USB3+ External', drive: { firmwareRevision: '0283' } }]
        }
    })

    const result = await service.check({ silent: false })

    assert.equal(fetchCount, 1)
    assert.equal(result.ok, true)
    assert.equal(result.manager.status, 'available')
    assert.equal(result.manager.availableVersion, '1.5.0')
    assert.equal(result.firmware.status, 'available')
    assert.deepEqual(result.firmware.updates, [{ product: 'RDX QuikStor USB3+ External', currentRevision: '0283', availableRevision: '0284' }])
    assert.equal('install' in result, false)
    assert.equal('apply' in result, false)
})

test('firmware metadata remains not applicable when no product identity matches', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const payload = {
        expiresAt: '2026-09-30T00:00:00.000Z',
        firmware: [{ product: 'RDX QuikStor USB3+ External', revision: '0284', url: 'https://updates.example.test/rdx-0284.bin' }],
        issuedAt: '2026-08-28T00:00:00.000Z',
        manager: { url: 'https://updates.example.test/manager', version: '1.4.0' },
        schemaVersion: 1
    }
    const body = signedManifest(payload, privateKey)
    const service = new UpdateService({
        currentVersion: '1.4.0',
        endpoint: 'https://updates.example.test/openrdx.json',
        /** @returns {Promise<object>} Returns one signed manifest. */
        async fetch() {
            return { ok: true, status: 200, url: 'https://updates.example.test/openrdx.json', text: async () => body }
        },
        now: () => new Date('2026-08-28T09:00:00.000Z'),
        publicKey,
        /** @returns {Promise<object[]>} Returns an unrelated currently discovered product. */
        async devices() {
            return [{ product: 'Unlisted RDX Product', drive: { firmwareRevision: '0001' } }]
        }
    })

    const result = await service.check({ silent: true })

    assert.equal(result.ok, true)
    assert.deepEqual(result.firmware, { status: 'not-applicable', updates: [] })
})

test('update checking requires an explicitly configured HTTPS authority', async () => {
    const service = new UpdateService({ currentVersion: '1.4.0' })
    assert.deepEqual(await service.check({ silent: true }), { ok: false, reason: 'update-endpoint-unconfigured' })
})

test('preload and main accept only bounded support/update requests and results', async () => {
    const calls = []
    const handlers = new Map()
    const services = {
        /** @returns {boolean} Accepts the controlled local sender. */
        isTrustedSender() {
            return true
        },
        support: {
            /** @returns {Promise<object>} Returns one main-owned saved summary path. */
            async generateSummary() {
                return { ok: true, savedPath: '/safe/RdxSystemSummary.txt', deviceCount: 2 }
            }
        },
        updates: {
            /** @param {object} request - Strict explicit/silent request. @returns {Promise<object>} Distinct update categories. */
            async check(request) {
                calls.push(request)
                return { ok: true, silent: request.silent, manager: { status: 'current', currentVersion: '1.4.0' }, firmware: { status: 'not-applicable', updates: [] } }
            }
        }
    }
    registerIpcHandlers({
        ipcMain: {
            /** @param {string} channel - Exact route. @param {Function} handler - Route handler. @returns {void} Registers it. */
            handle(channel, handler) {
                handlers.set(channel, handler)
            },
            /** @returns {void} Test registry disposal is unused. */
            removeHandler() {}
        },
        services
    })
    const transport = {
        /** @param {string} channel - Exact route. @param {object} request - Validated request. @returns {Promise<object>} Main handler result. */
        invoke(channel, request) {
            return handlers.get(channel)({}, request)
        },
        /** @returns {void} Subscription is unused. */
        on() {},
        /** @returns {void} Subscription is unused. */
        removeListener() {}
    }
    const api = createPreloadApi(transport)

    assert.deepEqual(await api.support.generateSummary(), { ok: true, savedPath: '/safe/RdxSystemSummary.txt', deviceCount: 2 })
    assert.deepEqual(await api.updates.check({ silent: true }), {
        ok: true,
        silent: true,
        manager: { status: 'current', currentVersion: '1.4.0' },
        firmware: { status: 'not-applicable', updates: [] }
    })
    await assert.rejects(api.updates.check({ silent: false, endpoint: 'https://attacker.invalid' }), /Invalid OpenRDX request/)
    assert.deepEqual(calls, [{ silent: true }])
})

test('IPC rejects contradictory firmware availability from an injected service', async () => {
    const handlers = new Map()
    registerIpcHandlers({
        ipcMain: {
            /** @param {string} channel - Exact route. @param {Function} handler - Registered handler. @returns {void} Stores it. */
            handle(channel, handler) {
                handlers.set(channel, handler)
            },
            /** @returns {void} Disposal is unused. */
            removeHandler() {}
        },
        services: {
            /** @returns {boolean} Accepts the controlled sender. */
            isTrustedSender() {
                return true
            },
            updates: {
                /** @returns {Promise<object>} Returns a deliberately contradictory update result. */
                async check() {
                    return {
                        ok: true,
                        silent: false,
                        manager: { status: 'current', currentVersion: '1.4.0' },
                        firmware: { status: 'current', updates: [{ product: 'RDX', currentRevision: '1', availableRevision: '2' }] }
                    }
                }
            }
        }
    })

    assert.deepEqual(await handlers.get('openrdx:updates:check')({}, { silent: false }), { ok: false, reason: 'invalid-service-response' })
})

test('activity view filters locally, exposes logging state, and keeps export explicit', () => {
    const { dom, document } = createDom()
    const view = renderActivityView(
        {
            enabled: false,
            entries: [
                { id: 'activity:1', occurredAt: '2026-08-28T08:00:00.000Z', severity: 'info', messageKey: 'activity.operation' },
                { id: 'activity:2', occurredAt: '2026-08-28T08:01:00.000Z', severity: 'error', messageKey: 'activity.failure', supportCorrelationId: 'support:22' }
            ],
            filter: 'error'
        },
        { document, translator: translateEnglish }
    )

    assert.equal(view.querySelector('[data-setting="event-logging"]').checked, false)
    assert.equal(view.querySelectorAll('[data-activity-entry]').length, 1)
    assert.match(view.textContent, /support:22/)
    assert.equal(view.querySelector('[data-action="export-logs"]').disabled, false)
    dom.window.close()
})

test('local F1 help includes support order, contacts, and historical compatibility warnings', () => {
    const { dom, document } = createDom()
    const help = renderHelpView({ activeTopic: 'troubleshooting', topics: HELP_TOPICS }, { document, translator: translateEnglish })

    assert.equal(findHelpTopic('troubleshooting')?.source, '25-support-troubleshooting-and-known-limitations.md')
    assert.match(help.textContent, /Check for updates.*Event Logging.*Status.*Tests.*System Summary/is)
    assert.match(help.textContent, /supportEMEA@overlandtandberg\.com/)
    assert.match(help.textContent, /13\.1\.0\.1058/)
    assert.match(help.textContent, /historical/i)
    assert.doesNotMatch(help.innerHTML, /href="https?:|href="ftp:/i)
    dom.window.close()
})

test('help and activity surfaces route their complete user-facing copy through the translator', () => {
    const { dom, document } = createDom()
    /** @param {string} key - Catalog key. @param {object} [params={}] - Interpolation values. @returns {string} Visible key marker. */
    function markerTranslator(key, params = {}) {
        const suffix = Object.keys(params).length === 0 ? '' : `:${Object.values(params).join('|')}`
        return `«${key}${suffix}»`
    }
    const help = renderHelpView({ activeTopic: 'troubleshooting', topics: HELP_TOPICS }, { document, translator: markerTranslator })
    const activity = renderActivityView(
        {
            entries: [{ id: 'activity:1', occurredAt: '2026-08-28T08:00:00.000Z', severity: 'error', messageKey: 'activity.failure' }]
        },
        { document, translator: markerTranslator }
    )

    assert.match(help.textContent, /«help\.title\.local»/)
    assert.match(help.textContent, /«help\.topic\.troubleshooting\.paragraph1»/)
    assert.match(help.textContent, /«help\.supportTools\.privacy»/)
    assert.doesNotMatch(help.textContent, /Bundled documentation|Check for updates|About/)
    assert.match(activity.textContent, /«activity\.title»/)
    assert.match(activity.textContent, /«activity\.failure»/)
    assert.match(activity.textContent, /«activity\.privacy»/)
    assert.doesNotMatch(activity.textContent, /Event Log|Logs stay local|Export redacted log/)
    dom.window.close()
})

test('activity toggle follows a later persisted settings hydration', async () => {
    const { dom, document } = createDom()
    const root = document.createElement('div')
    document.body.append(root)
    let state = { ...createFixtureState({ mode: 'one-device' }), settings: { autoScan: true } }
    const listeners = []
    const store = {
        /** @returns {object} Current controlled renderer state. */
        getState() {
            return state
        },
        /** @returns {object} Controlled store ignores actions unused by this test. */
        dispatch() {
            return state
        },
        /** @param {Function} listener - Store listener. @returns {Function} Cleanup callback. */
        subscribe(listener) {
            listeners.push(listener)
            return () => {}
        }
    }
    const supportApi = {
        logs: {
            /** @returns {Promise<object>} Empty redacted activity. */
            async list() {
                return { ok: true, entries: [] }
            }
        }
    }
    const controller = mountApplication(root, { store, supportApi })
    root.querySelector('[data-action="open-event-log"]').click()
    await settleRenderer()
    assert.equal(root.querySelector('[data-setting="event-logging"]').checked, true)
    root.querySelector('[data-action="close-support-panel"]').click()
    state = { ...state, settings: { ...state.settings, eventLogging: false } }
    listeners[0](state)
    root.querySelector('[data-action="open-event-log"]').click()
    await settleRenderer()

    assert.equal(root.querySelector('[data-setting="event-logging"]').checked, false)
    controller.destroy()
    dom.window.close()
})

test('enabled startup checking publishes retained Manager and applicable firmware availability without a device action', async () => {
    const { dom, document } = createDom()
    const root = document.createElement('div')
    document.body.append(root)
    const requests = []
    const mutations = []
    const supportApi = {
        support: {
            /** @returns {Promise<object>} Records any summary action, which this flow must not invoke. */
            async generateSummary() {
                mutations.push('summary')
                return { ok: true, savedPath: '/safe/RdxSystemSummary.txt', deviceCount: 1 }
            }
        },
        updates: {
            /** @param {object} request - Exact configured silent request. @returns {Promise<object>} Available signed-metadata projection. */
            async check(request) {
                requests.push(request)
                return {
                    ok: true,
                    silent: true,
                    manager: { status: 'available', currentVersion: '1.4.0', availableVersion: '1.5.0' },
                    firmware: { status: 'available', updates: [{ product: 'RDX QuikStor USB3+ External', currentRevision: '0283', availableRevision: '0284' }] }
                }
            }
        }
    }
    const controller = mountApplication(root, { store: createStore(createFixtureState({ mode: 'one-device' })), supportApi })
    await settleRenderer()

    root.querySelector('[data-action="open-support"]').click()
    await settleRenderer()

    assert.deepEqual(requests, [{ silent: true }])
    assert.match(root.querySelector('[data-support-result="help"]').textContent, /Manager 1\.5\.0/)
    assert.match(root.querySelector('[data-support-result="help"]').textContent, /1 applicable firmware update/)
    assert.equal(root.querySelector('[data-action*="firmware"][data-action*="apply"]'), null)
    assert.deepEqual(mutations, [])
    controller.destroy()
    dom.window.close()
})

test('disabled startup checking performs no metadata request', async () => {
    const { dom, document } = createDom()
    const root = document.createElement('div')
    document.body.append(root)
    const requests = []
    const fixtureState = createFixtureState({ mode: 'one-device' })
    const controller = mountApplication(root, {
        store: createStore({ ...fixtureState, settings: { ...fixtureState.settings, updateChecks: false } }),
        supportApi: {
            updates: {
                /** @param {object} request - Forbidden disabled request. @returns {Promise<object>} Controlled failure. */
                async check(request) {
                    requests.push(request)
                    return { ok: false, reason: 'unexpected-check' }
                }
            }
        }
    })
    await settleRenderer()

    assert.deepEqual(requests, [])
    controller.destroy()
    dom.window.close()
})

test('failed startup checking stays silent and leaves device operations untouched', async () => {
    const { dom, document } = createDom()
    const root = document.createElement('div')
    document.body.append(root)
    const requests = []
    const mutations = []
    const supportApi = {
        support: {
            /** @returns {Promise<object>} Records any forbidden support action. */
            async generateSummary() {
                mutations.push('summary')
                return { ok: false, reason: 'unexpected-action' }
            }
        },
        updates: {
            /** @param {object} request - Exact configured silent request. @returns {Promise<object>} Rejects as a network failure. */
            async check(request) {
                requests.push(request)
                throw new Error('offline')
            }
        }
    }
    const controller = mountApplication(root, { store: createStore(createFixtureState({ mode: 'one-device' })), supportApi })
    await settleRenderer()

    root.querySelector('[data-action="open-support"]').click()
    await settleRenderer()

    assert.deepEqual(requests, [{ silent: true }])
    assert.equal(root.querySelector('[data-support-result="help"]').textContent, '')
    assert.deepEqual(mutations, [])
    controller.destroy()
    dom.window.close()
})

test('mounted application opens local F1 help and drives local support tools through named methods', async () => {
    const { dom, document } = createDom()
    const root = document.createElement('div')
    document.body.append(root)
    const calls = []
    const supportApi = {
        app: {
            /** @returns {Promise<object>} Returns bounded About metadata. */
            async getInfo() {
                return { ok: true, app: { name: 'OpenRDXManager', platform: 'darwin', version: '1.4.0' } }
            }
        },
        logs: {
            /** @returns {Promise<object>} Returns redacted activity. */
            async list() {
                calls.push('logs:list')
                return { ok: true, entries: [{ id: 'activity:1', occurredAt: '2026-08-28T08:00:00.000Z', severity: 'error', messageKey: 'activity.failure' }] }
            },
            /** @param {object} request - Exact logging toggle. @returns {Promise<object>} Accepted toggle. */
            async setEnabled(request) {
                calls.push(`logs:${request.enabled}`)
                return { ok: true }
            },
            /** @returns {Promise<object>} Returns selected local save path. */
            async export() {
                calls.push('logs:export')
                return { ok: true, savedPath: '/safe/RDXManagerActivity.txt' }
            }
        },
        support: {
            /** @returns {Promise<object>} Returns selected local summary path. */
            async generateSummary() {
                calls.push('support:summary')
                return { ok: true, savedPath: '/safe/RdxSystemSummary.txt', deviceCount: 1 }
            }
        },
        updates: {
            /** @returns {Promise<object>} Returns read-only availability. */
            async check() {
                calls.push('updates:check')
                return { ok: true, silent: false, manager: { status: 'available', currentVersion: '1.4.0', availableVersion: '1.5.0' }, firmware: { status: 'current', updates: [] } }
            }
        }
    }
    const fixtureState = createFixtureState({ mode: 'one-device' })
    const controller = mountApplication(root, { store: createStore({ ...fixtureState, settings: { ...fixtureState.settings, updateChecks: false } }), supportApi })

    root.dispatchEvent(new dom.window.KeyboardEvent('keydown', { bubbles: true, key: 'F1' }))
    assert.equal(root.querySelector('[data-help-view="help"]') !== null, true)
    const helpDialog = root.querySelector('[role="dialog"]')
    assert.equal(helpDialog.getAttribute('aria-labelledby'), 'help-title')
    assert.equal(helpDialog.querySelector('#help-title').textContent, 'OpenRDXManager Help')
    const gettingStartedTopic = root.querySelector('[data-help-topic="getting-started"]')
    gettingStartedTopic.focus()
    gettingStartedTopic.click()
    assert.equal(document.activeElement.dataset.focusKey, 'support:topic:getting-started')
    root.querySelector('[data-action="close-support-panel"]').click()
    root.querySelector('[data-action="open-event-log"]').click()
    await settleRenderer()
    assert.equal(root.querySelectorAll('[data-activity-entry]').length, 1)
    const filter = root.querySelector('[data-activity-filter]')
    filter.focus()
    filter.value = 'error'
    filter.dispatchEvent(new dom.window.Event('change', { bubbles: true }))
    assert.equal(document.activeElement.dataset.focusKey, 'activity:filter')
    const logging = root.querySelector('[data-setting="event-logging"]')
    logging.focus()
    logging.checked = false
    logging.dispatchEvent(new dom.window.Event('change', { bubbles: true }))
    await settleRenderer()
    assert.equal(document.activeElement.dataset.focusKey, 'activity:logging')
    const exportButton = root.querySelector('[data-action="export-logs"]')
    exportButton.focus()
    exportButton.click()
    await settleRenderer()
    assert.match(root.querySelector('[data-support-result="activity"]').textContent, /RDXManagerActivity\.txt/)
    assert.equal(document.activeElement.dataset.focusKey, 'activity:export')
    root.querySelector('[data-action="close-support-panel"]').click()
    root.querySelector('[data-action="open-support"]').click()
    await settleRenderer()
    const updateButton = root.querySelector('[data-action="check-updates"]')
    updateButton.focus()
    updateButton.click()
    await settleRenderer()
    assert.match(root.querySelector('[data-support-result="help"]').textContent, /Manager 1\.5\.0/)
    assert.equal(document.activeElement.dataset.focusKey, 'support:updates')
    root.querySelector('[data-action="generate-summary"]').click()
    await settleRenderer()
    assert.match(root.querySelector('[data-support-result="help"]').textContent, /RdxSystemSummary\.txt/)
    assert.deepEqual(calls, ['logs:list', 'logs:false', 'logs:export', 'updates:check', 'support:summary'])

    controller.destroy()
    dom.window.close()
})
