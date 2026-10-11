// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomUUID } from 'node:crypto'
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'

const LANGUAGE_CODES = new Set(['en', 'zh', 'de', 'fr', 'it', 'pt', 'es', 'ja'])
const PUBLIC_SETTING_KEYS = new Set(['autoScan', 'eventLogging', 'language', 'lastSafeView', 'updateChecks'])
const DESKTOP_SETTING_KEYS = new Set(['lastSafeView', 'windowBounds'])
const PERSISTED_SETTING_KEYS = new Set([...PUBLIC_SETTING_KEYS, ...DESKTOP_SETTING_KEYS])
const SAFE_VIEWS = new Set(['status', 'encryption', 'tests', 'utilities'])
const DEFAULT_SETTINGS = Object.freeze({ autoScan: true, eventLogging: true, language: 'en', lastSafeView: 'status', updateChecks: true, windowBounds: null })

/** @param {unknown} value - Candidate plain data record. @returns {boolean} True only for a plain own-key record. */
function isPlainRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
    const prototype = Object.getPrototypeOf(value)
    return prototype === Object.prototype || prototype === null
}

/** @param {unknown} value - Candidate window bounds. @returns {boolean} True for bounded visible-size geometry. */
function isWindowBounds(value) {
    if (value === null) return true
    if (!isPlainRecord(value) || Object.keys(value).length !== 4) return false
    return ['x', 'y', 'width', 'height'].every((key) => Number.isSafeInteger(value[key])) && value.width >= 1024 && value.width <= 16_384 && value.height >= 768 && value.height <= 16_384 && Math.abs(value.x) <= 131_072 && Math.abs(value.y) <= 131_072
}

/** @param {string} key - Persisted setting key. @param {unknown} value - Candidate value. @returns {boolean} True only for the exact key's safe value domain. */
function isSettingValue(key, value) {
    if (['autoScan', 'eventLogging', 'updateChecks'].includes(key)) return typeof value === 'boolean'
    if (key === 'language') return typeof value === 'string' && LANGUAGE_CODES.has(value)
    if (key === 'lastSafeView') return typeof value === 'string' && SAFE_VIEWS.has(value)
    if (key === 'windowBounds') return isWindowBounds(value)
    return false
}

/** @param {unknown} input - Candidate persisted record. @returns {object|null} Complete safe settings or null. */
function parsePersistedSettings(input) {
    if (!isPlainRecord(input)) return null
    const keys = Object.keys(input)
    if (keys.some((key) => !PERSISTED_SETTING_KEYS.has(key))) return null
    const settings = { ...DEFAULT_SETTINGS }
    for (const key of keys) {
        if (!isSettingValue(key, input[key])) return null
        settings[key] = key === 'windowBounds' && input[key] !== null ? { ...input[key] } : input[key]
    }
    return settings
}

/** @param {object} settings - Complete internal settings. @returns {object} Renderer-safe public settings. */
function publicSettings(settings) {
    return { autoScan: settings.autoScan, eventLogging: settings.eventLogging, language: settings.language, lastSafeView: settings.lastSafeView, updateChecks: settings.updateChecks }
}

/**
 * Resolves saved language versus the documented `-l <code>` override.
 * @param {{argv: string[], persistedLanguage: string, warn?: (message: string) => void}} options - Startup inputs and warning sink.
 * @returns {{language: string, source: 'command-line'|'invalid-command-line'|'settings'}} Safe startup language decision.
 */
export function resolveStartupLanguage(options) {
    const argv = Array.isArray(options?.argv) ? options.argv : []
    const index = argv.lastIndexOf('-l')
    if (index >= 0) {
        const candidate = argv[index + 1]
        if (typeof candidate === 'string' && LANGUAGE_CODES.has(candidate)) return { language: candidate, source: 'command-line' }
        options?.warn?.('Unsupported language code; using English.')
        return { language: 'en', source: 'invalid-command-line' }
    }
    return { language: LANGUAGE_CODES.has(options?.persistedLanguage) ? options.persistedLanguage : 'en', source: 'settings' }
}

/** Persists the exact privacy-safe desktop settings allowlist. */
export class SettingsService {
    #filePath
    #sessionLanguage = null
    #settings = { ...DEFAULT_SETTINGS }

    /** @param {{filePath: string}} options - Exact application-owned settings file. @throws {TypeError} For an invalid path. */
    constructor(options) {
        if (typeof options?.filePath !== 'string' || options.filePath.length === 0) throw new TypeError('SettingsService requires a file path')
        this.#filePath = options.filePath
    }

    /** @returns {Promise<object>} Complete loaded internal settings with safe defaults on failure. */
    async load() {
        this.#sessionLanguage = null
        try {
            const parsed = parsePersistedSettings(JSON.parse(await readFile(this.#filePath, 'utf8')))
            this.#settings = parsed ?? { ...DEFAULT_SETTINGS }
        } catch {
            this.#settings = { ...DEFAULT_SETTINGS }
        }
        return this.getDesktopState()
    }

    /** @returns {Promise<{ok: true, settings: object}>} Renderer-safe public settings response. */
    async get() {
        return { ok: true, settings: publicSettings(this.#effectiveSettings()) }
    }

    /**
     * Applies the already validated startup override for this process without
     * changing the user's durable preference.
     * @param {unknown} language - Candidate supported language code.
     * @returns {boolean} True only when the session language was accepted.
     */
    setSessionLanguage(language) {
        if (!isSettingValue('language', language)) return false
        this.#sessionLanguage = language
        return true
    }

    /**
     * Applies only IPC-published safe settings and persists the complete safe record.
     * @param {unknown} request - Strict partial public settings update.
     * @returns {Promise<{ok: true, settings: object}|{ok: false, reason: string}>} Accepted state or stable rejection.
     */
    async update(request) {
        if (!isPlainRecord(request)) return { ok: false, reason: 'invalid-request' }
        const keys = Object.keys(request)
        if (keys.length === 0 || keys.some((key) => !PUBLIC_SETTING_KEYS.has(key) || !isSettingValue(key, request[key]))) return { ok: false, reason: 'invalid-request' }
        const previous = this.#settings
        const previousSessionLanguage = this.#sessionLanguage
        this.#settings = { ...this.#settings, ...request }
        if (typeof request.language === 'string') this.#sessionLanguage = request.language
        if (!(await this.#persist())) {
            this.#settings = previous
            this.#sessionLanguage = previousSessionLanguage
            return { ok: false, reason: 'settings-write-failed' }
        }
        return { ok: true, settings: publicSettings(this.#effectiveSettings()) }
    }

    /**
     * Applies main-owned window/view state without exposing it as a general renderer store.
     * @param {unknown} request - Exact partial desktop-only settings update.
     * @returns {Promise<boolean>} True only after durable persistence.
     */
    async updateDesktopState(request) {
        if (!isPlainRecord(request)) return false
        const keys = Object.keys(request)
        if (keys.length === 0 || keys.some((key) => !DESKTOP_SETTING_KEYS.has(key) || !isSettingValue(key, request[key]))) return false
        const previous = this.#settings
        this.#settings = { ...this.#settings, ...request }
        if (await this.#persist()) return true
        this.#settings = previous
        return false
    }

    /** @returns {object} Detached complete safe desktop settings. */
    getDesktopState() {
        const settings = this.#effectiveSettings()
        return { ...settings, windowBounds: settings.windowBounds === null ? null : { ...settings.windowBounds } }
    }

    /** @returns {object} Internal settings with the non-durable startup language applied. */
    #effectiveSettings() {
        return this.#sessionLanguage === null ? this.#settings : { ...this.#settings, language: this.#sessionLanguage }
    }

    /** @returns {Promise<boolean>} True only after an atomic owner-only settings replacement. */
    async #persist() {
        const directory = dirname(this.#filePath)
        const temporaryPath = join(directory, `.settings-${process.pid}-${randomUUID()}.tmp`)
        try {
            await mkdir(directory, { mode: 0o700, recursive: true })
            await writeFile(temporaryPath, `${JSON.stringify(this.#settings, null, 2)}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 })
            await rename(temporaryPath, this.#filePath)
            await chmod(this.#filePath, 0o600)
            return true
        } catch {
            return false
        }
    }
}
