// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const executeFile = promisify(execFile)
const reader = fileURLToPath(new URL('./read-windows-startup-events.ps1', import.meta.url))
const modules = new Map([
    ['ntdll.dll', 'ntdll'],
    ['kernel32.dll', 'kernel32'],
    ['kernelbase.dll', 'kernelbase'],
    ['advapi32.dll', 'advapi32'],
    ['ucrtbase.dll', 'ucrt'],
    ['vcruntime140.dll', 'vcruntime'],
    ['vcruntime140_1.dll', 'vcruntime'],
    ['bcrypt.dll', 'bcrypt'],
    ['bcryptprimitives.dll', 'bcrypt']
])
const exceptions = new Map([
    ['c0000142', 'dll-init-failed'],
    ['c0000022', 'access-denied'],
    ['c0000005', 'access-violation'],
    ['c0000006', 'in-page-error'],
    ['c0000135', 'dll-not-found'],
    ['c000007b', 'invalid-image']
])

/** @param {string} status Fixed outcome. @param {object[]} [records] Reconstructed fixed categories. @returns {object} Diagnostic only, never admission or exact process attribution. */
function outcome(status, records = []) {
    return { status, correlation: 'fixture-name-and-time-only', startupProof: false, records }
}

/** @param {unknown} value Exact UTC timestamp. @returns {number|null} Epoch milliseconds or null. */
function timestamp(value) {
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) return null
    const result = Date.parse(value)
    return Number.isFinite(result) && new Date(result).toISOString() === value ? result : null
}

/** @param {object} window Requested observation interval. @returns {boolean} True for one finite interval of at most five minutes. */
function validWindow(window) {
    const start = timestamp(window?.since)
    const end = timestamp(window?.until)
    return start !== null && end !== null && end >= start && end - start <= 300_000
}

/** @param {unknown} value Untrusted collected record. @returns {boolean} True only for bounded scalar data; no OS text is forwarded. */
function validRecord(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'channel,fields,id,provider,time') return false
    if (typeof value.channel !== 'string' || value.channel.length > 32 || typeof value.provider !== 'string' || value.provider.length > 128 || !Number.isInteger(value.id) || timestamp(value.time) === null) return false
    if (value.fields === null || typeof value.fields !== 'object' || Array.isArray(value.fields) || Object.keys(value.fields).length > 32) return false
    return Object.entries(value.fields).every(([key, entry]) => key.length <= 64 && typeof entry === 'string' && entry.length <= 8192)
}

/** @param {string|undefined} name Untrusted exact basename. @returns {boolean} Fixed fixture-name correlation, not proof of an owned child. */
function fixtureName(name) {
    return typeof name === 'string' && name.toLowerCase() === 'openrdx-token-child.exe'
}

/** @param {string|undefined} name Untrusted module basename. @returns {string} Compiled category only; arbitrary paths are never basename-normalized. */
function moduleClass(name) {
    return typeof name === 'string' ? (modules.get(name.toLowerCase()) ?? 'other') : 'unknown'
}

/** @param {string|undefined} code Untrusted exact exception token. @returns {string} Compiled category without native code or text. */
function exceptionClass(code) {
    return typeof code === 'string' && /^(?:0x)?[a-f0-9]{8}$/iu.test(code) ? (exceptions.get(code.toLowerCase().replace(/^0x/u, '')) ?? 'other') : 'unknown'
}

/** @param {object} record Bounded observed record. @returns {object|null} Diagnostic categories only for a fixed provider/event schema. */
function classifyRecord(record) {
    const fields = record.fields
    if (record.channel === 'Application' && record.provider === 'Application Error' && record.id === 1000 && fixtureName(fields.AppName)) return { source: 'application-error', module: moduleClass(fields.ModuleName), exception: exceptionClass(fields.ExceptionCode) }
    if (record.channel === 'Application' && record.provider === 'Windows Error Reporting' && record.id === 1001 && fields.EventName === 'APPCRASH' && fixtureName(fields.P1)) return { source: 'wer-appcrash', module: moduleClass(fields.P4), exception: exceptionClass(fields.P7) }
    if (record.channel !== 'System' || record.provider !== 'Application Popup' || record.id !== 26) return null
    const text = `${fields.Caption ?? ''}\n${fields.Message ?? ''}\n${fields.Application ?? ''}`
    if (!/(?:^|[^a-z0-9_.-])openrdx-token-child\.exe(?:$|[^a-z0-9_.-])/iu.test(text)) return null
    const codes = [...new Set((text.match(/\b(?:0x)?[a-f0-9]{8}\b/giu) ?? []).map((code) => code.toLowerCase().replace(/^0x/u, '')))]
    return { source: 'application-popup', module: 'unknown', exception: codes.length === 1 ? exceptionClass(codes[0]) : 'unknown' }
}

/**
 * Reduces captured event data to fixed categories within the exact test interval.
 * Event names/times are correlations only; a reported module is not a root cause.
 * @param {unknown} input Private reader response, never logged verbatim.
 * @param {{since:string,until:string}} window Exact bounded UTC interval.
 * @returns {object} Closed observation; malformed input has no reusable records.
 */
export function classifyStartupEvents(input, window) {
    if (!validWindow(window) || input === null || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).sort().join(',') !== 'channels,records') return outcome('invalid')
    if (!Array.isArray(input.channels) || input.channels.length !== 2 || !Array.isArray(input.records) || input.records.length > 64 || !input.records.every(validRecord)) return outcome('invalid')
    const channels = new Map()
    for (const channel of input.channels) {
        if (channel === null || typeof channel !== 'object' || Object.keys(channel).sort().join(',') !== 'name,status' || !['Application', 'System'].includes(channel.name) || !['complete', 'failed', 'bounded'].includes(channel.status) || channels.has(channel.name)) return outcome('invalid')
        channels.set(channel.name, channel.status)
    }
    const rows = new Map()
    for (const record of input.records) {
        if (timestamp(record.time) < timestamp(window.since) || timestamp(record.time) > timestamp(window.until)) continue
        const row = classifyRecord(record)
        if (row === null) continue
        const key = `${row.source}:${row.module}:${row.exception}`
        const previous = rows.get(key)
        rows.set(key, { ...row, count: (previous?.count ?? 0) + 1 })
    }
    return outcome(
        [...channels.values()].every((status) => status === 'complete') ? 'complete' : 'partial',
        [...rows.entries()].sort(([left], [right]) => left.localeCompare(right, 'en')).map(([, row]) => row)
    )
}

/**
 * Executes only the fixed read-only event reader with a deadline and output cap.
 * Failure text, raw events, identity, paths and timestamps never reach its result.
 * @param {{since:string,until:string,platform?:string,execute?:Function}} options Bounded window and test-only process adapter.
 * @returns {Promise<object>} Closed observations; never changes a native gate result.
 */
export async function observeStartupEvents({ since, until, platform = process.platform, execute = executeFile }) {
    if (!validWindow({ since, until })) return outcome('invalid')
    if (platform !== 'win32') return outcome('unavailable')
    try {
        const result = await execute('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', reader, '-Since', since, '-Until', until], { timeout: 8000, maxBuffer: 4 * 1024 * 1024, windowsHide: true })
        if (typeof result.stdout !== 'string' || result.stdout.length > 4 * 1024 * 1024) return outcome('invalid')
        return classifyStartupEvents(JSON.parse(result.stdout.replace(/^\uFEFF/u, '')), { since, until })
    } catch {
        return outcome('unavailable')
    }
}

/** @returns {Promise<void>} Emits only the closed observation, including when the reader cannot run. */
async function main() {
    const result = process.argv.length === 4 && process.argv[2] === '--since' ? await observeStartupEvents({ since: process.argv[3], until: new Date().toISOString() }) : outcome('invalid')
    process.stdout.write(`${JSON.stringify(result)}\n`)
    process.exitCode = ['complete', 'partial'].includes(result.status) ? 0 : 1
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main()
