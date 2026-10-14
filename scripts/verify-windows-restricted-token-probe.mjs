// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify, stripVTControlCharacters } from 'node:util'

const execFileAsync = promisify(execFile)
const projectRoot = fileURLToPath(new URL('..', import.meta.url))
const maximumOutputBytes = 65_536
const testNames = Object.freeze({ baseline: 'service_acl::windows_impl::restricted_token_probe::native_restricted_token_observations', medium: 'service_acl::windows_impl::restricted_token_probe::medium::native_medium_restricted_token_observations' })
const mediumRequirements = Object.freeze({ 'source-open': true, 'derived-created': true, 'query-ok': true, 'medium-set-ok': true, 'source-unchanged': true, 'same-user': true, 'same-session': true, 'source-active-console': true, 'derived-active-console': true, 'source-console-user-match': true, 'derived-console-user-match': true, 'source-elevated': true, 'derived-elevated': false, 'source-integrity-high': true, 'admin-deny-only': true, 'no-enabled-admins': true, 'enabled-privilege-whitelist': true, 'present-privilege-whitelist': true, 'privileges-reduced': true, 'no-added-privileges': true, 'integrity-medium': true, 'integrity-high': false, 'integrity-reduced': true, 'ui-access-zero': true, 'sandbox-inert-zero': true, 'primary-token': true, 'elevation-type-known': true, 'elevation-type-full': false })
const diagnosticKeys = new Set([...Object.keys(mediumRequirements), 'source-admin-deny-only', 'source-no-enabled-admins', 'source-integrity-low', 'source-integrity-medium', 'source-integrity-system', 'integrity-low', 'integrity-system', 'elevation-type-default', 'elevation-type-limited'])

/**
 * Validates exact execution evidence and retains only closed boolean diagnostics.
 * Successful token queries do not establish Manager eligibility.
 * @param {string} stdout - Bounded Cargo standard output.
 * @param {string} stderr - Bounded Cargo standard error, never forwarded.
 * @param {object} [options] - Fixed experiment selection.
 * @param {'baseline'|'medium'} [options.mode] - Exact approved experiment.
 * @returns {{passed: boolean, facts: string[]}} Exact execution verdict and safe facts.
 */
export function validateRestrictedTokenProbeOutput(stdout, stderr, { mode = 'baseline' } = {}) {
    const failed = { passed: false, facts: [] }
    if (!Object.hasOwn(testNames, mode) || typeof stdout !== 'string' || typeof stderr !== 'string' || Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > maximumOutputBytes) return failed
    const lines = stripVTControlCharacters(stdout).split(/\r?\n/u)
    if (lines.filter((line) => /^running \d+ tests?$/u.test(line)).length !== 1 || !lines.includes('running 1 test')) return failed
    if (lines.filter((line) => line.startsWith('test result:')).length !== 1 || !lines.some((line) => /^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in \d+(?:\.\d+)?s$/u.test(line))) return failed
    const namedResults = lines.filter((line) => line.startsWith('test ') && !line.startsWith('test result:'))
    if (namedResults.length !== 1 || namedResults[0] !== `test ${testNames[mode]} ... ok`) return failed
    const facts = lines.filter((line) => line.startsWith('openrdx-token-probe '))
    const seen = new Map()
    for (const line of facts) {
        for (const pair of line.slice('openrdx-token-probe '.length).split(' ')) {
            const match = /^([a-z-]+)=(true|false)$/u.exec(pair)
            if (match === null || !diagnosticKeys.has(match[1]) || seen.has(match[1])) return failed
            seen.set(match[1], match[2] === 'true')
        }
    }
    if (seen.get('source-open') !== true || seen.get('derived-created') !== true || seen.get('query-ok') !== true) return failed
    if (mode === 'medium' && (Object.entries(mediumRequirements).some(([key, expected]) => seen.get(key) !== expected) || !seen.has('elevation-type-default') || !seen.has('elevation-type-limited') || Number(seen.get('elevation-type-default')) + Number(seen.get('elevation-type-limited')) !== 1)) return failed
    return { passed: true, facts }
}

/**
 * Runs the fixed Cargo probe without a shell, with bounded output and deadline.
 * @param {string} command - Fixed Cargo executable.
 * @param {readonly string[]} args - Fixed ignored/exact probe arguments.
 * @param {object} options - Closed child execution options.
 * @returns {Promise<{exitCode: number, stdout: string, stderr: string}>} Original Cargo exit and captured output.
 */
async function executeProbe(command, args, options) {
    try {
        const { stdout, stderr } = await execFileAsync(command, args, options)
        return { exitCode: 0, stdout, stderr }
    } catch (error) {
        // Numeric Cargo failures remain failures even if stdout resembles success.
        // Launch, signal, timeout and buffer errors have no reusable Cargo exit code.
        const exitCode = Number.isInteger(error.code) && error.code > 0 && error.code <= 255 ? error.code : 1
        return { exitCode, stdout: typeof error.stdout === 'string' ? error.stdout : '', stderr: typeof error.stderr === 'string' ? error.stderr : '' }
    }
}

/**
 * Requires one exact native test plus successful closed kernel-query evidence.
 * @param {object} [options] - Test-only execution dependency.
 * @param {Function} [options.execute] - Awaited executor; receives only the fixed command/options.
 * @param {'baseline'|'medium'} [options.mode] - Fixed experiment, never an arbitrary native filter.
 * @returns {Promise<{exitCode: number, passed: boolean, facts: string[]}>} Fail-closed verdict preserving Cargo failure.
 */
export async function runRestrictedTokenProbe({ execute = executeProbe, mode = 'baseline' } = {}) {
    try {
        if (!Object.hasOwn(testNames, mode)) return { exitCode: 1, passed: false, facts: [] }
        const cargoArguments = Object.freeze(['test', '--manifest-path', 'native/rdx-service/windows-native/Cargo.toml', '--locked', '--lib', testNames[mode], '--', '--ignored', '--exact', '--nocapture'])
        const result = await execute('cargo', cargoArguments, { cwd: projectRoot, shell: false, windowsHide: true, encoding: 'utf8', maxBuffer: maximumOutputBytes, timeout: 120_000 })
        if (result.exitCode !== 0) return { exitCode: Number.isInteger(result.exitCode) && result.exitCode > 0 && result.exitCode <= 255 ? result.exitCode : 1, passed: false, facts: [] }
        const evidence = validateRestrictedTokenProbeOutput(result.stdout, result.stderr, { mode })
        return { exitCode: evidence.passed ? 0 : 1, ...evidence }
    } catch {
        return { exitCode: 1, passed: false, facts: [] }
    }
}

/** @returns {Promise<void>} Runs only the fixed gate and emits sanitized evidence. */
async function main() {
    const mode = process.argv.length === 2 ? 'baseline' : process.argv.length === 3 && process.argv[2] === '--medium' ? 'medium' : null
    if (mode === null) {
        process.stderr.write('openrdx-token-probe-gate passed=false arguments-rejected=true\n')
        process.exitCode = 1
        return
    }
    const result = await runRestrictedTokenProbe({ mode })
    for (const line of result.facts) process.stdout.write(`${line}\n`)
    process.stdout.write(`openrdx-token-probe-gate passed=${result.passed}\n`)
    process.exitCode = result.exitCode
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main()
