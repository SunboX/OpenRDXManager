// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify, stripVTControlCharacters } from 'node:util'
import { debuggerControlEvidence } from './windows-debugger-control-evidence.mjs'
import { actualTokenControlEvidence } from './windows-actual-token-control-evidence.mjs'
import { objectMatrixEvidence } from './windows-object-dacl-matrix-evidence.mjs'
import { processControlEvidence, processControlRequirements } from './windows-process-dacl-control-evidence.mjs'
import { sourceControlEvidence, sourceControlRequirements } from './windows-source-token-control-evidence.mjs'

const execFileAsync = promisify(execFile)
const projectRoot = fileURLToPath(new URL('..', import.meta.url))
const maximumOutputBytes = 65_536
const testNames = Object.freeze({
    'debugger-control': 'service_acl::windows_impl::restricted_token_probe::medium::child::debugger_control::native_owned_medium_debugger_control',
    'actual-token-dacl-control': 'service_acl::windows_impl::restricted_token_probe::medium::child::actual_token_control::native_actual_child_token_dacl_control',
    baseline: 'service_acl::windows_impl::restricted_token_probe::native_restricted_token_observations',
    medium: 'service_acl::windows_impl::restricted_token_probe::medium::native_medium_restricted_token_observations',
    child: 'service_acl::windows_impl::restricted_token_probe::medium::child::native_medium_restricted_child_observations',
    'source-control': 'service_acl::windows_impl::restricted_token_probe::medium::child::source_control::native_source_context_child_control',
    'object-dacl-controls': 'service_acl::windows_impl::restricted_token_probe::medium::child::object_dacl_controls::native_object_dacl_matrix',
    'process-dacl-control': 'service_acl::windows_impl::restricted_token_probe::medium::child::process_dacl_control::native_process_dacl_child_control'
})
const mediumRequirements = Object.freeze({ 'source-open': true, 'derived-created': true, 'query-ok': true, 'medium-set-ok': true, 'source-unchanged': true, 'same-user': true, 'same-session': true, 'source-active-console': true, 'derived-active-console': true, 'source-console-user-match': true, 'derived-console-user-match': true, 'source-elevated': true, 'derived-elevated': false, 'source-integrity-high': true, 'admin-deny-only': true, 'no-enabled-admins': true, 'enabled-privilege-whitelist': true, 'present-privilege-whitelist': true, 'privileges-reduced': true, 'no-added-privileges': true, 'integrity-medium': true, 'integrity-high': false, 'integrity-reduced': true, 'ui-access-zero': true, 'sandbox-inert-zero': true, 'primary-token': true, 'elevation-type-known': true, 'elevation-type-full': false })
const childRequirements = Object.freeze({ 'source-open': true, 'derived-created': true, 'query-ok': true, 'fixture-protected': true, 'child-created': true, 'child-image-match': true, 'child-same-user': true, 'child-same-session': true, 'child-console-user-match': true, 'child-active-console': true, 'child-elevated': false, 'child-admin-deny-only': true, 'child-no-enabled-admins': true, 'child-present-privilege-whitelist': true, 'child-medium': true, 'child-ui-access-zero': true, 'child-sandbox-inert-zero': true, 'child-primary': true, 'child-suspended-proof': true, 'child-resumed': true, 'child-exited': true, 'child-exit-zero': true, 'owned-child-cleanup': true, 'negative-proof-reaped': true, 'timeout-reaped': true, 'api-error-rejected': true })
const diagnosticKeys = new Set([...Object.keys(mediumRequirements), ...Object.keys(childRequirements), 'source-unchanged-after-create', 'source-admin-deny-only', 'source-no-enabled-admins', 'source-integrity-low', 'source-integrity-medium', 'source-integrity-system', 'integrity-low', 'integrity-system', 'elevation-type-default', 'elevation-type-limited'])
const childPhases = new Set(['source-open', 'source-query', 'console-query', 'source-console', 'derive', 'medium', 'predicate-negatives', 'proof-fixture', 'query-only-token', 'api-denial', 'negative-create', 'negative-proof', 'negative-reap', 'timeout-fixture', 'timeout-create', 'timeout-proof', 'timeout-resume', 'timeout-wait', 'timeout-reap', 'timeout-cleanup', 'positive-create', 'source-requery', 'positive-proof', 'positive-resume', 'positive-wait', 'positive-cleanup'])
const nativeReasons = new Set(['UnsupportedPlatform', 'InvalidRequest', 'AccessDenied', 'Busy', 'ReadOnly', 'Cancelled', 'TimedOut', 'DeviceRemoved', 'NoMedia', 'EnumerationFailed', 'EvidenceIncomplete', 'ResourceLimit', 'Other'])
const childExitCategories = new Set(['success', 'self-token-open', 'self-process-session', 'self-console-session', 'self-token-session', 'self-elevation', 'self-ui-access', 'self-sandbox-inert', 'self-primary', 'self-integrity', 'status-dll-not-found', 'status-dll-init-failed', 'status-invalid-image-format', 'unknown'])
const desktopContextKeys = new Set(['source-groups-query-ok', 'source-logon-single', 'derived-groups-query-ok', 'derived-logon-single', 'logon-same', 'source-interactive-enabled', 'source-batch-enabled', 'source-service-enabled', 'derived-interactive-enabled', 'derived-batch-enabled', 'derived-service-enabled', 'current-station-query-ok', 'current-station-winsta-zero', 'current-desktop-query-ok', 'current-desktop-default', 'station-descriptor-query-ok', 'desktop-descriptor-query-ok', 'source-station-access-query-ok', 'source-station-access-allowed', 'derived-station-access-query-ok', 'derived-station-access-allowed', 'source-desktop-access-query-ok', 'source-desktop-access-allowed', 'derived-desktop-access-query-ok', 'derived-desktop-access-allowed'])
const mandatoryContextKeys = new Set([...['station', 'desktop'].flatMap((subject) => ['query-ok', 'query-unsupported', 'parse-valid', 'present', 'single', 'known', 'implicit-medium', 'low', 'medium', 'high', 'system', 'policy-known', 'no-write-up', 'no-read-up', 'no-execute-up'].map((key) => `${subject}-label-${key}`)), ...['source', 'derived'].flatMap((subject) => ['query-ok', 'known', 'off', 'no-write-up', 'new-process-min'].map((key) => `${subject}-policy-${key}`))])
const libraryContextKeys = new Set(['system-directory-query-ok', ...['source', 'derived'].flatMap((subject) => ['restricted-sids-query-ok', 'restricted-sids-empty', 'restricted-sids-present', 'has-restrictions-query-ok', 'has-restrictions-api-ok', 'has-restrictions-size-match', 'has-restrictions'].map((key) => `${subject}-${key}`)), ...['kernel32', 'advapi32'].flatMap((library) => ['file-query-ok', 'descriptor-query-ok'].map((key) => `${library}-${key}`)), ...['source', 'derived'].flatMap((subject) => ['kernel32', 'advapi32'].flatMap((library) => ['read', 'execute'].flatMap((access) => ['query-ok', 'allowed'].map((key) => `${subject}-${library}-${access}-${key}`))))])
const windowAccessKeys = new Set(['source', 'derived'].flatMap((subject) => ['station', 'desktop'].flatMap((object) => ['read-control', 'full'].flatMap((access) => ['query-ok', 'allowed'].map((key) => `${subject}-${object}-${access}-${key}`)))))

const objectContextKeys = new Set(['child-process-descriptor-query-ok', 'child-thread-descriptor-query-ok', 'child-token-open-query-ok', 'child-token-descriptor-query-ok', ...['source', 'derived'].flatMap((subject) => ['default-dacl-query-ok', 'default-dacl-valid', 'default-dacl-null', 'owner-query-ok', 'owner-equals-user'].map((key) => `${subject}-${key}`)), ...['source', 'derived', 'actual'].flatMap((subject) => ['process', 'thread', 'token'].flatMap((object) => (object === 'token' ? ['read-control', 'query', 'all'] : ['read-control', 'query', 'synchronize', 'all']).flatMap((access) => ['query-ok', 'allowed'].map((key) => `${subject}-${object}-${access}-${key}`))))])

const effectiveContextKeys = new Set([
    'actual-snapshot-query-ok',
    'derived-fresh-snapshot-query-ok',
    'actual-derived-snapshot-match',
    'fixture-root-descriptor-query-ok',
    'fixture-image-descriptor-query-ok',
    ...['user', 'session', 'elevation', 'integrity', 'ui-access', 'sandbox-inert', 'type', 'elevation-type', 'groups', 'privileges'].map((key) => `actual-derived-${key}-match`),
    ...['child-process', 'child-thread', 'child-token', 'fixture-root', 'fixture-image'].flatMap((object) => ['query-ok', 'query-unsupported', 'parse-valid', 'present', 'single', 'known', 'implicit-medium', 'low', 'medium', 'high', 'system', 'policy-known', 'no-write-up', 'no-read-up', 'no-execute-up'].map((key) => `${object}-label-${key}`)),
    ...['source', 'derived', 'actual'].flatMap((subject) => ['principals-query-ok', 'builtin-users-enabled', 'logon-single', 'logon-enabled'].map((key) => `${subject}-${key}`)),
    ...['source', 'derived', 'actual'].flatMap((subject) => ['root', 'image'].flatMap((object) => ['read', 'execute'].flatMap((access) => ['query-ok', 'allowed'].map((key) => `${subject}-fixture-${object}-${access}-${key}`))))
])

/**
 * Reconstructs only bounded, schema-validated partial diagnostics; never authorizes a pass.
 * @param {string} stdout - Captured standard output, never forwarded verbatim.
 * @param {string} stderr - Captured standard error, used only for the combined bound.
 * @returns {{facts: string[], context: string[], mandatoryContext: string[], libraryContext: string[], objectContext: string[], effectiveContext: string[], sourceControl: string[], processControl: string[], objectMatrix: string[], stage: string|null, childExit: string|null, observedFailure: boolean, seen: Map<string,boolean>, reason: string|null}} Closed evidence.
 */
function closedEvidence(stdout, stderr) {
    /** @param {string} reason Fixed rejection token. @returns {object} Empty fail-closed diagnostics. */
    const reject = (reason) => ({ facts: [], context: [], mandatoryContext: [], libraryContext: [], objectContext: [], effectiveContext: [], sourceControl: [], processControl: [], objectMatrix: [], actualControl: [], debuggerControl: [], stage: null, childExit: null, observedFailure: false, seen: new Map(), reason })
    if (typeof stdout !== 'string' || typeof stderr !== 'string') return reject('output-type')
    if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > maximumOutputBytes) return reject('output-bound')
    const debuggerEvidence = debuggerControlEvidence(stripVTControlCharacters(stdout).split(/\r?\n/u))
    if (debuggerEvidence.reason !== null) return reject(debuggerEvidence.reason)
    const debuggerControl = debuggerEvidence.lines
    const actualEvidence = actualTokenControlEvidence(stripVTControlCharacters(stdout).split(/\r?\n/u))
    if (actualEvidence.reason !== null) return reject(actualEvidence.reason)
    const actualControl = actualEvidence.lines
    const matrixEvidence = objectMatrixEvidence(stripVTControlCharacters(stdout).split(/\r?\n/u))
    if (matrixEvidence.reason !== null) return reject(matrixEvidence.reason)
    const objectMatrix = matrixEvidence.lines
    const sourceEvidence = sourceControlEvidence(stripVTControlCharacters(stdout).split(/\r?\n/u))
    if (sourceEvidence.reason !== null) return reject(sourceEvidence.reason)
    const sourceControl = sourceEvidence.lines
    const processEvidence = processControlEvidence(stripVTControlCharacters(stdout).split(/\r?\n/u))
    if (processEvidence.reason !== null) return reject(processEvidence.reason)
    const processControl = processEvidence.lines
    const facts = []
    const context = []
    const contextSeen = new Set()
    const mandatoryContext = []
    const mandatorySeen = new Set()
    const libraryContext = []
    const librarySeen = new Set()
    const objectContext = []
    const objectSeen = new Set()
    const effectiveContext = []
    const effectiveSeen = new Set()
    let stage = null
    let observedFailure = false
    let stageFailure = false
    let childExit = null
    let childExitFailure = false
    const exitPhases = new Set()
    const seen = new Map()
    for (const line of stripVTControlCharacters(stdout).split(/\r?\n/u)) {
        if (line.startsWith('openrdx-token-probe ')) {
            const pairs = []
            for (const pair of line.slice('openrdx-token-probe '.length).split(' ')) {
                const match = /^([a-z-]+)=(true|false)$/u.exec(pair)
                if (match === null || !diagnosticKeys.has(match[1])) return reject('fact-schema')
                if (seen.has(match[1])) return reject('fact-duplicate')
                seen.set(match[1], match[2] === 'true')
                pairs.push(`${match[1]}=${match[2]}`)
            }
            facts.push(`openrdx-token-probe ${pairs.join(' ')}`)
        } else if (line.startsWith('openrdx-token-probe-stage ')) {
            const match = /^openrdx-token-probe-stage phase=([a-z-]+) status=(begin|ok|failed)(?: reason=([A-Za-z]+))?$/u.exec(line)
            if (match === null || !childPhases.has(match[1]) || (match[2] === 'failed' ? !nativeReasons.has(match[3]) : match[3] !== undefined)) return reject('stage-schema')
            // Keep the first failed transition even if cleanup or contradictory
            // later evidence supplies ok/begin. Later markers cannot authorize a pass.
            if (!stageFailure) stage = `openrdx-token-probe-stage phase=${match[1]} status=${match[2]}${match[3] === undefined ? '' : ` reason=${match[3]}`}`
            if (match[2] === 'failed') {
                stageFailure = true
                observedFailure = true
            }
        } else if (line.startsWith('openrdx-token-desktop-context ')) {
            const pairs = []
            for (const pair of line.slice('openrdx-token-desktop-context '.length).split(' ')) {
                const match = /^([a-z-]+)=(true|false)$/u.exec(pair)
                if (match === null || !desktopContextKeys.has(match[1]) || contextSeen.has(match[1])) return reject('desktop-context-schema')
                contextSeen.add(match[1])
                pairs.push(`${match[1]}=${match[2]}`)
            }
            // These are observations only: neither denied nor allowed DACL facts
            // alter native child execution/admission requirements.
            context.push(`openrdx-token-desktop-context ${pairs.join(' ')}`)
        } else if (line.startsWith('openrdx-token-mandatory-context ')) {
            const pairs = []
            for (const pair of line.slice('openrdx-token-mandatory-context '.length).split(' ')) {
                const match = /^([a-z-]+)=(true|false)$/u.exec(pair)
                if (match === null || !mandatoryContextKeys.has(match[1]) || mandatorySeen.has(match[1])) return reject('mandatory-context-schema')
                mandatorySeen.add(match[1])
                pairs.push(`${match[1]}=${match[2]}`)
            }
            // Label and token-policy observations never change child admission.
            mandatoryContext.push(`openrdx-token-mandatory-context ${pairs.join(' ')}`)
        } else if (line.startsWith('openrdx-token-library-context ') || line.startsWith('openrdx-token-window-access ')) {
            const window = line.startsWith('openrdx-token-window-access ')
            const prefix = window ? 'openrdx-token-window-access ' : 'openrdx-token-library-context '
            const keys = window ? windowAccessKeys : libraryContextKeys
            const pairs = []
            for (const pair of line.slice(prefix.length).split(' ')) {
                const match = /^([a-z0-9-]+)=(true|false)$/u.exec(pair)
                if (match === null || !keys.has(match[1]) || librarySeen.has(match[1])) return reject('library-context-schema')
                librarySeen.add(match[1])
                pairs.push(`${match[1]}=${match[2]}`)
            }
            // File/window rights and restricting-SID facts are observations only.
            libraryContext.push(`${prefix}${pairs.join(' ')}`)
        } else if (line.startsWith('openrdx-token-object-context ')) {
            const pairs = []
            for (const pair of line.slice('openrdx-token-object-context '.length).split(' ')) {
                const match = /^([a-z-]+)=(true|false)$/u.exec(pair)
                if (match === null || !objectContextKeys.has(match[1]) || objectSeen.has(match[1])) return reject('object-context-schema')
                objectSeen.add(match[1])
                pairs.push(`${match[1]}=${match[2]}`)
            }
            // Actual child descriptors remain observations, never execution authority.
            objectContext.push(`openrdx-token-object-context ${pairs.join(' ')}`)
        } else if (line.startsWith('openrdx-token-effective-context ')) {
            const pairs = []
            for (const pair of line.slice('openrdx-token-effective-context '.length).split(' ')) {
                const match = /^([a-z-]+)=(true|false)$/u.exec(pair)
                if (match === null || !effectiveContextKeys.has(match[1]) || effectiveSeen.has(match[1])) return reject('effective-context-schema')
                effectiveSeen.add(match[1])
                pairs.push(`${match[1]}=${match[2]}`)
            }
            // Labels/fixture/full-rights/token comparisons are optional observations only.
            effectiveContext.push(`openrdx-token-effective-context ${pairs.join(' ')}`)
        } else if (line.startsWith('openrdx-token-child-exit ')) {
            const match = /^openrdx-token-child-exit phase=(timeout-wait|positive-wait) category=([a-z-]+)$/u.exec(line)
            if (match === null || !childExitCategories.has(match[2])) return reject('child-exit-schema')
            if (exitPhases.has(match[1])) return reject('child-exit-duplicate')
            exitPhases.add(match[1])
            // Any early timeout exit is failure, including zero. Keep its original
            // category if later contradictory evidence claims successful execution.
            if (!childExitFailure) childExit = `openrdx-token-child-exit phase=${match[1]} category=${match[2]}`
            if (match[1] === 'timeout-wait' || match[2] !== 'success') {
                childExitFailure = true
                observedFailure = true
            }
        }
    }
    return { facts, context, mandatoryContext, libraryContext, objectContext, effectiveContext, sourceControl, sourceEvidence, processControl, processEvidence, objectMatrix, matrixEvidence, actualControl, actualEvidence, debuggerControl, debuggerEvidence, stage, childExit, observedFailure, seen, reason: null }
}

/**
 * Validates exact execution evidence and retains only closed boolean diagnostics.
 * Successful token queries do not establish Manager eligibility.
 * @param {string} stdout - Bounded Cargo standard output.
 * @param {string} stderr - Bounded Cargo standard error, never forwarded.
 * @param {object} [options] - Fixed experiment selection.
 * @param {'baseline'|'medium'|'child'|'source-control'|'process-dacl-control'|'object-dacl-controls'|'actual-token-dacl-control'|'debugger-control'} [options.mode] - Exact approved experiment.
 * @returns {{passed: boolean, facts: string[], reason: string}} Exact execution verdict and closed rejection reason.
 */
export function validateRestrictedTokenProbeOutput(stdout, stderr, { mode = 'baseline' } = {}) {
    /** @param {string} reason Fixed rejection token. @returns {object} Failed verdict without acceptance facts. */
    const failed = (reason) => ({ passed: false, facts: [], reason })
    if (!Object.hasOwn(testNames, mode)) return failed('mode')
    const closed = closedEvidence(stdout, stderr)
    if (closed.reason !== null) return failed(closed.reason)
    if (mode !== 'debugger-control' && closed.debuggerControl.length !== 0) return failed('debugger-control-mode')
    if (mode === 'debugger-control' && ([closed.facts, closed.context, closed.mandatoryContext, closed.libraryContext, closed.objectContext, closed.effectiveContext, closed.sourceControl, closed.processControl, closed.objectMatrix, closed.actualControl].some((lines) => lines.length !== 0) || closed.stage !== null || closed.childExit !== null)) return failed('debugger-control-cross-mode')
    if (mode === 'debugger-control' && (!closed.debuggerEvidence.complete || !closed.debuggerEvidence.reproduced || closed.debuggerEvidence.changed)) return failed('debugger-control-evidence')
    if (mode !== 'actual-token-dacl-control' && closed.actualControl.length !== 0) return failed('actual-control-mode')
    if (mode === 'actual-token-dacl-control' && ([closed.facts, closed.context, closed.mandatoryContext, closed.libraryContext, closed.objectContext, closed.effectiveContext, closed.sourceControl, closed.processControl, closed.objectMatrix].some((lines) => lines.length !== 0) || closed.stage !== null || closed.childExit !== null)) return failed('actual-control-cross-mode')
    if (mode === 'actual-token-dacl-control' && (!closed.actualEvidence.complete || !closed.actualEvidence.startupProof)) return failed('actual-control-evidence')
    if (mode !== 'object-dacl-controls' && closed.objectMatrix.length !== 0) return failed('object-matrix-mode')
    if (mode === 'object-dacl-controls' && (closed.stage !== null || closed.childExit !== null)) return failed('object-matrix-cross-mode')
    if (mode === 'object-dacl-controls' && [closed.facts, closed.context, closed.mandatoryContext, closed.libraryContext, closed.objectContext, closed.effectiveContext, closed.sourceControl, closed.processControl].some((lines) => lines.length !== 0)) return failed('object-matrix-cross-mode')
    if (mode === 'object-dacl-controls' && !closed.matrixEvidence.complete) return failed('object-matrix-evidence')
    if (mode !== 'process-dacl-control' && closed.processControl.length !== 0) return failed('process-control-mode')
    if (mode === 'process-dacl-control' && (closed.processEvidence.failure || closed.processEvidence.exits.get('baseline-wait') !== 'status-dll-init-failed' || closed.processEvidence.exits.get('positive-wait') !== 'success' || closed.processEvidence.lastStatus !== 'ok' || Object.entries(processControlRequirements).some(([key, expected]) => closed.processEvidence.seen.get(key) !== expected))) return failed('process-control-evidence')
    if (mode !== 'source-control' && closed.sourceControl.length !== 0) return failed('source-control-mode')
    if (mode === 'source-control' && (closed.sourceEvidence.failure || closed.sourceEvidence.exit !== 'self-elevation' || closed.sourceEvidence.lastStatus !== 'ok' || Object.entries(sourceControlRequirements).some(([key, expected]) => closed.sourceEvidence.seen.get(key) !== expected))) return failed('source-control-evidence')
    if (closed.observedFailure || (closed.stage !== null && !closed.stage.includes(' status=ok'))) return failed('stage-result')
    if (mode === 'child' && closed.childExit !== 'openrdx-token-child-exit phase=positive-wait category=success') return failed('child-exit-evidence')
    if (mode !== 'child' && closed.childExit !== null) return failed('child-exit-mode')
    const lines = stripVTControlCharacters(stdout).split(/\r?\n/u)
    if (lines.filter((line) => /^running \d+ tests?$/u.test(line)).length !== 1 || !lines.includes('running 1 test')) return failed('running-count')
    if (lines.filter((line) => line.startsWith('test result:')).length !== 1 || !lines.some((line) => /^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in \d+(?:\.\d+)?s$/u.test(line))) return failed('test-summary')
    const namedResults = lines.filter((line) => line.startsWith('test ') && !line.startsWith('test result:'))
    if (namedResults.length !== 1 || namedResults[0] !== `test ${testNames[mode]} ... ok`) return failed('named-result')
    const { seen, facts } = closed
    if (!['source-control', 'process-dacl-control', 'object-dacl-controls', 'actual-token-dacl-control', 'debugger-control'].includes(mode) && (seen.get('source-open') !== true || seen.get('derived-created') !== true || seen.get('query-ok') !== true)) return failed('query-facts')
    if (mode === 'medium' && (Object.entries(mediumRequirements).some(([key, expected]) => seen.get(key) !== expected) || !seen.has('elevation-type-default') || !seen.has('elevation-type-limited') || Number(seen.get('elevation-type-default')) + Number(seen.get('elevation-type-limited')) !== 1)) return failed('medium-facts')
    if (mode === 'child' && Object.entries(childRequirements).some(([key, expected]) => seen.get(key) !== expected)) return failed('child-facts')
    return { passed: true, facts, reason: 'none' }
}

/**
 * Runs the fixed Cargo probe without a shell, with bounded output and deadline.
 * @param {string} command - Fixed Cargo executable.
 * @param {readonly string[]} args - Fixed ignored/exact probe arguments.
 * @param {object} options - Closed child execution options.
 * @returns {Promise<object>} Original Cargo exit or a separately classified execution error, with captured output.
 */
async function executeProbe(command, args, options) {
    try {
        const { stdout, stderr } = await execFileAsync(command, args, options)
        return { exitCode: 0, stdout, stderr }
    } catch (error) {
        // Numeric Cargo failures remain failures even if stdout resembles success.
        // Launch, signal, timeout and buffer errors have no reusable Cargo exit code.
        const cargoExit = Number.isInteger(error.code) && error.code > 0 && error.code <= 255 ? error.code : null
        const executionError = cargoExit !== null ? null : error.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' ? 'buffer' : error.killed ? 'timeout' : error.signal ? 'signal' : 'launch'
        return { exitCode: cargoExit, executionError, stdout: typeof error.stdout === 'string' ? error.stdout : '', stderr: typeof error.stderr === 'string' ? error.stderr : '' }
    }
}

/**
 * Requires one exact native test plus successful closed kernel-query evidence.
 * @param {object} [options] - Test-only execution dependency.
 * @param {Function} [options.execute] - Awaited executor; receives only the fixed command/options.
 * @param {'baseline'|'medium'|'child'|'source-control'|'process-dacl-control'|'object-dacl-controls'|'actual-token-dacl-control'|'debugger-control'} [options.mode] - Fixed experiment, never an arbitrary native filter.
 * @returns {Promise<object>} Fail-closed verdict preserving genuine Cargo failure and separately labeling execution errors.
 */
export async function runRestrictedTokenProbe({ execute = executeProbe, mode = 'baseline' } = {}) {
    try {
        if (!Object.hasOwn(testNames, mode)) return { exitCode: 1, passed: false, facts: [], context: [], mandatoryContext: [], libraryContext: [], objectContext: [], effectiveContext: [], sourceControl: [], processControl: [], objectMatrix: [], actualControl: [], debuggerControl: [], stage: null, childExit: null, cargoExitCode: null, failureClass: 'evidence', failureReason: 'mode' }
        // Serial libtest prints the test-name prefix before nocapture output. Two fixed
        // threads keep the exact standalone name/result and diagnostic line contract.
        const cargoArguments = Object.freeze(['test', '--manifest-path', 'native/rdx-service/windows-native/Cargo.toml', '--locked', '--lib', testNames[mode], '--', '--ignored', '--exact', '--nocapture', '--test-threads=2'])
        const result = await execute('cargo', cargoArguments, { cwd: projectRoot, shell: false, windowsHide: true, encoding: 'utf8', maxBuffer: maximumOutputBytes, timeout: 120_000 })
        if (result.executionError || !Number.isInteger(result.exitCode) || result.exitCode < 0 || result.exitCode > 255) return { exitCode: 1, passed: false, facts: [], context: [], mandatoryContext: [], libraryContext: [], objectContext: [], effectiveContext: [], sourceControl: [], processControl: [], objectMatrix: [], actualControl: [], debuggerControl: [], stage: null, childExit: null, cargoExitCode: null, failureClass: 'execution', failureReason: ['timeout', 'buffer', 'signal', 'launch'].includes(result.executionError) ? result.executionError : 'launch' }
        const closed = closedEvidence(result.stdout, result.stderr)
        const diagnostics = { facts: closed.facts, context: closed.context, mandatoryContext: closed.mandatoryContext, libraryContext: closed.libraryContext, objectContext: closed.objectContext, effectiveContext: closed.effectiveContext, sourceControl: closed.sourceControl, processControl: closed.processControl, objectMatrix: closed.objectMatrix, actualControl: closed.actualControl, debuggerControl: closed.debuggerControl, stage: closed.stage, childExit: closed.childExit, cargoExitCode: result.exitCode }
        if (result.exitCode !== 0) return { exitCode: result.exitCode, passed: false, ...diagnostics, failureClass: 'native-exit', failureReason: 'cargo-nonzero' }
        const evidence = validateRestrictedTokenProbeOutput(result.stdout, result.stderr, { mode })
        return { exitCode: evidence.passed ? 0 : 1, passed: evidence.passed, ...diagnostics, failureClass: evidence.passed ? 'none' : 'evidence', failureReason: evidence.reason }
    } catch {
        return { exitCode: 1, passed: false, facts: [], context: [], mandatoryContext: [], libraryContext: [], objectContext: [], effectiveContext: [], sourceControl: [], processControl: [], objectMatrix: [], actualControl: [], debuggerControl: [], stage: null, childExit: null, cargoExitCode: null, failureClass: 'execution', failureReason: 'launch' }
    }
}

/** @returns {Promise<void>} Runs only the fixed gate and emits sanitized evidence. */
async function main() {
    const mode = process.argv.length === 2 ? 'baseline' : process.argv.length === 3 && process.argv[2] === '--medium' ? 'medium' : process.argv.length === 3 && process.argv[2] === '--child' ? 'child' : process.argv.length === 3 && process.argv[2] === '--source-control' ? 'source-control' : process.argv.length === 3 && process.argv[2] === '--process-dacl-control' ? 'process-dacl-control' : process.argv.length === 3 && process.argv[2] === '--object-dacl-controls' ? 'object-dacl-controls' : process.argv.length === 3 && process.argv[2] === '--actual-token-dacl-control' ? 'actual-token-dacl-control' : process.argv.length === 3 && process.argv[2] === '--debugger-control' ? 'debugger-control' : null
    if (mode === null) {
        process.stderr.write('openrdx-token-probe-gate passed=false arguments-rejected=true\n')
        process.exitCode = 1
        return
    }
    const result = await runRestrictedTokenProbe({ mode })
    for (const line of result.facts) process.stdout.write(`${line}\n`)
    for (const line of result.context) process.stdout.write(`${line}\n`)
    for (const line of result.mandatoryContext) process.stdout.write(`${line}\n`)
    for (const line of result.libraryContext) process.stdout.write(`${line}\n`)
    for (const line of result.objectContext) process.stdout.write(`${line}\n`)
    for (const line of result.effectiveContext) process.stdout.write(`${line}\n`)
    for (const line of result.sourceControl) process.stdout.write(`${line}\n`)
    for (const line of result.processControl) process.stdout.write(`${line}\n`)
    for (const line of result.objectMatrix) process.stdout.write(`${line}\n`)
    for (const line of result.actualControl) process.stdout.write(`${line}\n`)
    for (const line of result.debuggerControl) process.stdout.write(`${line}\n`)
    if (result.stage !== null) process.stdout.write(`${result.stage}\n`)
    if (result.childExit !== null) process.stdout.write(`${result.childExit}\n`)
    process.stdout.write(`openrdx-token-probe-gate passed=${result.passed} class=${result.failureClass} reason=${result.failureReason} cargo-exit-observed=${result.cargoExitCode !== null} cargo-exit-zero=${result.cargoExitCode === 0} cargo-exit-nonzero=${result.cargoExitCode !== null && result.cargoExitCode !== 0}\n`)
    process.exitCode = result.exitCode
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main()
