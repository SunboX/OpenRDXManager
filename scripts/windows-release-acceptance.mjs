// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { lstat, open } from 'node:fs/promises'
import { join, parse, resolve } from 'node:path'
import { expectedInstallerNames, verifyReleaseAssets } from './release-assets.mjs'

const receiptLimit = 65536
const metadataLimit = 1048576
const shaPattern = /^[a-f0-9]{64}$/u
const commitPattern = /^[a-f0-9]{40}$/u
const repositoryPattern = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u
const actorPattern = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/u
const maxAge = 7 * 24 * 60 * 60 * 1000
const futureSkew = 5 * 60 * 1000
const receiptKeys = ['schemaVersion', 'version', 'repository', 'buildRunId', 'buildRunAttempt', 'sourceCommit', 'verifierSha256', 'reviewedBy', 'reviewedAt', 'windows']
const entryKeys = ['architecture', 'installer', 'installerSha256', 'completedAt', 'evidenceSha256', 'evidence']
const reportKeys = ['version', 'sourceCommit', 'mode', 'status', 'phase', 'completed', 'failure', 'childCleanup']
const fullMarker = 'OpenRDX Windows installation acceptance passed: clean, repair, upgrade, tamper-denied, copied-manager-denied, owned-removal'
const authMarker = 'OpenRDXManager installed service authentication passed: platform=win32'
const mcpMarker = 'OpenRDXManager packaged MCP bridge passed: external-node=true'
const workerMarker = 'OpenRDX Manager worker: prerequisite=ready elevation-query=True elevation-size-match=True elevated=False token-process-session-match=True token-console-match=True'
const managerMarker = 'OpenRDX worker-selected Manager: elevation-query=True elevation-size-match=True elevated=False session-query=True session-size-match=True process-session-query=True token-process-session-match=True token-console-match=True process-console-match=True'
const copiedMarker = 'Windows copied Manager privileged authentication denied'
const tamperMarker = 'OpenRDX native failure: phase=verify-enrollment reason=AccessDenied'

/** @param {boolean} condition Required invariant. @param {string} reason Fixed nonprivate failure code. @returns {void} @throws {Error} When the invariant fails. */
function requireFact(condition, reason) {
    if (!condition) throw new Error(`windows-release-acceptance: ${reason}`)
}

/** @param {unknown} value JSON object. @param {string[]} keys Required exact fields. @param {string[]} [optional] Permitted optional fields. @returns {void} @throws {Error} For missing/extra fields or nonobjects. */
function exactKeys(value, keys, optional = []) {
    requireFact(value !== null && typeof value === 'object' && !Array.isArray(value), 'invalid-object')
    requireFact(keys.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => keys.includes(key) || optional.includes(key)), 'invalid-fields')
}

/** @param {unknown} value Decimal run ID. @returns {string} Validated decimal ID. @throws {Error} For nonpositive, noncanonical or unsafe values. */
function decimalId(value) {
    requireFact((typeof value === 'string' && /^[1-9]\d*$/u.test(value)) || (typeof value === 'number' && Number.isSafeInteger(value)), 'invalid-run-id')
    requireFact(Number.isSafeInteger(Number(value)) && Number(value) > 0, 'invalid-run-id')
    return String(value)
}

/** @param {unknown} value UTC ISO timestamp. @returns {number} Epoch milliseconds. @throws {Error} For malformed or impossible calendar timestamps. */
function timestamp(value) {
    requireFact(typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/u.test(value), 'invalid-timestamp')
    const time = Date.parse(value)
    requireFact(Number.isFinite(time) && new Date(time).toISOString().slice(0, 19) === value.slice(0, 19), 'invalid-timestamp')
    return time
}

/**
 * Validates authenticated GitHub API run metadata; does not infer execution from a receipt.
 * @param {object} run GitHub workflow run response.
 * @param {{repository:string, runId:string|number}} options Exact selected repository/run.
 * @returns {{sourceCommit:string, runId:string, runAttempt:number, startedAt:string}} Fixed candidate metadata.
 * @throws {Error} For mismatched workflow, source, repository, branch, event or unsuccessful run.
 */
export function validateBuildRun(run, { repository, runId }) {
    requireFact(typeof repository === 'string' && repositoryPattern.test(repository), 'invalid-repository')
    const selected = decimalId(runId)
    requireFact(run !== null && typeof run === 'object' && !Array.isArray(run), 'invalid-run')
    requireFact(decimalId(run.id) === selected, 'wrong-run')
    requireFact(Number.isSafeInteger(run.run_attempt) && run.run_attempt > 0, 'invalid-run-attempt')
    requireFact(run.head_repository?.full_name === repository && (run.repository === undefined || run.repository?.full_name === repository), 'foreign-run')
    requireFact(run.name === 'Build installers' && run.path === '.github/workflows/build-installers.yml', 'wrong-workflow')
    requireFact(run.head_branch === 'main' && ['push', 'workflow_dispatch'].includes(run.event), 'wrong-run-origin')
    requireFact(run.status === 'completed' && run.conclusion === 'success', 'unsuccessful-run')
    requireFact(typeof run.head_sha === 'string' && commitPattern.test(run.head_sha), 'invalid-source-commit')
    timestamp(run.run_started_at)
    return { sourceCommit: run.head_sha, runId: selected, runAttempt: run.run_attempt, startedAt: run.run_started_at }
}

/**
 * Rejects symlinks in an input path, including parent directories, before reading or writing.
 * @param {string} path Absolute or relative local path.
 * @param {boolean} [allowMissingLeaf] Permits only an absent final output file.
 * @returns {Promise<void>} Completes once every existing component is checked.
 * @throws {Error} For linked paths, nondirectory parents or unavailable paths.
 */
export async function assertAcceptancePath(path, allowMissingLeaf = false) {
    requireFact(typeof path === 'string' && path.length > 0 && !path.includes('\0'), 'invalid-path')
    const absolute = resolve(path)
    const root = parse(absolute).root
    const components = absolute.slice(root.length).split(/[\\/]/u).filter(Boolean)
    let current = root
    for (let index = 0; index < components.length; index++) {
        current = join(current, components[index])
        let info
        try {
            info = await lstat(current)
        } catch (error) {
            if (error.code === 'ENOENT' && allowMissingLeaf && index === components.length - 1) return
            throw new Error('windows-release-acceptance: unavailable-path')
        }
        requireFact(!info.isSymbolicLink(), 'linked-path')
        if (index < components.length - 1) requireFact(info.isDirectory(), 'invalid-parent-directory')
    }
}

/**
 * Reads a bounded regular file with a no-follow final open and bounded allocation; never executes it.
 * @param {string} path Local input path.
 * @param {number} [limit] Maximum byte count, defaulting to metadata size.
 * @returns {Promise<Buffer>} Exact bounded bytes.
 * @throws {Error} For linked, oversized, missing or nonregular files.
 */
export async function readAcceptanceFile(path, limit = metadataLimit) {
    await assertAcceptancePath(path)
    const info = await lstat(path)
    requireFact(info.isFile() && info.nlink === 1 && info.size <= limit, 'invalid-input-file')
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
    try {
        const opened = await handle.stat()
        requireFact(opened.isFile() && opened.nlink === 1 && opened.size <= limit, 'invalid-input-file')
        const bytes = Buffer.alloc(limit + 1)
        let offset = 0
        while (offset < bytes.length) {
            const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, null)
            if (bytesRead === 0) break
            offset += bytesRead
        }
        requireFact(offset <= limit, 'oversized-input-file')
        return bytes.subarray(0, offset)
    } finally {
        await handle.close()
    }
}

/** @param {unknown} value JSON tree. @returns {unknown} Recursively sorted tree, preserving array order. @throws {Error} For values outside finite JSON. */
function canonical(value) {
    if (Array.isArray(value)) return value.map(canonical)
    if (value !== null && typeof value === 'object')
        return Object.fromEntries(
            Object.keys(value)
                .sort()
                .map((key) => [key, canonical(value[key])])
        )
    requireFact(value === null || typeof value === 'string' || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value)), 'invalid-json-value')
    return value
}

/** @param {object} evidence Exported helper evidence. @returns {object} Copy dropping only the documented private VM identifier. @throws {Error} For non-JSON evidence. */
function retainedEvidence(evidence) {
    const copy = canonical(evidence)
    if (copy?.report && typeof copy.report === 'object') delete copy.report.vm
    return copy
}

/**
 * Hashes recursively key-sorted JSON after omitting only report.vm; normalized receipts retain the same hash.
 * This is evidence integrity for a reviewed operator attestation, never independent VM execution proof.
 * @param {object} evidence JSON helper evidence.
 * @returns {string} SHA-256 digest of retained canonical evidence.
 * @throws {Error} For non-JSON input.
 */
export function evidenceSha256(evidence) {
    return createHash('sha256')
        .update(JSON.stringify(retainedEvidence(evidence)))
        .digest('hex')
}

/** @param {string} text Bounded stdout. @returns {void} @throws {Error} For missing, contradictory or private transcript content. */
function validateStdout(text) {
    const lines = text.split(/\r?\n/u).filter((line) => line !== '')
    for (const [marker, count] of [
        [fullMarker, 1],
        [authMarker, 3],
        [mcpMarker, 3],
        [workerMarker, 3],
        [managerMarker, 3],
        [copiedMarker, 1],
        [tamperMarker, 1]
    ]) {
        requireFact(lines.filter((line) => line === marker).length === count, 'incomplete-acceptance-transcript')
    }
    const exact = new Set([fullMarker, authMarker, mcpMarker, workerMarker, managerMarker, copiedMarker, tamperMarker, 'OpenRDX interactive task: runlevel-query=True runlevel-is-lua=True', 'OpenRDX Manager launch: result=ok', 'OpenRDX setup verified: trust=local runtime=protected-and-hash-verified service=LocalService service-sid=unrestricted device-access=unverified', 'OpenRDX native failure: phase=entrypoint reason=AccessDenied', 'OpenRDX setup incomplete: launch installed Manager as the active console user, then rerun the elevated installer Repair action', 'OpenRDX setup verified: admission=revoked runtime=owned quiescence=verified', 'OpenRDX setup verified: service=removed enrollment=revoked journal=preserved', 'owned-remover-only-residue-scheduled-for-reboot'])
    // Default tokens without a linked elevated token are valid for a standard console user.
    const token = /^OpenRDX token context: subject=(?:worker|worker-selected-manager) type-query=True type-size-match=True (?:type-default=False type-full=False type-limited=True linked-query=True linked-size-match=True linked-available=True|type-default=True type-full=False type-limited=False linked-query=False linked-size-match=False linked-available=False)$/u
    const consoleContext = /^OpenRDX console context: uac-query=True enablelua-is-one=True local-builtin-admin-query=True local-builtin-admin=(?:True|False)$/u
    // These are closed software readiness flags; hardware=true is never physical-device proof.
    const readiness = /^OpenRDXManager service readiness: ready native hardware=(?:true|false) capability=available reason=none$/u
    const smoke = /^OpenRDXManager smoke test passed: renderer=mounted service=ready mode=native hardware=(?:true|false) capability=none reason=none$/u
    requireFact(
        lines.every((line) => exact.has(line) || token.test(line) || consoleContext.test(line) || readiness.test(line) || smoke.test(line)),
        'unrecognized-acceptance-transcript'
    )
    requireFact(lines.at(-1) === fullMarker, 'incomplete-acceptance-transcript')
}

/** @param {object} evidence Exported helper files. @param {string} architecture Exact EXE architecture. @param {string} sourceCommit Exact build source. @returns {object} Closed retained evidence. @throws {Error} For incomplete, failed or private evidence. */
function validateEvidence(evidence, architecture, sourceCommit) {
    exactKeys(evidence, ['report', 'stdout', 'stderr'])
    exactKeys(evidence.report, reportKeys, ['vm'])
    const report = evidence.report
    if (Object.hasOwn(report, 'vm')) requireFact(typeof report.vm === 'string' && /^(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|\{[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\})$/iu.test(report.vm), 'invalid-vm-identifier')
    requireFact(report.version === 1 && report.sourceCommit === sourceCommit && report.mode === architecture && report.status === 'passed' && report.phase === 'complete', 'failed-helper-report')
    requireFact(Array.isArray(report.completed) && report.completed.length === 1 && report.completed[0] === `acceptance-${architecture}` && report.failure === '' && report.childCleanup === 'observed-exit', 'incomplete-helper-report')
    requireFact(typeof evidence.stdout === 'string' && evidence.stderr === '', 'failed-helper-output')
    validateStdout(evidence.stdout)
    return retainedEvidence(evidence)
}

/** @param {string} path Safe regular installer. @returns {Promise<string>} Streaming SHA-256 digest. @throws {Error} For unreadable or nonregular files. */
async function installerSha256(path) {
    await assertAcceptancePath(path)
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
    try {
        requireFact((await handle.stat()).isFile() && (await handle.stat()).nlink === 1, 'invalid-installer')
        const hash = createHash('sha256')
        for await (const chunk of handle.createReadStream({ autoClose: false })) hash.update(chunk)
        return hash.digest('hex')
    } finally {
        await handle.close()
    }
}

/**
 * Verifies all sixteen trusted release assets and binds both reviewed VM reports to one exact build attempt.
 * Reads only candidate package.json and the Windows verifier; candidate code is never imported or run.
 * @param {{run:object,receipt:object,repository:string,actor:string,runId:string|number,sourceDirectory:string,installerDirectory:string,now?:Date|number}} options Exact build, reviewed receipt and local downloaded inputs.
 * @returns {Promise<{sourceCommit:string,version:string,installers:string[],receipt:object}>} Closed normalized receipt and exact inventory.
 * @throws {Error} For any malformed, stale, mismatched, unsuccessful or unsafe input.
 */
export async function verifyWindowsReleaseAcceptance({ run, receipt, repository, actor, runId, sourceDirectory, installerDirectory, now = new Date() }) {
    const candidate = validateBuildRun(run, { repository, runId })
    requireFact(Buffer.byteLength(JSON.stringify(receipt) ?? '') <= receiptLimit, 'oversized-receipt')
    exactKeys(receipt, receiptKeys)
    requireFact(receipt.schemaVersion === 1 && receipt.repository === repository && receipt.buildRunId === candidate.runId && receipt.buildRunAttempt === candidate.runAttempt && receipt.sourceCommit === candidate.sourceCommit, 'receipt-build-mismatch')
    requireFact(typeof actor === 'string' && actorPattern.test(actor) && typeof receipt.reviewedBy === 'string' && actorPattern.test(receipt.reviewedBy) && receipt.reviewedBy.toLowerCase() === actor.toLowerCase(), 'review-actor-mismatch')
    requireFact(typeof receipt.verifierSha256 === 'string' && shaPattern.test(receipt.verifierSha256), 'invalid-verifier-hash')
    const current = Number(now)
    requireFact(Number.isFinite(current), 'invalid-current-time')
    const started = timestamp(candidate.startedAt)
    const reviewed = timestamp(receipt.reviewedAt)
    requireFact(reviewed >= started && reviewed >= current - maxAge && reviewed <= current + futureSkew, 'receipt-time-outside-window')
    await assertAcceptancePath(sourceDirectory)
    await assertAcceptancePath(installerDirectory)
    requireFact((await lstat(sourceDirectory)).isDirectory() && (await lstat(installerDirectory)).isDirectory(), 'invalid-input-directory')
    const manifest = JSON.parse((await readAcceptanceFile(join(sourceDirectory, 'package.json'))).toString('utf8'))
    const version = manifest.version
    requireFact(typeof version === 'string' && receipt.version === version, 'receipt-version-mismatch')
    expectedInstallerNames(version)
    const verifier = await readAcceptanceFile(join(sourceDirectory, 'scripts', 'verify-windows-installation.ps1'))
    requireFact(createHash('sha256').update(verifier).digest('hex') === receipt.verifierSha256, 'verifier-hash-mismatch')
    requireFact(Array.isArray(receipt.windows) && receipt.windows.length === 2, 'missing-windows-results')
    const seen = new Set()
    const windows = []
    for (const entry of receipt.windows) {
        exactKeys(entry, entryKeys)
        requireFact(['x64', 'arm64'].includes(entry.architecture) && !seen.has(entry.architecture), 'duplicate-or-invalid-architecture')
        seen.add(entry.architecture)
        const expected = `OpenRDXManager-${version}-win-${entry.architecture}.exe`
        requireFact(entry.installer === expected, 'installer-name-mismatch')
        requireFact(typeof entry.installerSha256 === 'string' && shaPattern.test(entry.installerSha256) && typeof entry.evidenceSha256 === 'string' && shaPattern.test(entry.evidenceSha256), 'invalid-result-hash')
        const completed = timestamp(entry.completedAt)
        requireFact(completed >= started && completed >= current - maxAge && completed <= reviewed && completed <= current + futureSkew, 'completion-time-outside-window')
        const evidence = validateEvidence(entry.evidence, entry.architecture, candidate.sourceCommit)
        requireFact(evidenceSha256(evidence) === entry.evidenceSha256, 'evidence-hash-mismatch')
        requireFact((await installerSha256(join(installerDirectory, expected))) === entry.installerSha256, 'installer-hash-mismatch')
        windows.push({ ...entry, evidence })
    }
    // The existing inventory writer must never follow a linked checksum output.
    await assertAcceptancePath(join(installerDirectory, 'SHA256SUMS.txt'), true)
    try {
        const checksumInfo = await lstat(join(installerDirectory, 'SHA256SUMS.txt'))
        requireFact(checksumInfo.isFile() && checksumInfo.nlink === 1, 'invalid-checksum-file')
    } catch (error) {
        if (error.code !== 'ENOENT') throw error
    }
    const { installers } = await verifyReleaseAssets({ directory: installerDirectory, version })
    return { sourceCommit: candidate.sourceCommit, version, installers, receipt: { ...receipt, windows: windows.sort((a, b) => a.architecture.localeCompare(b.architecture)) } }
}
