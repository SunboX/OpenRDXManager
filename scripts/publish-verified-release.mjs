// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { open } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { assertAcceptancePath, readAcceptanceFile, verifyWindowsReleaseAcceptance } from './windows-release-acceptance.mjs'

const executeGh = promisify(execFile)
const limits = { timeout: 120000, maxBuffer: 4194304, encoding: 'utf8', shell: false }
const shaPattern = /^[a-f0-9]{40}$/u

/** @param {boolean} condition Required publication fact. @returns {void} @throws {Error} For unsafe remote state; never includes private diagnostics. */
function requireFact(condition) {
    if (!condition) throw new Error('release-publication-state-invalid')
}

/** Executes bounded structured gh argv, retaining no raw failures. @param {Function} execute execFile-compatible command boundary. @param {string[]} args Structured argv. @param {number} [timeout] Release-only command deadline in milliseconds. @returns {Promise<object>} Command output. @throws {Error} Fixed failure without raw child diagnostics. */
async function command(execute, args, timeout = limits.timeout) {
    try {
        return await execute('gh', args, { ...limits, timeout })
    } catch {
        throw new Error('release-github-command-failed; inspect any existing draft before retrying')
    }
}

/** Reads bounded authenticated REST output; only a parsed HTTP 404 can mean absence. @param {Function} execute Command boundary. @param {string} endpoint Validated REST endpoint. @param {boolean} [allowMissing] Allows confirmed HTTP 404. @returns {Promise<object|null>} JSON response or confirmed absence. @throws {Error} For all other errors or malformed responses. */
async function api(execute, endpoint, allowMissing = false) {
    let output
    try {
        output = await execute('gh', ['api', '--include', '--method', 'GET', endpoint], limits)
    } catch (error) {
        // gh exits nonzero for HTTP errors; inspect only the bounded HTTP header,
        // never an error-message substring such as an unrelated "HTTP 404".
        output = { stdout: typeof error.stdout === 'string' ? error.stdout : '', failed: true }
    }
    const text = output?.stdout
    requireFact(typeof text === 'string' && Buffer.byteLength(text) <= limits.maxBuffer)
    const header = /^HTTP\/\S+ (\d{3})[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n/u.exec(text)
    requireFact(Boolean(header))
    if (header[1] === '404' && allowMissing) return null
    requireFact(!output.failed && header[1] === '200')
    try {
        return JSON.parse(text.slice(header[0].length))
    } catch {
        throw new Error('release-github-response-invalid')
    }
}

/** Resolves a tag with bounded annotated-tag peeling and cycle rejection. @param {Function} execute Command boundary. @param {string} repository Validated repository. @param {string} tag Manifest tag. @returns {Promise<string|null>} Commit or missing tag. @throws {Error} For loops, other objects, malformed refs or remote errors. */
async function tagCommit(execute, repository, tag) {
    const ref = await api(execute, `repos/${repository}/git/ref/tags/${tag}`, true)
    if (ref === null) return null
    let object = ref.object
    const seen = new Set()
    for (let depth = 0; depth <= 4; depth++) {
        requireFact(object && shaPattern.test(object.sha) && !seen.has(object.sha))
        seen.add(object.sha)
        if (object.type === 'commit') return object.sha
        requireFact(object.type === 'tag' && depth < 4)
        object = (await api(execute, `repos/${repository}/git/tags/${object.sha}`)).object
    }
    throw new Error('release-tag-depth-exceeded')
}

/** Computes the exact upload size and digest from a safe open file. @param {string} path Local installer/checksum. @returns {Promise<object>} Expected server metadata. @throws {Error} For unsafe, changed or unreadable files. */
async function assetMetadata(path) {
    await assertAcceptancePath(path)
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
    try {
        const before = await handle.stat()
        requireFact(before.isFile() && before.nlink === 1 && before.size > 0)
        const hash = createHash('sha256')
        for await (const chunk of handle.createReadStream({ autoClose: false })) hash.update(chunk)
        const after = await handle.stat()
        requireFact(before.size === after.size && before.mtimeMs === after.mtimeMs)
        return { size: before.size, digest: `sha256:${hash.digest('hex')}` }
    } finally {
        await handle.close()
    }
}

/** Verifies release identity, exact target, tag and every uploaded byte digest. @param {Function} execute Command boundary. @param {object} context Validated publication context. @param {boolean} draft Required draft state. @param {number} [id] Existing release ID. @returns {Promise<number>} Stable release ID. @throws {Error} For mismatches, incomplete assets or moved tags. */
async function inspectRelease(execute, { repository, tag, sourceCommit, assets }, draft, id) {
    const release = await api(execute, id === undefined ? `repos/${repository}/releases/tags/${tag}` : `repos/${repository}/releases/${id}`)
    requireFact(Number.isSafeInteger(release?.id) && release.id > 0 && (id === undefined || release.id === id))
    requireFact(release.tag_name === tag && release.target_commitish === sourceCommit && release.draft === draft && release.prerelease === false)
    requireFact((await tagCommit(execute, repository, tag)) === sourceCommit)
    const uploaded = await api(execute, `repos/${repository}/releases/${release.id}/assets?per_page=100`)
    requireFact(Array.isArray(uploaded) && uploaded.length === assets.size)
    const seen = new Set()
    for (const asset of uploaded) {
        const expected = assets.get(asset.name)
        requireFact(Boolean(expected) && !seen.has(asset.name) && asset.state === 'uploaded' && asset.size === expected.size && asset.digest === expected.digest)
        seen.add(asset.name)
    }
    return release.id
}

/**
 * Validates reviewed Windows acceptance before any GitHub call; creates a new exact-target draft,
 * verifies all seventeen assets, then publishes and rechecks. Interrupted writes leave drafts for inspection.
 * The receipt is an operator attestation, not independent VM execution proof.
 * @param {object} options Arguments accepted by verifyWindowsReleaseAcceptance.
 * @param {{execute?:Function}} [dependencies] Bounded execFile command boundary; no shell.
 * @returns {Promise<{status:string,tag:string}>} Confirmed complete public release.
 * @throws {Error} For invalid acceptance, unsafe notes, existing release, moved tag or incomplete upload.
 */
export async function publishVerifiedRelease(options, { execute = executeGh } = {}) {
    const verified = await verifyWindowsReleaseAcceptance(options)
    const notesPath = join(options.sourceDirectory, 'docs/releases/locally-trusted-installers.md')
    const notes = await readAcceptanceFile(notesPath, 65536)
    requireFact(notes.length > 0 && !notes.includes(0))
    const tag = `v${verified.version}`
    const assets = new Map()
    const paths = []
    for (const name of [...verified.installers, 'SHA256SUMS.txt']) {
        const path = join(options.installerDirectory, name)
        paths.push(path)
        assets.set(name, await assetMetadata(path))
    }
    const context = { repository: options.repository, tag, sourceCommit: verified.sourceCommit, assets }
    // Repeat preflight immediately before creation to narrow concurrent replacement races.
    // GitHub does not offer an atomic tag compare-and-publish operation; post-creation
    // and post-publication checks fail closed if another authorized writer moves it.
    for (let check = 0; check < 2; check++) {
        requireFact((await api(execute, `repos/${options.repository}/releases/tags/${tag}`, true)) === null)
        const existing = await tagCommit(execute, options.repository, tag)
        requireFact(existing === null || existing === verified.sourceCommit)
    }
    if ((await tagCommit(execute, options.repository, tag)) === null) {
        // A draft does not guarantee creation of its new tag. Create a ref with
        // GitHub's non-overwriting endpoint, then verify it before draft upload.
        await command(execute, ['api', '--method', 'POST', `repos/${options.repository}/git/refs`, '-f', `ref=refs/tags/${tag}`, '-f', `sha=${verified.sourceCommit}`])
    }
    requireFact((await tagCommit(execute, options.repository, tag)) === verified.sourceCommit)
    await command(execute, ['release', 'create', tag, ...paths, '--repo', options.repository, '--target', verified.sourceCommit, '--title', `OpenRDXManager ${verified.version}`, '--notes-file', notesPath, '--draft', '--verify-tag'], 600000)
    const id = await inspectRelease(execute, context, true)
    // A second identity/tag/asset check immediately precedes the public write.
    await inspectRelease(execute, context, true, id)
    // Publish by the verified numeric release ID rather than looking it up again
    // by tag: a concurrently replaced tag must not select a different draft.
    await command(execute, ['api', '--method', 'PATCH', `repos/${options.repository}/releases/${id}`, '-F', 'draft=false', '-f', 'make_latest=true'])
    await inspectRelease(execute, context, false, id)
    return { status: 'published', tag }
}

/** Runs the main-only explicit publication CLI; input values are never shell source or logged. @param {string[]} args Explicit metadata, source, installer paths. @param {object} env Workflow environment. @returns {Promise<void>} Fixed successful status. @throws {Error} For unauthorized context or invalid bounded inputs. */
export async function runVerifiedReleasePublisherCli(args, env = process.env) {
    requireFact(env.GITHUB_REF === 'refs/heads/main' && env.GITHUB_EVENT_NAME === 'workflow_dispatch' && env.PUBLISH_RELEASE === 'true' && args.length === 3)
    const [metadataPath, sourceDirectory, installerDirectory] = args
    requireFact(typeof env.RECEIPT_PATH === 'string' && !env.WINDOWS_ACCEPTANCE)
    const run = JSON.parse((await readAcceptanceFile(metadataPath)).toString('utf8'))
    const receipt = JSON.parse((await readAcceptanceFile(env.RECEIPT_PATH, 65536)).toString('utf8'))
    await publishVerifiedRelease({ run, receipt, repository: env.GITHUB_REPOSITORY, actor: env.GITHUB_ACTOR, runId: env.BUILD_RUN_ID, sourceDirectory, installerDirectory })
    console.log('Verified release publication completed')
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        await runVerifiedReleasePublisherCli(process.argv.slice(2))
    } catch {
        console.error('Verified release publication failed; inspect any existing draft before retrying')
        process.exitCode = 1
    }
}
