// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { execFile } from 'node:child_process'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { isDeepStrictEqual } from 'node:util'
import { readAcceptanceFile } from './windows-release-acceptance.mjs'
import { releaseAssetMetadata, verifyReleaseCandidate } from './release-candidate.mjs'

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

/**
 * Looks up drafts and published releases with the authenticated publication token.
 * GitHub's tag endpoint only returns published releases; push-authorized list reads
 * include drafts. Read through a terminal short page so absence and uniqueness are
 * known, rejecting pagination races/duplicates and repositories beyond the bound.
 * @param {Function} execute Bounded command boundary.
 * @param {string} repository Validated repository.
 * @param {string} tag Exact manifest tag.
 * @returns {Promise<number|null>} Unique release ID or confirmed complete-list absence.
 * @throws {Error} For malformed, ambiguous, inaccessible or over-limit listings.
 */
async function releaseIdForTag(execute, repository, tag) {
    let match = null
    const seen = new Set()
    for (let page = 1; page <= 10; page++) {
        const releases = await api(execute, `repos/${repository}/releases?per_page=100&page=${page}`)
        requireFact(Array.isArray(releases) && releases.length <= 100)
        for (const release of releases) {
            requireFact(Number.isSafeInteger(release?.id) && release.id > 0 && !seen.has(release.id) && typeof release.tag_name === 'string' && typeof release.draft === 'boolean')
            seen.add(release.id)
            if (release.tag_name === tag) {
                requireFact(match === null)
                match = release.id
            }
        }
        if (releases.length < 100) return match
    }
    throw new Error('release-list-limit-exceeded')
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

/** Verifies release identity, exact target, tag and every uploaded byte digest. @param {Function} execute Command boundary. @param {object} context Validated publication context. @param {boolean} draft Required draft state. @param {number} id Required verified release ID. @returns {Promise<number>} Stable release ID. @throws {Error} For mismatches, incomplete assets or moved tags. */
async function inspectRelease(execute, { repository, tag, sourceCommit, assets }, draft, id) {
    requireFact(Number.isSafeInteger(id) && id > 0)
    const release = await api(execute, `repos/${repository}/releases/${id}`)
    requireFact(release?.id === id)
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
 * Validates successful build provenance and complete assets before any GitHub call; creates a new exact-target draft,
 * verifies all seventeen assets, then publishes and rechecks. Interrupted writes leave drafts for inspection.
 * @param {object} options Arguments accepted by verifyReleaseCandidate.
 * @param {{execute?:Function}} [dependencies] Bounded execFile command boundary; no shell.
 * @returns {Promise<{status:string,tag:string}>} Confirmed complete public release.
 * @throws {Error} For invalid candidate, unsafe notes, existing release, moved tag or incomplete upload.
 */
export async function publishVerifiedRelease(options, { execute = executeGh } = {}) {
    const verified = await verifyReleaseCandidate(options)
    const notesPath = join(options.sourceDirectory, 'docs/releases/locally-trusted-installers.md')
    const notes = await readAcceptanceFile(notesPath, 65536)
    requireFact(notes.length > 0 && !notes.includes(0))
    const tag = `v${verified.version}`
    const assets = new Map()
    const paths = []
    for (const name of [...verified.installers, 'SHA256SUMS.txt']) {
        const path = join(options.installerDirectory, name)
        paths.push(path)
        const metadata = await releaseAssetMetadata(path)
        requireFact(isDeepStrictEqual(metadata, verified.assets[name]))
        assets.set(name, metadata)
    }
    const context = { repository: options.repository, tag, sourceCommit: verified.sourceCommit, assets }
    // Repeat preflight immediately before creation to narrow concurrent replacement races.
    // GitHub does not offer an atomic tag compare-and-publish operation; post-creation
    // and post-publication checks fail closed if another authorized writer moves it.
    for (let check = 0; check < 2; check++) {
        requireFact((await releaseIdForTag(execute, options.repository, tag)) === null)
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
    const id = await releaseIdForTag(execute, options.repository, tag)
    requireFact(id !== null)
    await inspectRelease(execute, context, true, id)
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
    requireFact(typeof env.CANDIDATE_PATH === 'string')
    const run = JSON.parse((await readAcceptanceFile(metadataPath)).toString('utf8'))
    const expectedCandidate = JSON.parse((await readAcceptanceFile(env.CANDIDATE_PATH)).toString('utf8'))
    await publishVerifiedRelease({ run, expectedCandidate, repository: env.GITHUB_REPOSITORY, runId: env.BUILD_RUN_ID, sourceDirectory, installerDirectory })
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
