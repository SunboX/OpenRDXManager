// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { randomUUID } from 'node:crypto'
import { execFile } from 'node:child_process'
import { constants } from 'node:fs'
import { chmod, copyFile, link, lstat, mkdir, open, readFile, readdir, realpath, rename, rm, stat, unlink } from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'

import { resolveDeviceServiceExecutable } from '../src/main/device-service-transport.mjs'
import { validateSigningBuildEnvironment } from './signing-build-policy.mjs'

const execFileAsync = promisify(execFile)
const defaultProjectRoot = fileURLToPath(new URL('..', import.meta.url))
const cargoOutputLimit = 16 * 1024 * 1024
const defaultLockTimeoutMs = 300_000
const defaultLockPollMs = 50
const malformedLockGraceMs = 2_000
const maximumLockBytes = 1_024
const maximumAcquisitionIntents = 128
const maximumRecoveryClaims = 128
const recoveryClaimTokenPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u

/**
 * Maps one supported Node platform to the development resource directory.
 * @param {string} platform - Node platform identifier.
 * @returns {string} Stable native resource directory name.
 * @throws {RangeError} When the platform is unsupported.
 */
function runtimePlatformDirectory(platform) {
    if (platform === 'darwin') return 'macos'
    if (platform === 'win32') return 'windows'
    if (platform === 'linux') return 'linux'
    throw new RangeError('unsupported-platform')
}

/**
 * Resolves the controlled Cargo target and deterministic development runtime paths.
 * The explicit target directory makes ambient `CARGO_TARGET_DIR` values irrelevant.
 * @param {{projectRoot?: string, platform?: string}} [options] - Host project and platform.
 * @returns {{executableName: string, lockPath: string, manifestPath: string, runtimePath: string, runtimeRoot: string, targetDirectory: string}} Absolute build paths.
 * @throws {TypeError|RangeError} For an invalid root or unsupported platform.
 */
export function getNativeServiceBuildPaths({ projectRoot = defaultProjectRoot, platform = process.platform } = {}) {
    if (typeof projectRoot !== 'string' || !isAbsolute(projectRoot)) {
        throw new TypeError('native-service-project-root-invalid')
    }
    const normalizedRoot = resolve(projectRoot)
    const runtimePath = resolveDeviceServiceExecutable({ appPath: normalizedRoot, resourcesPath: normalizedRoot, isPackaged: false, platform })
    return {
        executableName: platform === 'win32' ? 'openrdx-hardware.exe' : 'openrdx-hardware',
        lockPath: join(normalizedRoot, '.tmp', 'openrdx-native-service-build.lock'),
        manifestPath: join(normalizedRoot, 'native', 'rdx-service', 'Cargo.toml'),
        runtimePath,
        runtimeRoot: join(normalizedRoot, 'out', 'native'),
        targetDirectory: join(normalizedRoot, 'native', 'rdx-service', 'target', 'openrdx-runtime-build')
    }
}

/**
 * Checks whether one path remains strictly below a controlled root.
 * @param {string} root - Canonical controlled directory.
 * @param {string} candidate - Absolute candidate path.
 * @returns {boolean} True only for a descendant path.
 */
function isControlledDescendant(root, candidate) {
    const childPath = relative(root, candidate)
    return childPath !== '' && childPath !== '..' && !childPath.startsWith(`..${sep}`) && !isAbsolute(childPath)
}

/**
 * Returns whether a filesystem failure reports a missing path.
 * @param {unknown} error - Candidate filesystem exception.
 * @returns {boolean} True only for an ENOENT failure.
 */
function isMissingPath(error) {
    return error !== null && typeof error === 'object' && error.code === 'ENOENT'
}

/**
 * Resolves an existing, caller-selected root without trusting a link at the root.
 * Ancestors outside the selected root may be platform aliases such as macOS `/var`;
 * every controlled child is therefore derived from the returned canonical path.
 * @param {string} root - Existing absolute directory selected by application code.
 * @returns {Promise<string>} Canonical non-link directory path.
 * @throws {Error} When the root is absent, linked, or not a directory.
 */
async function canonicalizeControlledRoot(root) {
    let metadata
    try {
        metadata = await lstat(root)
    } catch {
        throw new Error('native-service-project-root-invalid')
    }
    if (metadata.isSymbolicLink()) throw new Error('native-service-path-symlink')
    if (!metadata.isDirectory()) throw new Error('native-service-project-root-invalid')
    return resolve(await realpath(root))
}

/**
 * Verifies that the canonical root still identifies the same non-link directory.
 * @param {string} root - Canonical controlled root.
 * @returns {Promise<void>} Resolves after the identity check.
 * @throws {Error} When the root moved, became a link, or is no longer a directory.
 */
async function verifyControlledRoot(root) {
    let metadata
    try {
        metadata = await lstat(root)
    } catch {
        throw new Error('native-service-path-invalid')
    }
    if (metadata.isSymbolicLink()) throw new Error('native-service-path-symlink')
    if (!metadata.isDirectory() || resolve(await realpath(root)) !== root) throw new Error('native-service-path-invalid')
}

/**
 * Walks a controlled directory one component at a time and rejects links or
 * non-directories. Missing components are created without recursive traversal.
 * Node exposes Windows junctions as symbolic links through `lstat`; other exotic
 * reparse tags remain subject to the guarantees of the host Node filesystem API.
 * @param {string} root - Canonical controlled root.
 * @param {string} directory - Descendant directory to verify or create.
 * @returns {Promise<string>} Canonical verified directory.
 * @throws {Error} When containment or a component identity check fails.
 */
async function ensureControlledDirectory(root, directory) {
    const normalizedDirectory = resolve(directory)
    if (!isControlledDescendant(root, normalizedDirectory)) throw new Error('native-service-path-invalid')
    await verifyControlledRoot(root)
    let current = root
    for (const component of relative(root, normalizedDirectory).split(sep)) {
        current = join(current, component)
        let metadata
        try {
            metadata = await lstat(current)
        } catch (error) {
            if (!isMissingPath(error)) throw new Error('native-service-path-invalid')
            try {
                await mkdir(current, { mode: 0o700 })
            } catch (mkdirError) {
                if (mkdirError?.code !== 'EEXIST') throw new Error('native-service-path-invalid')
            }
            metadata = await lstat(current)
        }
        if (metadata.isSymbolicLink()) throw new Error('native-service-path-symlink')
        if (!metadata.isDirectory()) throw new Error('native-service-path-invalid')
        const canonicalCurrent = resolve(await realpath(current))
        if (!isControlledDescendant(root, canonicalCurrent)) throw new Error('native-service-path-invalid')
    }
    await verifyControlledRoot(root)
    const canonicalDirectory = resolve(await realpath(normalizedDirectory))
    if (!isControlledDescendant(root, canonicalDirectory)) throw new Error('native-service-path-invalid')
    return canonicalDirectory
}

/**
 * Verifies every ancestor and one regular file immediately before use.
 * @param {string} root - Canonical controlled root.
 * @param {string} filePath - Strict descendant file candidate.
 * @returns {Promise<void>} Resolves after containment and identity checks.
 * @throws {Error} When the file or any controlled ancestor is unsafe.
 */
async function verifyControlledFile(root, filePath) {
    const normalizedFile = resolve(filePath)
    if (!isControlledDescendant(root, normalizedFile)) throw new Error('native-service-artifact-invalid')
    await ensureControlledDirectory(root, dirname(normalizedFile))
    let metadata
    try {
        metadata = await lstat(normalizedFile)
    } catch {
        throw new Error('native-service-artifact-invalid')
    }
    if (metadata.isSymbolicLink()) throw new Error('native-service-path-symlink')
    if (!metadata.isFile()) throw new Error('native-service-artifact-invalid')
    const canonicalFile = resolve(await realpath(normalizedFile))
    if (!isControlledDescendant(root, canonicalFile)) throw new Error('native-service-artifact-invalid')
}

/**
 * Waits for one bounded lock poll interval.
 * @param {number} milliseconds - Fixed bounded delay.
 * @returns {Promise<void>} Resolves after the delay.
 */
async function wait(milliseconds) {
    await delay(milliseconds)
}

/**
 * Checks whether an operating-system process is still observable. Permission
 * failures are conservatively treated as alive so a lock is never stolen.
 * @param {number} pid - Positive lock-owner process identifier.
 * @returns {boolean} True unless the operating system reports ESRCH.
 */
function isProcessAlive(pid) {
    try {
        process.kill(pid, 0)
        return true
    } catch (error) {
        return error?.code !== 'ESRCH'
    }
}

/**
 * Parses one small strict lock owner record.
 * @param {string} contents - Bounded UTF-8 lock contents.
 * @returns {{version: 1, token: string, pid: number, createdAt: number}|null} Valid owner or null.
 */
function parseLockOwner(contents) {
    let owner
    try {
        owner = JSON.parse(contents)
    } catch {
        return null
    }
    const keys = owner !== null && typeof owner === 'object' && !Array.isArray(owner) ? Object.keys(owner).sort() : []
    if (owner === null || typeof owner !== 'object' || Array.isArray(owner) || keys.length !== 4 || keys[0] !== 'createdAt' || keys[1] !== 'pid' || keys[2] !== 'token' || keys[3] !== 'version' || owner.version !== 1 || typeof owner.token !== 'string' || !recoveryClaimTokenPattern.test(owner.token) || !Number.isSafeInteger(owner.pid) || owner.pid < 1 || !Number.isSafeInteger(owner.createdAt) || owner.createdAt < 0) {
        return null
    }
    return owner
}

/**
 * Reads one existing lock without following a link or accepting unbounded data.
 * @param {string} root - Canonical project root.
 * @param {string} lockPath - Controlled lock path.
 * @returns {Promise<{metadata: import('node:fs').Stats, owner: object|null}>} Stable snapshot.
 * @throws {Error} When the lock entry is unsafe.
 */
async function readLockSnapshot(root, lockPath) {
    await ensureControlledDirectory(root, dirname(lockPath))
    const metadata = await lstat(lockPath)
    if (metadata.isSymbolicLink()) throw new Error('native-service-path-symlink')
    if (!metadata.isFile()) throw new Error('native-service-build-lock-invalid')
    const contents = metadata.size <= maximumLockBytes ? await readFile(lockPath, 'utf8') : ''
    return { metadata, owner: parseLockOwner(contents) }
}

/**
 * Compares immutable-enough filesystem identity fields across an immediate
 * recovery check. Owner tokens provide the cooperative-process identity.
 * @param {import('node:fs').Stats} first - Initial lock metadata.
 * @param {import('node:fs').Stats} second - Immediate comparison metadata.
 * @returns {boolean} True when both snapshots identify the same entry.
 */
function sameFilesystemEntry(first, second) {
    return first.dev === second.dev && first.ino === second.ino && first.size === second.size && first.mtimeMs === second.mtimeMs
}

/**
 * Returns the namespace prefix shared by every active recovery claim.
 * @param {string} lockPath - Controlled lock path.
 * @returns {string} Claim basename prefix.
 */
function recoveryClaimPrefix(lockPath) {
    return `${basename(lockPath)}.claim-`
}

/**
 * Returns the namespace prefix shared by acquisition intents. An intent is
 * visible before its process checks for recovery claims and remains visible
 * until that attempt either rolls back or owns the stable shared lock.
 * @param {string} lockPath - Controlled lock path.
 * @returns {string} Intent basename prefix.
 */
function acquisitionIntentPrefix(lockPath) {
    return `${basename(lockPath)}.intent-`
}

/**
 * Creates one process-unique recovery claim path that cooperative processes
 * never reuse. Uniqueness makes an abandoned claim safe to adopt by rename.
 * @param {string} lockPath - Controlled lock path.
 * @returns {string} Unique sibling claim path.
 */
function createRecoveryClaimPath(lockPath) {
    return `${lockPath}.claim-${process.pid}-${randomUUID()}`
}

/**
 * Creates one process-unique acquisition-intent path.
 * @param {string} lockPath - Controlled lock path.
 * @param {{pid: number, token: string}} owner - Exact attempt identity.
 * @returns {string} Unique sibling intent path.
 */
function createAcquisitionIntentPath(lockPath, owner) {
    return `${lockPath}.intent-${owner.pid}-${owner.token}`
}

/**
 * Parses the claimant identity encoded atomically in a unique claim basename.
 * @param {string} lockPath - Controlled lock path.
 * @param {string} claimPath - Candidate sibling claim.
 * @returns {{pid: number, token: string}|null} Strict claimant identity.
 */
function parseRecoveryClaimIdentity(lockPath, claimPath) {
    const name = basename(claimPath)
    const prefix = recoveryClaimPrefix(lockPath)
    if (!name.startsWith(prefix)) return null
    const match = /^(\d+)-(.+)$/u.exec(name.slice(prefix.length))
    if (match === null || !recoveryClaimTokenPattern.test(match[2])) return null
    const pid = Number(match[1])
    if (!Number.isSafeInteger(pid) || pid < 1) return null
    return { pid, token: match[2] }
}

/**
 * Parses the process identity encoded in one acquisition-intent basename.
 * @param {string} lockPath - Controlled lock path.
 * @param {string} intentPath - Candidate sibling intent.
 * @returns {{pid: number, token: string}|null} Strict process identity.
 */
function parseAcquisitionIntentIdentity(lockPath, intentPath) {
    const name = basename(intentPath)
    const prefix = acquisitionIntentPrefix(lockPath)
    if (!name.startsWith(prefix)) return null
    const match = /^(\d+)-(.+)$/u.exec(name.slice(prefix.length))
    if (match === null || !recoveryClaimTokenPattern.test(match[2])) return null
    const pid = Number(match[1])
    if (!Number.isSafeInteger(pid) || pid < 1) return null
    return { pid, token: match[2] }
}

/**
 * Determines whether one bound lock entry is safe to recover now. A valid PID
 * that has been reused remains conservatively live; it can delay recovery but
 * can never cause a live generation to be overclaimed.
 * @param {{metadata: import('node:fs').Stats, owner: object|null}} snapshot - Bound entry snapshot.
 * @param {{now: () => number, processAlive: (pid: number) => boolean}} controls - Clock and process observation.
 * @returns {boolean} True only for a dead valid owner or old malformed entry.
 */
function isRecoverableSnapshot(snapshot, controls) {
    if (snapshot.owner !== null) return !controls.processAlive(snapshot.owner.pid)
    return controls.now() - snapshot.metadata.mtimeMs >= malformedLockGraceMs
}

/**
 * Lists active recovery claims without accepting an unbounded claim namespace.
 * @param {string} root - Canonical project root.
 * @param {string} lockPath - Controlled lock path.
 * @returns {Promise<string[]>} Sorted active claim paths.
 * @throws {Error} When claim volume exceeds the fixed safety bound.
 */
async function listRecoveryClaims(root, lockPath) {
    const lockDirectory = await ensureControlledDirectory(root, dirname(lockPath))
    const prefix = recoveryClaimPrefix(lockPath)
    const names = (await readdir(lockDirectory)).filter((name) => name.startsWith(prefix)).sort()
    if (names.length > maximumRecoveryClaims) throw new Error('native-service-build-lock-invalid')
    return names.map((name) => join(lockDirectory, name))
}

/**
 * Lists acquisition intents without accepting an unbounded marker namespace.
 * @param {string} root - Canonical project root.
 * @param {string} lockPath - Controlled lock path.
 * @returns {Promise<string[]>} Sorted intent paths.
 * @throws {Error} When intent volume exceeds the fixed safety bound.
 */
async function listAcquisitionIntents(root, lockPath) {
    const lockDirectory = await ensureControlledDirectory(root, dirname(lockPath))
    const prefix = acquisitionIntentPrefix(lockPath)
    const names = (await readdir(lockDirectory)).filter((name) => name.startsWith(prefix)).sort()
    if (names.length > maximumAcquisitionIntents) throw new Error('native-service-build-lock-invalid')
    return names.map((name) => join(lockDirectory, name))
}

/**
 * Removes abandoned acquisition intents and reports whether no live attempt can
 * still publish a lock after having observed an empty recovery namespace.
 * Valid-looking markers owned by an observable or reused PID are conservative
 * blockers even when their contents are malformed or only partly published.
 * @param {string} root - Canonical project root.
 * @param {string} lockPath - Controlled lock path.
 * @param {{now: () => number, processAlive: (pid: number) => boolean}} controls - Clock and process observation.
 * @returns {Promise<boolean>} True only when no live or fresh intent remains.
 */
async function settleAcquisitionIntents(root, lockPath, controls) {
    let blocked = false
    for (const intentPath of await listAcquisitionIntents(root, lockPath)) {
        let metadata
        try {
            metadata = await lstat(intentPath)
        } catch (error) {
            if (isMissingPath(error)) continue
            throw new Error('native-service-build-lock-invalid')
        }
        if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error('native-service-build-lock-invalid')
        const identity = parseAcquisitionIntentIdentity(lockPath, intentPath)
        if (identity !== null && controls.processAlive(identity.pid)) {
            blocked = true
            continue
        }
        if (identity === null && controls.now() - metadata.mtimeMs < malformedLockGraceMs) {
            blocked = true
            continue
        }
        await rm(intentPath, { force: true })
    }
    return !blocked
}

/**
 * Publishes a process-owned hard-link claim that atomically binds all later
 * removal to the lock entry occupying the shared name at this instant.
 * @param {string} root - Canonical project root.
 * @param {string} lockPath - Controlled lock path.
 * @returns {Promise<string|null>} Unique claim path, or null when the lock raced away.
 */
async function createRecoveryClaim(root, lockPath) {
    await ensureControlledDirectory(root, dirname(lockPath))
    const claimPath = createRecoveryClaimPath(lockPath)
    try {
        await link(lockPath, claimPath)
    } catch (error) {
        if (isMissingPath(error)) return null
        throw new Error('native-service-build-lock-invalid')
    }
    try {
        await verifyControlledFile(root, claimPath)
        return claimPath
    } catch (error) {
        await rm(claimPath, { force: true })
        throw error
    }
}

/**
 * Removes the shared lock only while an active hard-link claim still binds the
 * exact checked entry. Every acquisition path waits for all such claims.
 * @param {string} root - Canonical project root.
 * @param {string} lockPath - Controlled lock path.
 * @param {string} claimPath - Process-owned or safely adopted claim.
 * @param {{now: () => number, onBeforeRecoveryUnlink?: () => Promise<void>|void, processAlive: (pid: number) => boolean}} controls - Clock, process observation, and optional deterministic test gate.
 * @returns {Promise<boolean>} True when a stale shared entry was removed or already absent.
 */
async function processRecoveryClaim(root, lockPath, claimPath, controls) {
    try {
        const claimed = await readLockSnapshot(root, claimPath)
        if (!isRecoverableSnapshot(claimed, controls)) return false
        let current
        try {
            current = await readLockSnapshot(root, lockPath)
        } catch (error) {
            if (isMissingPath(error)) return true
            throw error
        }
        if (!sameFilesystemEntry(claimed.metadata, current.metadata)) return true
        await controls.onBeforeRecoveryUnlink?.()
        if (!(await settleAcquisitionIntents(root, lockPath, controls))) return false
        try {
            current = await readLockSnapshot(root, lockPath)
        } catch (error) {
            if (isMissingPath(error)) return true
            throw error
        }
        if (!sameFilesystemEntry(claimed.metadata, current.metadata)) return true
        try {
            await unlink(lockPath)
        } catch (error) {
            if (isMissingPath(error)) return true
            // Concurrent Windows unlink calls can report a sharing error to the
            // loser even though the competing recoverer removed this exact
            // directory entry. Re-read the controlled path before classifying
            // that observable race as filesystem corruption.
            try {
                current = await readLockSnapshot(root, lockPath)
            } catch (recheckError) {
                if (isMissingPath(recheckError)) return true
                throw recheckError
            }
            if (!sameFilesystemEntry(claimed.metadata, current.metadata)) return true
            throw new Error('native-service-build-lock-invalid')
        }
        return true
    } finally {
        await rm(claimPath, { force: true })
    }
}

/**
 * Atomically adopts one claim only after its encoded claimant is dead. Claim
 * names are UUID-unique and never reused, so a delayed rename cannot target a
 * newer claim generation. Old malformed names are recoverable after the same
 * grace used for malformed locks.
 * @param {string} root - Canonical project root.
 * @param {string} lockPath - Controlled lock path.
 * @param {string} claimPath - Existing active claim.
 * @param {{now: () => number, processAlive: (pid: number) => boolean}} controls - Clock and process observation.
 * @returns {Promise<{state: 'adopted', path: string}|{state: 'blocked'}|{state: 'raced'}>} Adoption outcome.
 */
async function adoptRecoveryClaim(root, lockPath, claimPath, controls) {
    let metadata
    try {
        metadata = await lstat(claimPath)
    } catch (error) {
        if (isMissingPath(error)) return { state: 'raced' }
        throw new Error('native-service-build-lock-invalid')
    }
    if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error('native-service-build-lock-invalid')
    const identity = parseRecoveryClaimIdentity(lockPath, claimPath)
    if (identity !== null && controls.processAlive(identity.pid)) return { state: 'blocked' }
    if (identity === null && controls.now() - metadata.mtimeMs < malformedLockGraceMs) return { state: 'blocked' }

    const adoptedPath = createRecoveryClaimPath(lockPath)
    try {
        await rename(claimPath, adoptedPath)
    } catch (error) {
        if (isMissingPath(error)) return { state: 'raced' }
        throw new Error('native-service-build-lock-invalid')
    }
    await verifyControlledFile(root, adoptedPath)
    return { state: 'adopted', path: adoptedPath }
}

/**
 * Recovers claims abandoned by killed recoverers and reports whether no live
 * claimant currently protects a lock transition.
 * @param {string} root - Canonical project root.
 * @param {string} lockPath - Controlled lock path.
 * @param {{now: () => number, processAlive: (pid: number) => boolean}} controls - Clock and process observation.
 * @returns {Promise<boolean>} True only when the active claim namespace is empty.
 */
async function settleRecoveryClaims(root, lockPath, controls) {
    while (true) {
        const claims = await listRecoveryClaims(root, lockPath)
        if (claims.length === 0) return true
        let blocked = false
        let changed = false
        for (const claimPath of claims) {
            const adopted = await adoptRecoveryClaim(root, lockPath, claimPath, controls)
            if (adopted.state === 'blocked') {
                blocked = true
                continue
            }
            changed = true
            if (adopted.state === 'adopted') await processRecoveryClaim(root, lockPath, adopted.path, controls)
        }
        if (!changed) return !blocked
    }
}

/**
 * Removes one dead-owner or long-malformed lock while a hard-link claim blocks
 * every compliant acquisition. Revalidation occurs through the claimed inode,
 * never through a reusable pathname alone.
 * @param {string} root - Canonical project root.
 * @param {string} lockPath - Controlled lock path.
 * @param {{now: () => number, processAlive: (pid: number) => boolean}} controls - Clock and process observation.
 * @returns {Promise<boolean>} True when a stale entry was removed or raced away.
 */
async function recoverStaleLock(root, lockPath, controls) {
    let initial
    try {
        initial = await readLockSnapshot(root, lockPath)
    } catch (error) {
        if (isMissingPath(error)) return true
        throw error
    }
    if (!isRecoverableSnapshot(initial, controls)) return false
    const claimPath = await createRecoveryClaim(root, lockPath)
    if (claimPath === null) return true
    try {
        const claimed = await readLockSnapshot(root, claimPath)
        const ownerMatches = initial.owner === null ? claimed.owner === null : claimed.owner?.token === initial.owner.token
        if (!ownerMatches || !sameFilesystemEntry(initial.metadata, claimed.metadata)) return false
        return await processRecoveryClaim(root, lockPath, claimPath, controls)
    } finally {
        await rm(claimPath, { force: true })
    }
}

/**
 * Publishes one complete, synced process-owned acquisition intent.
 * @param {string} root - Canonical project root.
 * @param {string} lockPath - Controlled lock path.
 * @param {{version: 1, token: string, pid: number, createdAt: number}} owner - Unique owner record.
 * @returns {Promise<string>} Exact process-unique intent path.
 */
async function createAcquisitionIntent(root, lockPath, owner) {
    const lockDirectory = await ensureControlledDirectory(root, dirname(lockPath))
    const intentPath = createAcquisitionIntentPath(lockPath, owner)
    let handle
    let created = false
    try {
        handle = await open(intentPath, 'wx', 0o600)
        created = true
        await handle.writeFile(JSON.stringify(owner), 'utf8')
        await handle.sync()
        await handle.close()
        handle = undefined
        await verifyControlledFile(root, intentPath)
        return intentPath
    } catch (error) {
        try {
            await handle?.close()
        } catch {
            // Cleanup must preserve the acquisition failure that caused it.
        }
        if (created) await rm(intentPath, { force: true })
        throw error
    }
}

/**
 * Attempts one atomic hard-link installation from a published intent.
 * @param {string} root - Canonical project root.
 * @param {string} lockPath - Controlled lock path.
 * @param {string} intentPath - Complete process-owned intent.
 * @param {{token: string}} owner - Exact owner identity.
 * @returns {Promise<{lockPath: string, metadata: import('node:fs').Stats, token: string}|null>} Owned lock or null on contention.
 */
async function tryCreateBuildLock(root, lockPath, intentPath, owner) {
    try {
        await link(intentPath, lockPath)
    } catch (error) {
        if (error?.code === 'EEXIST') return null
        throw new Error('native-service-build-lock-invalid')
    }
    try {
        const [intent, snapshot] = await Promise.all([readLockSnapshot(root, intentPath), readLockSnapshot(root, lockPath)])
        if (intent.owner?.token !== owner.token || snapshot.owner?.token !== owner.token || !sameFilesystemEntry(intent.metadata, snapshot.metadata)) throw new Error('native-service-build-lock-invalid')
        return { lockPath, metadata: snapshot.metadata, token: owner.token }
    } catch (error) {
        try {
            const [intent, snapshot] = await Promise.all([readLockSnapshot(root, intentPath), readLockSnapshot(root, lockPath)])
            if (intent.owner?.token === owner.token && snapshot.owner?.token === owner.token && sameFilesystemEntry(intent.metadata, snapshot.metadata)) await unlink(lockPath)
        } catch {}
        throw error
    }
}

/**
 * Removes an exact just-installed lock while its acquisition intent still
 * fences every recoverer. No operation touches the shared path after unlink.
 * @param {string} root - Canonical project root.
 * @param {{lockPath: string, metadata: import('node:fs').Stats, token: string}} lock - Exact acquired lock.
 * @returns {Promise<void>} Resolves after rolling back the exact entry.
 */
async function rollbackAcquiredBuildLock(root, lock) {
    await assertBuildLockOwnership(root, lock)
    await unlink(lock.lockPath)
}

/**
 * Acquires the project-wide cross-process build lock with a bounded wait.
 * @param {string} root - Canonical project root.
 * @param {string} lockPath - Controlled lock path.
 * @param {{lockTimeoutMs: number, lockPollMs: number, now: () => number, onAfterLockCreate?: () => Promise<void>|void, onBeforeLockCreate?: () => Promise<void>|void, onLockWait?: () => Promise<void>|void, processAlive: (pid: number) => boolean}} controls - Fixed lock controls.
 * @returns {Promise<{lockPath: string, metadata: import('node:fs').Stats, token: string}>} Owned lock identity.
 * @throws {Error} When the lock is unsafe or the wait expires.
 */
async function acquireBuildLock(root, lockPath, controls) {
    const deadline = controls.now() + controls.lockTimeoutMs
    let waitReported = false
    while (true) {
        await settleAcquisitionIntents(root, lockPath, controls)
        const owner = { version: 1, token: randomUUID(), pid: process.pid, createdAt: controls.now() }
        const intentPath = await createAcquisitionIntent(root, lockPath, owner)
        let acquisitionBlocked = false
        try {
            if (!(await settleRecoveryClaims(root, lockPath, controls))) {
                acquisitionBlocked = true
            } else {
                await controls.onBeforeLockCreate?.()
                const lock = await tryCreateBuildLock(root, lockPath, intentPath, owner)
                if (lock !== null) {
                    try {
                        await controls.onAfterLockCreate?.()
                        if (!(await settleRecoveryClaims(root, lockPath, controls))) {
                            await rollbackAcquiredBuildLock(root, lock)
                            acquisitionBlocked = true
                        } else {
                            await assertBuildLockOwnership(root, lock)
                            return lock
                        }
                    } catch (error) {
                        if (!acquisitionBlocked) {
                            try {
                                await rollbackAcquiredBuildLock(root, lock)
                            } catch {
                                // A lost lock must not mask the original ownership failure.
                            }
                        }
                        throw error
                    }
                }
            }
        } finally {
            await rm(intentPath, { force: true })
        }
        if (acquisitionBlocked) {
            if (!waitReported) {
                waitReported = true
                await controls.onLockWait?.()
            }
            if (controls.now() >= deadline) throw new Error('native-service-build-lock-timeout')
            await wait(Math.min(controls.lockPollMs, Math.max(1, deadline - controls.now())))
            continue
        }
        if (!waitReported) {
            waitReported = true
            await controls.onLockWait?.()
        }
        if (await recoverStaleLock(root, lockPath, controls)) continue
        if (controls.now() >= deadline) throw new Error('native-service-build-lock-timeout')
        await wait(Math.min(controls.lockPollMs, Math.max(1, deadline - controls.now())))
    }
}

/**
 * Verifies the exact immutable lock generation owned by this build.
 * @param {string} root - Canonical project root.
 * @param {{lockPath: string, metadata: import('node:fs').Stats, token: string}} lock - Exact acquired lock.
 * @returns {Promise<void>} Resolves only while ownership remains intact.
 * @throws {Error} When ownership was lost or replaced.
 */
async function assertBuildLockOwnership(root, lock) {
    let snapshot
    try {
        snapshot = await readLockSnapshot(root, lock.lockPath)
    } catch {
        throw new Error('native-service-build-lock-invalid')
    }
    if (snapshot.owner?.token !== lock.token || !sameFilesystemEntry(snapshot.metadata, lock.metadata)) throw new Error('native-service-build-lock-invalid')
}

/**
 * Releases only the exact token-owned lock while a bound claim prevents a new
 * acquisition until the unlink is complete.
 * @param {string} root - Canonical project root.
 * @param {{lockPath: string, metadata: import('node:fs').Stats, token: string}} lock - Exact acquired lock.
 * @returns {Promise<void>} Resolves after removing the owned lock entry.
 */
async function releaseBuildLock(root, lock) {
    const claimPath = await createRecoveryClaim(root, lock.lockPath)
    if (claimPath === null) throw new Error('native-service-build-lock-invalid')
    try {
        const claimed = await readLockSnapshot(root, claimPath)
        if (claimed.owner?.token !== lock.token || !sameFilesystemEntry(claimed.metadata, lock.metadata)) throw new Error('native-service-build-lock-invalid')
        await assertBuildLockOwnership(root, lock)
        await unlink(lock.lockPath)
    } finally {
        await rm(claimPath, { force: true })
    }
}

/**
 * Extracts the one exact binary artifact from Cargo's bounded JSON output.
 * @param {string} output - Cargo JSON-lines stdout.
 * @param {{executableName: string, targetDirectory: string}} paths - Expected artifact identity and root.
 * @returns {string} Absolute executable path reported by Cargo.
 * @throws {Error} When output is malformed, ambiguous, or outside the controlled target.
 */
function parseCargoArtifact(output, paths) {
    const candidates = []
    for (const line of output.split(/\r?\n/u)) {
        if (line.length === 0) continue
        let message
        try {
            message = JSON.parse(line)
        } catch {
            throw new Error('native-service-cargo-output-invalid')
        }
        if (message?.reason === 'compiler-artifact' && message.target?.name === 'openrdx-hardware' && message.target?.kind?.includes('bin') && message.profile?.test === false && typeof message.executable === 'string') {
            candidates.push(message.executable)
        }
    }
    const uniqueCandidates = [...new Set(candidates)]
    if (uniqueCandidates.length !== 1) throw new Error('native-service-artifact-missing')
    const artifactPath = uniqueCandidates[0]
    if (!isAbsolute(artifactPath) || basename(artifactPath) !== paths.executableName || !isControlledDescendant(paths.targetDirectory, artifactPath)) {
        throw new Error('native-service-artifact-invalid')
    }
    return artifactPath
}

/**
 * Verifies that an optional staged destination is either absent or one regular
 * controlled file. A linked destination is never replaced.
 * @param {string} root - Canonical runtime root.
 * @param {string} runtimePath - Exact deterministic runtime destination.
 * @returns {Promise<void>} Resolves when atomic replacement is safe to attempt.
 */
async function verifyRuntimeDestination(root, runtimePath) {
    await ensureControlledDirectory(root, dirname(runtimePath))
    let metadata
    try {
        metadata = await lstat(runtimePath)
    } catch (error) {
        if (isMissingPath(error)) return
        throw new Error('native-service-path-invalid')
    }
    if (metadata.isSymbolicLink()) throw new Error('native-service-path-symlink')
    if (!metadata.isFile()) throw new Error('native-service-path-invalid')
    const canonicalRuntime = resolve(await realpath(runtimePath))
    if (!isControlledDescendant(root, canonicalRuntime)) throw new Error('native-service-path-invalid')
}

/**
 * Copies one verified Cargo artifact through a same-directory temporary file.
 * @param {string} artifactPath - Verified Cargo executable.
 * @param {{platform: string, runtimePath: string, runtimeRoot: string, targetDirectory: string}} paths - Canonical source and destination controls.
 * @param {() => Promise<void>} assertOwnership - Immediate lock ownership gate.
 * @param {() => Promise<void>} beforeRename - Test-only deterministic race gate.
 * @returns {Promise<void>} Resolves after the atomic rename.
 */
async function stageArtifact(artifactPath, paths, assertOwnership, beforeRename) {
    const runtimeDirectory = dirname(paths.runtimePath)
    const temporaryPath = join(runtimeDirectory, `.${basename(paths.runtimePath)}.${process.pid}.${randomUUID()}.tmp`)
    await ensureControlledDirectory(paths.runtimeRoot, runtimeDirectory)
    try {
        await verifyRuntimeDestination(paths.runtimeRoot, paths.runtimePath)
        await ensureControlledDirectory(paths.runtimeRoot, runtimeDirectory)
        await verifyControlledFile(paths.targetDirectory, artifactPath)
        await assertOwnership()
        await copyFile(artifactPath, temporaryPath, constants.COPYFILE_EXCL)
        if (paths.platform !== 'win32') await chmod(temporaryPath, 0o755)
        await verifyControlledFile(paths.runtimeRoot, temporaryPath)
        const artifact = await stat(temporaryPath)
        if (!artifact.isFile()) throw new Error('native-service-artifact-invalid')
        await ensureControlledDirectory(paths.runtimeRoot, runtimeDirectory)
        await verifyControlledFile(paths.runtimeRoot, temporaryPath)
        await verifyRuntimeDestination(paths.runtimeRoot, paths.runtimePath)
        await beforeRename()
        await assertOwnership()
        // Same-directory rename keeps the previous executable present until the
        // replacement commits. Windows sharing failures abort with the old file
        // intact because this hook never pre-deletes or renames it away.
        await rename(temporaryPath, paths.runtimePath)
        await verifyControlledFile(paths.runtimeRoot, paths.runtimePath)
    } catch (error) {
        await rm(temporaryPath, { force: true })
        throw error
    }
}

/**
 * Executes Cargo with fixed arguments, environment handling, and output bounds.
 * @param {{args: string[], cwd: string, environment: NodeJS.ProcessEnv}} invocation - Controlled Cargo invocation.
 * @returns {Promise<{stdout: string}>} Bounded Cargo JSON-lines output.
 */
async function runCargo(invocation) {
    return execFileAsync('cargo', invocation.args, {
        cwd: invocation.cwd,
        encoding: 'utf8',
        env: { ...invocation.environment, CARGO_TERM_COLOR: 'never' },
        maxBuffer: cargoOutputLimit,
        windowsHide: true
    })
}

/**
 * Validates the narrow public build options shared by production and tests.
 * @param {unknown} options - Candidate build options.
 * @returns {{environment: NodeJS.ProcessEnv, platform: string, projectRoot: string, testRuntimeRoot?: string}} Normalized options.
 * @throws {TypeError} When a caller supplies an arbitrary or malformed override.
 */
function validateBuildOptions(options) {
    if (options === null || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('native-service-build-options-invalid')
    const allowedOptions = new Set(['environment', 'platform', 'projectRoot', 'testRuntimeRoot'])
    if (Object.keys(options).some((key) => !allowedOptions.has(key))) throw new TypeError('native-service-runtime-path-invalid')
    const environment = options.environment ?? process.env
    const platform = options.platform ?? process.platform
    const projectRoot = options.projectRoot ?? defaultProjectRoot
    if (environment === null || typeof environment !== 'object') throw new TypeError('native-service-build-environment-invalid')
    validateSigningBuildEnvironment(environment)
    if (typeof projectRoot !== 'string' || !isAbsolute(projectRoot)) throw new TypeError('native-service-project-root-invalid')
    if (options.testRuntimeRoot !== undefined && (typeof options.testRuntimeRoot !== 'string' || !isAbsolute(options.testRuntimeRoot))) throw new TypeError('native-service-runtime-path-invalid')
    return { environment, platform, projectRoot, ...(options.testRuntimeRoot === undefined ? {} : { testRuntimeRoot: options.testRuntimeRoot }) }
}

/**
 * Validates bounded test-only dependency controls without exposing them through
 * the production command entrypoint.
 * @param {unknown} controls - Candidate deterministic test controls.
 * @returns {{lockTimeoutMs: number, lockPollMs: number, now: () => number, onAfterLockCreate?: () => Promise<void>|void, onBeforeCargo?: () => Promise<void>|void, onBeforeLockCreate?: () => Promise<void>|void, onBeforeRecoveryUnlink?: () => Promise<void>|void, onBeforeStageRename?: () => Promise<void>|void, onLockWait?: () => Promise<void>|void, processAlive: (pid: number) => boolean, runCargo: Function}} Normalized controls.
 */
function validateBuildControls(controls) {
    if (controls === null || typeof controls !== 'object' || Array.isArray(controls)) throw new TypeError('native-service-build-controls-invalid')
    const allowedControls = new Set(['isProcessAlive', 'lockPollMs', 'lockTimeoutMs', 'now', 'onAfterLockCreate', 'onBeforeCargo', 'onBeforeLockCreate', 'onBeforeRecoveryUnlink', 'onBeforeStageRename', 'onLockWait', 'runCargo'])
    if (Object.keys(controls).some((key) => !allowedControls.has(key))) throw new TypeError('native-service-build-controls-invalid')
    const lockTimeoutMs = controls.lockTimeoutMs ?? defaultLockTimeoutMs
    const lockPollMs = controls.lockPollMs ?? defaultLockPollMs
    const now = controls.now ?? Date.now
    const processAlive = controls.isProcessAlive ?? isProcessAlive
    const cargoRunner = controls.runCargo ?? runCargo
    if (!Number.isInteger(lockTimeoutMs) || lockTimeoutMs < 10 || lockTimeoutMs > defaultLockTimeoutMs || !Number.isInteger(lockPollMs) || lockPollMs < 1 || lockPollMs > 1_000 || lockPollMs > lockTimeoutMs || typeof now !== 'function' || typeof processAlive !== 'function' || typeof cargoRunner !== 'function' || (controls.onAfterLockCreate !== undefined && typeof controls.onAfterLockCreate !== 'function') || (controls.onBeforeCargo !== undefined && typeof controls.onBeforeCargo !== 'function') || (controls.onBeforeLockCreate !== undefined && typeof controls.onBeforeLockCreate !== 'function') || (controls.onBeforeRecoveryUnlink !== undefined && typeof controls.onBeforeRecoveryUnlink !== 'function') || (controls.onBeforeStageRename !== undefined && typeof controls.onBeforeStageRename !== 'function') || (controls.onLockWait !== undefined && typeof controls.onLockWait !== 'function')) {
        throw new TypeError('native-service-build-controls-invalid')
    }
    return { lockTimeoutMs, lockPollMs, now, onAfterLockCreate: controls.onAfterLockCreate, onBeforeCargo: controls.onBeforeCargo, onBeforeLockCreate: controls.onBeforeLockCreate, onBeforeRecoveryUnlink: controls.onBeforeRecoveryUnlink, onBeforeStageRename: controls.onBeforeStageRename, onLockWait: controls.onLockWait, processAlive, runCargo: cargoRunner }
}

/**
 * Builds under one exact project lock and stages only after complete validation.
 * @param {object} rawOptions - Validated by this internal boundary.
 * @param {object} rawControls - Validated production or deterministic test controls.
 * @returns {Promise<{artifactPath: string, runtimePath: string, targetDirectory: string}>} Verified artifact and stage paths.
 * @throws {Error} With a bounded stable build, path, or artifact failure code.
 */
async function buildNativeServiceInternal(rawOptions, rawControls) {
    const options = validateBuildOptions(rawOptions)
    const controls = validateBuildControls(rawControls)
    const { environment, platform, projectRoot } = options
    const cargoEnvironment = { ...environment }
    if (platform === 'darwin') {
        // ld 1267 can emit a locally valid Mach-O that dyld never advances past
        // _dyld_start on macOS 26. Disable chained fixups at the final Rust link;
        // the explicit Cargo setting also prevents ambient flags from undoing it.
        delete cargoEnvironment.RUSTFLAGS
        cargoEnvironment.CARGO_ENCODED_RUSTFLAGS = '-Clink-arg=-Wl,-no_fixup_chains'
    }
    const canonicalProjectRoot = await canonicalizeControlledRoot(projectRoot)
    const basePaths = getNativeServiceBuildPaths({ platform, projectRoot: canonicalProjectRoot })
    const lock = await acquireBuildLock(canonicalProjectRoot, basePaths.lockPath, controls)
    try {
        const assertOwnership = async () => {
            if (!(await settleRecoveryClaims(canonicalProjectRoot, lock.lockPath, controls))) throw new Error('native-service-build-lock-invalid')
            await assertBuildLockOwnership(canonicalProjectRoot, lock)
        }
        await assertOwnership()
        const runtimeRoot = options.testRuntimeRoot === undefined ? await ensureControlledDirectory(canonicalProjectRoot, basePaths.runtimeRoot) : await canonicalizeControlledRoot(options.testRuntimeRoot)
        const runtimePath = options.testRuntimeRoot === undefined ? basePaths.runtimePath : join(runtimeRoot, runtimePlatformDirectory(platform), basePaths.executableName)
        const paths = { ...basePaths, platform, runtimePath, runtimeRoot }

        await ensureControlledDirectory(canonicalProjectRoot, dirname(paths.manifestPath))
        await verifyControlledFile(canonicalProjectRoot, paths.manifestPath)
        paths.targetDirectory = await ensureControlledDirectory(canonicalProjectRoot, paths.targetDirectory)
        await ensureControlledDirectory(runtimeRoot, dirname(runtimePath))

        let result
        try {
            const args = ['build', '--quiet', '--locked', '--message-format=json', '--manifest-path', paths.manifestPath, '--bin', 'openrdx-hardware', '--target-dir', paths.targetDirectory]
            await controls.onBeforeCargo?.()
            await assertOwnership()
            result = await controls.runCargo({ args, cwd: canonicalProjectRoot, environment: cargoEnvironment, paths: Object.freeze({ ...paths }) })
        } catch {
            throw new Error('native-service-cargo-failed')
        }
        if (typeof result?.stdout !== 'string' || Buffer.byteLength(result.stdout, 'utf8') > cargoOutputLimit) throw new Error('native-service-cargo-output-invalid')

        const artifactPath = parseCargoArtifact(result.stdout, paths)
        await verifyControlledFile(paths.targetDirectory, artifactPath)
        await assertOwnership()
        await stageArtifact(artifactPath, paths, assertOwnership, async () => controls.onBeforeStageRename?.())
        return { artifactPath, runtimePath, targetDirectory: paths.targetDirectory }
    } finally {
        await releaseBuildLock(canonicalProjectRoot, lock)
    }
}

/**
 * Builds and stages the exact Cargo-reported native service binary with fixed
 * production dependencies and a deterministic development destination.
 * @param {{environment?: NodeJS.ProcessEnv, platform?: string, projectRoot?: string, testRuntimeRoot?: string}} [options] - Controlled build inputs. `testRuntimeRoot` must be one explicit existing non-link directory.
 * @returns {Promise<{artifactPath: string, runtimePath: string, targetDirectory: string}>} Verified artifact and stage paths.
 */
export async function buildNativeService(options = {}) {
    return buildNativeServiceInternal(options, {})
}

/**
 * Runs the same locked build with bounded deterministic test dependencies. This
 * export is test infrastructure; the CLI and runtime never accept these hooks.
 * @param {{environment?: NodeJS.ProcessEnv, platform?: string, projectRoot?: string, testRuntimeRoot?: string}} [options] - Controlled build inputs.
 * @param {{isProcessAlive?: (pid: number) => boolean, lockPollMs?: number, lockTimeoutMs?: number, now?: () => number, onAfterLockCreate?: () => Promise<void>|void, onBeforeCargo?: () => Promise<void>|void, onBeforeLockCreate?: () => Promise<void>|void, onBeforeRecoveryUnlink?: () => Promise<void>|void, onBeforeStageRename?: () => Promise<void>|void, onLockWait?: () => Promise<void>|void, runCargo?: Function}} [controls] - Bounded test-only controls.
 * @returns {Promise<{artifactPath: string, runtimePath: string, targetDirectory: string}>} Verified artifact and stage paths.
 */
export async function buildNativeServiceForTest(options = {}, controls = {}) {
    return buildNativeServiceInternal(options, controls)
}

/** @returns {boolean} True when Node launched this module as the build hook. */
function isDirectInvocation() {
    return process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)
}

/** @returns {Promise<void>} Runs the build hook with bounded diagnostics. */
async function runCommand() {
    try {
        await buildNativeService()
    } catch (error) {
        const code = error instanceof Error && /^native-service-[a-z-]+$/u.test(error.message) ? error.message : 'native-service-build-failed'
        process.stderr.write(`${code}\n`)
        process.exitCode = 1
    }
}

if (isDirectInvocation()) await runCommand()
