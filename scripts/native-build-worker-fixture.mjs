// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { access, mkdir, open, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'

import { buildNativeServiceForTest } from './build-native-service.mjs'

const [projectRoot, testRuntimeRootArgument, mode, startedPath, releasePath, waitingPath, artifactContents, lockTimeoutArgument, recoveryGatePath, recoveryReleasePath, criticalPath, overlapPath, beforeLockCreateGatePath, beforeLockCreateReleasePath, afterLockCreateGatePath, afterLockCreateReleasePath] = process.argv.slice(2)

/** @returns {Promise<void>} Yields briefly while a deterministic test gate is held. */
async function pause() {
    await delay(10)
}

/**
 * Waits for the parent-owned release marker with a hard test bound.
 * @returns {Promise<void>} Resolves when released.
 * @throws {Error} When the parent never releases this worker.
 */
async function waitForRelease(markerPath) {
    const deadline = Date.now() + 10_000
    while (Date.now() < deadline) {
        try {
            await access(markerPath)
            return
        } catch {
            await pause()
        }
    }
    throw new Error('native-build-worker-release-timeout')
}

/**
 * Publishes one gate marker and waits for its parent-owned release marker.
 * @param {string} gatePath - Marker proving that the worker reached the gate.
 * @param {string} gateReleasePath - Marker that releases the worker.
 * @returns {Promise<void>} Resolves when the parent releases the gate.
 */
async function holdGate(gatePath, gateReleasePath) {
    await writeFile(gatePath, 'gated')
    await waitForRelease(gateReleasePath)
}

/**
 * Emits one exact Cargo artifact record for a worker-created executable.
 * @param {string} artifactPath - Controlled executable candidate.
 * @returns {string} Cargo JSON-lines output.
 */
function cargoArtifactOutput(artifactPath) {
    return `${JSON.stringify({ reason: 'compiler-artifact', target: { name: 'openrdx-hardware', kind: ['bin'] }, profile: { test: false }, executable: artifactPath })}\n`
}

/** @returns {Promise<void>} Runs one gated build invocation for the parent test. */
async function runWorker() {
    const options = { projectRoot }
    if (testRuntimeRootArgument !== '-') options.testRuntimeRoot = testRuntimeRootArgument
    const controls = {
        onAfterLockCreate:
            afterLockCreateGatePath === '-'
                ? undefined
                : async () => {
                      await holdGate(afterLockCreateGatePath, afterLockCreateReleasePath)
                  },
        onBeforeLockCreate:
            beforeLockCreateGatePath === '-'
                ? undefined
                : async () => {
                      await holdGate(beforeLockCreateGatePath, beforeLockCreateReleasePath)
                  },
        onBeforeRecoveryUnlink:
            recoveryGatePath === '-'
                ? undefined
                : async () => {
                      await holdGate(recoveryGatePath, recoveryReleasePath)
                  },
        lockTimeoutMs: Number(lockTimeoutArgument),
        onLockWait:
            waitingPath === '-'
                ? undefined
                : async () => {
                      await writeFile(waitingPath, 'waiting')
                  },
        runCargo: async ({ paths }) => {
            let criticalHandle
            try {
                if (criticalPath !== '-') {
                    try {
                        criticalHandle = await open(criticalPath, 'wx')
                    } catch (error) {
                        if (error?.code === 'EEXIST') await writeFile(overlapPath, 'overlap')
                        throw error
                    }
                }
                await writeFile(startedPath, 'started')
                await waitForRelease(releasePath)
                if (mode === 'failure') throw new Error('controlled-cargo-failure')
                const artifactPath = join(paths.targetDirectory, 'debug', paths.executableName)
                await mkdir(join(paths.targetDirectory, 'debug'), { recursive: true })
                await writeFile(artifactPath, artifactContents)
                return { stdout: cargoArtifactOutput(artifactPath) }
            } finally {
                try {
                    await criticalHandle?.close()
                } catch {
                    // Preserve the gated build result while still removing its marker.
                }
                if (criticalHandle !== undefined) await rm(criticalPath, { force: true })
            }
        }
    }
    try {
        await buildNativeServiceForTest(options, controls)
        if (mode !== 'success' && mode !== 'success-or-lock-timeout') throw new Error('native-build-worker-unexpected-success')
    } catch (error) {
        const expectedFailure = mode === 'failure' && error?.message === 'native-service-cargo-failed'
        const expectedTimeout = (mode === 'lock-timeout' || mode === 'success-or-lock-timeout') && error?.message === 'native-service-build-lock-timeout'
        if (!expectedFailure && !expectedTimeout) throw error
    }
}

try {
    await runWorker()
} catch {
    process.stderr.write('native-build-worker-failed\n')
    process.exitCode = 1
}
