// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { constants } from 'node:fs'
import { open } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { verifyReleaseCandidate } from './release-candidate.mjs'
import { assertAcceptancePath, readAcceptanceFile, validateBuildRun } from './windows-release-acceptance.mjs'

/** Writes bounded workflow-owned metadata to a regular no-follow output. @param {string} path Explicit output. @param {string} text Closed metadata. @param {boolean} [append] Append GitHub outputs. @returns {Promise<void>} Completes after close. @throws {Error} For unsafe or unwritable outputs. */
async function writeOutput(path, text, append = false) {
    await assertAcceptancePath(path, true)
    const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_NOFOLLOW | (append ? constants.O_APPEND : 0), 0o600)
    try {
        const info = await handle.stat()
        if (!info.isFile() || info.nlink !== 1) throw new Error('invalid-output')
        // Check the pinned file before truncation so a rejected hard link cannot
        // change another file's contents as a side effect of opening the output.
        if (!append) await handle.truncate(0)
        await handle.writeFile(text)
    } finally {
        await handle.close()
    }
}

/** Validates metadata before downloads or verifies exact assets before publication. @param {string[]} args Fixed mode and paths; optional retained candidate for rechecking. @param {object} [env] Authenticated workflow context. @returns {Promise<void>} Writes closed metadata only. @throws {Error} For unsafe/mismatched inputs or changed source/attempt. */
export async function runReleaseCandidateCli(args, env = process.env) {
    const [mode, metadataPath, sourceDirectory, installerDirectory, output, expectedPath] = args
    if (!((mode === 'metadata' && args.length === 2) || (mode === 'verify' && [5, 6].includes(args.length)))) throw new Error('invalid-command-arguments')
    const run = JSON.parse((await readAcceptanceFile(metadataPath)).toString('utf8'))
    const build = validateBuildRun(run, { repository: env.GITHUB_REPOSITORY, runId: env.BUILD_RUN_ID })
    if (mode === 'metadata') {
        if (env.GITHUB_OUTPUT) await writeOutput(env.GITHUB_OUTPUT, `source_commit=${build.sourceCommit}\nrun_id=${build.runId}\nrun_attempt=${build.runAttempt}\n`, true)
        return
    }
    if ((env.EXPECTED_SOURCE_COMMIT && env.EXPECTED_SOURCE_COMMIT !== build.sourceCommit) || (env.EXPECTED_RUN_ATTEMPT && env.EXPECTED_RUN_ATTEMPT !== String(build.runAttempt))) throw new Error('changed-build-attempt')
    const expectedCandidate = expectedPath ? JSON.parse((await readAcceptanceFile(expectedPath)).toString('utf8')) : undefined
    const candidate = await verifyReleaseCandidate({ run, repository: env.GITHUB_REPOSITORY, runId: env.BUILD_RUN_ID, sourceDirectory, installerDirectory, expectedCandidate })
    await writeOutput(output, JSON.stringify(candidate))
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        await runReleaseCandidateCli(process.argv.slice(2))
    } catch {
        console.error('Release candidate verification failed')
        process.exitCode = 1
    }
}
