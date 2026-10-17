// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { constants } from 'node:fs'
import { open } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { assertAcceptancePath, readAcceptanceFile, validateBuildRun, verifyWindowsReleaseAcceptance } from './windows-release-acceptance.mjs'

/** @param {string} path Output file. @param {string} text Validated fixed data. @param {boolean} [append] Appends GitHub outputs. @returns {Promise<void>} Safe file write. @throws {Error} For unsafe output paths or write failures. */
async function writeOutput(path, text, append = false) {
    await assertAcceptancePath(path, true)
    const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_NOFOLLOW | (append ? constants.O_APPEND : 0), 0o600)
    try {
        const metadata = await handle.stat()
        if (!metadata.isFile() || metadata.nlink !== 1) throw new Error('invalid-output-file')
        if (!append) await handle.truncate(0)
        await handle.writeFile(text, 'utf8')
    } finally {
        await handle.close()
    }
}

/**
 * Runs the trusted local gate CLI with environment input, never executable workflow interpolation.
 * @param {string[]} args Mode and explicit filesystem arguments.
 * @param {object} env Environment containing authenticated workflow context.
 * @returns {Promise<void>} Writes only validated fixed metadata or a normalized reviewed receipt.
 * @throws {Error} For invalid context, bounded inputs, evidence or arguments.
 */
export async function runWindowsReleaseAcceptanceCli(args, env = process.env) {
    const [mode, metadataPath, sourceDirectory, installerDirectory, receiptOutput] = args
    if (!((mode === 'metadata' && args.length === 2) || (mode === 'verify' && args.length === 5))) throw new Error('invalid-command-arguments')
    const run = JSON.parse((await readAcceptanceFile(metadataPath)).toString('utf8'))
    const candidate = validateBuildRun(run, { repository: env.GITHUB_REPOSITORY, runId: env.BUILD_RUN_ID })
    if (mode === 'metadata') {
        if (env.GITHUB_OUTPUT) await writeOutput(env.GITHUB_OUTPUT, `source_commit=${candidate.sourceCommit}\nrun_id=${candidate.runId}\nrun_attempt=${candidate.runAttempt}\n`, true)
        return
    }
    if (!env.GITHUB_ACTOR) throw new Error('missing-review-actor')
    if (env.RECEIPT_PATH && env.WINDOWS_ACCEPTANCE) throw new Error('ambiguous-receipt-input')
    const text = env.RECEIPT_PATH ? (await readAcceptanceFile(env.RECEIPT_PATH, 65536)).toString('utf8') : env.WINDOWS_ACCEPTANCE
    if (typeof text !== 'string' || Buffer.byteLength(text) > 65536) throw new Error('missing-or-oversized-receipt')
    const receipt = JSON.parse(text)
    const result = await verifyWindowsReleaseAcceptance({ run, receipt, repository: env.GITHUB_REPOSITORY, actor: env.GITHUB_ACTOR, runId: env.BUILD_RUN_ID, sourceDirectory, installerDirectory })
    await writeOutput(receiptOutput, JSON.stringify(result.receipt))
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        await runWindowsReleaseAcceptanceCli(process.argv.slice(2))
    } catch {
        // Input data may contain credentials: log no raw JSON, paths, child output or parse errors.
        console.error('Windows release acceptance validation failed')
        process.exitCode = 1
    }
}
