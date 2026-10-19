// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { link, readFile, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'
import { verifyReleaseAssets } from '../scripts/release-assets.mjs'
import { verifyReleaseCandidate } from '../scripts/release-candidate.mjs'
import { runReleaseCandidateCli } from '../scripts/verify-release-candidate.mjs'
import { fixture } from './helpers/windows-release-acceptance-fixture.mjs'

/** Creates real complete installer files without supplying any manual acceptance. @param {object} t Cleanup context. @returns {Promise<object>} Candidate options. */
async function inputs(t) {
    const options = await fixture(t)
    delete options.receipt
    await verifyReleaseAssets({ directory: options.installerDirectory, version: '1.0.1' })
    return options
}

test('successful complete build verifies without VM receipts and retains every asset hash', async (t) => {
    const options = await inputs(t)
    const candidate = await verifyReleaseCandidate(options)
    assert.equal(candidate.installers.length, 16)
    assert.equal(Object.keys(candidate.assets).length, 17)
    assert.equal(candidate.runAttempt, 2)
    assert.equal(Object.hasOwn(candidate, 'receipt'), false)
    assert.deepEqual(await verifyReleaseCandidate({ ...options, expectedCandidate: candidate }), candidate)
})

for (const mutation of ['failed', 'foreign', 'pull-request', 'attempt', 'commit', 'hash', 'checksum', 'missing', 'extra', 'version', 'hardlink']) {
    test(`candidate rejects ${mutation} without modifying checksum evidence`, async (t) => {
        const options = await inputs(t)
        const expectedCandidate = await verifyReleaseCandidate(options)
        const checksumPath = join(options.installerDirectory, 'SHA256SUMS.txt')
        if (mutation === 'failed') options.run.conclusion = 'failure'
        if (mutation === 'foreign') options.run.head_repository.full_name = 'foreign/repository'
        if (mutation === 'pull-request') options.run.event = 'pull_request'
        if (mutation === 'attempt') options.run.run_attempt++
        if (mutation === 'commit') options.run.head_sha = 'b'.repeat(40)
        if (mutation === 'hash') await writeFile(join(options.installerDirectory, expectedCandidate.installers[0]), 'changed installer')
        if (mutation === 'checksum') await writeFile(checksumPath, 'invalid checksums\n')
        if (mutation === 'missing') await rm(join(options.installerDirectory, expectedCandidate.installers[0]))
        if (mutation === 'extra') await writeFile(join(options.installerDirectory, 'unexpected.exe'), 'extra')
        if (mutation === 'version') await writeFile(join(options.sourceDirectory, 'package.json'), '{"version":"1.0.2"}')
        if (mutation === 'hardlink') await link(join(options.installerDirectory, expectedCandidate.installers[0]), join(options.root, 'hardlink'))
        const checksumBefore = await readFile(checksumPath)
        await assert.rejects(verifyReleaseCandidate({ ...options, expectedCandidate }))
        assert.deepEqual(await readFile(checksumPath), checksumBefore)
    })
}

test('candidate CLI binds refreshed metadata to the original source and attempt and protects linked outputs', async (t) => {
    const options = await inputs(t)
    const metadata = join(options.root, 'run.json')
    const output = join(options.root, 'candidate.json')
    const env = { BUILD_RUN_ID: options.runId, GITHUB_REPOSITORY: options.repository, EXPECTED_SOURCE_COMMIT: options.run.head_sha, EXPECTED_RUN_ATTEMPT: '2' }
    await writeFile(metadata, JSON.stringify(options.run))
    const args = ['verify', metadata, options.sourceDirectory, options.installerDirectory, output]
    await runReleaseCandidateCli(args, env)
    await runReleaseCandidateCli(['verify', metadata, options.sourceDirectory, options.installerDirectory, join(options.root, 'rechecked.json'), output], env)
    await assert.rejects(runReleaseCandidateCli(args, { ...env, EXPECTED_RUN_ATTEMPT: '3' }))
    await assert.rejects(runReleaseCandidateCli(args, { ...env, EXPECTED_SOURCE_COMMIT: 'b'.repeat(40) }))
    const protectedFile = join(options.root, 'protected-output')
    await writeFile(protectedFile, 'keep these bytes')
    const linkedOutput = join(options.root, 'linked-output')
    await link(protectedFile, linkedOutput)
    await assert.rejects(runReleaseCandidateCli(['verify', metadata, options.sourceDirectory, options.installerDirectory, linkedOutput], env))
    assert.equal(await readFile(protectedFile, 'utf8'), 'keep these bytes')
})
