// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { link, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { promisify } from 'node:util'
import { test } from 'node:test'
import { evidenceSha256, validateBuildRun, verifyWindowsReleaseAcceptance } from '../scripts/windows-release-acceptance.mjs'
import { authMarker, buildRun, commit, evidence, fixture, fullMarker, manager, mcpMarker, repository, sha } from './helpers/windows-release-acceptance-fixture.mjs'

const execute = promisify(execFile)
const cli = resolve('scripts/verify-windows-release-acceptance.mjs')

/** Recomputes fixture binding after an intentional evidence mutation. @param {object} receipt Fixture receipt. @returns {void} */
function rehash(receipt) {
    for (const entry of receipt.windows) entry.evidenceSha256 = evidenceSha256(entry.evidence)
}

/** @param {object} input Verification fixture. @returns {Promise<object>} Real gate result. */
async function verify(input) {
    return await verifyWindowsReleaseAcceptance(input)
}

test('accepts exact successful candidate, checks all sixteen installers and removes only VM identity', async (t) => {
    const input = await fixture(t)
    const result = await verify(input)
    assert.equal(result.sourceCommit, commit)
    assert.equal(result.version, '1.0.1')
    assert.equal(result.installers.length, 16)
    assert.equal(Object.hasOwn(result.receipt.windows[0].evidence.report, 'vm'), false)
    assert.equal(result.receipt.reviewedBy, 'Maintainer')
    assert.match(await readFile(join(input.installerDirectory, 'SHA256SUMS.txt'), 'utf8'), /OpenRDXManager-1\.0\.1-win-arm64\.exe/u)
    assert.equal(input.receipt.windows[0].evidence.report.vm, '11111111-1111-4111-8111-111111111111')
})

test('canonical evidence hashing sorts recursively, preserves arrays and omits the existing VM identifier', () => {
    const one = { stdout: 'ok', stderr: '', report: { version: 1, vm: 'private', childCleanup: { z: 2, a: 1 } } }
    const two = { report: { childCleanup: { a: 1, z: 2 }, version: 1 }, stderr: '', stdout: 'ok' }
    const expected = sha('{"report":{"childCleanup":{"a":1,"z":2},"version":1},"stderr":"","stdout":"ok"}')
    assert.equal(evidenceSha256(one), expected)
    assert.equal(evidenceSha256(two), expected)
})

for (const [description, change] of [
    [
        'wrong run',
        (r) => {
            r.id = 124
        }
    ],
    [
        'unsafe run id',
        (r) => {
            r.id = Number.MAX_SAFE_INTEGER + 1
        }
    ],
    [
        'zero attempt',
        (r) => {
            r.run_attempt = 0
        }
    ],
    [
        'failed build',
        (r) => {
            r.conclusion = 'failure'
        }
    ],
    [
        'incomplete build',
        (r) => {
            r.status = 'in_progress'
        }
    ],
    [
        'PR event',
        (r) => {
            r.event = 'pull_request'
        }
    ],
    [
        'tag event',
        (r) => {
            r.event = 'release'
        }
    ],
    [
        'non-main branch',
        (r) => {
            r.head_branch = 'feature'
        }
    ],
    [
        'foreign head repository',
        (r) => {
            r.head_repository.full_name = 'evil/OpenRDX'
        }
    ],
    [
        'wrong workflow path',
        (r) => {
            r.path = '.github/workflows/evil.yml'
        }
    ],
    [
        'wrong workflow name',
        (r) => {
            r.name = 'Other'
        }
    ],
    [
        'invalid source',
        (r) => {
            r.head_sha = 'abc'
        }
    ],
    [
        'invalid start time',
        (r) => {
            r.run_started_at = 'yesterday'
        }
    ]
])
    test(`rejects ${description}`, () => {
        const run = buildRun()
        change(run)
        assert.throws(() => validateBuildRun(run, { repository, runId: '123' }))
    })

test('validates metadata into fixed safe fields and accepts manual builds', () => {
    const run = buildRun()
    run.event = 'workflow_dispatch'
    assert.deepEqual(validateBuildRun(run, { repository, runId: '123' }), { sourceCommit: commit, runId: '123', runAttempt: 2, startedAt: '2026-10-17T08:00:00Z' })
    for (const runId of ['01', '-1', '0', '1\nsource_commit=evil', '9007199254740992']) assert.throws(() => validateBuildRun(run, { repository, runId }))
})

for (const [description, change] of [
    [
        'wrong version',
        (r) => {
            r.version = '1.0.2'
        }
    ],
    [
        'wrong repository',
        (r) => {
            r.repository = 'evil/OpenRDX'
        }
    ],
    [
        'wrong run receipt',
        (r) => {
            r.buildRunId = '124'
        }
    ],
    [
        'wrong attempt',
        (r) => {
            r.buildRunAttempt = 1
        }
    ],
    [
        'wrong source',
        (r) => {
            r.sourceCommit = 'b'.repeat(40)
        }
    ],
    [
        'wrong verifier',
        (r) => {
            r.verifierSha256 = 'b'.repeat(64)
        }
    ],
    [
        'wrong review actor',
        (r) => {
            r.reviewedBy = 'someone-else'
        }
    ],
    [
        'stale review',
        (r) => {
            r.reviewedAt = '2026-10-01T12:00:00Z'
        }
    ],
    [
        'future review',
        (r) => {
            r.reviewedAt = '2026-10-17T12:05:01Z'
        }
    ],
    [
        'malformed review time',
        (r) => {
            r.reviewedAt = '2026-02-30T10:00:00Z'
        }
    ],
    [
        'review predates build',
        (r) => {
            r.reviewedAt = '2026-10-17T07:59:59Z'
        }
    ],
    [
        'completion predates build',
        (r) => {
            r.windows[0].completedAt = '2026-10-17T07:59:59Z'
        }
    ],
    [
        'completion after review',
        (r) => {
            r.windows[0].completedAt = '2026-10-17T11:00:01Z'
        }
    ],
    [
        'missing architecture',
        (r) => {
            r.windows.pop()
        }
    ],
    [
        'duplicate architecture',
        (r) => {
            r.windows[1] = structuredClone(r.windows[0])
        }
    ],
    [
        'unsafe installer path',
        (r) => {
            r.windows[0].installer = '../installer.exe'
        }
    ],
    [
        'installer hash mismatch',
        (r) => {
            r.windows[0].installerSha256 = 'b'.repeat(64)
        }
    ],
    [
        'tampered evidence hash',
        (r) => {
            r.windows[0].evidenceSha256 = 'b'.repeat(64)
        }
    ],
    [
        'private receipt extra',
        (r) => {
            r.password = 'private'
        }
    ],
    [
        'private entry extra',
        (r) => {
            r.windows[0].hardware = true
        }
    ]
])
    test(`rejects ${description}`, async (t) => {
        const input = await fixture(t)
        change(input.receipt)
        await assert.rejects(verify(input))
    })

for (const [description, change] of [
    [
        'helper source mismatch',
        (e) => {
            e.report.sourceCommit = 'b'.repeat(40)
        }
    ],
    [
        'helper wrong mode',
        (e) => {
            e.report.mode = 'diagnostic'
        }
    ],
    [
        'helper failure',
        (e) => {
            e.report.failure = 'failed'
        }
    ],
    [
        'helper failed status',
        (e) => {
            e.report.status = 'failure'
        }
    ],
    [
        'helper incomplete lifecycle',
        (e) => {
            e.report.completed = []
        }
    ],
    [
        'helper wrong phase',
        (e) => {
            e.report.phase = 'running'
        }
    ],
    [
        'unobserved child exit',
        (e) => {
            e.report.childCleanup = 'not-observed'
        }
    ],
    [
        'private helper extra',
        (e) => {
            e.report.token = 'private'
        }
    ],
    [
        'private nested helper extra',
        (e) => {
            e.report.completed.push('private')
        }
    ],
    [
        'private evidence extra',
        (e) => {
            e.machinePassword = 'private'
        }
    ],
    [
        'nonempty stderr',
        (e) => {
            e.stderr = 'failure'
        }
    ],
    [
        'missing lifecycle success',
        (e) => {
            e.stdout = e.stdout.replace(fullMarker, '')
        }
    ],
    [
        'failed service authentication',
        (e) => {
            e.stdout = e.stdout.replace(authMarker, 'authentication failed')
        }
    ],
    [
        'missing external MCP pass',
        (e) => {
            e.stdout = e.stdout.replace(mcpMarker, '')
        }
    ],
    [
        'elevated worker',
        (e) => {
            e.stdout = e.stdout.replace('elevated=False', 'elevated=True')
        }
    ],
    [
        'elevated selected manager',
        (e) => {
            e.stdout = e.stdout.replace(manager, manager.replace('elevated=False', 'elevated=True'))
        }
    ],
    [
        'failed token fact',
        (e) => {
            e.stdout = e.stdout.replace('type-limited=True', 'type-limited=False')
        }
    ],
    [
        'missing copied rejection',
        (e) => {
            e.stdout = e.stdout.replace('Windows copied Manager privileged authentication denied', '')
        }
    ],
    [
        'missing native tamper rejection',
        (e) => {
            e.stdout = e.stdout.replace('OpenRDX native failure: phase=verify-enrollment reason=AccessDenied', '')
        }
    ],
    [
        'private arbitrary stdout',
        (e) => {
            e.stdout += '\npassword=secret'
        }
    ]
])
    test(`rejects ${description} even when rehashed by the operator`, async (t) => {
        const input = await fixture(t)
        change(input.receipt.windows[0].evidence)
        try {
            rehash(input.receipt)
        } catch {
            return
        }
        await assert.rejects(verify(input))
    })

test('rejects oversized API receipts and missing non-Windows installer assets', async (t) => {
    const input = await fixture(t)
    const original = input.receipt.windows[0].evidence.stdout
    input.receipt.windows[0].evidence.stdout = 'x'.repeat(65537)
    await assert.rejects(verify(input))
    input.receipt.windows[0].evidence.stdout = original
    await rm(join(input.installerDirectory, 'OpenRDXManager-1.0.1-mac-x64.pkg'))
    await assert.rejects(verify(input))
})

for (const relative of ['package.json', 'scripts/verify-windows-installation.ps1'])
    test(`rejects linked candidate ${relative}`, async (t) => {
        const input = await fixture(t)
        const path = join(input.sourceDirectory, relative)
        const external = join(input.root, 'external')
        await writeFile(external, await readFile(path))
        await rm(path)
        await symlink(external, path)
        await assert.rejects(verify(input))
    })

test('rejects linked source directories, installer files and checksum output without following them', async (t) => {
    const input = await fixture(t)
    const sourceLink = join(input.root, 'linked-source')
    await symlink(input.sourceDirectory, sourceLink)
    await assert.rejects(verify({ ...input, sourceDirectory: sourceLink }))
    const installer = join(input.installerDirectory, input.receipt.windows[0].installer)
    const external = join(input.root, 'external-installer')
    await writeFile(external, await readFile(installer))
    await rm(installer)
    await symlink(external, installer)
    await assert.rejects(verify(input))
    await rm(installer)
    await writeFile(installer, await readFile(external))
    const untouched = join(input.root, 'untouched')
    await writeFile(untouched, 'private')
    await symlink(untouched, join(input.installerDirectory, 'SHA256SUMS.txt'))
    await assert.rejects(verify(input))
    assert.equal(await readFile(untouched, 'utf8'), 'private')
})

test('rejects oversized and nonregular candidate metadata', async (t) => {
    const input = await fixture(t)
    await writeFile(join(input.sourceDirectory, 'package.json'), ' '.repeat(1048577))
    await assert.rejects(verify(input))
    await rm(join(input.sourceDirectory, 'package.json'))
    await mkdir(join(input.sourceDirectory, 'package.json'))
    await assert.rejects(verify(input))
})

test('CLI metadata writes only fixed validated outputs and refuses invalid metadata without output', async (t) => {
    const input = await fixture(t)
    const metadata = join(input.root, 'run.json')
    const output = join(input.root, 'outputs')
    await writeFile(metadata, JSON.stringify(input.run))
    const env = { ...process.env, BUILD_RUN_ID: '123', GITHUB_REPOSITORY: repository, GITHUB_OUTPUT: output }
    await execute(process.execPath, [cli, 'metadata', metadata], { env })
    assert.equal(await readFile(output, 'utf8'), `source_commit=${commit}\nrun_id=123\nrun_attempt=2\n`)
    await rm(output)
    input.run.event = 'pull_request'
    await writeFile(metadata, JSON.stringify(input.run))
    await assert.rejects(execute(process.execPath, [cli, 'metadata', metadata], { env }))
    await assert.rejects(readFile(output))
})

test('CLI verify reads environment JSON, re-verifies normalized receipt paths and refuses malformed or oversized input', async (t) => {
    const input = await fixture(t)
    // CLI time is intentionally live; adjust all fixture timestamps relative to this process.
    const started = new Date(Date.now() - 120000).toISOString()
    input.run.run_started_at = started
    input.receipt.reviewedAt = new Date().toISOString()
    for (const item of input.receipt.windows) item.completedAt = started
    const metadata = join(input.root, 'run.json')
    const output = join(input.root, 'receipt.json')
    await writeFile(metadata, JSON.stringify(input.run))
    const args = [cli, 'verify', metadata, input.sourceDirectory, input.installerDirectory, output]
    const env = { ...process.env, BUILD_RUN_ID: '123', GITHUB_REPOSITORY: repository, GITHUB_ACTOR: 'maintainer', WINDOWS_ACCEPTANCE: JSON.stringify(input.receipt) }
    await execute(process.execPath, args, { env })
    const normalized = JSON.parse(await readFile(output, 'utf8'))
    assert.equal(Object.hasOwn(normalized.windows[0].evidence.report, 'vm'), false)
    delete env.WINDOWS_ACCEPTANCE
    env.RECEIPT_PATH = output
    await execute(process.execPath, [...args.slice(0, -1), join(input.root, 'second.json')], { env })
    delete env.RECEIPT_PATH
    for (const receipt of ['{', ' '.repeat(65537), '{}']) {
        env.WINDOWS_ACCEPTANCE = receipt
        await assert.rejects(execute(process.execPath, args, { env }))
    }
})

test('rejects unsafe manifest versions before resolving installer paths', async (t) => {
    const input = await fixture(t)
    input.receipt.version = '../outside'
    await writeFile(join(input.sourceDirectory, 'package.json'), JSON.stringify({ version: '../outside' }))
    for (const item of input.receipt.windows) item.installer = `OpenRDXManager-../outside-win-${item.architecture}.exe`
    await assert.rejects(verify(input))
})

test('rejects receipts older than seven days even for a matching old successful build', async (t) => {
    const input = await fixture(t)
    input.run.run_started_at = '2026-10-01T08:00:00Z'
    input.receipt.reviewedAt = '2026-10-01T11:00:00Z'
    for (const item of input.receipt.windows) item.completedAt = '2026-10-01T10:00:00Z'
    await assert.rejects(verify(input))
})

test('CLI rejects linked metadata, linked receipt inputs and linked output without disclosing private data', async (t) => {
    const input = await fixture(t)
    const metadata = join(input.root, 'run.json')
    const link = join(input.root, 'run-link.json')
    const output = join(input.root, 'outputs')
    const privateOutput = join(input.root, 'private')
    await writeFile(metadata, JSON.stringify(input.run))
    await symlink(metadata, link)
    const env = { ...process.env, BUILD_RUN_ID: '123', GITHUB_REPOSITORY: repository, GITHUB_OUTPUT: output }
    await assert.rejects(execute(process.execPath, [cli, 'metadata', link], { env }))
    await writeFile(privateOutput, 'private')
    await symlink(privateOutput, output)
    await assert.rejects(execute(process.execPath, [cli, 'metadata', metadata], { env }))
    assert.equal(await readFile(privateOutput, 'utf8'), 'private')
    const receipt = join(input.root, 'receipt.json')
    const linkedReceipt = join(input.root, 'linked-receipt.json')
    await writeFile(receipt, JSON.stringify(input.receipt))
    await symlink(receipt, linkedReceipt)
    env.GITHUB_ACTOR = 'maintainer'
    env.RECEIPT_PATH = linkedReceipt
    await assert.rejects(execute(process.execPath, [cli, 'verify', metadata, input.sourceDirectory, input.installerDirectory, join(input.root, 'result.json')], { env }))
})

test('CLI bounds metadata before JSON parsing and never logs input values', async (t) => {
    const input = await fixture(t)
    const metadata = join(input.root, 'run.json')
    await writeFile(metadata, 'private-secret'.repeat(100000))
    const env = { ...process.env, BUILD_RUN_ID: '123', GITHUB_REPOSITORY: repository }
    await assert.rejects(execute(process.execPath, [cli, 'metadata', metadata], { env }), (error) => {
        assert.equal(error.code, 1)
        assert.doesNotMatch(error.stderr, /private-secret/u)
        return true
    })
})

test('accepts LF transcript and receipt age/future-skew boundaries without relaxing marker equality', async (t) => {
    const input = await fixture(t)
    for (const item of input.receipt.windows) item.evidence.stdout = item.evidence.stdout.replaceAll('\r\n', '\n')
    rehash(input.receipt)
    await verify(input)
    input.receipt.reviewedAt = '2026-10-17T12:05:00Z'
    await verify(input)
    input.receipt.windows[0].evidence.stdout = input.receipt.windows[0].evidence.stdout.replace(authMarker, ` ${authMarker}`)
    rehash(input.receipt)
    await assert.rejects(verify(input))
})

test('rejects extra successful authentication markers and nonempty whitespace stderr', async (t) => {
    const input = await fixture(t)
    input.receipt.windows[0].evidence.stdout = `${authMarker}\n${input.receipt.windows[0].evidence.stdout}`
    rehash(input.receipt)
    await assert.rejects(verify(input))
    input.receipt.windows[0].evidence = evidence('x64')
    input.receipt.windows[0].evidence.stderr = '\n'
    rehash(input.receipt)
    await assert.rejects(verify(input))
})

test('rejects hardlinked checksum output without overwriting the other link', async (t) => {
    const input = await fixture(t)
    const privateFile = join(input.root, 'private-file')
    await writeFile(privateFile, 'untouched private state')
    await link(privateFile, join(input.installerDirectory, 'SHA256SUMS.txt'))
    await assert.rejects(verify(input))
    assert.equal(await readFile(privateFile, 'utf8'), 'untouched private state')
})

test('accepts the closed real successful transcript inventory without treating hardware flags as physical proof', async (t) => {
    const input = await fixture(t)
    const extra = ['OpenRDX Manager launch: result=ok', 'OpenRDX setup verified: trust=local runtime=protected-and-hash-verified service=LocalService service-sid=unrestricted device-access=unverified', 'OpenRDXManager service readiness: ready native hardware=true capability=available reason=none', 'OpenRDXManager smoke test passed: renderer=mounted service=ready mode=native hardware=true capability=none reason=none', 'OpenRDX native failure: phase=entrypoint reason=AccessDenied', 'OpenRDX setup incomplete: launch installed Manager as the active console user, then rerun the elevated installer Repair action', 'OpenRDX setup verified: admission=revoked runtime=owned quiescence=verified', 'OpenRDX setup verified: service=removed enrollment=revoked journal=preserved', 'owned-remover-only-residue-scheduled-for-reboot']
    for (const item of input.receipt.windows) {
        item.evidence.stdout = [...extra, item.evidence.stdout.replaceAll('local-builtin-admin=True', 'local-builtin-admin=False')].join('\n')
    }
    rehash(input.receipt)
    const result = await verify(input)
    assert.equal(Object.hasOwn(result, 'hardwareVerified'), false)
})

test('accepts a standard non-admin default token with no linked token', async (t) => {
    const input = await fixture(t)
    for (const item of input.receipt.windows) item.evidence.stdout = item.evidence.stdout.replaceAll('type-default=False type-full=False type-limited=True linked-query=True linked-size-match=True linked-available=True', 'type-default=True type-full=False type-limited=False linked-query=False linked-size-match=False linked-available=False')
    rehash(input.receipt)
    await verify(input)
})

for (const [description, prefix] of [
    ['worker token context', 'OpenRDX token context: subject=worker '],
    ['selected Manager token context', 'OpenRDX token context: subject=worker-selected-manager '],
    ['console context', 'OpenRDX console context: '],
    ['interactive task', 'OpenRDX interactive task: ']
]) {
    for (const mutation of ['missing one', 'missing all', 'repeated'])
        test(`rejects ${mutation} ${description} records even after evidence rehash`, async (t) => {
            const input = await fixture(t)
            const item = input.receipt.windows[0]
            const lines = item.evidence.stdout.split('\r\n')
            const first = lines.findIndex((line) => line.startsWith(prefix))
            assert.ok(first >= 0)
            if (mutation === 'missing one') lines.splice(first, 1)
            else if (mutation === 'missing all') {
                for (let index = lines.length - 1; index >= 0; index--) if (lines[index].startsWith(prefix)) lines.splice(index, 1)
            } else lines.splice(first, 0, lines[first])
            item.evidence.stdout = lines.join('\r\n')
            rehash(input.receipt)
            await assert.rejects(verify(input), /incomplete-acceptance-transcript/u)
        })
}

test('CLI roundtrips a valid compact receipt of exactly 65536 bytes without adding bytes', async (t) => {
    const input = await fixture(t)
    const started = new Date(Date.now() - 120000).toISOString()
    input.run.run_started_at = started
    input.receipt.reviewedAt = new Date().toISOString()
    for (const item of input.receipt.windows) {
        item.completedAt = started
        delete item.evidence.report.vm
    }
    let missing = 65536 - Buffer.byteLength(JSON.stringify(input.receipt))
    if (missing % 2 !== 0) {
        input.receipt.reviewedAt = input.receipt.reviewedAt.replace(/(\.\d{2})\dZ$/u, '$1Z')
        missing++
    }
    assert.ok(missing > 0 && missing % 2 === 0)
    input.receipt.windows[0].evidence.stdout = `${'\n'.repeat(missing / 2)}${input.receipt.windows[0].evidence.stdout}`
    rehash(input.receipt)
    const receiptText = JSON.stringify(input.receipt)
    assert.equal(Buffer.byteLength(receiptText), 65536)
    const metadata = join(input.root, 'run.json')
    const output = join(input.root, 'receipt.json')
    const second = join(input.root, 'receipt-second.json')
    await writeFile(metadata, JSON.stringify(input.run))
    const args = [cli, 'verify', metadata, input.sourceDirectory, input.installerDirectory, output]
    const env = { ...process.env, BUILD_RUN_ID: '123', GITHUB_REPOSITORY: repository, GITHUB_ACTOR: 'maintainer', WINDOWS_ACCEPTANCE: receiptText }
    await execute(process.execPath, args, { env })
    assert.equal((await readFile(output)).length, 65536)
    delete env.WINDOWS_ACCEPTANCE
    env.RECEIPT_PATH = output
    await execute(process.execPath, [...args.slice(0, -1), second], { env })
    assert.equal((await readFile(second)).length, 65536)
})
