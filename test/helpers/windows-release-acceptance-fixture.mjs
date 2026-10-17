// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { evidenceSha256 } from '../../scripts/windows-release-acceptance.mjs'

export const repository = 'example/OpenRDX'
export const commit = 'a'.repeat(40)
export const now = new Date('2026-10-17T12:00:00.000Z')
export const fullMarker = 'OpenRDX Windows installation acceptance passed: clean, repair, upgrade, tamper-denied, copied-manager-denied, owned-removal'
export const authMarker = 'OpenRDXManager installed service authentication passed: platform=win32'
export const mcpMarker = 'OpenRDXManager packaged MCP bridge passed: external-node=true'
export const worker = 'OpenRDX Manager worker: prerequisite=ready elevation-query=True elevation-size-match=True elevated=False token-process-session-match=True token-console-match=True'
export const manager = 'OpenRDX worker-selected Manager: elevation-query=True elevation-size-match=True elevated=False session-query=True session-size-match=True process-session-query=True token-process-session-match=True token-console-match=True process-console-match=True'
export const token = 'type-query=True type-size-match=True type-default=False type-full=False type-limited=True linked-query=True linked-size-match=True linked-available=True'
export const consoleContext = 'OpenRDX console context: uac-query=True enablelua-is-one=True local-builtin-admin-query=True local-builtin-admin=True'

/** @returns {object} Authenticated GitHub run metadata with unrelated API fields permitted. */
export function buildRun() {
    return { id: 123, run_attempt: 2, head_sha: commit, head_branch: 'main', head_repository: { full_name: repository }, repository: { full_name: repository }, path: '.github/workflows/build-installers.yml', name: 'Build installers', event: 'push', status: 'completed', conclusion: 'success', run_started_at: '2026-10-17T08:00:00Z' }
}

/** @param {string|Buffer} value Bytes to bind. @returns {string} Independent fixture hash. */
export function sha(value) {
    return createHash('sha256').update(value).digest('hex')
}

/** @param {string} architecture Exact accepted installer architecture. @returns {object} Closed successful helper evidence without identities. */
export function evidence(architecture) {
    return {
        report: { version: 1, sourceCommit: commit, mode: architecture, status: 'passed', phase: 'complete', completed: [`acceptance-${architecture}`], failure: '', childCleanup: 'observed-exit', vm: '11111111-1111-4111-8111-111111111111' },
        stdout: [...Array.from({ length: 3 }, () => [worker, `OpenRDX token context: subject=worker ${token}`, consoleContext, manager, `OpenRDX token context: subject=worker-selected-manager ${token}`, 'OpenRDX interactive task: runlevel-query=True runlevel-is-lua=True', authMarker, mcpMarker]).flat(), 'Windows copied Manager privileged authentication denied', 'OpenRDX native failure: phase=verify-enrollment reason=AccessDenied', fullMarker].join('\r\n'),
        stderr: ''
    }
}

/** Creates real candidate inputs; tests never execute candidate scripts. @param {object} t Test cleanup context. @returns {Promise<object>} Isolated verification arguments. */
export async function fixture(t) {
    const root = await mkdtemp(join(await realpath(tmpdir()), 'openrdx-release-'))
    t.after(async () => {
        await rm(root, { recursive: true, force: true })
    })
    const sourceDirectory = join(root, 'source')
    const installerDirectory = join(root, 'installers')
    await mkdir(join(sourceDirectory, 'scripts'), { recursive: true })
    await mkdir(installerDirectory)
    await writeFile(join(sourceDirectory, 'package.json'), '{"version":"1.0.1"}')
    await writeFile(join(sourceDirectory, 'scripts/verify-windows-installation.ps1'), '# candidate verifier; never execute')
    const names = []
    for (const [platform, extensions] of [
        ['mac', ['dmg', 'pkg', 'zip']],
        ['win', ['exe', 'zip']],
        ['linux', ['AppImage', 'deb', 'tar.gz']]
    ]) {
        for (const architecture of ['x64', 'arm64']) {
            for (const extension of extensions) names.push(`OpenRDXManager-1.0.1-${platform}-${architecture}.${extension}`)
        }
    }
    for (const name of names) await writeFile(join(installerDirectory, name), `installer ${name}`)
    const receipt = { schemaVersion: 1, version: '1.0.1', repository, buildRunId: '123', buildRunAttempt: 2, sourceCommit: commit, verifierSha256: sha('# candidate verifier; never execute'), reviewedBy: 'Maintainer', reviewedAt: '2026-10-17T11:00:00Z', windows: [] }
    for (const architecture of ['x64', 'arm64']) {
        const installer = `OpenRDXManager-1.0.1-win-${architecture}.exe`
        const itemEvidence = evidence(architecture)
        receipt.windows.push({ architecture, installer, installerSha256: sha(`installer ${installer}`), completedAt: '2026-10-17T10:00:00Z', evidenceSha256: evidenceSha256(itemEvidence), evidence: itemEvidence })
    }
    return { root, run: buildRun(), receipt, repository, actor: 'maintainer', runId: '123', sourceDirectory, installerDirectory, now }
}
