// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'
import { fixture, commit, sha } from './helpers/windows-release-acceptance-fixture.mjs'

/** Loads the real publisher with an assertion explaining the missing feature. @returns {Promise<Function>} Publisher. */
async function publisher() {
    let module
    try {
        module = await import('../scripts/publish-verified-release.mjs')
    } catch (error) {
        assert.fail(`reviewed release publisher must exist: ${error.code}`)
    }
    assert.equal(typeof module.publishVerifiedRelease, 'function')
    return module.publishVerifiedRelease
}

/** Creates the exact fixed notes file alongside real candidate/installer files. @param {object} t Cleanup context. @returns {Promise<object>} Gate options. */
async function inputs(t) {
    const options = await fixture(t)
    await mkdir(join(options.sourceDirectory, 'docs/releases'), { recursive: true })
    await writeFile(join(options.sourceDirectory, 'docs/releases/locally-trusted-installers.md'), '# Fixed candidate release notes\n')
    return options
}

/** Models only remote GitHub responses, preserving real local validation/hash behavior. @param {object} options Real inputs. @param {object} changes Scenario overrides. @returns {object} Command boundary and recorded writes. */
function github(options, changes = {}) {
    const calls = []
    let created = false
    let publicRelease = false
    let tagReads = 0
    let tagCreated = false
    let releaseReads = 0
    /** Supplies authenticated API headers/body. @param {number} status HTTP status. @param {object} body JSON response. @returns {object} execFile result. */
    function response(status, body) {
        return { stdout: `HTTP/2.0 ${status} OK\r\nContent-Type: application/json\r\n\r\n${JSON.stringify(body)}`, stderr: '' }
    }
    /** Runs the command boundary without any real external write. @param {string} file Executable. @param {string[]} args Structured argv. @param {object} limits Bounds. @returns {Promise<object>} Remote result. */
    async function execute(file, args, limits) {
        calls.push({ file, args, limits })
        assert.equal(file, 'gh')
        assert.equal(limits.shell, false)
        assert.equal(limits.timeout, args[0] === 'release' && args[1] === 'create' ? 600000 : 120000)
        assert.ok(limits.maxBuffer > 0 && limits.maxBuffer <= 4194304)
        if (changes.failure && calls.length === 1) throw { stdout: changes.failure === '404-text' ? '' : 'HTTP/2.0 403 Forbidden\r\n\r\n{}', stderr: 'private GitHub diagnostic HTTP 404' }
        if (args[0] === 'api') {
            const endpoint = args.at(-1)
            if (args.includes('PATCH')) {
                assert.deepEqual(args, ['api', '--method', 'PATCH', `repos/${options.repository}/releases/42`, '-F', 'draft=false', '-f', 'make_latest=true'])
                publicRelease = true
                return { stdout: '{}', stderr: '' }
            }
            if (args.includes('POST')) {
                assert.deepEqual(args, ['api', '--method', 'POST', `repos/${options.repository}/git/refs`, '-f', 'ref=refs/tags/v1.0.1', '-f', `sha=${commit}`])
                if (changes.tagCreateFailure) throw { stdout: `HTTP/2.0 ${changes.tagCreateFailure} Failure\r\n\r\n{}`, stderr: 'private concurrent tag conflict' }
                tagCreated = true
                return { stdout: '{}', stderr: '' }
            }
            // Match the documented GitHub API: draft releases are visible to
            // push-authorized listing/ID reads, never the published-tag endpoint.
            if (endpoint.includes('/releases/tags/')) {
                if ((changes.existing && !changes.existingDraft) || publicRelease) return response(200, { id: 42, tag_name: 'v1.0.1', draft: false })
                return response(404, { message: 'Not Found' })
            }
            if (/\/releases\?per_page=100&page=\d+$/u.test(endpoint)) {
                const page = Number(endpoint.split('page=').at(-1))
                const entries = [...(changes.releasePages?.[page - 1] ?? [])]
                if (changes.fullReleasePages) for (let index = 0; index < 100; index++) entries.push({ id: page * 100 + index, tag_name: `v-old-${page}-${index}`, draft: false })
                if ((changes.existing || created) && page === (changes.targetPage ?? 1)) entries.push({ id: Object.hasOwn(changes, 'releaseId') ? changes.releaseId : 42, tag_name: 'v1.0.1', draft: changes.existingDraft || !publicRelease })
                if (changes.duplicateTarget && created) entries.push({ id: 43, tag_name: 'v1.0.1', draft: true })
                return response(200, entries)
            }
            if (endpoint.endsWith('/releases/42')) {
                releaseReads++
                return response(200, { id: changes.releaseIdRace && releaseReads >= 2 ? 43 : 42, tag_name: 'v1.0.1', target_commitish: changes.target ?? commit, draft: !publicRelease, prerelease: false })
            }
            if (endpoint.includes('/git/ref/tags/')) {
                tagReads++
                if (changes.race && tagReads >= 2) return response(200, { object: { type: 'commit', sha: 'b'.repeat(40) } })
                if (!tagCreated && !changes.tag) return response(404, { message: 'Not Found' })
                return response(200, { object: (created ? changes.tagAfterCreate : undefined) ?? changes.tag ?? (tagCreated && changes.createdTagWrong ? { type: 'commit', sha: 'b'.repeat(40) } : { type: 'commit', sha: commit }) })
            }
            if (endpoint.includes('/git/tags/')) return response(200, { object: changes.peeled ?? { type: 'commit', sha: 'b'.repeat(40) } })
            if (endpoint.includes('/releases/42/assets')) {
                const names = (await readFile(join(options.installerDirectory, 'SHA256SUMS.txt'), 'utf8'))
                    .trim()
                    .split('\n')
                    .map((line) => line.slice(66))
                names.push('SHA256SUMS.txt')
                const assets = []
                for (const name of names) {
                    const bytes = await readFile(join(options.installerDirectory, name))
                    assets.push({ name, size: bytes.length, state: 'uploaded', digest: `sha256:${sha(bytes)}` })
                }
                if (publicRelease && changes.postPublishFailure) assets.pop()
                if (changes.assets === 'duplicate') assets[1] = { ...assets[0] }
                if (changes.assets === 'partial') assets.pop()
                if (changes.assets === 'extra') assets.push({ ...assets[0], name: 'receipt.json' })
                if (changes.assets === 'digest') assets[0].digest = `sha256:${'0'.repeat(64)}`
                if (changes.assets === 'missing-digest') delete assets[0].digest
                if (changes.assets === 'size') assets[0].size++
                return response(200, assets)
            }
            assert.fail(`unexpected API endpoint ${endpoint}`)
        }
        if (args[1] === 'create') {
            if (changes.createFailure) throw { stderr: 'private partial upload diagnostic' }
            created = true
            return { stdout: 'https://example.invalid/release', stderr: '' }
        }
        assert.fail('unexpected GitHub mutation')
    }
    return { execute, calls }
}

test('publication never contacts GitHub when real acceptance validation fails', async () => {
    const calls = []
    await assert.rejects((await publisher())({}, { execute: async (...args) => calls.push(args) }))
    assert.equal(calls.length, 0)
})

test('valid reviewed candidate creates exact explicit assets and publishes only after remote verification', async (t) => {
    const options = await inputs(t)
    const remote = github(options)
    assert.deepEqual(await (await publisher())(options, remote), { status: 'published', tag: 'v1.0.1' })
    const creates = remote.calls.filter((call) => call.args[1] === 'create')
    assert.equal(creates.length, 1)
    const argv = creates[0].args
    assert.deepEqual(argv.slice(0, 3), ['release', 'create', 'v1.0.1'])
    assert.equal(argv.filter((arg) => arg.startsWith(options.installerDirectory + '/')).length, 17)
    const installerNames = ['OpenRDXManager-1.0.1-mac-x64.dmg', 'OpenRDXManager-1.0.1-mac-x64.pkg', 'OpenRDXManager-1.0.1-mac-x64.zip', 'OpenRDXManager-1.0.1-mac-arm64.dmg', 'OpenRDXManager-1.0.1-mac-arm64.pkg', 'OpenRDXManager-1.0.1-mac-arm64.zip', 'OpenRDXManager-1.0.1-win-x64.exe', 'OpenRDXManager-1.0.1-win-x64.zip', 'OpenRDXManager-1.0.1-win-arm64.exe', 'OpenRDXManager-1.0.1-win-arm64.zip', 'OpenRDXManager-1.0.1-linux-x64.AppImage', 'OpenRDXManager-1.0.1-linux-x64.deb', 'OpenRDXManager-1.0.1-linux-x64.tar.gz', 'OpenRDXManager-1.0.1-linux-arm64.AppImage', 'OpenRDXManager-1.0.1-linux-arm64.deb', 'OpenRDXManager-1.0.1-linux-arm64.tar.gz'].sort()
    assert.deepEqual(
        argv.slice(3, 20),
        [...installerNames, 'SHA256SUMS.txt'].map((name) => join(options.installerDirectory, name))
    )
    assert.deepEqual(argv.slice(20), ['--repo', options.repository, '--target', commit, '--title', 'OpenRDXManager 1.0.1', '--notes-file', join(options.sourceDirectory, 'docs/releases/locally-trusted-installers.md'), '--draft', '--verify-tag'])
    const edit = remote.calls.findIndex((call) => call.args.includes('PATCH'))
    assert.ok(edit > remote.calls.findIndex((call) => call.args.at(-1).includes('/releases/42/assets')))
    assert.deepEqual(remote.calls[edit].args, ['api', '--method', 'PATCH', `repos/${options.repository}/releases/42`, '-F', 'draft=false', '-f', 'make_latest=true'])
    assert.equal(remote.calls.at(-1).args.at(-1), `repos/${options.repository}/releases/42/assets?per_page=100`)
})

for (const [name, changes] of [
    ['existing release', { existing: true }],
    ['conflicting lightweight tag', { tag: { type: 'commit', sha: 'b'.repeat(40) } }],
    ['conflicting annotated tag', { tag: { type: 'tag', sha: 'c'.repeat(40) } }],
    ['cyclic annotated tag', { tag: { type: 'tag', sha: 'c'.repeat(40) }, peeled: { type: 'tag', sha: 'c'.repeat(40) } }],
    ['authentication failure', { failure: 'auth' }],
    ['network failure with misleading 404 text', { failure: '404-text' }],
    ['tag replacement before creation', { race: true }]
])
    test(`refuses ${name} before creating a draft`, async (t) => {
        const options = await inputs(t)
        const remote = github(options, changes)
        await assert.rejects((await publisher())(options, remote), (error) => !error.message.includes('private'))
        assert.equal(remote.calls.filter((call) => call.args[0] === 'release').length, 0)
    })

for (const assets of ['partial', 'extra', 'digest', 'missing-digest', 'size', 'duplicate'])
    test(`refuses ${assets} uploaded assets before public edit`, async (t) => {
        const options = await inputs(t)
        const remote = github(options, { assets })
        await assert.rejects((await publisher())(options, remote))
        assert.equal(remote.calls.filter((call) => call.args[1] === 'create').length, 1)
        assert.equal(remote.calls.filter((call) => call.args.includes('PATCH')).length, 0)
    })

test('failed creation leaves any partial draft for inspection without edit or deletion', async (t) => {
    const options = await inputs(t)
    const remote = github(options, { createFailure: true })
    await assert.rejects((await publisher())(options, remote), (error) => !error.message.includes('private'))
    assert.equal(remote.calls.filter((call) => call.args[0] === 'release').length, 1)
})

test('refuses a release targeting a different candidate before public edit', async (t) => {
    const options = await inputs(t)
    const remote = github(options, { target: 'b'.repeat(40) })
    await assert.rejects((await publisher())(options, remote))
    assert.equal(remote.calls.filter((call) => call.args.includes('PATCH')).length, 0)
})

test('missing tag is created once without overwrite before draft upload', async (t) => {
    const options = await inputs(t)
    const remote = github(options)
    await (
        await publisher()
    )(options, remote)
    const tagWrites = remote.calls.filter((call) => call.args.includes('POST'))
    assert.equal(tagWrites.length, 1)
    assert.ok(remote.calls.indexOf(tagWrites[0]) < remote.calls.findIndex((call) => call.args[1] === 'create'))
    assert.ok(remote.calls.find((call) => call.args[1] === 'create').args.includes('--verify-tag'))
})

for (const status of [422, 403])
    test(`tag creation HTTP ${status} refuses draft creation without replacing tag`, async (t) => {
        const options = await inputs(t)
        const remote = github(options, { tagCreateFailure: status })
        await assert.rejects((await publisher())(options, remote))
        assert.equal(remote.calls.filter((call) => call.args[0] === 'release').length, 0)
    })

test('exact annotated candidate tag is accepted without a tag write', async (t) => {
    const options = await inputs(t)
    const remote = github(options, { tag: { type: 'tag', sha: 'c'.repeat(40) }, peeled: { type: 'commit', sha: commit } })
    await (
        await publisher()
    )(options, remote)
    assert.equal(remote.calls.filter((call) => call.args.includes('POST')).length, 0)
})

test('tag replaced during draft creation blocks public edit', async (t) => {
    const options = await inputs(t)
    const remote = github(options, { tagAfterCreate: { type: 'commit', sha: 'b'.repeat(40) } })
    await assert.rejects((await publisher())(options, remote))
    assert.equal(remote.calls.filter((call) => call.args.includes('PATCH')).length, 0)
})

test('post-publication incomplete assets never report publication success', async (t) => {
    const options = await inputs(t)
    const remote = github(options, { postPublishFailure: true })
    await assert.rejects((await publisher())(options, remote))
    assert.equal(remote.calls.filter((call) => call.args.includes('PATCH')).length, 1)
})

for (const corruption of ['hash', 'extra-field', 'reviewer'])
    test(`malformed ${corruption} receipt makes zero GitHub calls`, async (t) => {
        const options = await inputs(t)
        if (corruption === 'hash') options.receipt.windows[0].installerSha256 = '0'.repeat(64)
        if (corruption === 'extra-field') options.receipt.secret = 'never-log-this'
        if (corruption === 'reviewer') options.receipt.reviewedBy = 'someone-else'
        const remote = github(options)
        await assert.rejects((await publisher())(options, remote))
        assert.equal(remote.calls.length, 0)
    })

test('oversized candidate release notes make zero GitHub calls', async (t) => {
    const options = await inputs(t)
    await writeFile(join(options.sourceDirectory, 'docs/releases/locally-trusted-installers.md'), 'x'.repeat(65537))
    const remote = github(options)
    await assert.rejects((await publisher())(options, remote))
    assert.equal(remote.calls.length, 0)
})

test('newly created wrong tag aborts before draft creation', async (t) => {
    const options = await inputs(t)
    const remote = github(options, { createdTagWrong: true })
    await assert.rejects((await publisher())(options, remote))
    assert.equal(remote.calls.filter((call) => call.args.includes('POST')).length, 1)
    assert.equal(remote.calls.filter((call) => call.args[0] === 'release').length, 0)
})

test('exact lightweight candidate tag is accepted without a tag write', async (t) => {
    const options = await inputs(t)
    const remote = github(options, { tag: { type: 'commit', sha: commit } })
    await (
        await publisher()
    )(options, remote)
    assert.equal(remote.calls.filter((call) => call.args.includes('POST')).length, 0)
})

for (const releaseId of [null, -1, '42'])
    test(`invalid release ID ${releaseId} blocks public write`, async (t) => {
        const options = await inputs(t)
        const remote = github(options, { releaseId })
        await assert.rejects((await publisher())(options, remote))
        assert.equal(remote.calls.filter((call) => call.args.includes('PATCH')).length, 0)
    })

test('changed release ID before public write blocks publication', async (t) => {
    const options = await inputs(t)
    const remote = github(options, { releaseIdRace: true })
    await assert.rejects((await publisher())(options, remote))
    assert.equal(remote.calls.filter((call) => call.args.includes('PATCH')).length, 0)
})

test('existing draft absent from published-tag endpoint is refused before any write', async (t) => {
    const options = await inputs(t)
    const remote = github(options, { existing: true, existingDraft: true })
    await assert.rejects((await publisher())(options, remote))
    assert.equal(remote.calls.filter((call) => call.args[0] === 'release' || call.args.includes('POST') || call.args.includes('PATCH')).length, 0)
})

test('new draft is resolved through authenticated listing and inspected by numeric ID', async (t) => {
    const options = await inputs(t)
    const remote = github(options)
    assert.deepEqual(await (await publisher())(options, remote), { status: 'published', tag: 'v1.0.1' })
    assert.equal(remote.calls.filter((call) => call.args.at(-1).includes('/releases/tags/')).length, 0)
    const creation = remote.calls.findIndex((call) => call.args[1] === 'create')
    const draftLookup = remote.calls.findIndex((call, index) => index > creation && call.args.at(-1).includes('/releases?per_page=100&page=1'))
    const idRead = remote.calls.findIndex((call, index) => index > draftLookup && call.args.at(-1).endsWith('/releases/42'))
    const publicWrite = remote.calls.findIndex((call) => call.args.includes('PATCH'))
    assert.ok(draftLookup > creation && idRead > draftLookup && publicWrite > idRead)
})

for (const draft of [true, false])
    test(`release on later list page (draft=${draft}) is refused before any write`, async (t) => {
        const options = await inputs(t)
        const page = Array.from({ length: 100 }, (_, index) => ({ id: 100 + index, tag_name: `old-${index}`, draft: false }))
        const remote = github(options, { existing: true, existingDraft: draft, releasePages: [page], targetPage: 2 })
        await assert.rejects((await publisher())(options, remote))
        assert.equal(remote.calls.filter((call) => call.args[0] === 'release' || call.args.includes('POST') || call.args.includes('PATCH')).length, 0)
        assert.ok(remote.calls.some((call) => call.args.at(-1).endsWith('/releases?per_page=100&page=2')))
    })

test('full bounded release pages without a terminal short page fail closed', async (t) => {
    const options = await inputs(t)
    const remote = github(options, { fullReleasePages: true })
    await assert.rejects((await publisher())(options, remote))
    assert.equal(remote.calls.filter((call) => call.args.at(-1).includes('/releases?per_page=100&page=')).length, 10)
    assert.equal(remote.calls.filter((call) => call.args[0] === 'release' || call.args.includes('POST') || call.args.includes('PATCH')).length, 0)
})

test('ambiguous matching drafts after creation block the public write', async (t) => {
    const options = await inputs(t)
    const remote = github(options, { duplicateTarget: true })
    await assert.rejects((await publisher())(options, remote))
    assert.equal(remote.calls.filter((call) => call.args.includes('PATCH')).length, 0)
})
