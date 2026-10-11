// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import test from 'node:test'

const packageUrl = new URL('../package.json', import.meta.url)
const runtimeDocsUrl = new URL('../docs/development/runtime-setup.md', import.meta.url)
const gitignoreUrl = new URL('../.gitignore', import.meta.url)
const htmlUrl = new URL('../src/index.html', import.meta.url)
const mainUrl = new URL('../src/main.mjs', import.meta.url)
const preloadUrl = new URL('../src/preload.mjs', import.meta.url)
const rendererUrl = new URL('../src/renderer.mjs', import.meta.url)
const execFileAsync = promisify(execFile)

/**
 * Confirms that the locally installed Zod package can be imported by ESM.
 * @returns {Promise<void>} Resolves when the package import succeeds.
 */
async function importZod() {
    await import('zod')
}

/**
 * Confirms that an application resource specifier resolves to a readable file.
 * @param {string} resource - Package resource specifier to resolve.
 * @returns {Promise<void>} Resolves when the resource is readable.
 */
async function accessResolvedResource(resource) {
    await access(new URL(import.meta.resolve(resource)))
}

/**
 * Verifies the installed application dependencies and ignored tool state.
 * @returns {Promise<void>} Resolves when the resource contract is satisfied.
 */
async function testApplicationResources() {
    const packageJson = JSON.parse(await readFile(packageUrl, 'utf8'))
    const gitignore = await readFile(gitignoreUrl, 'utf8')

    assert.equal(packageJson.dependencies['@phosphor-icons/web'], '^2.1.2')
    assert.ok(packageJson.dependencies['@fontsource/inter'])
    assert.ok(packageJson.dependencies['@fontsource/oxanium'])
    assert.ok(packageJson.dependencies.zod)
    assert.ok(packageJson.devDependencies.jsdom)

    await assert.doesNotReject(importZod)
    for (const resource of ['@fontsource/inter/latin.css', '@fontsource/oxanium/latin.css', '@phosphor-icons/web/regular']) {
        await accessResolvedResource(resource)
    }
    await accessResolvedResource('jsdom')

    assert.match(gitignore, /^\.superpowers\/$/m)
    // Exercise the checked-in rules, not the caller's cwd, Git ownership or
    // parent repository. Exported/staged source trees need not contain .git.
    const fixture = await mkdtemp(join(tmpdir(), 'openrdx-ignore-rules-'))
    try {
        await writeFile(join(fixture, '.gitignore'), gitignore)
        const options = { cwd: fixture, windowsHide: true }
        await execFileAsync('git', ['init', '--quiet'], options)
        for (const path of ['.DS_Store.root-after-reorganization', '.superpowers/', 'docs/superpowers/', 'docs/superpowers/specs/local-draft.md', 'analysis/', 'analysis/fixtures/local-reference.json', 'analysis/scripts/receiver-model-contract.mjs', 'original-inputs/', 'original-inputs/RDX2E__STD__F-0283.bin', 'original-inputs/reference-manual.pdf', 'original-inputs/RDXManagerInstaller_2.0.1.50.exe', 'original-inputs/vendor.EXE', 'original-inputs/vendor.exe.c', 'original-inputs/RDXManagerInstaller_2.0.1.54.zip', 'original-inputs/RdxManagerInstallerMac0.1.0.1.zip']) {
            const { stdout } = await execFileAsync('git', ['-c', 'core.excludesFile=', 'check-ignore', '-q', path], options)
            assert.equal(stdout, '')
        }
        for (const path of ['docs/specs/full-implementation-2026-08-25.md', 'docs/plans/implementation-roadmap-2026-08-25.md']) {
            await assert.rejects(execFileAsync('git', ['-c', 'core.excludesFile=', 'check-ignore', '-q', path], options), { code: 1 })
        }
    } finally {
        await rm(fixture, { recursive: true, force: true })
    }
}

/**
 * Verifies the package metadata and native-ESM Electron commands.
 * @returns {Promise<void>} Resolves when the project metadata is valid.
 */
async function testPackageMetadata() {
    const packageJson = JSON.parse(await readFile(packageUrl, 'utf8'))

    assert.equal(packageJson.name, 'openrdxmanager')
    assert.equal(packageJson.productName, 'OpenRDXManager')
    assert.equal(packageJson.private, true)
    assert.equal(packageJson.type, 'module')
    assert.equal(packageJson.engines.node, '>=22.12.0')
    assert.equal(packageJson.main, 'src/main.mjs')
    assert.equal(packageJson.scripts['build:native-service'], 'node scripts/build-native-service.mjs && node scripts/build-windows-client-addon.mjs')
    assert.equal(packageJson.scripts['build:runtime'], 'npm run build:preload && npm run build:native-service && npm run build:macos-service-management && node scripts/prepare-windows-runtime.mjs')
    assert.equal(packageJson.scripts.prestart, undefined)
    assert.equal(packageJson.scripts.presmoke, undefined)
    assert.equal(packageJson.scripts.start, 'node scripts/run-development.mjs')
    assert.equal(packageJson.scripts.test, 'node --test test/*.test.mjs test/integration/*.test.mjs')
    assert.equal(packageJson.scripts.smoke, 'node scripts/run-development.mjs --smoke-test')
    assert.equal(packageJson.scripts['test:visual'], 'electron electron-test/visual-qa.mjs')
    assert.match(packageJson.devDependencies.electron, /^\^?\d+\.\d+\.\d+$/)
    assert.match(packageJson.devDependencies['node-gyp'], /^\^?\d+\.\d+\.\d+$/)
}

test('package exposes the minimal native-ESM Electron commands', testPackageMetadata)
test('application resources are installed locally and research/tool state is ignored', testApplicationResources)

/**
 * Verifies the portable native staging guarantees and filesystem limitations
 * are documented for contributors on every supported host.
 * @returns {Promise<void>} Resolves when the staging note remains complete.
 */
async function testNativeBuildStagingDocumentation() {
    const runtimeDocs = await readFile(runtimeDocsUrl, 'utf8')

    assert.match(runtimeDocs, /last-known-good/u)
    assert.match(runtimeDocs, /cross-process lock/u)
    assert.match(runtimeDocs, /junctions and symbolic links/u)
    assert.match(runtimeDocs, /reparse tags/u)
    assert.match(runtimeDocs, /time-of-check\/time-of-use/u)
}

test('documents native build staging guarantees and filesystem limits', testNativeBuildStagingDocumentation)

/**
 * Verifies the local-only renderer document exposes the application mount and
 * loads bundled styles, fonts, icons, and the native ESM entry point.
 * @returns {Promise<void>} Resolves when the renderer resource contract is valid.
 */
async function testRendererDocumentLoadsOnlyLocalApplicationResources() {
    const [html, renderer] = await Promise.all([readFile(htmlUrl, 'utf8'), readFile(rendererUrl, 'utf8')])

    assert.match(html, /<title>OpenRDXManager<\/title>/)
    assert.match(html, /<div id="app"><\/div>/)
    assert.match(html, /\.\.\/node_modules\/@fontsource\/inter\/400\.css/)
    assert.match(html, /\.\.\/node_modules\/@fontsource\/oxanium\/600\.css/)
    assert.match(html, /\.\.\/node_modules\/@phosphor-icons\/web\/src\/regular\/style\.css/)
    assert.match(html, /\.\.\/node_modules\/@phosphor-icons\/web\/src\/duotone\/style\.css/)
    assert.doesNotMatch(html, /https?:\/\//)
    assert.match(html, /<script type="module" src="\.\/renderer\.mjs"><\/script>/)
    assert.match(renderer, /mountApplication/)
    assert.match(renderer, /createFixtureState/)
}

test('renderer document loads only local application resources', testRendererDocumentLoadsOnlyLocalApplicationResources)

/**
 * Proves screenshot fixture selection remains confined to the separate test
 * application even though production retains one fixed safe fallback state for
 * a missing preload bridge.
 * @returns {Promise<void>} Resolves when production exposes no fixture activator.
 */
async function testVisualFixtureActivationIsTestOnly() {
    const [main, preload, renderer] = await Promise.all([readFile(mainUrl, 'utf8'), readFile(preloadUrl, 'utf8'), readFile(rendererUrl, 'utf8')])
    const productionSources = `${main}\n${preload}\n${renderer}`

    assert.doesNotMatch(productionSources, /visual-fixture|mountVisualFixture|__openRdxVisualFixture|--visual/)
    assert.match(renderer, /createFixtureState\(\{ mode: 'service-unavailable' \}\)/)
}

test('visual fixture activation is isolated from the production entrypoints', testVisualFixtureActivationIsTestOnly)

/**
 * Yields one event-loop turn so a prematurely settled readiness promise is
 * observable without using timing assumptions.
 * @returns {Promise<void>} Resolves on the next immediate turn.
 */
async function nextTurn() {
    await new Promise((resolve) => setImmediate(resolve))
}

/**
 * Verifies smoke readiness remains pending until both independently ordered
 * startup signals have arrived and accepts unavailable as a terminal service
 * result without calling it hardware-ready.
 * @returns {Promise<void>} Resolves when both signal orderings are proven.
 */
async function testSmokeReadinessRequiresMountedRendererAndTerminalService() {
    const { SmokeReadinessGate } = await import('../src/main/smoke-readiness.mjs')

    for (const order of ['renderer-first', 'service-first']) {
        const gate = new SmokeReadinessGate()
        let settled = false
        /** @returns {Promise<object>} Records settlement only after both smoke signals arrive. */
        async function observeReadiness() {
            const result = await gate.wait()
            settled = true
            return result
        }
        const readiness = observeReadiness()

        if (order === 'renderer-first') {
            gate.markRendererMounted()
        } else {
            gate.markServiceTerminal({ status: 'ready', mode: 'no-device', hardwareReady: false })
        }
        await nextTurn()
        assert.equal(settled, false, `${order} must not complete smoke alone`)

        if (order === 'renderer-first') {
            gate.markServiceTerminal({ status: 'ready', mode: 'no-device', hardwareReady: false })
        } else {
            gate.markRendererMounted()
        }
        assert.deepEqual(await readiness, {
            renderer: 'mounted',
            service: { status: 'ready', mode: 'no-device', hardwareReady: false }
        })
    }

    const unavailableGate = new SmokeReadinessGate()
    unavailableGate.markServiceTerminal({ status: 'unavailable', reason: 'service-start-failed' })
    unavailableGate.markRendererMounted()
    assert.deepEqual(await unavailableGate.wait(), {
        renderer: 'mounted',
        service: { status: 'unavailable', reason: 'service-start-failed' }
    })
}

test('smoke readiness requires mounted renderer and terminal service state', testSmokeReadinessRequiresMountedRendererAndTerminalService)
