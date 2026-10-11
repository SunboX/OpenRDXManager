// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { copyFile, mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { after, before, test } from 'node:test'
import { promisify } from 'node:util'

import electronPath from 'electron'

const execFileAsync = promisify(execFile)
const projectDirectory = fileURLToPath(new URL('..', import.meta.url))
const visualQaPath = fileURLToPath(new URL('../electron-test/visual-qa.mjs', import.meta.url))
const visualRasterComparePath = fileURLToPath(new URL('../electron-test/visual-raster-compare.mjs', import.meta.url))
const canonicalEvidenceDirectory = join(projectDirectory, 'docs/evidence/phase-4-task-8')
let evidenceDirectory
const visualQaProcessTimeoutMs = 180_000

/** Prepares isolated evidence after npm pretest has built the runtime. @returns {Promise<void>} */
async function prepareEvidence() {
    evidenceDirectory = await mkdtemp(join(tmpdir(), 'openrdx-visual-baseline-'))
}

before(prepareEvidence)
after(async () => {
    if (evidenceDirectory) await rm(evidenceDirectory, { recursive: true, force: true, maxRetries: 5 })
})

/**
 * Runs the real visual-QA Electron process with one test-only injected console
 * error and returns its complete observable process result.
 * @param {'before-mount' | 'during-transition'} injectionPoint - Exact visual operation to pressure.
 * @returns {Promise<{code: number|string, output: string}>} Exit status and combined output.
 */
async function runInjectedVisualQa(injectionPoint) {
    const evidenceDirectory = await mkdtemp(join(tmpdir(), 'openrdx-visual-negative-'))
    const environment = {
        ...process.env,
        OPENRDX_VISUAL_QA_EVIDENCE_DIRECTORY: evidenceDirectory,
        OPENRDX_ELECTRON_TEST_PROFILE: join(evidenceDirectory, 'profile')
    }
    delete environment.ELECTRON_RUN_AS_NODE

    try {
        try {
            const { stdout, stderr } = await execFileAsync(electronPath, [visualQaPath, `--visual-qa-inject-console-error=${injectionPoint}`], { cwd: projectDirectory, env: environment, timeout: visualQaProcessTimeoutMs, maxBuffer: 5 * 1024 * 1024 })
            return { code: 0, output: `${stdout}${stderr}` }
        } catch (error) {
            const processDiagnostic = error.code == null ? `${error.message}\n` : ''
            return { code: error.code ?? error.signal ?? 0, output: `${error.stdout ?? ''}${error.stderr ?? ''}${processDiagnostic}` }
        }
    } finally {
        await rm(evidenceDirectory, { recursive: true, force: true })
    }
}

/**
 * Runs the public visual-QA npm command with a real Electron process.
 * @param {string[]} [visualArguments=[]] - Dedicated harness arguments.
 * @param {string|null} [evidenceDirectoryOverride=null] - Optional isolated evidence destination.
 * @returns {Promise<string>} Combined successful process output.
 */
async function runVisualQaCommand(visualArguments = [], evidenceDirectoryOverride = evidenceDirectory) {
    const environment = { ...process.env }
    environment.OPENRDX_ELECTRON_TEST_PROFILE = await mkdtemp(join(evidenceDirectoryOverride ?? evidenceDirectory, 'profile-'))
    delete environment.ELECTRON_RUN_AS_NODE
    if (evidenceDirectoryOverride !== null) {
        environment.OPENRDX_VISUAL_QA_EVIDENCE_DIRECTORY = evidenceDirectoryOverride
    }
    // npm pretest prepares the runtime before parallel test workers start.
    // Never invoke the repair-capable preload hook while sibling workers are
    // importing packages: npm ci would remove their shared dependencies.
    const npmArguments = ['--ignore-scripts', 'run', 'test:visual']
    if (visualArguments.length > 0) npmArguments.push('--', ...visualArguments)
    // execFile cannot execute npm.cmd. Invoke the current Windows Node install's
    // npm CLI directly, with an argument array and no command shell.
    const command = process.platform === 'win32' ? process.execPath : 'npm'
    const argumentsList = process.platform === 'win32' ? [join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js'), ...npmArguments] : npmArguments
    const result = await execFileAsync(command, argumentsList, {
        cwd: projectDirectory,
        env: environment,
        timeout: visualQaProcessTimeoutMs,
        windowsHide: true,
        maxBuffer: 5 * 1024 * 1024
    })
    return `${result.stdout}${result.stderr}`
}

/**
 * Compares two PNG files through the production normalized raster contract and
 * applies one deterministic accepted channel variation after a valid baseline.
 * @param {string} expectedPath - Canonical screenshot path.
 * @param {string} candidatePath - Replacement screenshot path.
 * @returns {Promise<object>} Serializable normalized comparison evidence.
 */
async function compareNormalizedVisualEvidence(expectedPath, candidatePath) {
    const environment = { ...process.env }
    environment.OPENRDX_ELECTRON_TEST_PROFILE = await mkdtemp(join(evidenceDirectory, 'comparison-profile-'))
    delete environment.ELECTRON_RUN_AS_NODE
    const result = await execFileAsync(electronPath, [visualRasterComparePath, expectedPath, candidatePath, '--inject-one-channel-delta'], {
        cwd: projectDirectory,
        env: environment,
        timeout: 30_000,
        maxBuffer: 5 * 1024 * 1024
    })
    return JSON.parse(result.stdout.trim())
}

/**
 * Hashes one evidence file without depending on filesystem metadata.
 * @param {string} path - Absolute evidence path.
 * @returns {Promise<string>} Lowercase SHA-256 digest.
 */
async function hashEvidenceFile(path) {
    return createHash('sha256')
        .update(await readFile(path))
        .digest('hex')
}

/**
 * Hashes the sorted PNG names and bytes as one deterministic evidence set.
 * @param {string} [directory] - Isolated capture or canonical evidence directory.
 * @returns {Promise<string>} Lowercase SHA-256 digest for all screenshot files.
 */
async function hashScreenshotSet(directory = evidenceDirectory) {
    const screenshotNames = []
    for (const name of await readdir(directory)) {
        if (name.endsWith('.png')) screenshotNames.push(name)
    }
    screenshotNames.sort()
    const hash = createHash('sha256')
    for (const name of screenshotNames) {
        hash.update(name)
        hash.update('\0')
        hash.update(await readFile(join(directory, name)))
    }
    return hash.digest('hex')
}

/**
 * Hashes canonical checked-in evidence without depending on a containing Git
 * checkout. All test captures go to a disposable host-specific baseline.
 * @returns {Promise<object>} Exact canonical manifest and screenshot identities.
 */
async function canonicalEvidenceIdentity() {
    return { manifest: await hashEvidenceFile(join(canonicalEvidenceDirectory, 'visual-qa-results.json')), screenshots: await hashScreenshotSet(canonicalEvidenceDirectory) }
}

/**
 * Identifies changing inspection fields without dumping a complete manifest.
 * @param {object} expected - First independently validated manifest.
 * @param {object} actual - Repeated independently validated manifest.
 * @returns {string} Bounded diagnostic of at most ten changed fields.
 */
function describeManifestChanges(expected, actual) {
    const changes = []
    for (let index = 0; index < expected.results.length; index++) {
        const first = expected.results[index]
        const repeated = actual.results[index]
        for (const field of Object.keys(first.inspection)) {
            const before = JSON.stringify(first.inspection[field])
            const after = JSON.stringify(repeated?.inspection[field])
            if (before !== after) changes.push(`${first.screenshot}/${field}: ${before.slice(0, 800)} -> ${after?.slice(0, 800)}`)
            if (changes.length === 10) return changes.join('\n')
        }
    }
    return changes.join('\n')
}

/**
 * Verifies exact console errors fail the real visual harness at both requested
 * operation boundaries without invoking Electron's deprecated signature.
 * @param {import('node:test').TestContext} context - Parent subtest context.
 * @returns {Promise<void>} Resolves after both negative processes are verified.
 */
async function testRealElectronConsoleErrors(context) {
    for (const injectionPoint of ['before-mount', 'during-transition']) {
        /** Verifies one process-level injected console error. @returns {Promise<void>} */
        async function testInjectionPoint() {
            const expectedMessage = `openrdx-visual-injected-${injectionPoint}`
            const result = await runInjectedVisualQa(injectionPoint)

            assert.equal(result.code, 1, result.output)
            assert.match(result.output, new RegExp(`console errors: ${expectedMessage}`))
            assert.doesNotMatch(result.output, /console-message.*deprecated|deprecated.*console-message/i)
        }
        await context.test(injectionPoint, testInjectionPoint)
    }
}

test('real Electron visual QA rejects exact console errors before mount and during transition', testRealElectronConsoleErrors)

test('consecutive real visual QA commands preserve isolated captures and leave canonical evidence unchanged', async () => {
    const canonicalBefore = await canonicalEvidenceIdentity()
    // Establish a genuine baseline on this host before testing preservation;
    // Windows fonts/chrome must not rewrite macOS research screenshots.
    const runs = []
    const manifests = []
    for (let index = 0; index < 2; index += 1) {
        const output = await runVisualQaCommand(index === 0 ? [] : ['--visual-qa-inject-raster-noise=starting-runtime-minimum-1024x768.png'])
        // A zero process exit alone does not prove the complete matrix ran.
        assert.match(output, /OpenRDXManager visual QA passed: 62 screenshots/)
        assert.doesNotMatch(output, /No handler registered|Error occurred in handler/u)
        runs.push({
            manifestHash: await hashEvidenceFile(join(evidenceDirectory, 'visual-qa-results.json')),
            screenshotSetHash: await hashScreenshotSet(),
            canonicalEvidence: await canonicalEvidenceIdentity()
        })
        manifests.push(JSON.parse(await readFile(join(evidenceDirectory, 'visual-qa-results.json'), 'utf8')))
        if (index === 1) assert.deepEqual(runs[1], runs[0], `${output}\n${describeManifestChanges(manifests[0], manifests[1])}`)
        const metrics = JSON.parse(await readFile(join(evidenceDirectory, 'visual-qa-capture-metrics.json'), 'utf8'))
        assert.equal(metrics.captures.length, 62)
        for (const capture of metrics.captures) assert.ok(Number.isInteger(capture.attempts) && capture.attempts >= 1 && capture.attempts <= 4)
        if (index === 1) assert.match(output, /OpenRDXManager visual QA preserved injected raster noise: starting-runtime-minimum-1024x768\.png/)
    }

    assert.deepEqual(runs[1].canonicalEvidence, canonicalBefore)
    for (const size of ['minimum-1024x768', 'expanded-1440x900']) {
        assert.notEqual(await hashEvidenceFile(join(evidenceDirectory, `encryption-${size}.png`)), await hashEvidenceFile(join(evidenceDirectory, `disabled-reasons-${size}.png`)), `disabled-reasons must be a distinct viewport-visible capture at ${size}`)
    }
})

test('injected raster noise cannot preserve a visibly wrong screenshot', async () => {
    const corruptEvidenceDirectory = await mkdtemp(join(tmpdir(), 'openrdx-visual-corrupt-capture-'))
    try {
        await assert.rejects(runVisualQaCommand(['--visual-qa-inject-raster-corruption=no-device-minimum-1024x768.png'], corruptEvidenceDirectory), (error) => {
            assert.match(`${error.stdout ?? ''}${error.stderr ?? ''}`, /raster anchors missing.*brand/i)
            return true
        })
    } finally {
        await rm(corruptEvidenceDirectory, { recursive: true, force: true })
    }

    const isolatedEvidenceDirectory = await mkdtemp(join(tmpdir(), 'openrdx-visual-wrong-seed-'))
    const screenshotName = 'starting-runtime-minimum-1024x768.png'
    const isolatedScreenshotPath = join(isolatedEvidenceDirectory, screenshotName)
    const expectedScreenshotPath = join(evidenceDirectory, screenshotName)
    const wrongScreenshotPath = join(evidenceDirectory, 'no-device-minimum-1024x768.png')

    try {
        await copyFile(wrongScreenshotPath, isolatedScreenshotPath)
        const wrongHash = await hashEvidenceFile(isolatedScreenshotPath)
        assert.notEqual(wrongHash, await hashEvidenceFile(expectedScreenshotPath))

        const output = await runVisualQaCommand([`--visual-qa-inject-raster-noise=${screenshotName}`], isolatedEvidenceDirectory)

        assert.match(output, /OpenRDXManager visual QA passed: 62 screenshots/)
        assert.doesNotMatch(output, /preserved injected raster noise: starting-runtime-minimum-1024x768\.png/)
        assert.notEqual(await hashEvidenceFile(isolatedScreenshotPath), wrongHash)
        const comparison = await compareNormalizedVisualEvidence(expectedScreenshotPath, isolatedScreenshotPath)
        assert.equal(comparison.baselineMeaningfulDifference, false)
        assert.equal(comparison.meaningfulDifference, false)
        assert.equal(comparison.injectedChannelCount, 1)
        assert.equal(comparison.maximumInjectedDelta, 1)
        assert.deepEqual(comparison.canonicalSize, comparison.candidateSize)
    } finally {
        await rm(isolatedEvidenceDirectory, { recursive: true, force: true })
    }
})
