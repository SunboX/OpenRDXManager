// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

/** @param {string} source Workflow source. @param {string} title Exact named step. @returns {string} One required step, excluding any neighboring optional diagnostic. */
function step(source, title) {
    const start = source.indexOf(`            - name: ${title}\n`)
    assert.notEqual(start, -1, title)
    const end = source.indexOf('\n            - ', start + 1)
    return source.slice(start, end === -1 ? undefined : end)
}

test('build retains fatal production checks and cannot publish or execute hosted EXE acceptance', async () => {
    const source = await readFile(new URL('../.github/workflows/build-installers.yml', import.meta.url), 'utf8')
    for (const title of ['Verify Windows shared local trust policy', 'Verify Windows native security and installer policy', 'Verify protected Windows service descriptor on disposable runner', 'Verify Windows PowerShell installer boundary', 'Test application on macOS and Windows', 'Test application on Linux', 'Verify packaged application on macOS and Windows', 'Install and verify the macOS PKG', 'Install and verify the Linux DEB', 'Verify complete installer inventory and generate checksums']) assert.doesNotMatch(step(source, title), /continue-on-error/u, title)
    for (const command of ['npm run format:check', 'npm run native:test', 'npm test', 'npm run verify:packaged-app', 'node scripts/release-assets.mjs']) assert.ok(source.includes(command), command)
    assert.match(source, /needs: build/u)
    assert.match(source, /name: installers-all/u)
    assert.doesNotMatch(source, /continue-on-error|contents: write|gh release|publish_release|verify-windows-installation\.ps1|verify-windows-restricted-token-probe|windows-token-diagnostics-|observe-windows-startup-events/u)
})

test('manual main-only verification pins candidate before artifacts and repeats the gate before publication', async () => {
    const source = await readFile(new URL('../.github/workflows/publish-verified-release.yml', import.meta.url), 'utf8')
    assert.match(source, /workflow_dispatch:/u)
    assert.doesNotMatch(source, /^    (?:push|pull_request):/mu)
    for (const input of ['build_run_id', 'windows_acceptance', 'publish_release']) assert.match(source, new RegExp(`            ${input}:`, 'u'))
    assert.match(source, /publish_release:[\s\S]*?default: false/u)
    const verify = source.slice(source.indexOf('    verify:'), source.indexOf('    publish:'))
    const publish = source.slice(source.indexOf('    publish:'))
    assert.match(verify, /github.ref == 'refs\/heads\/main'/u)
    assert.doesNotMatch(verify, /contents: write/u)
    assert.match(verify, /timeout-minutes: 20/u)
    assert.match(publish, /timeout-minutes: 20/u)
    assert.match(publish, /needs: verify/u)
    assert.match(publish, /inputs.publish_release/u)
    assert.match(publish, /github.ref == 'refs\/heads\/main'/u)
    assert.match(publish, /contents: write/u)
    assert.match(source, /actions: read/u)
    assert.match(source, /WINDOWS_ACCEPTANCE: \$\{\{ inputs.windows_acceptance \}\}/u)
    assert.match(source, /BUILD_RUN_ID: \$\{\{ inputs.build_run_id \}\}/u)
    assert.match(verify, /Number.isSafeInteger/u)
    assert.ok(verify.indexOf('metadata verification/build-run.json') < verify.indexOf('name: installers-all'))
    assert.match(verify, /path: candidate-source/u)
    assert.match(publish, /path: candidate-source/u)
    assert.match(verify, /ref: \$\{\{ steps.metadata.outputs.source_commit \}\}/u)
    assert.match(publish, /ref: \$\{\{ needs.verify.outputs.source_commit \}\}/u)
    assert.match(verify, /retention-days: 3/u)
    assert.match(publish, /RECEIPT_PATH:/u)
    const refresh = step(publish, 'Refresh authenticated build metadata before publication')
    assert.match(refresh, /Number.isSafeInteger/u)
    assert.match(refresh, /gh api/u)
    assert.ok(publish.indexOf('name: Refresh authenticated build metadata before publication') < publish.indexOf('verify-windows-release-acceptance.mjs verify'))
    assert.ok(publish.indexOf('verify-windows-release-acceptance.mjs verify') < publish.indexOf('node scripts/publish-verified-release.mjs'))
    assert.doesNotMatch(source, /continue-on-error|node candidate-source|run:.*\$\{\{ inputs\./u)
})

test('standalone experimental workflow retains fatal native verdicts and diagnostic-only evidence', async () => {
    const source = await readFile(new URL('../.github/workflows/windows-token-diagnostics.yml', import.meta.url), 'utf8')
    for (const [title, mode] of [
        ['Observe restricted Windows token on disposable runner', ''],
        ['Verify medium restricted Windows token on disposable runner', ' --medium'],
        ['Verify owned medium Windows child on disposable runner', ' --child']
    ]) {
        const block = step(source, title)
        assert.ok(block.includes(`node scripts/verify-windows-restricted-token-probe.mjs${mode} | Tee-Object`))
        assert.match(block, /\$probeExitCode = \$LASTEXITCODE\s+exit \$probeExitCode/u)
        assert.doesNotMatch(block, /continue-on-error/u)
    }
    assert.match(source, /cargo test --manifest-path native\/rdx-service\/windows-native\/Cargo\.toml --locked --lib --no-run/u)
    assert.match(source, /workflow_dispatch:/u)
    assert.match(source, /contents: read/u)
    assert.match(source, /windows-2025-vs2026/u)
    assert.match(source, /windows-11-arm/u)
    assert.match(source, /retention-days: 3/u)
    assert.doesNotMatch(source, /contents: write|gh release|publish_release|electron-builder|verify-windows-installation\.ps1|pattern: installers-/u)
    assert.equal((source.match(/out\/verification\/windows-token-[a-z-]+\.log\s*$/gmu) ?? []).length >= 9, true)
})
