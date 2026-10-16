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

test('release keeps production security, real installer and installed authentication acceptance mandatory', async () => {
    const source = await readFile(new URL('../.github/workflows/build-installers.yml', import.meta.url), 'utf8')
    for (const title of ['Verify Windows shared local trust policy', 'Verify Windows native security and installer policy', 'Verify protected Windows service descriptor on disposable runner', 'Verify Windows PowerShell installer boundary', 'Install and verify the Windows EXE', 'Test application on macOS and Windows', 'Verify packaged application on macOS and Windows']) assert.doesNotMatch(step(source, title), /continue-on-error/u, title)
    assert.match(step(source, 'Install and verify the Windows EXE'), /verify-windows-installation\.ps1/u)
    assert.match(step(source, 'Verify packaged application on macOS and Windows'), /npm run verify:packaged-app/u)
    assert.match(source, /needs: build/u)
    assert.match(source, /needs: collect/u)
    assert.doesNotMatch(source, /verify-windows-restricted-token-probe|windows-token-diagnostics-|windows-token-fixtures|observe-windows-startup-events/u)
    const acceptance = await readFile(new URL('../scripts/verify-windows-installation.ps1', import.meta.url), 'utf8')
    assert.match(acceptance, /'--installed', '--require-service'/u)
    assert.doesNotMatch(acceptance, /continue-on-error/u)
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
