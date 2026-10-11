// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'

import { app, nativeImage } from 'electron'

import { compareVisualImages, hasMeaningfulVisualDifference, injectSingleChannelRasterNoise } from './visual-raster.mjs'
import { initializeIsolatedElectronProfile } from './isolated-profile.mjs'

initializeIsolatedElectronProfile(app, process.env.OPENRDX_ELECTRON_TEST_PROFILE)

const noiseOption = '--inject-one-channel-delta'

/**
 * Reads the two screenshot paths and optional deterministic-noise switch from
 * this dedicated Electron test entrypoint.
 * @returns {{canonicalPath: string, candidatePath: string, injectNoise: boolean}} Validated arguments.
 */
function readArguments() {
    const entrypointIndex = process.argv.indexOf(fileURLToPath(import.meta.url))
    assert.notEqual(entrypointIndex, -1, 'Visual raster comparison entrypoint is missing from process arguments')
    const argumentsList = process.argv.slice(entrypointIndex + 1)
    const injectNoise = argumentsList.includes(noiseOption)
    const screenshotPaths = argumentsList.filter((argument) => argument !== noiseOption)
    assert.equal(screenshotPaths.length, 2, 'Visual raster comparison requires canonical and candidate PNG paths')
    return { canonicalPath: screenshotPaths[0], candidatePath: screenshotPaths[1], injectNoise }
}

/**
 * Measures observable channel differences between like-for-like normalized
 * rasters for deterministic regression evidence.
 * @param {{bitmap: Uint8Array}} canonicalRaster - Canonical physical raster.
 * @param {{bitmap: Uint8Array}} candidateRaster - Candidate physical raster.
 * @returns {{changedChannelCount: number, maximumDelta: number}} Difference summary.
 */
function measureRasterDifference(canonicalRaster, candidateRaster) {
    let changedChannelCount = 0
    let maximumDelta = 0
    for (let index = 0; index < canonicalRaster.bitmap.length; index += 1) {
        const delta = Math.abs(canonicalRaster.bitmap[index] - candidateRaster.bitmap[index])
        if (delta > 0) changedChannelCount += 1
        if (delta > maximumDelta) maximumDelta = delta
    }
    return { changedChannelCount, maximumDelta }
}

/**
 * Compares two real PNG files through the production normalized raster path.
 * Test-only noise is applied only when the unmodified baseline is already
 * accepted, preventing the hook from masking meaningful drift.
 * @returns {Promise<object>} Serializable comparison evidence.
 */
async function runComparison() {
    await app.whenReady()
    const { canonicalPath, candidatePath, injectNoise } = readArguments()
    const canonicalImage = nativeImage.createFromPath(canonicalPath)
    const candidateImage = nativeImage.createFromPath(candidatePath)
    assert.equal(canonicalImage.isEmpty(), false, `Canonical visual evidence is unreadable: ${canonicalPath}`)
    assert.equal(candidateImage.isEmpty(), false, `Candidate visual evidence is unreadable: ${candidatePath}`)

    const baseline = compareVisualImages(canonicalImage, candidateImage)
    let comparedRaster = baseline.freshRaster
    if (injectNoise && !baseline.meaningfulDifference) {
        comparedRaster = injectSingleChannelRasterNoise(baseline.trackedRaster, baseline.freshRaster)
    }
    const difference = measureRasterDifference(baseline.trackedRaster, comparedRaster)
    const meaningfulDifference = hasMeaningfulVisualDifference(baseline.trackedRaster, comparedRaster)
    return {
        baselineMeaningfulDifference: baseline.meaningfulDifference,
        meaningfulDifference,
        injectedChannelCount: difference.changedChannelCount,
        maximumInjectedDelta: difference.maximumDelta,
        canonicalSize: { width: baseline.trackedRaster.width, height: baseline.trackedRaster.height },
        candidateSize: { width: baseline.freshRaster.width, height: baseline.freshRaster.height }
    }
}

/**
 * Runs the comparison and publishes its decision without blocking app readiness.
 * @returns {Promise<void>} Resolves after reporting the outcome and exiting.
 */
async function runComparisonEntrypoint() {
    try {
        const evidence = await runComparison()
        console.log(JSON.stringify(evidence))
        app.exit(evidence.meaningfulDifference ? 1 : 0)
    } catch (error) {
        console.error(error)
        app.exit(1)
    }
}

void runComparisonEntrypoint()
