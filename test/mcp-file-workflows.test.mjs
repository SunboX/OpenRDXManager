// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { createSymlinkFixture } from './helpers/symlink-fixture.mjs'
import test from 'node:test'

import { FirmwareFileSelectionService } from '../src/main/firmware-file-selection-service.mjs'
import { createSupportRuntimeServices } from '../src/main/support-runtime.mjs'
import { SupportSummaryService } from '../src/main/support-summary-service.mjs'

/** @returns {object} Renderer-safe runtime fixture containing forbidden fields beside allowlisted values. */
function supportFixture() {
    return {
        client: {
            /** @returns {Promise<object>} Returns one current public device snapshot. */
            async list() {
                return {
                    devices: [
                        {
                            authorizationBlob: [1, 2, 3],
                            derivedKey: 'forbidden-derived-key',
                            drive: { firmwareRevision: '0283' },
                            password: 'forbidden-password',
                            product: 'RDX QuikStor',
                            revision: 7,
                            serial: '7810544062',
                            vendor: 'TANDBERG'
                        }
                    ],
                    ok: true
                }
            }
        },
        /** @returns {object} Returns the current service readiness. */
        getReadiness() {
            return { hardwareReady: true, hardwareVerified: true, mode: 'native', status: 'ready' }
        },
        logger: {
            /** @returns {Promise<object>} Returns a redacted public activity projection with forbidden fields beside it. */
            async list() {
                return {
                    entries: [
                        {
                            authorizationBlob: [4, 5, 6],
                            derivedKey: 'forbidden-activity-key',
                            messageKey: 'activity.operation.completed',
                            occurredAt: '2026-09-10T10:00:00.000Z',
                            password: 'forbidden-activity-password',
                            severity: 'info',
                            supportCorrelationId: 'support:42'
                        }
                    ],
                    ok: true
                }
            },
            /** @returns {Promise<object>} Accepts the existing logging toggle contract. */
            async setEnabled() {
                return { ok: true }
            }
        }
    }
}

/** @param {string} exportDirectory - Main-owned automatic export directory. @param {() => Promise<object>} chooseDestination - GUI chooser boundary. @returns {object} Support services under test. */
function createServices(exportDirectory, chooseDestination, randomUUID) {
    return createSupportRuntimeServices({
        application: { getName: () => 'OpenRDXManager', getVersion: () => '1.5.0' },
        chooseDestination,
        exportDirectory,
        host: { architecture: () => 'arm64', platform: () => 'darwin', release: () => '25.6.0' },
        randomUUID,
        runtime: supportFixture()
    })
}

test('direct firmware registration claims exact bytes once without invoking a chooser', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-mcp-firmware-'))
    const imagePath = join(directory, 'RDX_USB3_0283.BIN')
    const expected = Buffer.from([0x52, 0x44, 0x58, 0x00, 0xff])
    let chooserCalled = false
    await writeFile(imagePath, expected)
    const service = new FirmwareFileSelectionService({
        /** @returns {Promise<object>} Records a forbidden GUI interaction. */
        async showOpenDialog() {
            chooserCalled = true
            return { canceled: true, filePaths: [] }
        }
    })

    try {
        const registered = await service.registerFirmwarePath(imagePath)
        assert.equal(registered.ok, true)
        assert.match(registered.fileToken, /^firmware:[a-f0-9-]+$/u)
        assert.equal(chooserCalled, false)

        const claimed = await service.claimFirmwareFile(registered.fileToken)
        assert.deepEqual(claimed, { bytes: expected, extension: '.BIN', size: 5 })
        assert.deepEqual(await service.claimFirmwareFile(registered.fileToken), { ok: false, reason: 'firmware-file-token-invalid' })
    } finally {
        await rm(directory, { force: true, recursive: true })
    }
})

test('direct firmware registration rejects invalid paths and symbolic links with chooser-equivalent reasons', async (context) => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-mcp-firmware-invalid-'))
    const imagePath = join(directory, 'firmware.BIP')
    const linkPath = join(directory, 'firmware-link.BIP')
    const unsupportedPath = join(directory, 'firmware.txt')
    await writeFile(imagePath, Buffer.from([0x01]))
    await writeFile(unsupportedPath, 'not firmware')
    const service = new FirmwareFileSelectionService()

    try {
        assert.deepEqual(await service.registerFirmwarePath(undefined), { ok: false, reason: 'firmware-selection-invalid' })
        assert.deepEqual(await service.registerFirmwarePath('relative.BIN'), { ok: false, reason: 'firmware-selection-invalid' })
        assert.deepEqual(await service.registerFirmwarePath(unsupportedPath), { ok: false, reason: 'firmware-file-type-unsupported' })
        assert.deepEqual(await service.registerFirmwarePath(join(directory, 'missing.BIN')), { ok: false, reason: 'firmware-file-invalid' })
        await context.test('rejects a real file symlink when the host permits its creation', async (child) => {
            if (!(await createSymlinkFixture(child, imagePath, linkPath))) return
            assert.deepEqual(await service.registerFirmwarePath(linkPath), { ok: false, reason: 'firmware-file-invalid' })
        })
    } finally {
        await rm(directory, { force: true, recursive: true })
    }
})

test('direct firmware registration detects a changed image and still consumes its token', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-mcp-firmware-changed-'))
    const imagePath = join(directory, 'firmware.bin')
    await writeFile(imagePath, Buffer.from([0x01, 0x02]))
    const service = new FirmwareFileSelectionService()

    try {
        const registered = await service.registerFirmwarePath(imagePath)
        await writeFile(imagePath, Buffer.from([0x03, 0x04, 0x05]))

        assert.deepEqual(await service.claimFirmwareFile(registered.fileToken), { ok: false, reason: 'firmware-file-changed' })
        assert.deepEqual(await service.claimFirmwareFile(registered.fileToken), { ok: false, reason: 'firmware-file-token-invalid' })
    } finally {
        await rm(directory, { force: true, recursive: true })
    }
})

test('automation support reads redacted summary and activity without invoking a chooser', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-mcp-reports-'))
    let chooserCalls = 0
    const services = createServices(directory, async () => {
        chooserCalls += 1
        throw new Error('automation reads must not open a chooser')
    })

    try {
        const summary = await services.automationSupport.readSummary()
        const activity = await services.automationSupport.readActivity()

        assert.equal(summary.ok, true)
        assert.match(summary.text, /Firmware revision: 0283/u)
        assert.doesNotMatch(summary.text, /password|derivedKey|authorizationBlob|forbidden-/iu)
        assert.equal(activity.ok, true)
        assert.match(activity.text, /activity\.operation\.completed.*support:42/u)
        assert.doesNotMatch(activity.text, /password|derivedKey|authorizationBlob|forbidden-/iu)
        assert.equal(chooserCalls, 0)
        assert.deepEqual(Object.keys(services).sort(), ['automationSupport', 'logs', 'support', 'updates'])
    } finally {
        await rm(directory, { force: true, recursive: true })
    }
})

test('automatic support exports create exclusive generated files without invoking a chooser or overwriting existing files', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-mcp-exports-'))
    const existingSummaryPath = join(directory, 'RdxSystemSummary.txt')
    const existingActivityPath = join(directory, 'RDXManagerActivity.txt')
    await writeFile(existingSummaryPath, 'keep summary')
    await writeFile(existingActivityPath, 'keep activity')
    let chooserCalls = 0
    const services = createServices(directory, async () => {
        chooserCalls += 1
        throw new Error('automatic exports must not open a chooser')
    })

    try {
        const firstSummary = await services.automationSupport.exportSummary()
        const secondSummary = await services.automationSupport.exportSummary()
        const activity = await services.automationSupport.exportActivity()

        for (const result of [firstSummary, secondSummary, activity]) {
            assert.equal(result.ok, true)
            assert.equal(dirname(result.savedPath), directory)
        }
        assert.notEqual(firstSummary.savedPath, secondSummary.savedPath)
        assert.match(firstSummary.savedPath, /RdxSystemSummary-[a-f0-9-]+\.txt$/u)
        assert.match(activity.savedPath, /RDXManagerActivity-[a-f0-9-]+\.txt$/u)
        assert.equal(await readFile(existingSummaryPath, 'utf8'), 'keep summary')
        assert.equal(await readFile(existingActivityPath, 'utf8'), 'keep activity')
        assert.match(await readFile(firstSummary.savedPath, 'utf8'), /Firmware revision: 0283/u)
        assert.match(await readFile(activity.savedPath, 'utf8'), /activity\.operation\.completed.*support:42/u)
        assert.equal(chooserCalls, 0)
        assert.equal((await readdir(directory)).length, 5)
    } finally {
        await rm(directory, { force: true, recursive: true })
    }
})

test('automatic support export creates its configured application directory on first use', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-mcp-export-parent-'))
    const exportDirectory = join(directory, 'exports')
    const services = createServices(exportDirectory, async () => {
        throw new Error('automatic exports must not open a chooser')
    })

    try {
        const result = await services.automationSupport.exportActivity()

        assert.equal(result.ok, true)
        assert.equal(dirname(result.savedPath), exportDirectory)
        assert.match(await readFile(result.savedPath, 'utf8'), /activity\.operation\.completed.*support:42/u)
    } finally {
        await rm(directory, { force: true, recursive: true })
    }
})

test('automatic support export fails closed instead of overwriting a generated-name collision', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-mcp-export-collision-'))
    const collisionPath = join(directory, 'RdxSystemSummary-00000000-0000-4000-8000-000000000000.txt')
    await writeFile(collisionPath, 'existing report')
    let chooserCalls = 0
    const services = createServices(
        directory,
        async () => {
            chooserCalls += 1
            throw new Error('automatic exports must not open a chooser')
        },
        () => '00000000-0000-4000-8000-000000000000'
    )

    try {
        assert.deepEqual(await services.automationSupport.exportSummary(), { ok: false, reason: 'support-summary-save-failed' })
        assert.equal(await readFile(collisionPath, 'utf8'), 'existing report')
        assert.equal(chooserCalls, 0)
    } finally {
        await rm(directory, { force: true, recursive: true })
    }
})

test('automatic support exports require a configured main-owned export directory', async () => {
    const services = createServices(undefined, async () => {
        throw new Error('automatic exports must not open a chooser')
    })

    assert.deepEqual(await services.automationSupport.exportSummary(), { ok: false, reason: 'support-export-unavailable' })
    assert.deepEqual(await services.automationSupport.exportActivity(), { ok: false, reason: 'log-export-unavailable' })
})

test('shared summary rendering preserves the existing chooser export failure contract', async () => {
    const service = new SupportSummaryService({
        /** @returns {Promise<object>} Simulates a failed main-owned snapshot collection. */
        async collect() {
            throw new Error('contained collection detail')
        },
        /** @returns {Promise<object>} Must remain unused after collection fails. */
        async chooseDestination() {
            return { canceled: true }
        },
        /** @returns {Promise<void>} Must remain unused after collection fails. */
        async writeText() {}
    })

    assert.deepEqual(await service.generateSummary(), { ok: false, reason: 'support-summary-save-failed' })
})
