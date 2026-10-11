// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdir, mkdtemp, rename, rm, writeFile } from 'node:fs/promises'
import { createSymlinkFixture } from './helpers/symlink-fixture.mjs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { FirmwareFileSelectionService } from '../src/main/firmware-file-selection-service.mjs'
import { dispatchRegisteredFirmwareOperation } from '../src/main/service-runtime.mjs'
import { registerFirmwareImageFrames } from '../src/main/firmware-registration-client.mjs'

/** @param {Buffer} bytes - Test snapshot. @returns {string} SHA-256 identity. */
function digest(bytes) {
    return createHash('sha256').update(bytes).digest('hex')
}

/**
 * Creates a bounded non-bootable OpenRDX envelope for main-process file tests.
 * Native tests separately validate the complete container and TI records.
 * @param {import('node:test').TestContext} context - Cleanup owner.
 * @returns {Promise<object>} Isolated image, sidecar, and file service.
 */
async function selectionFixture(context) {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-image-'))
    context.after(() => rm(directory, { recursive: true, force: true }))
    const imagePath = join(directory, 'OpenRDX-v1-07.bin')
    const manifestPath = join(directory, 'OpenRDX-v1-07.json')
    const bytes = Buffer.alloc(62110)
    bytes.write('OPENRDX1', 0x108, 'ascii')
    const manifest = { authentication_scheme: 'openrdx-sha256-v1', container: 'OpenRDX-v1-07.bin', container_length: bytes.length, container_sha256: digest(bytes), boot_region_sha256: digest(bytes.subarray(0x18c, -4)), release_version: '1.07', requires_openrdx_receiver: true, template_sha256: '73d528801aefc032d3a53637b035f65d72809151b2f127c6b2050e9bacc76f3b' }
    await writeFile(imagePath, bytes)
    await writeFile(manifestPath, JSON.stringify(manifest))
    return { bytes, imagePath, manifest, manifestPath, service: new FirmwareFileSelectionService({ showOpenDialog: async () => ({ canceled: false, filePaths: [imagePath] }) }) }
}

/** @param {import('node:test').TestContext} context - Test resources. @returns {Promise<void>} Verifies manifest identity survives every main-owned boundary. */
async function testOpenRdxRegistration(context) {
    const fixture = await selectionFixture(context)
    const selection = await fixture.service.registerFirmwarePath(fixture.imagePath)
    const frames = []
    const result = await dispatchRegisteredFirmwareOperation({
        firmwareFileService: fixture.service,
        operation: { operationId: 'op:openrdx', request: { kind: 'firmware-update', firmwareFileToken: selection.fileToken } },
        client: {
            /** @param {object} registration - Path-free bytes and manifest facts. @returns {Promise<object>} Captured registration. */
            async registerFirmwareImage(registration) {
                return registerFirmwareImageFrames({
                    registration,
                    request: async (method, payload) => {
                        frames.push({ method, payload })
                        return { ok: true }
                    }
                })
            },
            /** @returns {Promise<object>} Records successful admission only. */
            async startOperation() {
                return { ok: true }
            }
        }
    })
    assert.deepEqual(result, { ok: true })
    assert.deepEqual(frames[0].payload.openRdx, { containerSha256: fixture.manifest.container_sha256, bootRegionSha256: fixture.manifest.boot_region_sha256, releaseVersion: '1.07' })
    assert.equal(JSON.stringify(frames).includes(fixture.imagePath), false)
}

/** @param {import('node:test').TestContext} context - Test resources. @returns {Promise<void>} Rejects missing, mismatched, malformed, and oversized sidecars before registration. */
async function testRejectedOpenRdxManifests(context) {
    const fixture = await selectionFixture(context)
    const variants = ['x'.repeat(65537), JSON.stringify({ ...fixture.manifest, release_version: '1.7' }), JSON.stringify({ ...fixture.manifest, container: '../other.bin' }), JSON.stringify({ ...fixture.manifest, requires_openrdx_receiver: false }), JSON.stringify({ ...fixture.manifest, container_sha256: 'invalid-hash' })]
    for (const contents of variants) {
        await writeFile(fixture.manifestPath, contents)
        const selected = await fixture.service.registerFirmwarePath(fixture.imagePath)
        assert.deepEqual(await fixture.service.claimFirmwareFile(selected.fileToken), { ok: false, reason: 'firmware-openrdx-manifest-invalid' })
    }
}

test('OpenRDX firmware carries verified release metadata through native registration', testOpenRdxRegistration)
test('OpenRDX firmware requires its matching bounded release manifest', testRejectedOpenRdxManifests)

/** @param {import('node:test').TestContext} context - Isolated fixture owner. @returns {Promise<void>} Explains each actionable sidecar failure without disclosing local paths. */
async function testManifestFailureReasons(context) {
    const variants = [
        { name: 'missing sidecar', changes: null, reason: 'firmware-openrdx-manifest-missing' },
        { name: 'malformed JSON', contents: '{', reason: 'firmware-openrdx-manifest-malformed' },
        { name: 'image filename mismatch', changes: { container: 'OpenRDX-v1-06.bin' }, reason: 'firmware-openrdx-manifest-filename-mismatch' },
        { name: 'image hash mismatch', changes: { container_sha256: '0'.repeat(64) }, reason: 'firmware-openrdx-manifest-hash-mismatch' },
        { name: 'boot hash mismatch', changes: { boot_region_sha256: '0'.repeat(64) }, reason: 'firmware-openrdx-manifest-hash-mismatch' }
    ]
    for (const variant of variants) {
        await context.test(variant.name, async (child) => {
            const fixture = await selectionFixture(child)
            if (variant.changes === null) await rm(fixture.manifestPath)
            else await writeFile(fixture.manifestPath, variant.contents ?? JSON.stringify({ ...fixture.manifest, ...variant.changes }))
            const selected = await fixture.service.registerFirmwarePath(fixture.imagePath)
            assert.deepEqual(await fixture.service.claimFirmwareFile(selected.fileToken), { ok: false, reason: variant.reason })
            assert.deepEqual(await fixture.service.claimFirmwareFile(selected.fileToken), { ok: false, reason: 'firmware-file-token-invalid' })
        })
    }
}

test('OpenRDX sidecar failures identify the missing, malformed, filename, or hash cause', testManifestFailureReasons)

/** @param {import('node:test').TestContext} context - Isolated fixture owner. @returns {Promise<void>} Preserves strict pairing for browser-renamed downloads. */
async function testRenamedReleaseFiles(context) {
    const fixture = await selectionFixture(context)
    const renamedImage = fixture.imagePath.replace('OpenRDX-v1-07.bin', '_rdx_OpenRDX-v1-07.bin')
    const renamedManifest = fixture.manifestPath.replace('OpenRDX-v1-07.json', '_rdx_OpenRDX-v1-07.json')
    await rename(fixture.imagePath, renamedImage)
    let selected = await fixture.service.registerFirmwarePath(renamedImage)
    assert.deepEqual(await fixture.service.claimFirmwareFile(selected.fileToken), { ok: false, reason: 'firmware-openrdx-manifest-missing' })
    await rename(fixture.manifestPath, renamedManifest)
    selected = await fixture.service.registerFirmwarePath(renamedImage)
    assert.deepEqual(await fixture.service.claimFirmwareFile(selected.fileToken), { ok: false, reason: 'firmware-openrdx-manifest-filename-mismatch' })
}

test('renamed OpenRDX downloads distinguish absent sidecars from renamed image pairs', testRenamedReleaseFiles)

/** @param {import('node:test').TestContext} context - Cleanup owner. @returns {Promise<void>} Rejects special sidecars before any blocking read. */
async function testSpecialManifests(context) {
    for (const type of ['directory', 'symlink', ...(process.platform === 'win32' ? [] : ['fifo'])]) {
        await context.test(type, async (child) => {
            const fixture = await selectionFixture(child)
            await rm(fixture.manifestPath)
            if (type === 'directory') await mkdir(fixture.manifestPath)
            else if (type === 'symlink') {
                if (!(await createSymlinkFixture(child, fixture.imagePath, fixture.manifestPath))) return
            } else execFileSync('mkfifo', [fixture.manifestPath])
            const selected = await fixture.service.registerFirmwarePath(fixture.imagePath)
            assert.deepEqual(await fixture.service.claimFirmwareFile(selected.fileToken), { ok: false, reason: 'firmware-openrdx-manifest-invalid' }, type)
        })
    }
}

test('OpenRDX firmware rejects directories, symlinks, and FIFOs as manifests', { timeout: 2000 }, testSpecialManifests)

/** @param {import('node:test').TestContext} context - Isolated fixture owner. @returns {Promise<void>} Rejects bad release pairs in the chooser before returning operation authority. */
async function testChooserManifestPreflight(context) {
    for (const [contents, reason] of [
        [null, 'firmware-openrdx-manifest-missing'],
        ['{', 'firmware-openrdx-manifest-malformed'],
        [{ container: 'other.bin' }, 'firmware-openrdx-manifest-filename-mismatch'],
        [{ container_sha256: '0'.repeat(64) }, 'firmware-openrdx-manifest-hash-mismatch']
    ]) {
        await context.test(reason, async (child) => {
            const fixture = await selectionFixture(child)
            if (contents === null) await rm(fixture.manifestPath)
            else await writeFile(fixture.manifestPath, typeof contents === 'string' ? contents : JSON.stringify({ ...fixture.manifest, ...contents }))
            const result = await fixture.service.chooseFirmware()
            assert.deepEqual(result, { ok: false, reason })
            assert.equal(JSON.stringify(result).includes(fixture.imagePath), false)
            // Rejection releases the pending slot, allowing repeated corrections.
            for (let attempt = 0; attempt < 17; attempt += 1) assert.deepEqual(await fixture.service.chooseFirmware(), result)
        })
    }
}

test('firmware chooser rejects missing and mismatched manifests before issuing a token', testChooserManifestPreflight)

/** @param {import('node:test').TestContext} context - Isolated fixture owner. @returns {Promise<void>} Rechecks the sidecar after successful selection instead of trusting cached metadata. */
async function testManifestRevalidation(context) {
    const fixture = await selectionFixture(context)
    const selected = await fixture.service.chooseFirmware()
    assert.equal(selected.ok, true)
    await rm(fixture.manifestPath)
    assert.deepEqual(await fixture.service.claimFirmwareFile(selected.fileToken), { ok: false, reason: 'firmware-openrdx-manifest-missing' })
    assert.deepEqual(await fixture.service.claimFirmwareFile(selected.fileToken), { ok: false, reason: 'firmware-file-token-invalid' })
}

test('successful chooser preflight retains strict manifest revalidation at claim time', testManifestRevalidation)
