// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { lstat, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises'
import { createSymlinkFixture } from './helpers/symlink-fixture.mjs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { FirmwareFileSelectionService } from '../src/main/firmware-file-selection-service.mjs'

/** @returns {Promise<void>} Verifies a selected local image becomes only an opaque one-shot token. */
async function testOpaqueSelection() {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-firmware-selection-'))
    const imagePath = join(directory, 'RDX_USB3_0283.BIN')
    const dialogCalls = []
    await writeFile(imagePath, Buffer.from([0x52, 0x44, 0x58, 0x01]))
    const service = new FirmwareFileSelectionService({
        translate: (key) => `localized:${key}`,
        /** @param {object} options - Electron chooser options. @returns {Promise<object>} Controlled selection. */
        async showOpenDialog(options) {
            dialogCalls.push(options)
            return { canceled: false, filePaths: [imagePath] }
        }
    })

    try {
        const selection = await service.chooseFirmware()
        assert.equal(selection.ok, true)
        assert.match(selection.fileToken, /^firmware:[a-f0-9-]+$/)
        assert.equal(JSON.stringify(selection).includes(imagePath), false)
        assert.deepEqual(dialogCalls, [
            {
                buttonLabel: 'localized:filePicker.firmware.open',
                filters: [{ extensions: ['bin', 'BIN', 'bip', 'BIP'], name: 'localized:filePicker.firmware.filterName' }],
                properties: ['openFile'],
                title: 'localized:filePicker.firmware.title'
            }
        ])

        const claimed = await service.claimFirmwareFile(selection.fileToken)
        assert.equal(claimed.extension, '.BIN')
        assert.equal(claimed.size, 4)
        assert.deepEqual(claimed.bytes, Buffer.from([0x52, 0x44, 0x58, 0x01]))
        assert.equal('path' in claimed, false)
        assert.equal(JSON.stringify(claimed).includes(await realpath(imagePath)), false)
        assert.deepEqual(await service.claimFirmwareFile(selection.fileToken), { ok: false, reason: 'firmware-file-token-invalid' })
    } finally {
        await rm(directory, { force: true, recursive: true })
    }
}

/** @returns {Promise<void>} Verifies claiming uses only bounded positional reads. */
async function testBoundedClaimRead() {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-firmware-bounded-read-'))
    const imagePath = join(directory, 'RDX2E__STD__F-0283.bin')
    try {
        await writeFile(imagePath, Buffer.from([0x52, 0x44, 0x58, 0x01]))
        const metadata = await lstat(imagePath)
        let unboundedReadCalled = false
        const service = new FirmwareFileSelectionService({
            /** @returns {Promise<object>} One controlled local selection. */
            showOpenDialog: async () => ({ canceled: false, filePaths: [imagePath] }),
            /** @returns {Promise<object>} Exact bounded file-handle fixture. */
            open: async () => ({
                /** @returns {Promise<void>} Completes fixture closure. */
                close: async () => {},
                /** @param {Buffer} buffer - Bounded destination. @param {number} offset - Destination offset. @param {number} length - Maximum read. @param {number} position - Exact file position. @returns {Promise<object>} Bounded read result. */
                read: async (buffer, offset, length, position) => {
                    const source = Buffer.from([0x52, 0x44, 0x58, 0x01])
                    const bytesRead = Math.min(length, Math.max(0, source.length - position))
                    source.copy(buffer, offset, position, position + bytesRead)
                    return { buffer, bytesRead }
                },
                /** @returns {Promise<Buffer>} Forbidden unbounded fixture path. */
                readFile: async () => {
                    unboundedReadCalled = true
                    return Buffer.from([0x52, 0x44, 0x58, 0x01])
                },
                /** @returns {Promise<object>} Original selected-file identity. */
                stat: async () => metadata
            })
        })
        const selection = await service.chooseFirmware()
        const claimed = await service.claimFirmwareFile(selection.fileToken)
        assert.deepEqual(claimed.bytes, Buffer.from([0x52, 0x44, 0x58, 0x01]))
        assert.equal(unboundedReadCalled, false)
    } finally {
        await rm(directory, { force: true, recursive: true })
    }
}

/** @param {object} context - Isolated subtest owner. @returns {Promise<void>} Verifies cancellation and invalid local files fail without issuing tokens. */
async function testInvalidSelections(context) {
    const directory = await mkdtemp(join(tmpdir(), 'openrdx-firmware-selection-invalid-'))
    const textPath = join(directory, 'firmware.txt')
    const imagePath = join(directory, 'firmware.BIP')
    const linkPath = join(directory, 'firmware-link.BIP')
    await writeFile(textPath, 'not firmware')
    await writeFile(imagePath, Buffer.from([0x01]))
    const selections = [
        { canceled: true, filePaths: [] },
        { canceled: false, filePaths: [textPath] },
        { canceled: false, filePaths: [imagePath, textPath] }
    ]
    const service = new FirmwareFileSelectionService({
        /** @returns {Promise<object>} Returns each controlled dialog result. */
        async showOpenDialog() {
            return selections.shift()
        }
    })

    try {
        assert.deepEqual(await service.chooseFirmware(), { ok: false, reason: 'firmware-selection-cancelled' })
        assert.deepEqual(await service.chooseFirmware(), { ok: false, reason: 'firmware-file-type-unsupported' })
        assert.deepEqual(await service.chooseFirmware(), { ok: false, reason: 'firmware-selection-invalid' })
        await context.test('rejects a real file symlink when the host permits its creation', async (child) => {
            if (!(await createSymlinkFixture(child, imagePath, linkPath))) return
            selections.push({ canceled: false, filePaths: [linkPath] })
            assert.deepEqual(await service.chooseFirmware(), { ok: false, reason: 'firmware-file-invalid' })
        })
    } finally {
        await rm(directory, { force: true, recursive: true })
    }
}

test('firmware chooser returns only a validated opaque one-shot local token', testOpaqueSelection)
test('firmware chooser snapshots with bounded positional reads', testBoundedClaimRead)
test('firmware chooser rejects cancellation, wrong types, symlinks, and multiple files', testInvalidSelections)
