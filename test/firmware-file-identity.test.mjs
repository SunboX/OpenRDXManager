// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { join } from 'node:path'
import test from 'node:test'
import { FirmwareFileSelectionService } from '../src/main/firmware-file-selection-service.mjs'

/** Supplies synthetic regular-file identity with the Windows pathname/handle distinction. */
function metadata(dev, overrides = {}) {
    return { dev, ino: 73, size: 4, mtimeMs: 123.25, isFile: () => true, isSymbolicLink: () => false, ...overrides }
}

/** Creates a no-hardware, no-filesystem fixture retaining each opened handle's identity. */
function fixture({ claimDevice = 42, secondPath = metadata(0) } = {}) {
    let opened = 0
    let closed = 0
    let pathsRead = 0
    let dataReads = 0
    const path = join(process.cwd(), 'fixture-firmware.BIN')
    const service = new FirmwareFileSelectionService({
        /** Returns pathname metadata; Windows may report an unavailable device ID as zero. */
        async lstat() {
            return ++pathsRead === 1 ? metadata(0) : secondPath
        },
        /** Keeps the fixture path canonical without touching the filesystem. */
        async realpath(value) {
            return value
        },
        /** Captures one immutable handle binding while permitting a later replaced-volume test. */
        async open() {
            const device = ++opened === 1 ? 42 : claimDevice
            return {
                /** Returns the actual handle device identity rather than pathname metadata. */
                async stat() {
                    return metadata(device)
                },
                /** Implements the real caller's bounded positional read and EOF check. */
                async read(buffer, offset, length, position) {
                    dataReads += 1
                    const bytes = Buffer.from([1, 2, 3, 4])
                    const bytesRead = Math.min(length, Math.max(0, bytes.length - position))
                    bytes.copy(buffer, offset, position, position + bytesRead)
                    return { bytesRead, buffer }
                },
                /** Records deterministic resource release, including rejection paths. */
                async close() {
                    closed += 1
                }
            }
        }
    })
    return { service, path, counts: () => ({ opened, closed, dataReads }) }
}

/** Comparing handle metadata consistently accepts the reproduced Windows dev=0 pathname case. */
async function testConsistentHandleIdentity() {
    const value = fixture()
    const selected = await value.service.registerFirmwarePath(value.path)
    assert.equal(selected.ok, true)
    const claimed = await value.service.claimFirmwareFile(selected.fileToken)
    assert.deepEqual(claimed.bytes, Buffer.from([1, 2, 3, 4]))
    claimed.bytes.fill(0)
    assert.deepEqual(value.counts(), { opened: 2, closed: 2, dataReads: 2 })
}

/** A volume change still rejects identical inode, size and timestamp before reading bytes. */
async function testChangedDeviceRejected() {
    const value = fixture({ claimDevice: 84 })
    const selected = await value.service.registerFirmwarePath(value.path)
    assert.equal(selected.ok, true)
    assert.deepEqual(await value.service.claimFirmwareFile(selected.fileToken), { ok: false, reason: 'firmware-file-changed' })
    assert.deepEqual(value.counts(), { opened: 2, closed: 2, dataReads: 0 })
}

/** A file replaced while its initial handle is opened cannot receive a usable token. */
async function testSelectionRaceRejected() {
    const value = fixture({ secondPath: metadata(0, { ino: 74 }) })
    assert.deepEqual(await value.service.registerFirmwarePath(value.path), { ok: false, reason: 'firmware-file-invalid' })
    assert.deepEqual(value.counts(), { opened: 1, closed: 1, dataReads: 0 })
}

test('firmware selection compares handle identity when Windows pathname dev is zero', testConsistentHandleIdentity)
test('firmware claim still rejects a changed volume with otherwise identical metadata', testChangedDeviceRejected)
test('firmware selection rejects pathname replacement while opening its initial handle', testSelectionRaceRejected)
