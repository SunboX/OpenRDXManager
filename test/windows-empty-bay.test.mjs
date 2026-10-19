// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

/** Confirms that production discovery classifies no-media before inspecting placeholder volumes. */
async function testEmptyBayInspectionOrder() {
    const source = await readFile(new URL('../native/rdx-service/windows-native/src/native/layout.rs', import.meta.url), 'utf8')
    const start = source.indexOf('pub(crate) fn volume_facts(')
    const end = source.indexOf('pub(crate) fn write_read_file(', start)
    assert.ok(start >= 0 && end > start)
    const method = source.slice(start, end)
    const capacity = method.indexOf('crate::media::verified_media_capacity(')
    const emptyBay = method.indexOf('return Ok((false, false, 0, 0, true));')
    const volumes = method.indexOf('volumes::pin_disk_volume_metadata(')
    assert.ok(capacity >= 0 && emptyBay > capacity && volumes > emptyBay)
    assert.ok(method.indexOf('let capacity = disk_capacity(', volumes) > volumes)
    assert.match(method, /self\.revalidate_exact\(\)\?;/)
    assert.match(method, /\|\| self\.revalidate_exact\(\)/)
    assert.match(method, /self\.revalidate_volume_leases\(&scanned\.leases\)\?;/)
    assert.match(method, /disk_has_protected_partition_roles/)
}

test('Windows empty-bay discovery precedes complete present-cartridge volume checks', testEmptyBayInspectionOrder)
