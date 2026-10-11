// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

/** Confirms that actual Windows enumeration uses the tested same-handle type gate. */
async function testNativeVolumeTypeGate() {
    const source = await readFile(new URL('../native/rdx-service/windows-native/src/native/volumes.rs', import.meta.url), 'utf8')
    const start = source.indexOf('fn volume_topology(')
    const end = source.indexOf('fn volume_mount_paths(', start)
    assert.ok(start >= 0 && end > start)
    assert.match(source.slice(start, end), /query_volume_topology\(storage_device_identity\(volume\), \|\|\s*\{\s*volume_disk_extents\(volume\)/u)
    // All inspected volumes, including positively identified optical drives,
    // still carry mount paths into the complete inventory used by safety checks.
    assert.match(source, /let \(record, lease\) = inspect_volume\(&name, disk_number\)\?;/u)
    assert.match(source, /records\.push\(record\);/u)
    assert.match(source, /VolumeRecord::new_with_mount_paths\(volume_name\.to_vec\(\), topology, mount_paths, target\)\?/u)
}

test('Windows volume enumeration classifies optical devices before disk-only queries', testNativeVolumeTypeGate)
