// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

/** Reads implementation evidence without opening any hardware transport. */
async function source(path) {
    return readFile(new URL(`../native/rdx-service/${path}`, import.meta.url), 'utf8')
}

/** Checks both production mappings and rejects a generic vendor-command escape hatch. */
async function testFixedReadMappings() {
    const semantic = await source('src/platform/windows/semantic.rs')
    const mapping = await source('src/platform/windows/command_mapping.rs')
    for (const [variant, builder] of [
        ['First', 'first'],
        ['Second', 'second']
    ]) {
        assert.match(semantic, new RegExp(`same_wire_command\\(\\s*command,\\s*&crate::protocol::openrdx_manufacturing_record_${builder}\\(\\),?\\s*\\)[\\s\\S]*?WindowsSemanticCommand::ManufacturingRecord${variant}`, 'u'))
        assert.match(mapping, new RegExp(`WindowsSemanticCommand::ManufacturingRecord${variant} => \\{\\s*rdx_windows_native::ScsiOperation::openrdx_manufacturing_record_${builder}\\(\\)`, 'u'))
    }
    assert.match(mapping, /WindowsSemanticCommand::Unknown => \{\s*return Err\(rdx_windows_native::NativeError::InvalidRequest\);/u)
    assert.doesNotMatch(mapping, /raw_command|from_cdb|execute_raw/u)
}

/** Backup and repeated full-record checks still precede the first firmware write. */
async function testPreservationOrder() {
    const firmware = await source('src/service/hardware/firmware.rs')
    const method = firmware.slice(firmware.indexOf('pub(super) fn execute_firmware_operation('))
    const capture = method.indexOf('Some(resolved.manufacturing_record().map_err(')
    const backup = method.indexOf('.backup_manufacturing_record(')
    const compare = method.indexOf('.and_then(|fresh| record.verify(&fresh))')
    const writing = method.indexOf('observer.reached("firmware-writing", false)')
    assert.ok(capture > 0 && backup > capture && compare > backup && writing > compare)
    const host = await source('src/platform/windows/host.rs')
    assert.match(host, /Err\(_\) => return CommandDispatch::NotSent\(TransportError::Unavailable\)/u)
}

test('Windows factory preservation reads use two exact closed native mappings', testFixedReadMappings)
test('Windows firmware mapping does not bypass backup or pre-transfer record comparison', testPreservationOrder)
