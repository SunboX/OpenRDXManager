// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact wire and validation coverage for the fixed manufacturing restore protocol.

use rdx_service::protocol::{
    DataDirection, openrdx_manufacturing_restore_capability, openrdx_manufacturing_sector_chunk,
    openrdx_mechanism_diagnostics, openrdx_restore_manufacturing,
};

/// Builds a synthetic checksum-valid desired record and damaged current record.
fn payload() -> Vec<u8> {
    let mut data = vec![0; 528];
    data[..8].copy_from_slice(b"RDXMFG01");
    data[8..12].copy_from_slice(&0x12345678_u32.to_le_bytes());
    data[16..272].fill(0xa5);
    data[272..276].copy_from_slice(&[0x78, 0x56, 0x34, 0x12]);
    data
}

/// Every sector chunk stays within the fixed 4096-byte manufacturing sector.
#[test]
fn manufacturing_restore_reads_are_fixed_and_bounded() {
    for (index, expected) in [
        (0, [0xe7, 0, 3, 0xe0, 0, 0x80]),
        (1, [0xe7, 0, 3, 0xe0, 0x80, 0x80]),
        (31, [0xe7, 0, 3, 0xef, 0x80, 0x80]),
    ] {
        let command = openrdx_manufacturing_sector_chunk(index).unwrap();
        assert_eq!(command.cdb(), expected);
        assert_eq!(command.direction(), DataDirection::FromDevice);
        assert_eq!(command.data(), [0; 128]);
    }
    assert!(openrdx_manufacturing_sector_chunk(32).is_err());
    assert!(openrdx_manufacturing_sector_chunk(255).is_err());
    let diagnostics = openrdx_mechanism_diagnostics();
    assert_eq!(diagnostics.cdb(), [0xe8, 0, 0, 0, 0, 128]);
    assert_eq!(diagnostics.direction(), DataDirection::FromDevice);
    assert_eq!(diagnostics.data(), [0; 128]);
}

/// Capability and mutation have distinct fixed offsets and no caller flash address.
#[test]
fn manufacturing_restore_commands_match_the_receiver_contract() {
    let probe = openrdx_manufacturing_restore_capability();
    assert_eq!(probe.cdb(), [0x3b, 2, 0x4d, 0, 0, 1, 0, 0, 0, 0]);
    assert_eq!(probe.direction(), DataDirection::None);
    assert!(probe.data().is_empty());
    let data = payload();
    let command = openrdx_restore_manufacturing(&data).unwrap();
    assert_eq!(command.cdb(), [0x3b, 2, 0x4d, 0, 0, 0, 0, 2, 0x10, 0]);
    assert_eq!(command.direction(), DataDirection::ToDevice);
    assert_eq!(command.timeout_ms(), 120_000);
    assert_eq!(command.data(), data);
    assert_eq!(format!("{command:?}"), "Command(<private>)");
}

/// Framing and all four checksum lanes are mandatory; damaged baselines remain recoverable.
#[test]
fn manufacturing_restore_payload_is_validated_without_rejecting_damaged_current() {
    let data = payload();
    for index in [0, 7, 12, 13, 14, 15, 272, 273, 274, 275, 524, 525, 526, 527] {
        let mut invalid = data.clone();
        invalid[index] ^= 1;
        assert!(openrdx_restore_manufacturing(&invalid).is_err());
    }
    assert!(openrdx_restore_manufacturing(&data[..527]).is_err());
    let mut oversized = data.clone();
    oversized.push(0);
    assert!(openrdx_restore_manufacturing(&oversized).is_err());
    let mut erased = data.clone();
    erased[272..].fill(0xff);
    assert!(openrdx_restore_manufacturing(&erased).is_err());
    erased = data;
    erased[16..272].fill(0xff);
    assert!(openrdx_restore_manufacturing(&erased).is_ok());
}
