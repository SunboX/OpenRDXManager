// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed read-only OpenRDX record contracts; no test opens a device.

use rdx_service::model::RiskClass;
use rdx_service::platform::macos::build_scsi_task;
use rdx_service::protocol::{
    DataDirection, openrdx_manufacturing_record_first, openrdx_manufacturing_record_second,
    openrdx_operational_state_record,
};

/// The TI handler consumes a BE32 address and an exact one-byte length in a six-byte CDB.
#[test]
fn openrdx_record_reads_have_only_fixed_inbound_ranges() {
    for (command, expected, length) in [
        (
            openrdx_manufacturing_record_first(),
            [0xe7, 0, 3, 0xe0, 0, 0x80],
            128,
        ),
        (
            openrdx_manufacturing_record_second(),
            [0xe7, 0, 3, 0xe0, 0x80, 0x80],
            128,
        ),
        (
            openrdx_operational_state_record(),
            [0xe7, 0, 3, 0xf0, 0, 0x40],
            64,
        ),
    ] {
        assert_eq!(command.cdb(), expected);
        assert_eq!(command.direction(), DataDirection::FromDevice);
        assert_eq!(command.data_in_capacity(), length);
        assert_eq!(command.data(), vec![0; length]);
        assert!(command.data_out().is_empty());
        assert_eq!(command.timeout_ms(), 30_000);
        let packet = build_scsi_task(&command).unwrap();
        assert_eq!(packet.risk(), RiskClass::ReadOnly);
        assert_eq!(packet.transfer_length(), length as u32);
        assert_eq!(packet.timeout_ms(), 30_000);
    }
}
