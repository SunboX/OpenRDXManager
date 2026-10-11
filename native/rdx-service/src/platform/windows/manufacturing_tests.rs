// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression coverage for the previously rejected firmware-preservation reads.

use super::*;

/// Firmware preflight can dispatch both fixed halves as read-only native operations.
#[test]
fn factory_record_reads_have_closed_read_only_native_mappings() {
    for (command, expected) in [
        (
            crate::protocol::openrdx_manufacturing_record_first(),
            WindowsSemanticCommand::ManufacturingRecordFirst,
        ),
        (
            crate::protocol::openrdx_manufacturing_record_second(),
            WindowsSemanticCommand::ManufacturingRecordSecond,
        ),
    ] {
        let command = command.with_timeout_ms(2_001).unwrap();
        let packet = build_scsi_pass_through(&command).unwrap();
        assert_eq!(packet.semantic, expected);
        assert_eq!(packet.risk, RiskClass::ReadOnly);
        assert_eq!(packet.data_direction(), SCSI_IOCTL_DATA_IN);
        assert_eq!(packet.transfer_length(), 128);
        assert_eq!(packet.timeout_seconds(), 3);
        assert!(native_operation(&packet).is_ok());
    }
}

/// The complete closed preservation vocabulary maps without arbitrary flash access.
#[test]
fn preservation_support_maps_only_evidence_backed_commands() {
    for command in [
        crate::protocol::openrdx_operational_state_record(),
        crate::protocol::openrdx_manufacturing_restore_capability(),
        crate::protocol::openrdx_serial_capability(),
        crate::protocol::openrdx_mechanism_diagnostics(),
        crate::protocol::openrdx_manufacturing_sector_chunk(2).unwrap(),
    ] {
        let packet = build_scsi_pass_through(&command).unwrap();
        assert_ne!(packet.semantic, WindowsSemanticCommand::Unknown);
        assert_eq!(packet.risk, RiskClass::ReadOnly);
        assert!(native_operation(&packet).is_ok());
    }
    for index in 0..32 {
        assert!(
            native_operation(
                &build_scsi_pass_through(
                    &crate::protocol::openrdx_manufacturing_sector_chunk(index).unwrap()
                )
                .unwrap()
            )
            .is_ok()
        );
    }
    assert!(crate::protocol::openrdx_manufacturing_sector_chunk(32).is_err());
    let unsupported = crate::protocol::vendor_0283_factory_info();
    let packet = build_scsi_pass_through(&unsupported).unwrap();
    assert_eq!(packet.semantic, WindowsSemanticCommand::Unknown);
    assert!(native_operation(&packet).is_err());
}
