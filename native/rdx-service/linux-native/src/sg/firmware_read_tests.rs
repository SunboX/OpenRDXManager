// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Byte-exact closed factory-record reads and non-mutating receiver queries.

use super::*;

/// Each half uses the documented fixed TI memory read with exactly 128 data-in bytes.
#[test]
fn manufacturing_reads_encode_exact_fixed_offsets_and_lengths() {
    for (operation, offset) in [
        (ScsiOperation::openrdx_manufacturing_record_first(), 0),
        (ScsiOperation::openrdx_manufacturing_record_second(), 0x80),
    ] {
        let request = operation.into_request().unwrap();
        assert_eq!(request.cdb(), [0xe7, 0, 3, 0xe0, offset, 0x80]);
        assert_eq!(request.direction(), DataDirection::FromDevice);
        assert_eq!(request.data(), [0; 128]);
        assert_eq!(request.timeout_ms(), 30_000);
        assert_eq!(request.sense_capacity(), MAX_SENSE_LENGTH);
    }
}

/// The mode-2 capability encodings must never carry a write payload or arbitrary selector.
#[test]
fn interlock_queries_encode_exact_no_data_commands() {
    for (operation, selector) in [
        (
            ScsiOperation::openrdx_manufacturing_restore_capability(),
            0x4d,
        ),
        (ScsiOperation::openrdx_serial_capability(), 0x53),
    ] {
        let request = operation
            .with_timeout_ms(15_000)
            .unwrap()
            .into_request()
            .unwrap();
        assert_eq!(request.cdb(), [0x3b, 2, selector, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(request.direction(), DataDirection::None);
        assert!(request.data().is_empty());
        assert_eq!(request.timeout_ms(), 15_000);
    }
}
