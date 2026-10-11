// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Independent validation of the fixed manufacturing restore request.

/// Accepts only fixed framing with a checksum-valid, non-erased desired record.
/// The expected current record is opaque because recovery must accept corruption.
pub(crate) fn payload_is_valid(data: &[u8]) -> bool {
    if data.len() != 528 || &data[..8] != b"RDXMFG01" || data[12..16] != [0; 4] {
        return false;
    }
    let desired = &data[272..];
    let mut lanes = [0x78_u8, 0x56, 0x34, 0x12];
    for (index, byte) in desired.iter().enumerate().skip(4) {
        lanes[index & 3] = lanes[index & 3].wrapping_add(*byte);
    }
    !desired.iter().all(|byte| *byte == 0xff) && desired[..4] == lanes
}

#[cfg(test)]
mod tests {
    use crate::ScsiOperation;

    /// Constructors retain fixed semantic fields and reject malformed desired records.
    #[test]
    fn manufacturing_restore_operations_are_closed() {
        let probe = ScsiOperation::openrdx_manufacturing_restore_capability().into_request();
        assert_eq!(
            (
                probe.operation,
                probe.offset,
                probe.data_length,
                probe.save_pages
            ),
            (33, 0, 0, 0)
        );
        let mut data = vec![0; 528];
        data[..8].copy_from_slice(b"RDXMFG01");
        data[16..272].fill(0xa5);
        data[272..276].copy_from_slice(&[0x78, 0x56, 0x34, 0x12]);
        let operation = ScsiOperation::openrdx_restore_manufacturing(&data).unwrap();
        assert_eq!(format!("{operation:?}"), "ScsiOperation(<private>)");
        let request = operation.into_request();
        assert_eq!(request.timeout_ms, 120_000);
        assert_eq!(
            (
                request.operation,
                request.offset,
                request.data_length,
                request.save_pages
            ),
            (34, 0, 528, 0)
        );
        assert_eq!(&request.data[..528], data);
        for index in [0, 7, 12, 13, 14, 15, 272, 273, 274, 275, 524, 525, 526, 527] {
            let mut invalid = data.clone();
            invalid[index] ^= 1;
            assert!(ScsiOperation::openrdx_restore_manufacturing(&invalid).is_err());
        }
        assert!(ScsiOperation::openrdx_restore_manufacturing(&data[..527]).is_err());
        let mut oversized = data.clone();
        oversized.push(0);
        assert!(ScsiOperation::openrdx_restore_manufacturing(&oversized).is_err());
        data[16..272].fill(0xff);
        assert!(ScsiOperation::openrdx_restore_manufacturing(&data).is_ok());
        data[272..].fill(0xff);
        assert!(ScsiOperation::openrdx_restore_manufacturing(&data).is_err());
    }
}
