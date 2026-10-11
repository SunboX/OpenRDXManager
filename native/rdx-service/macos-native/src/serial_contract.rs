// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Independent validation of the fixed compare-and-set serial payload.

/// Accepts only a checksum-valid original record or explicitly erased reconstruction.
pub(crate) fn payload_is_valid(data: &[u8]) -> bool {
    if data.len() != 280
        || &data[..8] != b"RDXSER01"
        || data[12] > 1
        || data[13] != 0
        || !data[14..24].iter().all(u8::is_ascii_digit)
    {
        return false;
    }
    let record = &data[24..];
    if data[12] == 1 {
        return record.iter().all(|byte| *byte == 0xff);
    }
    let mut lanes = [0x78_u8, 0x56, 0x34, 0x12];
    for (index, byte) in record.iter().enumerate().skip(4) {
        lanes[index & 3] = lanes[index & 3].wrapping_add(*byte);
    }
    record[..4] == lanes
}

/// Serial workers require the exact supported USB product and complete decimal identity.
#[cfg(target_os = "macos")]
pub(crate) fn usb_identity_is_valid(identity: &crate::MacUsbIdentity) -> bool {
    identity.vendor_id() == 0x1a5a
        && identity.product_id() == 5
        && identity.location_id() != 0
        && identity.serial().len() == 12
        && identity.serial().starts_with("00")
        && identity.serial().bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use crate::ScsiOperation;

    /// The C boundary independently checks fixed restore commands and malformed records.
    #[cfg(all(target_os = "macos", feature = "test-hooks"))]
    #[test]
    fn manufacturing_restore_c_contract_is_closed() {
        unsafe extern "C" {
            fn rdx_macos_test_manufacturing_restore_contract() -> bool;
        }
        // SAFETY: the hook operates only on synthetic stack records, with no device I/O.
        assert!(unsafe { rdx_macos_test_manufacturing_restore_contract() });
    }

    /// All 32 chunks are fixed, and malformed mode/record/digit bytes fail locally.
    #[test]
    fn serial_operations_are_closed() {
        for index in 0..32 {
            let request = ScsiOperation::openrdx_manufacturing_sector_chunk(index)
                .unwrap()
                .into_request();
            assert_eq!(
                (
                    request.operation,
                    request.offset,
                    request.data_length,
                    request.save_pages
                ),
                (29, u32::from(index), 0, 0)
            );
        }
        assert!(ScsiOperation::openrdx_manufacturing_sector_chunk(32).is_err());
        assert!(ScsiOperation::openrdx_manufacturing_sector_chunk(255).is_err());
        let diagnostics = ScsiOperation::openrdx_mechanism_diagnostics().into_request();
        assert_eq!(
            (
                diagnostics.operation,
                diagnostics.offset,
                diagnostics.data_length,
                diagnostics.save_pages
            ),
            (32, 0, 0, 0)
        );
        let probe = ScsiOperation::openrdx_serial_capability().into_request();
        assert_eq!(
            (
                probe.operation,
                probe.offset,
                probe.data_length,
                probe.save_pages
            ),
            (30, 0, 0, 0)
        );
        let mut data = vec![0; 280];
        data[..8].copy_from_slice(b"RDXSER01");
        data[12] = 1;
        data[14..24].copy_from_slice(b"0123456789");
        data[24..].fill(0xff);
        assert!(ScsiOperation::openrdx_set_serial(data.clone()).is_ok());
        for index in [0, 12, 13, 14, 24] {
            let mut changed = data.clone();
            changed[index] = 0xfe;
            assert!(ScsiOperation::openrdx_set_serial(changed).is_err());
        }
        data[12] = 0;
        assert!(ScsiOperation::openrdx_set_serial(data.clone()).is_err());
        data[24..].fill(0);
        data[24..28].copy_from_slice(&[0x78, 0x56, 0x34, 0x12]);
        assert!(ScsiOperation::openrdx_set_serial(data.clone()).is_ok());
        data[279] = 1;
        assert!(ScsiOperation::openrdx_set_serial(data).is_err());
    }

    /// The capture worker independently rejects unrelated VID/PID, locations, or serial forms.
    #[cfg(target_os = "macos")]
    #[test]
    fn serial_worker_usb_identity_is_exact() {
        let mut bytes = Vec::from(0x100000_u32.to_le_bytes());
        bytes.extend_from_slice(&0x1a5a_u16.to_le_bytes());
        bytes.extend_from_slice(&5_u16.to_le_bytes());
        bytes.extend_from_slice(b"000123456789");
        let identity = crate::MacUsbIdentity::decode(&bytes).unwrap();
        assert!(super::usb_identity_is_valid(&identity));
        for index in [4, 6, 8, 19] {
            let mut invalid = bytes.clone();
            invalid[index] ^= 0x40;
            let identity = crate::MacUsbIdentity::decode(&invalid).unwrap();
            assert!(!super::usb_identity_is_valid(&identity));
        }
        let mut invalid = bytes;
        invalid[..4].fill(0);
        assert!(crate::MacUsbIdentity::decode(&invalid).is_err());
    }

    /// Native C rejects malformed semantic fields independently without opening hardware.
    #[cfg(all(target_os = "macos", feature = "test-hooks"))]
    #[test]
    fn serial_c_contract_is_closed() {
        unsafe extern "C" {
            fn rdx_macos_test_serial_contract() -> bool;
        }
        // SAFETY: the hook uses only stack records; it issues no IOKit calls.
        assert!(unsafe { rdx_macos_test_serial_contract() });
    }
}
