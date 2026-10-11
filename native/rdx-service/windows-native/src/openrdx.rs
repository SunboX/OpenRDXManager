// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed OpenRDX preservation operations; no arbitrary flash address API.

use super::{ScsiOperation, ScsiOperationKind};

/// Private semantic fields validated at construction, never arbitrary CDB bytes.
pub(super) enum Operation {
    SectorChunk(u8),
    OperationalState,
    Mechanism,
    RestoreCapability,
    SerialCapability,
    Restore(Vec<u8>),
}

impl ScsiOperation {
    /// Reads only one of the 32 fixed manufacturing-sector chunks.
    ///
    /// # Errors
    /// Rejects every index outside the fixed 4096-byte erase sector.
    pub fn openrdx_manufacturing_sector_chunk(index: u8) -> Result<Self, super::NativeError> {
        if index >= 32 {
            return Err(super::NativeError::InvalidRequest);
        }
        Ok(Self::new(ScsiOperationKind::OpenRdx(
            Operation::SectorChunk(index),
        )))
    }

    /// Reads only the fixed 64-byte operational-state record.
    #[must_use]
    pub const fn openrdx_operational_state_record() -> Self {
        Self::new(ScsiOperationKind::OpenRdx(Operation::OperationalState))
    }

    /// Reads the fixed mechanism snapshot without actuating any motor or sensor.
    #[must_use]
    pub const fn openrdx_mechanism_diagnostics() -> Self {
        Self::new(ScsiOperationKind::OpenRdx(Operation::Mechanism))
    }

    /// Probes compare-and-replace support with no data, flash write or reset.
    #[must_use]
    pub const fn openrdx_manufacturing_restore_capability() -> Self {
        Self::new(ScsiOperationKind::OpenRdx(Operation::RestoreCapability))
    }

    /// Queries serial-extension readiness with a fixed zero-data, non-mutating frame.
    #[must_use]
    pub const fn openrdx_serial_capability() -> Self {
        Self::new(ScsiOperationKind::OpenRdx(Operation::SerialCapability))
    }

    /// Constructs the guarded fixed-record restore, with independent payload validation.
    ///
    /// # Errors
    /// Rejects wrong magic, size, reserved bytes, checksum or an erased desired record.
    pub fn openrdx_restore_manufacturing(data: &[u8]) -> Result<Self, super::NativeError> {
        if !valid_restore(data) {
            return Err(super::NativeError::InvalidRequest);
        }
        Self::new(ScsiOperationKind::OpenRdx(Operation::Restore(
            data.to_vec(),
        )))
        .with_timeout_seconds(120)
    }
    /// Reads exactly the first 128 manufacturing bytes at SPI address `0x3E000`.
    #[must_use]
    pub const fn openrdx_manufacturing_record_first() -> Self {
        Self::new(ScsiOperationKind::OpenRdx(Operation::SectorChunk(0)))
    }

    /// Reads exactly the remaining 128 manufacturing bytes at SPI address `0x3E080`.
    #[must_use]
    pub const fn openrdx_manufacturing_record_second() -> Self {
        Self::new(ScsiOperationKind::OpenRdx(Operation::SectorChunk(1)))
    }
}

/// Independently checks the receiver's fixed compare-and-replace payload contract.
fn valid_restore(data: &[u8]) -> bool {
    if data.len() != 528 || &data[..8] != b"RDXMFG01" || data[12..16] != [0; 4] {
        return false;
    }
    let desired = &data[272..];
    let mut lanes = [0x78u8, 0x56, 0x34, 0x12];
    for (index, byte) in desired.iter().enumerate().skip(4) {
        lanes[index & 3] = lanes[index & 3].wrapping_add(*byte);
    }
    !desired.iter().all(|byte| *byte == 0xff) && desired[..4] == lanes
}

/// Encodes only the closed, constructor-validated BOT operation vocabulary.
#[cfg(any(windows, test))]
pub(super) fn encode(operation: Operation) -> (Vec<u8>, super::DataDirection, Vec<u8>) {
    use super::DataDirection::{FromDevice, None, ToDevice};
    match operation {
        Operation::SectorChunk(index) => (
            vec![0xe7, 0, 3, 0xe0 + index / 2, (index % 2) * 128, 128],
            FromDevice,
            vec![0; 128],
        ),
        Operation::OperationalState => (vec![0xe7, 0, 3, 0xf0, 0, 64], FromDevice, vec![0; 64]),
        Operation::Mechanism => (vec![0xe8, 0, 0, 0, 0, 128], FromDevice, vec![0; 128]),
        Operation::RestoreCapability => (vec![0x3b, 2, 0x4d, 0, 0, 1, 0, 0, 0, 0], None, vec![]),
        Operation::SerialCapability => (vec![0x3b, 2, 0x53, 0, 0, 1, 0, 0, 0, 0], None, vec![]),
        Operation::Restore(data) => (vec![0x3b, 2, 0x4d, 0, 0, 0, 0, 2, 0x10, 0], ToDevice, data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DataDirection, NativeError};

    /// The readiness probe never carries a serial value, data-out phase, or caller CDB.
    #[test]
    fn serial_capability_is_exact_and_non_mutating() {
        let request = ScsiOperation::openrdx_serial_capability()
            .into_request()
            .unwrap();
        assert_eq!(request.cdb_length, 10);
        assert_eq!(&request.cdb[..10], &[0x3b, 2, 0x53, 0, 0, 1, 0, 0, 0, 0]);
        assert_eq!(&request.cdb[10..], &[0; 6]);
        assert_eq!(request.direction, DataDirection::None);
        assert!(request.data.is_empty());
    }

    /// Every sector chunk has a fixed address and cannot escape the manufacturing sector.
    #[test]
    fn sector_reads_remain_bounded_and_exact() {
        for index in 0..32 {
            let request = ScsiOperation::openrdx_manufacturing_sector_chunk(index)
                .unwrap()
                .into_request()
                .unwrap();
            assert_eq!(
                &request.cdb[..6],
                &[0xe7, 0, 3, 0xe0 + index / 2, (index % 2) * 128, 128]
            );
            assert_eq!(request.data, vec![0; 128]);
            assert_eq!(request.direction, DataDirection::FromDevice);
        }
        for index in [32, 128, 255] {
            assert!(ScsiOperation::openrdx_manufacturing_sector_chunk(index).is_err());
        }
    }

    /// Restore is exactly compare-and-replace and independently rejects malformed identity.
    #[test]
    fn restore_command_rejects_invalid_payload_and_uses_fixed_wire_shape() {
        let mut data = vec![0; 528];
        data[..8].copy_from_slice(b"RDXMFG01");
        data[16..272].fill(0xff);
        data[272..276].copy_from_slice(&[0x78, 0x56, 0x34, 0x12]);
        let request = ScsiOperation::openrdx_restore_manufacturing(&data)
            .unwrap()
            .into_request()
            .unwrap();
        assert_eq!(&request.cdb[..10], &[0x3b, 2, 0x4d, 0, 0, 0, 0, 2, 0x10, 0]);
        assert_eq!(request.data, data);
        assert_eq!(request.direction, DataDirection::ToDevice);
        assert_eq!(request.timeout_seconds, 120);
        for index in [0, 7, 12, 15, 272, 275, 527] {
            let mut changed = data.clone();
            changed[index] ^= 1;
            assert!(ScsiOperation::openrdx_restore_manufacturing(&changed).is_err());
        }
        assert!(ScsiOperation::openrdx_restore_manufacturing(&data[..527]).is_err());
        data[272..].fill(0xff);
        assert!(ScsiOperation::openrdx_restore_manufacturing(&data).is_err());
        let probe = ScsiOperation::openrdx_manufacturing_restore_capability()
            .into_request()
            .unwrap();
        assert_eq!(&probe.cdb[..10], &[0x3b, 2, 0x4d, 0, 0, 1, 0, 0, 0, 0]);
        assert!(probe.data.is_empty());
        assert_eq!(probe.direction, DataDirection::None);
    }

    /// Both halves have immutable addresses, bounded zeroed receive buffers and no writes.
    #[test]
    fn manufacturing_reads_encode_exact_fixed_requests() {
        for (operation, offset) in [
            (ScsiOperation::openrdx_manufacturing_record_first(), 0),
            (ScsiOperation::openrdx_manufacturing_record_second(), 0x80),
        ] {
            assert_eq!(format!("{operation:?}"), "ScsiOperation(<private>)");
            let request = operation
                .with_timeout_seconds(3)
                .unwrap()
                .into_request()
                .unwrap();
            assert_eq!(request.cdb_length, 6);
            assert_eq!(&request.cdb[..6], &[0xe7, 0, 3, 0xe0, offset, 0x80]);
            assert_eq!(&request.cdb[6..], &[0; 10]);
            assert_eq!(request.direction, DataDirection::FromDevice);
            assert_eq!(request.data, vec![0; 128]);
            assert_eq!(request.timeout_seconds, 3);
        }
    }

    /// New read commands retain the same independent timeout validation as every operation.
    #[test]
    fn manufacturing_reads_reject_unbounded_timeouts() {
        for timeout in [0, 301, u32::MAX] {
            assert!(matches!(
                ScsiOperation::openrdx_manufacturing_record_first().with_timeout_seconds(timeout),
                Err(NativeError::InvalidRequest)
            ));
        }
    }
}
