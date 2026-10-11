// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private raw manufacturing preservation, independent of pinned migration profiles.

use crate::operations::HostPrimitiveError;
use zeroize::Zeroizing;

/// Complete SPI manufacturing bytes, never serialized or included in diagnostics.
/// The owned allocation is cleared when this update attempt ends.
pub(crate) struct ManufacturingRecord(Zeroizing<[u8; 256]>);

impl ManufacturingRecord {
    /// Preserves an opaque baseline, including damaged data needed for later recovery.
    /// Integrity here is exact repeated readback and durable host storage, not a
    /// claim that the factory checksum is valid. Restore sources validate separately.
    pub(crate) fn capture(bytes: Zeroizing<[u8; 256]>) -> Self {
        Self(bytes)
    }
    /// Supplies the complete opaque record only to the service-owned backup writer.
    pub(crate) fn bytes(&self) -> &[u8; 256] {
        &self.0
    }

    /// Accepts a checksum-valid or entirely erased baseline without changing bytes.
    /// An erased dock must be able to install the firmware providing serial repair;
    /// preserving that blank state does not recover or validate its lost identity.
    pub(crate) fn validate(bytes: Zeroizing<[u8; 256]>) -> Result<Self, HostPrimitiveError> {
        // Firmware sums each byte lane separately, beginning after the stored
        // checksum. Do not replace this with a word sum carrying between lanes.
        let mut checksum = [0x78u8, 0x56, 0x34, 0x12];
        for (index, byte) in bytes[4..].iter().enumerate() {
            checksum[index % 4] = checksum[index % 4].wrapping_add(*byte);
        }
        if !bytes.iter().all(|byte| *byte == 0xff) && bytes[..4] != checksum {
            return Err(HostPrimitiveError::ManufacturingInvalid);
        }
        Ok(Self(bytes))
    }

    /// Requires byte equality across the entire 256-byte record, including opaque data.
    pub(crate) fn verify(&self, actual: &Self) -> Result<(), HostPrimitiveError> {
        if self.0.as_ref() != actual.0.as_ref() {
            return Err(HostPrimitiveError::ManufacturingChanged);
        }
        Ok(())
    }
}
