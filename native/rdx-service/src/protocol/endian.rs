// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact big-endian encoders for fixed-width SCSI command fields.

use super::ProtocolBuildError;

/// Largest integer representable by a three-byte unsigned field.
pub const MAX_U24: u32 = 0x00FF_FFFF;

/// Encodes a 16-bit unsigned integer in big-endian byte order.
#[must_use]
pub const fn u16_be(value: u16) -> [u8; 2] {
    value.to_be_bytes()
}

/// Encodes a value in a three-byte unsigned big-endian field.
///
/// # Errors
///
/// Returns [`ProtocolBuildError::ValueOutOfRange`] when `value` exceeds
/// [`MAX_U24`].
pub fn u24_be(value: u32) -> Result<[u8; 3], ProtocolBuildError> {
    if value > MAX_U24 {
        return Err(ProtocolBuildError::ValueOutOfRange {
            field: "u24",
            value: u64::from(value),
            maximum: u64::from(MAX_U24),
        });
    }

    let bytes = value.to_be_bytes();
    Ok([bytes[1], bytes[2], bytes[3]])
}

/// Encodes a 32-bit unsigned integer in big-endian byte order.
#[must_use]
pub const fn u32_be(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}
