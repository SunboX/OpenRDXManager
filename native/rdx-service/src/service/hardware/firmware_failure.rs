// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sanitized device-status classification for firmware commands.

use crate::operations::HostPrimitiveError;
use crate::protocol::SenseData;

/// Converts parsed device status into stable firmware failure categories without
/// retaining or publishing raw sense bytes.
pub(super) const fn check_condition_cause(sense: &SenseData) -> HostPrimitiveError {
    match (sense.raw_key(), sense.asc(), sense.ascq()) {
        (0x07, 0x74, 0x08) => HostPrimitiveError::FirmwareSignatureRejected,
        (0x05, 0x20, 0x00) => HostPrimitiveError::FirmwareCommandUnsupported,
        (0x05, 0x24, 0x00) => HostPrimitiveError::FirmwareCommandInvalid,
        (0x02, _, _) => HostPrimitiveError::FirmwareDeviceNotReady,
        (0x04, _, _) => HostPrimitiveError::FirmwareHardwareFailure,
        (0x07, _, _) => HostPrimitiveError::FirmwareWriteProtected,
        (0x06, _, _) => HostPrimitiveError::FirmwareUnitAttention,
        _ => HostPrimitiveError::FirmwareDeviceRejected,
    }
}
