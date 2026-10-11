// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed self-test outcomes with no device identifiers or raw sense payloads.

use super::{ParsedScsiResult, WindowsIoFailure, WindowsResultError};

/// Preserves the actual parser/transport failure before the public generic error.
pub(super) fn self_test_code(
    result: &Result<ParsedScsiResult, WindowsResultError>,
) -> &'static str {
    match result {
        Ok(_) => "windows-self-test-succeeded",
        Err(WindowsResultError::CheckCondition(sense)) => {
            match (sense.raw_key(), sense.asc(), sense.ascq()) {
                (2, 0x3a, _) => "windows-self-test-no-media",
                (5, 0x20, 0) => "windows-self-test-invalid-command",
                (5, 0x24, 0) => "windows-self-test-invalid-field",
                (3, _, _) => "windows-self-test-medium-error",
                (4, _, _) => "windows-self-test-hardware-error",
                (6, _, _) => "windows-self-test-unit-attention",
                _ => "windows-self-test-check-condition",
            }
        }
        Err(WindowsResultError::Win32 {
            attempted: false, ..
        }) => "windows-self-test-not-sent",
        Err(WindowsResultError::Win32 {
            failure: WindowsIoFailure::TimedOut,
            ..
        }) => "windows-self-test-timeout",
        Err(WindowsResultError::Win32 {
            failure: WindowsIoFailure::AccessDenied,
            ..
        }) => "windows-self-test-access-denied",
        Err(WindowsResultError::Win32 { .. }) => "windows-self-test-native-error",
        Err(
            WindowsResultError::MalformedSense
            | WindowsResultError::SenseTruncated
            | WindowsResultError::SenseLengthOutOfBounds,
        ) => "windows-self-test-invalid-sense",
        Err(WindowsResultError::UnexpectedSense) => "windows-self-test-unexpected-sense",
        Err(WindowsResultError::ScsiStatus(_)) => "windows-self-test-scsi-status",
        Err(_) => "windows-self-test-invalid-transfer",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Closed classification distinguishes device rejection from malformed transport evidence.
    #[test]
    fn classifies_diagnostic_failure_without_raw_values() {
        assert_eq!(
            self_test_code(&Err(WindowsResultError::MalformedSense)),
            "windows-self-test-invalid-sense"
        );
        assert_eq!(
            self_test_code(&Err(WindowsResultError::UnexpectedSense)),
            "windows-self-test-unexpected-sense"
        );
        let sense = crate::protocol::SenseData::parse(&[0x72, 2, 0x3a, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            self_test_code(&Err(WindowsResultError::CheckCondition(sense))),
            "windows-self-test-no-media"
        );
    }
}
