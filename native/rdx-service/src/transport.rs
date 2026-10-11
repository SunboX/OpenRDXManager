// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit command-dispatch outcomes for identity-bound device sessions.

use serde::{Deserialize, Serialize};

use crate::protocol::SenseData;

/// Largest bounded response retained by the portable command layer.
pub const MAX_TRANSPORT_RESPONSE_LENGTH: usize = 0x1000;

/// A bounded successful command response containing only the actual bytes read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportResponse {
    data: Box<[u8]>,
}

/// Evidence-backed certainty describing whether one command reached the device.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DispatchCertainty {
    /// The adapter proves that no command was sent.
    NotSent,
    /// The device or adapter definitively rejected the command without applying it.
    DefinitelyRejected,
    /// The command may have reached or changed the device, but completion is unknown.
    CompletionUnknown,
    /// The adapter observed successful command completion.
    Succeeded,
}

/// Complete result of dispatching one internal command through an active lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandDispatch {
    /// No command reached the selected device.
    NotSent(TransportError),
    /// The command was definitely rejected without application.
    DefinitelyRejected(TransportError),
    /// Command application or completion cannot be proven.
    CompletionUnknown(TransportError),
    /// The command completed and returned bounded response data.
    Succeeded(TransportResponse),
}

impl CommandDispatch {
    /// Returns the explicit dispatch certainty for state-machine decisions.
    #[must_use]
    pub const fn certainty(&self) -> DispatchCertainty {
        match self {
            Self::NotSent(_) => DispatchCertainty::NotSent,
            Self::DefinitelyRejected(_) => DispatchCertainty::DefinitelyRejected,
            Self::CompletionUnknown(_) => DispatchCertainty::CompletionUnknown,
            Self::Succeeded(_) => DispatchCertainty::Succeeded,
        }
    }

    /// Returns sanitized failure evidence, or `None` for successful completion.
    #[must_use]
    pub const fn error(&self) -> Option<&TransportError> {
        match self {
            Self::NotSent(error)
            | Self::DefinitelyRejected(error)
            | Self::CompletionUnknown(error) => Some(error),
            Self::Succeeded(_) => None,
        }
    }

    /// Returns bounded response data only after proven successful completion.
    #[must_use]
    pub const fn response(&self) -> Option<&TransportResponse> {
        match self {
            Self::Succeeded(response) => Some(response),
            _ => None,
        }
    }
}

impl TransportResponse {
    /// Creates a response after enforcing the portable allocation bound.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ResponseTooLarge`] when `data` exceeds
    /// [`MAX_TRANSPORT_RESPONSE_LENGTH`].
    pub fn new(data: Vec<u8>) -> Result<Self, TransportError> {
        if data.len() > MAX_TRANSPORT_RESPONSE_LENGTH {
            return Err(TransportError::ResponseTooLarge {
                maximum: MAX_TRANSPORT_RESPONSE_LENGTH,
                actual: data.len(),
            });
        }
        Ok(Self {
            data: data.into_boxed_slice(),
        })
    }

    /// Creates a successful response with no data phase.
    #[must_use]
    pub fn empty() -> Self {
        Self { data: Box::new([]) }
    }

    /// Returns only the actual bytes received from the device.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Sanitized failure classes returned by a device-bound command transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// The bounded host-side command timeout expired.
    Timeout,
    /// The device-bound transport became unavailable before completion.
    Unavailable,
    /// The selected device was removed while the command was active.
    DeviceRemoved,
    /// The command returned CHECK CONDITION with bounded parsed sense.
    CheckCondition(SenseData),
    /// A data-out command returned GOOD status but the host reported that fewer
    /// bytes were transferred than the immutable request supplied.
    DataOutIncomplete,
    /// macOS completed the exact 670-byte mode-4 tail at offset 61,440 and
    /// returned 07/74/08. This proves only the documented staging response;
    /// command application and flash contents remain unknown.
    CompatibilityStagingSignature,
    /// A response exceeded the portable response allocation bound.
    ResponseTooLarge {
        /// Largest retained response.
        maximum: usize,
        /// Supplied response length.
        actual: usize,
    },
    /// A deterministic fixture had no response for a data-in command.
    MissingFixtureResponse,
    /// A device adapter panicked and was contained at the session boundary.
    AdapterPanic,
    /// The identity-bound session was inactive before dispatch.
    InactiveSession,
}

impl TransportError {
    /// Reports whether retrying a complete firmware transfer is evidence-backed.
    #[must_use]
    pub const fn permits_firmware_retry(&self) -> bool {
        match self {
            // Only explicitly transient device conditions can justify another
            // complete transfer after fresh identity, media and revision gates.
            // Replaying invalid fields, protection or hardware errors cannot
            // repair the command and can repeat earlier successful flash writes.
            Self::CheckCondition(sense) => matches!(
                (sense.raw_key(), sense.asc(), sense.ascq()),
                (0x06, _, _) | (0x02, 0x04, 0x01)
            ),
            Self::Timeout | Self::Unavailable | Self::DeviceRemoved | Self::AdapterPanic => true,
            _ => false,
        }
    }

    /// Reports whether command application cannot be determined safely.
    #[must_use]
    pub const fn is_ambiguous(&self) -> bool {
        matches!(
            self,
            Self::DeviceRemoved
                | Self::DataOutIncomplete
                | Self::AdapterPanic
                | Self::CompatibilityStagingSignature
        )
    }

    /// Reports the exact signature-rejection sense condition.
    #[must_use]
    pub fn is_firmware_signature_rejection(&self) -> bool {
        matches!(self, Self::CompatibilityStagingSignature)
            || matches!(self, Self::CheckCondition(sense) if sense.code() == "firmware-signature-error")
    }
}

#[cfg(test)]
mod retry_tests {
    use super::*;

    /// Device rejection is terminal unless its sense explicitly indicates a
    /// transient condition; no hardware command is dispatched by this test.
    #[test]
    fn firmware_retry_requires_transient_device_sense() {
        for (key, asc, ascq, expected) in [
            (0x05, 0x24, 0x00, false),
            (0x05, 0x20, 0x00, false),
            (0x05, 0x26, 0x00, false),
            (0x07, 0x74, 0x08, false),
            (0x07, 0x27, 0x00, false),
            (0x04, 0x44, 0x00, false),
            (0x03, 0x11, 0x00, false),
            (0x02, 0x3A, 0x00, false),
            (0x02, 0x04, 0x02, false),
            (0x00, 0x00, 0x00, false),
            (0x06, 0x29, 0x00, true),
            (0x02, 0x04, 0x01, true),
        ] {
            let sense = SenseData::parse(&[0x72, key, asc, ascq, 0, 0, 0, 0]).unwrap();
            assert_eq!(
                TransportError::CheckCondition(sense).permits_firmware_retry(),
                expected
            );
        }
    }
}
