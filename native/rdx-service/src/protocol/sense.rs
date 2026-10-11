// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Length-first parsing and sanitized interpretation of SCSI sense data.

use super::{EvidenceStatus, ProtocolParseError};

const SENSE_HEADER_LENGTH: usize = 8;
const FIXED_SENSE_TRIPLE_LENGTH: usize = 14;

/// Maximum bounded sense payload retained by the native service.
pub const MAX_SENSE_DATA_LENGTH: usize = 0xFC;

/// Parsed SCSI sense key, ASC, and ASCQ with a safe stable code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SenseData {
    raw_key: u8,
    asc: u8,
    ascq: u8,
    code: &'static str,
    evidence: EvidenceStatus,
}

impl SenseData {
    /// Parses complete fixed (`0x70/0x71`) or descriptor (`0x72/0x73`) sense data.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolParseError`] for short, oversized, inconsistent, or
    /// unsupported response formats. Fixed-format input must include ASC/ASCQ.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolParseError> {
        if bytes.len() > MAX_SENSE_DATA_LENGTH {
            return Err(ProtocolParseError::PayloadTooLarge {
                context: "SCSI sense data",
                maximum: MAX_SENSE_DATA_LENGTH,
                actual: bytes.len(),
            });
        }
        if bytes.len() < SENSE_HEADER_LENGTH {
            return Err(ProtocolParseError::PayloadTooShort {
                context: "SCSI sense header",
                minimum: SENSE_HEADER_LENGTH,
                actual: bytes.len(),
            });
        }

        let response_code = bytes[0] & 0x7F;
        let declared_total = SENSE_HEADER_LENGTH + usize::from(bytes[7]);
        if declared_total != bytes.len() {
            return Err(ProtocolParseError::PayloadLengthMismatch {
                context: "SCSI additional sense length",
                declared: declared_total,
                actual: bytes.len(),
            });
        }

        let (raw_key, asc, ascq) = match response_code {
            0x70 | 0x71 => {
                if bytes.len() < FIXED_SENSE_TRIPLE_LENGTH {
                    return Err(ProtocolParseError::PayloadTooShort {
                        context: "fixed-format sense key/ASC/ASCQ",
                        minimum: FIXED_SENSE_TRIPLE_LENGTH,
                        actual: bytes.len(),
                    });
                }
                (bytes[2] & 0x0F, bytes[12], bytes[13])
            }
            0x72 | 0x73 => (bytes[1] & 0x0F, bytes[2], bytes[3]),
            value => {
                return Err(ProtocolParseError::UnsupportedValue {
                    context: "SCSI sense response code",
                    value: u64::from(value),
                });
            }
        };

        let (code, evidence) = if (raw_key, asc, ascq) == (0x07, 0x74, 0x08) {
            (
                "firmware-signature-error",
                EvidenceStatus::ImplementationReference,
            )
        } else {
            ("scsi-check-condition", EvidenceStatus::Incomplete)
        };

        Ok(Self {
            raw_key,
            asc,
            ascq,
            code,
            evidence,
        })
    }

    /// Returns the unmodified four-bit sense key for trusted native diagnostics.
    #[must_use]
    pub const fn raw_key(&self) -> u8 {
        self.raw_key
    }

    /// Returns the unmodified additional sense code.
    #[must_use]
    pub const fn asc(&self) -> u8 {
        self.asc
    }

    /// Returns the unmodified additional sense qualifier.
    #[must_use]
    pub const fn ascq(&self) -> u8 {
        self.ascq
    }

    /// Returns a renderer-safe stable code without embedding raw bytes.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the evidence level for the stable code interpretation.
    #[must_use]
    pub const fn evidence(&self) -> EvidenceStatus {
        self.evidence
    }
}
