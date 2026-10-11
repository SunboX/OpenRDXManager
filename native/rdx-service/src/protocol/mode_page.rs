// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Round-trip-safe parsing for RDX MODE pages.

use super::{EvidenceStatus, ProtocolParseError};

const MODE_PARAMETER_HEADER_LENGTH: usize = 8;
const MODE_PAGE_HEADER_LENGTH: usize = 2;

/// Maximum response size requested by the MODE SENSE commands.
pub const MAX_MODE_PAGE_LENGTH: usize = 0xFE;

/// A validated RDX MODE page retaining the complete response for safe mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RdxFeaturePage {
    bytes: Vec<u8>,
    page_offset: usize,
    page_code: u8,
}

impl RdxFeaturePage {
    /// Parses one complete RDX MODE SENSE(10) response.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolParseError`] for short, oversized, inconsistent,
    /// subpage-formatted, unsupported, or recovery-field-truncated payloads.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProtocolParseError> {
        if bytes.len() > MAX_MODE_PAGE_LENGTH {
            return Err(ProtocolParseError::PayloadTooLarge {
                context: "MODE SENSE response",
                maximum: MAX_MODE_PAGE_LENGTH,
                actual: bytes.len(),
            });
        }
        let minimum = MODE_PARAMETER_HEADER_LENGTH + MODE_PAGE_HEADER_LENGTH;
        if bytes.len() < minimum {
            return Err(ProtocolParseError::PayloadTooShort {
                context: "MODE SENSE response",
                minimum,
                actual: bytes.len(),
            });
        }

        let declared_total = usize::from(u16::from_be_bytes([bytes[0], bytes[1]])) + 2;
        if declared_total != bytes.len() {
            return Err(ProtocolParseError::PayloadLengthMismatch {
                context: "MODE data length",
                declared: declared_total,
                actual: bytes.len(),
            });
        }

        let block_descriptor_length = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
        let page_offset = MODE_PARAMETER_HEADER_LENGTH + block_descriptor_length;
        if page_offset + MODE_PAGE_HEADER_LENGTH > bytes.len() {
            return Err(ProtocolParseError::PayloadLengthMismatch {
                context: "MODE block descriptor length",
                declared: block_descriptor_length,
                actual: bytes.len() - MODE_PARAMETER_HEADER_LENGTH,
            });
        }

        let raw_page = bytes[page_offset];
        let page_code = raw_page & 0x3F;
        if raw_page & 0x40 != 0 {
            return Err(ProtocolParseError::UnsupportedValue {
                context: "MODE subpage format",
                value: u64::from(page_code),
            });
        }
        let minimum_body = match page_code {
            0x31 => 3,
            0x33 => 2,
            0x34 => 5,
            _ => {
                return Err(ProtocolParseError::UnsupportedValue {
                    context: "RDX MODE page",
                    value: u64::from(page_code),
                });
            }
        };

        let declared_body = usize::from(bytes[page_offset + 1]);
        if declared_body < minimum_body {
            return Err(ProtocolParseError::PayloadTooShort {
                context: "RDX MODE page body",
                minimum: minimum_body,
                actual: declared_body,
            });
        }
        let declared_page_end = page_offset + MODE_PAGE_HEADER_LENGTH + declared_body;
        if declared_page_end != bytes.len() {
            return Err(ProtocolParseError::PayloadLengthMismatch {
                context: "RDX MODE page length",
                declared: declared_page_end - page_offset,
                actual: bytes.len() - page_offset,
            });
        }

        Ok(Self {
            bytes: bytes.to_vec(),
            page_offset,
            page_code,
        })
    }

    /// Returns the six-bit MODE page code.
    #[must_use]
    pub const fn page_code(&self) -> u8 {
        self.page_code
    }

    /// Returns the complete validated response bytes without modification.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the page and returns the complete response bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns the operation-mode low-three-bit field.
    #[must_use]
    pub fn operation_mode(&self) -> Option<u8> {
        (self.page_code == 0x34).then(|| self.bytes[self.page_offset + 4] & 0x07)
    }

    /// Changes only the operation-mode low-three-bit field.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolParseError::UnsupportedValue`] for a non-`0x34` page
    /// or a value outside the `0..=3` enumeration.
    pub fn set_operation_mode(&mut self, mode: u8) -> Result<(), ProtocolParseError> {
        if self.page_code != 0x34 || mode > 3 {
            return Err(ProtocolParseError::UnsupportedValue {
                context: "RDX operation mode",
                value: u64::from(mode),
            });
        }
        let field = &mut self.bytes[self.page_offset + 4];
        *field = (*field & 0xF8) | mode;
        Ok(())
    }

    /// Returns the maximum-host-SATA-speed byte.
    #[must_use]
    pub fn max_host_sata_speed(&self) -> Option<u8> {
        (self.page_code == 0x34).then(|| self.bytes[self.page_offset + 6])
    }

    /// Changes only the maximum-host-SATA-speed byte.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolParseError::UnsupportedValue`] unless this is page
    /// `0x34` and `speed` is one of the GUI values `2` or `3`.
    pub fn set_max_host_sata_speed(&mut self, speed: u8) -> Result<(), ProtocolParseError> {
        if self.page_code != 0x34 || !matches!(speed, 2 | 3) {
            return Err(ProtocolParseError::UnsupportedValue {
                context: "maximum host SATA speed",
                value: u64::from(speed),
            });
        }
        self.bytes[self.page_offset + 6] = speed;
        Ok(())
    }

    /// Returns the evidence level for MODE page offsets and meanings.
    #[must_use]
    pub const fn evidence(&self) -> EvidenceStatus {
        EvidenceStatus::ImplementationReference
    }
}
