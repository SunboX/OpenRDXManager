// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded parsing for standard LOG SENSE page and parameter headers.

use super::{EvidenceStatus, ProtocolParseError};

const PAGE_HEADER_LENGTH: usize = 4;
const PARAMETER_HEADER_LENGTH: usize = 4;

/// Maximum response size requested by the LOG SENSE commands.
pub const MAX_LOG_PAGE_LENGTH: usize = 0xFE;

/// A LOG SENSE parameter meaning with an established numeric ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogParameterMeaning {
    /// Drive-page parameter `0x0004` used for the connection-type value.
    DriveConnectionType,
    /// Drive-page parameter `0x0005` used for the bus-power state.
    DriveBusPowerStatus,
    /// Drive-page parameter `0x0006` used for supported link speeds.
    DriveLinkSpeedsSupported,
    /// Cartridge-page parameter `0x000A` used for the cartridge link speed.
    CartridgeLinkSpeed,
}

/// One length-delimited LOG SENSE parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogParameter {
    code: u16,
    control: u8,
    value: Vec<u8>,
    meaning: Option<LogParameterMeaning>,
}

impl LogParameter {
    /// Returns the big-endian parameter code.
    #[must_use]
    pub const fn code(&self) -> u16 {
        self.code
    }

    /// Returns the parameter control byte without assigning unproven flags.
    #[must_use]
    pub const fn control(&self) -> u8 {
        self.control
    }

    /// Returns the bounded opaque parameter bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns an established meaning, or `None` for unknown metadata.
    #[must_use]
    pub const fn meaning(&self) -> Option<LogParameterMeaning> {
        self.meaning
    }

    /// Returns the evidence level for the parameter's semantic meaning.
    #[must_use]
    pub const fn evidence(&self) -> EvidenceStatus {
        if self.meaning.is_some() {
            EvidenceStatus::ImplementationReference
        } else {
            EvidenceStatus::Incomplete
        }
    }

    /// Decodes a one-to-four-byte parameter value as an unsigned big-endian integer.
    ///
    /// Longer and empty opaque values return `None`; their meaning is not inferred.
    #[must_use]
    pub fn uint32(&self) -> Option<u32> {
        if self.value.is_empty() || self.value.len() > size_of::<u32>() {
            return None;
        }
        Some(
            self.value
                .iter()
                .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte)),
        )
    }
}

/// One complete vendor LOG SENSE page with bounded parameters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogPage {
    page_code: u8,
    parameters: Vec<LogParameter>,
}

impl LogPage {
    /// Returns the six-bit LOG page code.
    #[must_use]
    pub const fn page_code(&self) -> u8 {
        self.page_code
    }

    /// Returns parsed parameters in their original wire order.
    #[must_use]
    pub fn parameters(&self) -> &[LogParameter] {
        &self.parameters
    }

    /// Finds the last parameter with `code`, matching the lookup policy.
    ///
    /// All duplicate parameters remain available through [`Self::parameters`].
    /// The application visited every parameter in wire order and
    /// overwrote the prior match, so this convenience lookup returns the last.
    #[must_use]
    pub fn find(&self, code: u16) -> Option<&LogParameter> {
        self.parameters
            .iter()
            .rev()
            .find(|parameter| parameter.code == code)
    }

    /// Returns the evidence level for the vendor-specific page selection.
    #[must_use]
    pub const fn evidence(&self) -> EvidenceStatus {
        EvidenceStatus::ImplementationReference
    }

    /// Returns the evidence level for the standard page/parameter framing.
    #[must_use]
    pub const fn framing_evidence(&self) -> EvidenceStatus {
        EvidenceStatus::Documented
    }
}

/// Parses one complete RDX drive (`0x20`) or cartridge (`0x21`) LOG SENSE page.
///
/// Unknown parameter codes are retained as bounded opaque values. The parser
/// never assigns them a field meaning. The original v2.83 cartridge page's
/// two reserved trailing zero bytes are accepted only at their offset.
///
/// # Errors
///
/// Returns [`ProtocolParseError`] when the payload exceeds the supported
/// allocation, has an incomplete header or record, declares inconsistent
/// lengths, uses subpage format, or reports an unsupported page.
pub fn parse_log_page(bytes: &[u8]) -> Result<LogPage, ProtocolParseError> {
    ensure_bounded(
        bytes,
        "LOG SENSE page",
        PAGE_HEADER_LENGTH,
        MAX_LOG_PAGE_LENGTH,
    )?;

    let raw_page = bytes[0];
    let page_code = raw_page & 0x3F;
    if raw_page & 0x40 != 0 {
        return Err(ProtocolParseError::UnsupportedValue {
            context: "LOG SENSE subpage format",
            value: u64::from(page_code),
        });
    }
    if !matches!(page_code, 0x20 | 0x21) {
        return Err(ProtocolParseError::UnsupportedValue {
            context: "LOG SENSE page",
            value: u64::from(page_code),
        });
    }

    let declared_body = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    let declared_total = PAGE_HEADER_LENGTH + declared_body;
    if declared_total != bytes.len() {
        return Err(ProtocolParseError::PayloadLengthMismatch {
            context: "LOG SENSE page length",
            declared: declared_total,
            actual: bytes.len(),
        });
    }

    let mut offset = PAGE_HEADER_LENGTH;
    let mut parameters = Vec::new();
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < PARAMETER_HEADER_LENGTH {
            // Vendor FUN_08000614 allocates/declares 0x74 bytes, but its fourteen
            // records end at 0x72 (one u16 and thirteen u32 values). The cleared
            // allocation leaves two reserved zeros, which the original Manager
            // ignores. Do not generalize this to truncated or nonzero records.
            if page_code == 0x21
                && bytes.len() == 0x74
                && offset == 0x72
                && bytes[offset..] == [0, 0]
            {
                break;
            }
            return Err(ProtocolParseError::PayloadTooShort {
                context: "LOG SENSE parameter header",
                minimum: PARAMETER_HEADER_LENGTH,
                actual: remaining,
            });
        }
        let code = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let control = bytes[offset + 2];
        let value_length = usize::from(bytes[offset + 3]);
        let record_length = PARAMETER_HEADER_LENGTH + value_length;
        if record_length > remaining {
            return Err(ProtocolParseError::PayloadLengthMismatch {
                context: "LOG SENSE parameter length",
                declared: record_length,
                actual: remaining,
            });
        }
        let value_start = offset + PARAMETER_HEADER_LENGTH;
        let value_end = offset + record_length;
        parameters.push(LogParameter {
            code,
            control,
            value: bytes[value_start..value_end].to_vec(),
            meaning: parameter_meaning(page_code, code),
        });
        offset = value_end;
    }

    Ok(LogPage {
        page_code,
        parameters,
    })
}

/// Validates a parser input against explicit minimum and maximum sizes.
fn ensure_bounded(
    bytes: &[u8],
    context: &'static str,
    minimum: usize,
    maximum: usize,
) -> Result<(), ProtocolParseError> {
    if bytes.len() > maximum {
        return Err(ProtocolParseError::PayloadTooLarge {
            context,
            maximum,
            actual: bytes.len(),
        });
    }
    if bytes.len() < minimum {
        return Err(ProtocolParseError::PayloadTooShort {
            context,
            minimum,
            actual: bytes.len(),
        });
    }
    Ok(())
}

/// Maps only established vendor parameter meanings for a selected page.
const fn parameter_meaning(page_code: u8, code: u16) -> Option<LogParameterMeaning> {
    match (page_code, code) {
        (0x20, 0x0004) => Some(LogParameterMeaning::DriveConnectionType),
        (0x20, 0x0005) => Some(LogParameterMeaning::DriveBusPowerStatus),
        (0x20, 0x0006) => Some(LogParameterMeaning::DriveLinkSpeedsSupported),
        (0x21, 0x000A) => Some(LogParameterMeaning::CartridgeLinkSpeed),
        _ => None,
    }
}
