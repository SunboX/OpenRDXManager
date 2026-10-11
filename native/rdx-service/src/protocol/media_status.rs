// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded cartridge identity and temperature decoding supported by the RDX Manager implementation reference.

use super::ProtocolParseError;

const MEDIA_IDENTIFICATION_PAGE: u8 = 0xC0;
const MEDIA_DEVICE_PAGE: u8 = 0xC2;
const TEMPERATURE_PAGE: u8 = 0x0D;
const MAX_MEDIA_IDENTIFICATION_LENGTH: usize = 0xFE;
const MAX_MEDIA_DEVICE_LENGTH: usize = 0x200;
const MAX_TEMPERATURE_LENGTH: usize = 0xFE;

/// Renderer-independent cartridge identity decoded from the original VPD readers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CartridgeIdentity {
    vendor: String,
    model: String,
    serial: String,
    hdd_firmware: String,
}

impl CartridgeIdentity {
    /// Returns the cartridge vendor from variable field four of page `0xC0`.
    #[must_use]
    pub fn vendor(&self) -> &str {
        &self.vendor
    }

    /// Returns the cartridge model from variable field five of page `0xC0`.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Returns the cartridge serial from variable field six of page `0xC0`.
    #[must_use]
    pub fn serial(&self) -> &str {
        &self.serial
    }

    /// Returns the internal HDD firmware revision from page `0xC2`.
    #[must_use]
    pub fn hdd_firmware(&self) -> &str {
        &self.hdd_firmware
    }
}

/// Parses the original Manager's page-`0xC0` variable strings and page-`0xC2`
/// ATA identify-device firmware field.
///
/// # Errors
///
/// Rejects truncated, oversized, inconsistent, wrong-page, non-printable, or
/// incomplete identity evidence.
pub fn parse_cartridge_identity(
    media_identification: &[u8],
    media_device: &[u8],
) -> Result<CartridgeIdentity, ProtocolParseError> {
    validate_vpd(
        media_identification,
        MEDIA_IDENTIFICATION_PAGE,
        5,
        MAX_MEDIA_IDENTIFICATION_LENGTH,
    )?;
    validate_vpd(
        media_device,
        MEDIA_DEVICE_PAGE,
        0x3A,
        MAX_MEDIA_DEVICE_LENGTH,
    )?;

    let fields = parse_nul_fields(&media_identification[5..], 8)?;
    Ok(CartridgeIdentity {
        vendor: parse_text(fields[4], "cartridge vendor")?,
        model: parse_text(fields[5], "cartridge model")?,
        serial: parse_text(fields[6], "cartridge serial")?,
        hdd_firmware: parse_text(&media_device[0x32..0x3A], "HDD firmware")?,
    })
}

/// Parses current cartridge temperature parameter `0x0000` on page `0x0D`.
/// Returns `None` for the standard `0xFF` unavailable-sensor value; zero is valid.
///
/// # Errors
///
/// Rejects malformed framing, missing/duplicate current parameters, or invalid lengths.
pub fn parse_temperature_celsius(bytes: &[u8]) -> Result<Option<u8>, ProtocolParseError> {
    if bytes.len() > MAX_TEMPERATURE_LENGTH {
        return Err(ProtocolParseError::PayloadTooLarge {
            context: "temperature LOG page",
            maximum: MAX_TEMPERATURE_LENGTH,
            actual: bytes.len(),
        });
    }
    if bytes.len() < 10 {
        return Err(ProtocolParseError::PayloadTooShort {
            context: "temperature LOG page",
            minimum: 10,
            actual: bytes.len(),
        });
    }
    if bytes[0] & 0x40 != 0 || bytes[0] & 0x3F != TEMPERATURE_PAGE || bytes[1] != 0 {
        return Err(ProtocolParseError::UnsupportedValue {
            context: "temperature LOG page",
            value: u64::from(bytes[0]),
        });
    }
    let declared = usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) + 4;
    if declared != bytes.len() {
        return Err(ProtocolParseError::PayloadLengthMismatch {
            context: "temperature LOG page length",
            declared,
            actual: bytes.len(),
        });
    }
    let mut offset = 4;
    let mut current = None;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        if remaining.len() < 4 {
            return Err(ProtocolParseError::PayloadTooShort {
                context: "temperature parameter header",
                minimum: 4,
                actual: remaining.len(),
            });
        }
        let code = u16::from_be_bytes([remaining[0], remaining[1]]);
        let length = usize::from(remaining[3]);
        if length + 4 > remaining.len() {
            return Err(ProtocolParseError::PayloadLengthMismatch {
                context: "temperature parameter length",
                declared: length + 4,
                actual: remaining.len(),
            });
        }
        if code == 0 {
            if length != 2 || remaining[4] != 0 || current.is_some() {
                return Err(ProtocolParseError::UnsupportedValue {
                    context: "current temperature parameter",
                    value: u64::from(remaining[3]),
                });
            }
            current = Some(remaining[5]);
        }
        offset += length + 4;
    }
    let value = current.ok_or(ProtocolParseError::UnsupportedValue {
        context: "missing current temperature parameter",
        value: 0,
    })?;
    Ok((value != 0xFF).then_some(value))
}

/// Validates one complete bounded VPD response.
fn validate_vpd(
    bytes: &[u8],
    expected_page: u8,
    minimum: usize,
    maximum: usize,
) -> Result<(), ProtocolParseError> {
    if bytes.len() > maximum {
        return Err(ProtocolParseError::PayloadTooLarge {
            context: "cartridge VPD page",
            maximum,
            actual: bytes.len(),
        });
    }
    if bytes.len() < minimum.max(4) {
        return Err(ProtocolParseError::PayloadTooShort {
            context: "cartridge VPD page",
            minimum: minimum.max(4),
            actual: bytes.len(),
        });
    }
    if bytes[1] != expected_page {
        return Err(ProtocolParseError::UnsupportedValue {
            context: "cartridge VPD page code",
            value: u64::from(bytes[1]),
        });
    }
    let declared = usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) + 4;
    // The C2 command allocates exactly 0x0200 bytes while the device
    // declares a 0x0200-byte payload after its four-byte VPD header. Accept only
    // that exact allocation truncation; every identity field lies before it.
    let exact_c2_allocation_truncation = expected_page == MEDIA_DEVICE_PAGE
        && bytes.len() == MAX_MEDIA_DEVICE_LENGTH
        && declared == MAX_MEDIA_DEVICE_LENGTH + 4;
    if declared != bytes.len() && !exact_c2_allocation_truncation {
        return Err(ProtocolParseError::PayloadLengthMismatch {
            context: "cartridge VPD page length",
            declared,
            actual: bytes.len(),
        });
    }
    Ok(())
}

/// Returns exactly `count` bounded NUL-terminated variable fields.
fn parse_nul_fields(bytes: &[u8], count: usize) -> Result<Vec<&[u8]>, ProtocolParseError> {
    let mut fields = Vec::with_capacity(count);
    let mut remaining = bytes;
    for _ in 0..count {
        let Some(end) = remaining.iter().position(|byte| *byte == 0) else {
            return Err(ProtocolParseError::PayloadTooShort {
                context: "cartridge VPD variable fields",
                minimum: count,
                actual: fields.len(),
            });
        };
        fields.push(&remaining[..end]);
        remaining = &remaining[end + 1..];
    }
    Ok(fields)
}

/// Converts one bounded fixed or variable-width identity field to trimmed ASCII.
fn parse_text(bytes: &[u8], context: &'static str) -> Result<String, ProtocolParseError> {
    if bytes.is_empty() || !bytes.iter().all(|byte| (0x20..=0x7E).contains(byte)) {
        return Err(ProtocolParseError::UnsupportedValue { context, value: 0 });
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ProtocolParseError::UnsupportedValue { context, value: 0 })?
        .trim_end_matches(' ');
    if text.is_empty() || text.starts_with(' ') {
        return Err(ProtocolParseError::UnsupportedValue { context, value: 0 });
    }
    Ok(text.to_owned())
}
