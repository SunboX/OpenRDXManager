// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact, bounded parsing of the RDX discovery identity replies.

use std::error::Error;
use std::fmt::{Display, Formatter};

const STANDARD_MINIMUM_LENGTH: usize = 43;
const DEVICE_IDENTIFICATION_MINIMUM_LENGTH: usize = 42;

/// Sanitized reason one INQUIRY identity pair was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InquiryParseError {
    /// A reply was shorter than the complete identity layout.
    Truncated,
    /// A declared reply length did not equal the actual bounded response.
    InconsistentLength,
    /// A reply was not the exact disk or VPD page requested by discovery.
    WrongPage,
    /// A fixed text field was empty, non-ASCII, or contained control bytes.
    InvalidText,
    /// The standard RDX marker or product enumeration was unsupported.
    UnsupportedProduct,
    /// Standard and device-identification replies described different devices.
    IdentityMismatch,
}

impl InquiryParseError {
    /// Returns a stable path-free rejection code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Truncated => "inquiry-truncated",
            Self::InconsistentLength => "inquiry-length-mismatch",
            Self::WrongPage => "inquiry-wrong-page",
            Self::InvalidText => "inquiry-invalid-text",
            Self::UnsupportedProduct => "unsupported-product",
            Self::IdentityMismatch => "ambiguous-device-identity",
        }
    }
}

impl Display for InquiryParseError {
    /// Formats only the stable sanitized rejection code.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for InquiryParseError {}

/// Complete exact identity and capability bytes required for RDX admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RdxInquiryIdentity {
    vendor: String,
    product: String,
    serial: String,
    revision: String,
    born_on_date: Option<String>,
    product_type: u8,
    oem_type: u8,
    feature_mask_0: u8,
    feature_mask_1: u8,
}

impl RdxInquiryIdentity {
    /// Returns the validated standard/VPD vendor text.
    #[must_use]
    pub fn vendor(&self) -> &str {
        &self.vendor
    }

    /// Returns the validated standard/VPD product text.
    #[must_use]
    pub fn product(&self) -> &str {
        &self.product
    }

    /// Returns the validated fixed-width device serial.
    #[must_use]
    pub fn serial(&self) -> &str {
        &self.serial
    }

    /// Returns the validated four-byte standard INQUIRY revision text.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }

    /// Returns the optional fixed-width manufacturing date from page `0x83`.
    #[must_use]
    pub fn born_on_date(&self) -> Option<&str> {
        self.born_on_date.as_deref()
    }

    /// Returns the exact RDX product enumeration byte.
    #[must_use]
    pub const fn product_type(&self) -> u8 {
        self.product_type
    }

    /// Returns the OEM enumeration from standard INQUIRY byte `0x28`.
    #[must_use]
    pub const fn oem_type(&self) -> u8 {
        self.oem_type
    }

    /// Returns device-support bitmask zero.
    #[must_use]
    pub const fn feature_mask_0(&self) -> u8 {
        self.feature_mask_0
    }

    /// Returns device-support bitmask one.
    #[must_use]
    pub const fn feature_mask_1(&self) -> u8 {
        self.feature_mask_1
    }
}

/// Parses and cross-checks the exact standard and page-`0x83` RDX replies.
///
/// The standard reply must contain the `RDX` marker at offsets
/// `0x25..0x28`, a supported product enumeration at `0x24`, and both feature
/// bytes through `0x2A`. The device-identification reply must repeat the same
/// vendor/product fields and provide the fixed ten-byte dock serial.
///
/// # Errors
///
/// Returns [`InquiryParseError`] for any truncated, contradictory, unsupported,
/// or non-printable identity evidence.
pub fn parse_rdx_inquiry_identity(
    standard: &[u8],
    device_identification: &[u8],
) -> Result<RdxInquiryIdentity, InquiryParseError> {
    if standard.len() < STANDARD_MINIMUM_LENGTH
        || device_identification.len() < DEVICE_IDENTIFICATION_MINIMUM_LENGTH
    {
        return Err(InquiryParseError::Truncated);
    }
    let standard_length = usize::from(standard[4]) + 5;
    let identification_length = usize::from(u16::from_be_bytes([
        device_identification[2],
        device_identification[3],
    ])) + 4;
    if standard_length != standard.len() || identification_length != device_identification.len() {
        return Err(InquiryParseError::InconsistentLength);
    }
    if standard[0] & 0x1F != 0
        || device_identification[0] & 0x1F != 0
        || device_identification[1] != 0x83
    {
        return Err(InquiryParseError::WrongPage);
    }
    if &standard[37..40] != b"RDX" || !supported_product_type(standard[36]) {
        return Err(InquiryParseError::UnsupportedProduct);
    }

    let vendor = parse_fixed_text(&standard[8..16])?;
    let product = parse_fixed_text(&standard[16..32])?;
    let revision = parse_fixed_text(&standard[32..36])?;
    let identification_vendor = parse_fixed_text(&device_identification[8..16])?;
    let identification_product = parse_fixed_text(&device_identification[16..32])?;
    let serial = parse_fixed_text(&device_identification[32..42])?;
    let born_on_date = if device_identification.len() >= 50 {
        Some(parse_fixed_text(&device_identification[42..50])?)
    } else {
        None
    };
    if vendor != identification_vendor || product != identification_product {
        return Err(InquiryParseError::IdentityMismatch);
    }

    Ok(RdxInquiryIdentity {
        vendor,
        product,
        serial,
        revision,
        born_on_date,
        product_type: standard[36],
        oem_type: standard[40],
        feature_mask_0: standard[41],
        feature_mask_1: standard[42],
    })
}

/// Converts one fixed-width device field into trimmed printable ASCII.
fn parse_fixed_text(bytes: &[u8]) -> Result<String, InquiryParseError> {
    if bytes.is_empty() || !bytes.iter().all(|byte| (0x20..=0x7E).contains(byte)) {
        return Err(InquiryParseError::InvalidText);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| InquiryParseError::InvalidText)?;
    let text = text.trim_end_matches(' ');
    if text.is_empty() || text.starts_with(' ') {
        return Err(InquiryParseError::InvalidText);
    }
    Ok(text.to_owned())
}

/// Accepts only product enumerations mapped by the Manager UI.
const fn supported_product_type(product_type: u8) -> bool {
    matches!(product_type, 0..=6 | 0x35..=0x39)
}
