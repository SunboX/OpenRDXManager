// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Platform-neutral command construction with evidence-bounded inputs.

use std::error::Error;
use std::fmt::{Display, Formatter};

mod cdb;
/// Big-endian field encoders shared by exact command builders and parsers.
pub mod endian;
mod inquiry;
mod log_sense;
mod media_status;
mod mode_page;
mod security;
mod sense;

pub use cdb::{
    Command, DEFAULT_TIMEOUT_MS, DataDirection, InquiryPage, MAX_TIMEOUT_MS,
    compatibility_receiver_authorization, compatibility_receiver_header_setup, inquiry, led_test,
    log_sense, mode_select, mode_sense, openrdx_manufacturing_record_first,
    openrdx_manufacturing_record_second, openrdx_manufacturing_restore_capability,
    openrdx_manufacturing_sector_chunk, openrdx_mechanism_diagnostics,
    openrdx_operational_state_record, openrdx_restore_manufacturing, openrdx_serial_capability,
    security_in, security_out, self_test, unit_reset, vendor_0283_factory_info,
    vendor_0283_usb_identity, write_buffer,
};
pub use inquiry::{InquiryParseError, RdxInquiryIdentity, parse_rdx_inquiry_identity};
pub use log_sense::{
    LogPage, LogParameter, LogParameterMeaning, MAX_LOG_PAGE_LENGTH, parse_log_page,
};
pub use media_status::{CartridgeIdentity, parse_cartridge_identity, parse_temperature_celsius};
pub use mode_page::{MAX_MODE_PAGE_LENGTH, RdxFeaturePage};
pub use security::{
    AuthenticationKdfError, AuthenticationKdfParameters, AuthenticationMaterial,
    InboundSecurityDescriptor, MAX_INBOUND_SECURITY_AGGREGATE_LENGTH,
    MAX_INBOUND_SECURITY_DESCRIPTOR_LENGTH, OutboundSecurityDescriptorLayout, SecurityEvidence,
    SecurityOperation, derive_authentication_material, parse_inbound_security_descriptors,
};
pub use sense::{MAX_SENSE_DATA_LENGTH, SenseData};

/// Describes how directly a protocol interpretation is supported by evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceStatus {
    /// The behavior or wire structure is stated in vendor documentation.
    Documented,
    /// Supported by an implementation reference, without implying hardware validation.
    ImplementationReference,
    /// The available evidence is insufficient for a semantic interpretation.
    Incomplete,
}

/// A validation failure while parsing an evidence-bounded protocol payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolParseError {
    /// A payload is too short for its required header or layout.
    PayloadTooShort {
        /// Name of the payload or field being validated.
        context: &'static str,
        /// Smallest accepted byte length.
        minimum: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// A payload exceeds the explicit parser allocation bound.
    PayloadTooLarge {
        /// Name of the payload being validated.
        context: &'static str,
        /// Largest accepted byte length.
        maximum: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// A declared byte count disagrees with the supplied payload.
    PayloadLengthMismatch {
        /// Name of the length relation being validated.
        context: &'static str,
        /// Length declared by the payload.
        declared: usize,
        /// Supplied or remaining byte length.
        actual: usize,
    },
    /// A page, descriptor, format, or field value lacks sufficient evidence.
    UnsupportedValue {
        /// Name of the value being validated.
        context: &'static str,
        /// Unsupported numeric value.
        value: u64,
    },
}

impl Display for ProtocolParseError {
    /// Formats a non-sensitive description of the rejected protocol response.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooShort {
                context,
                minimum,
                actual,
            } => write!(
                formatter,
                "{context} requires at least {minimum} bytes, received {actual}"
            ),
            Self::PayloadTooLarge {
                context,
                maximum,
                actual,
            } => write!(
                formatter,
                "{context} accepts at most {maximum} bytes, received {actual}"
            ),
            Self::PayloadLengthMismatch {
                context,
                declared,
                actual,
            } => write!(
                formatter,
                "{context} declares {declared} bytes but received {actual}"
            ),
            Self::UnsupportedValue { context, value } => {
                write!(formatter, "unsupported {context} value 0x{value:X}")
            }
        }
    }
}

impl Error for ProtocolParseError {}

/// A validation failure while constructing an evidence-bounded command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolBuildError {
    /// Manufacturing restore framing or the desired record checksum is invalid.
    InvalidManufacturingRestorePayload,
    /// Compatibility authorization requires exactly ten printable ASCII serial bytes.
    InvalidCompatibilitySerial,
    /// The requested LOG SENSE page has no exact layout in the selected evidence set.
    UnsupportedLogPage(u8),
    /// The requested MODE page has no exact layout in the selected evidence set.
    UnsupportedModePage(u8),
    /// The MODE page uses the unsupported SPF/subpage header layout.
    UnsupportedModeSubpage(u8),
    /// The requested security selector is not one of the observed bounded selectors.
    UnsupportedSecuritySelector(u16),
    /// A SECURITY PROTOCOL OUT selector is observed, but its payload is not yet bounded.
    SecurityOutEvidenceIncomplete(u16),
    /// The requested WRITE BUFFER mode is not part of the proven modern update path.
    UnsupportedWriteBufferMode(u8),
    /// A payload is too short for its documented header or descriptor.
    PayloadTooShort {
        /// Name of the command field or payload being validated.
        context: &'static str,
        /// Smallest accepted byte length.
        minimum: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// A payload cannot fit in the corresponding CDB length field.
    PayloadTooLarge {
        /// Name of the command field or payload being validated.
        context: &'static str,
        /// Largest accepted byte length.
        maximum: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// A payload header or page length disagrees with the supplied byte count.
    PayloadLengthMismatch {
        /// Name of the length relation being validated.
        context: &'static str,
        /// Length declared by the payload.
        declared: usize,
        /// Actual or remaining byte length.
        actual: usize,
    },
    /// A numeric value cannot fit in its documented protocol field.
    ValueOutOfRange {
        /// Name of the field being encoded.
        field: &'static str,
        /// Supplied value.
        value: u64,
        /// Largest representable value.
        maximum: u64,
    },
    /// A WRITE BUFFER mode and payload presence violate the documented mode contract.
    WriteBufferPayloadMismatch {
        /// Supplied WRITE BUFFER mode.
        mode: u8,
        /// Human-readable expected payload shape.
        expected: &'static str,
        /// Supplied byte length.
        actual: usize,
    },
    /// A transport timeout lies outside the application safety bounds.
    TimeoutOutOfRange {
        /// Supplied timeout in whole milliseconds.
        milliseconds: u32,
    },
}

impl Display for ProtocolBuildError {
    /// Formats a non-sensitive description of the rejected protocol input.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidManufacturingRestorePayload => {
                formatter.write_str("manufacturing restore requires its exact validated payload")
            }
            Self::InvalidCompatibilitySerial => formatter.write_str(
                "compatibility receiver serial must contain exactly ten printable ASCII bytes",
            ),
            Self::UnsupportedLogPage(page) => {
                write!(formatter, "unsupported LOG SENSE page 0x{page:02X}")
            }
            Self::UnsupportedModePage(page) => {
                write!(formatter, "unsupported MODE page 0x{page:02X}")
            }
            Self::UnsupportedModeSubpage(page) => {
                write!(
                    formatter,
                    "unsupported MODE subpage format for page 0x{page:02X}"
                )
            }
            Self::UnsupportedSecuritySelector(selector) => {
                write!(formatter, "unsupported security selector 0x{selector:04X}")
            }
            Self::SecurityOutEvidenceIncomplete(selector) => write!(
                formatter,
                "SECURITY PROTOCOL OUT selector 0x{selector:04X} has no proven bounded descriptor payload"
            ),
            Self::UnsupportedWriteBufferMode(mode) => {
                write!(formatter, "unsupported WRITE BUFFER mode 0x{mode:02X}")
            }
            Self::PayloadTooShort {
                context,
                minimum,
                actual,
            } => write!(
                formatter,
                "{context} requires at least {minimum} bytes but received {actual}"
            ),
            Self::PayloadTooLarge {
                context,
                maximum,
                actual,
            } => write!(
                formatter,
                "{context} accepts at most {maximum} bytes but received {actual}"
            ),
            Self::PayloadLengthMismatch {
                context,
                declared,
                actual,
            } => write!(
                formatter,
                "{context} declares {declared} bytes but received {actual}"
            ),
            Self::ValueOutOfRange {
                field,
                value,
                maximum,
            } => write!(formatter, "{field} value {value} exceeds maximum {maximum}"),
            Self::WriteBufferPayloadMismatch {
                mode,
                expected,
                actual,
            } => write!(
                formatter,
                "WRITE BUFFER mode 0x{mode:02X} requires {expected} but received {actual} bytes"
            ),
            Self::TimeoutOutOfRange { milliseconds } => write!(
                formatter,
                "timeout {milliseconds} ms is outside 1..={MAX_TIMEOUT_MS} ms"
            ),
        }
    }
}

impl Error for ProtocolBuildError {}
