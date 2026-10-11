// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Renderer-safe projection of proven and unavailable device status fields.

use crate::firmware::ProductFamily;
use crate::host::DeviceInterface;
use crate::model::{
    DisplayText, DriveStatus, DriveStatusDetails, ReasonCode, SafeJsonInteger, StatusField,
};
use crate::protocol::RdxInquiryIdentity;

/// Correlated fields decoded from the single operation-mode response.
pub(super) struct ModeStatusProjection<'a> {
    /// Current Fixed/Removable operation mode when decoded.
    pub(super) operation_mode: Option<&'a str>,
    /// Current SATA link mode when decoded.
    pub(super) sata_mode: Option<&'a str>,
    /// Whether the exact response existed even when a field could not be decoded.
    pub(super) response_available: bool,
}

/// Fields decoded from the drive LOG page `0x20`.
pub(super) struct DriveLogProjection<'a> {
    /// Health label decoded from parameter `0x0000`.
    pub(super) status: Option<&'a str>,
    /// Persistent load count decoded from parameter `0x0001`.
    pub(super) load_count: Option<u32>,
    /// Drive error label decoded from parameter `0x0002`.
    pub(super) errors: Option<&'a str>,
    /// Mechanical cam state decoded from parameter `0x0003`.
    pub(super) cam_state: Option<&'a str>,
    /// Adapter/bus power label decoded from parameter `0x0005`.
    pub(super) power_source: Option<&'a str>,
    /// Whether the exact response existed even if an individual field was absent.
    pub(super) response_available: bool,
}

/// Maps the specified zero/nonzero drive-health contract.
pub(super) const fn drive_status_label(value: u32) -> Option<&'static str> {
    match value {
        0 => Some("Good"),
        1..=u32::MAX => Some("Drive error"),
    }
}

/// Mirrors the original Manager's priority mapping for drive LED/error reasons.
pub(super) const fn drive_error_label(value: u32) -> &'static str {
    if value & 1 != 0 {
        "POST failed"
    } else if value & 2 != 0 {
        "Host link down"
    } else if value & 4 != 0 {
        "Software reset"
    } else if value & 8 != 0 {
        "Eject failed"
    } else if value & 0x10 != 0 {
        "Firmware corrupt"
    } else if value == 0 {
        "None"
    } else {
        "Unknown drive error"
    }
}

/// Maps the specified two-byte cam-home state without accepting other values.
pub(super) const fn cam_state_label(value: u32) -> Option<&'static str> {
    match value {
        0 => Some("Not home"),
        1 => Some("Home"),
        _ => None,
    }
}

/// Maps only the supported bus-power values from LOG parameter `0x0005`.
pub(super) const fn power_source_label(value: u32) -> Option<&'static str> {
    match value {
        0 => Some("Power adapter"),
        1 => Some("USB bus power"),
        _ => None,
    }
}

/// Builds one complete drive projection without inventing unresolved semantics.
pub(super) fn drive_status_projection(
    identity: &RdxInquiryIdentity,
    interface: DeviceInterface,
    product_family: ProductFamily,
    modes: ModeStatusProjection<'_>,
    log: DriveLogProjection<'_>,
) -> DriveStatus {
    let details = DriveStatusDetails {
        oem_name: status_text_from_optional_probe(oem_name(identity.oem_type()), true),
        serial_number: reported_status_text(identity.serial()),
        product: reported_status_text(identity.product()),
        vendor: reported_status_text(identity.vendor()),
        firmware_revision: reported_status_text(identity.revision()),
        born_on_date: status_text_from_optional_probe(identity.born_on_date(), true),
        product_type: reported_status_text(product_family_label(product_family)),
        connection_type: reported_status_text(interface_label(interface)),
        operation_mode: status_text_from_optional_probe(
            modes.operation_mode,
            modes.response_available,
        ),
        sata_mode: status_text_from_optional_probe(modes.sata_mode, modes.response_available),
        status: status_text_from_optional_probe(log.status, log.response_available),
        load_count: status_number_from_optional_probe(log.load_count, log.response_available),
        errors: status_text_from_optional_probe(log.errors, log.response_available),
        cam_state: status_text_from_optional_probe(log.cam_state, log.response_available),
        policy: StatusField::unavailable("field-decoder-unavailable"),
        power_source: status_text_from_optional_probe(log.power_source, log.response_available),
        support_status: if log.response_available {
            StatusField::reported(
                ReasonCode::new("drive-status-page-available")
                    .expect("static support status is valid"),
            )
        } else {
            StatusField::unavailable("status-probe-unavailable")
        },
        sense_summary: StatusField::unavailable("no-safe-sense-available"),
    };
    DriveStatus {
        available_drive_letters: None,
        firmware_revision: display_text(identity.revision()),
        product_type: display_text(product_family_label(product_family)),
        connection_type: display_text(interface_label(interface)),
        operation_mode: modes.operation_mode.and_then(display_text),
        sata_mode: modes.sata_mode.and_then(display_text),
        power_source: log.power_source.and_then(display_text),
        details,
    }
}

/// Converts one optional reported counter into a typed reported status field.
fn status_number_from_optional_probe(
    value: Option<u32>,
    response_available: bool,
) -> StatusField<SafeJsonInteger> {
    value.map_or_else(
        || {
            StatusField::unavailable(if response_available {
                "field-decoder-unavailable"
            } else {
                "status-probe-unavailable"
            })
        },
        |value| {
            StatusField::reported(
                SafeJsonInteger::new(u64::from(value))
                    .expect("a protocol u32 is always a JSON-safe integer"),
            )
        },
    )
}

/// Converts trusted bounded protocol text into renderer-safe text.
fn display_text(value: &str) -> Option<DisplayText> {
    DisplayText::new(value).ok()
}

/// Converts proven bounded text into a typed reported status field.
fn reported_status_text(value: &str) -> StatusField<DisplayText> {
    display_text(value).map_or_else(
        || StatusField::unavailable("field-value-invalid"),
        StatusField::reported,
    )
}

/// Distinguishes a missing probe from an unavailable or invalid field.
fn status_text_from_optional_probe(
    value: Option<&str>,
    response_available: bool,
) -> StatusField<DisplayText> {
    value.map_or_else(
        || {
            StatusField::unavailable(if response_available {
                "field-decoder-unavailable"
            } else {
                "status-probe-unavailable"
            })
        },
        reported_status_text,
    )
}

/// Returns the stable renderer label for a validated product family.
const fn product_family_label(family: ProductFamily) -> &'static str {
    match family {
        ProductFamily::Usb3Sata3 => "USB 3 / SATA III",
        ProductFamily::Usb2Sata1 => "USB 2 / SATA I",
    }
}

/// Returns the stable renderer label for a validated interface family.
const fn interface_label(interface: DeviceInterface) -> &'static str {
    match interface {
        DeviceInterface::Usb3 => "USB 3",
        DeviceInterface::Sata3 => "SATA III",
        DeviceInterface::Legacy => "Legacy USB 2 / SATA I",
    }
}

/// Maps the complete OEM enumeration specified by the Manager reference.
const fn oem_name(value: u8) -> Option<&'static str> {
    match value {
        0 => Some("Unspecified"),
        1 => Some("Dell"),
        2 => Some("Tandberg"),
        3 => Some("Fujitsu"),
        4 => Some("NEC"),
        5 => Some("HPE"),
        6 => Some("IBM"),
        7 => Some("Imation"),
        8 => Some("Quantum"),
        _ => None,
    }
}
