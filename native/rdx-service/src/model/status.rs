// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Complete typed drive and cartridge field availability.

use serde::{Deserialize, Serialize};

use super::{DisplayText, DriveLetter, ReasonCode, SafeJsonInteger};

/// One renderer-safe status value that is either reported or carries a stable
/// explanation for why the current snapshot cannot report it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "availability", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StatusField<T> {
    /// The field was decoded from current bounded evidence.
    Reported {
        /// Current typed value.
        value: T,
    },
    /// The field is unavailable for the explicit stable reason.
    Unavailable {
        /// Path-free reason suitable for renderer and support presentation.
        reason: ReasonCode,
    },
}

impl<T> StatusField<T> {
    /// Wraps one current typed value as reported evidence.
    pub const fn reported(value: T) -> Self {
        Self::Reported { value }
    }

    /// Creates one unavailable value from a validated stable reason.
    pub fn unavailable(reason: &str) -> Self {
        Self::Unavailable {
            reason: ReasonCode::new(reason).expect("static status reason is valid"),
        }
    }

    /// Returns the current reported value, or none for an explicit absence.
    pub const fn reported_value(&self) -> Option<&T> {
        match self {
            Self::Reported { value } => Some(value),
            Self::Unavailable { .. } => None,
        }
    }
}

impl<T> Default for StatusField<T> {
    /// Defaults to an explicit absence instead of silently omitting the field.
    fn default() -> Self {
        Self::unavailable("not-reported")
    }
}

/// Complete documented cartridge status with typed values and per-field
/// unavailable reasons. Arbitrary raw response buffers are never represented.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MediaStatusDetails {
    /// Cartridge vendor.
    pub vendor: StatusField<DisplayText>,
    /// Cartridge model or product name.
    pub model: StatusField<DisplayText>,
    /// Cartridge serial number.
    pub serial_number: StatusField<DisplayText>,
    /// Current cartridge health/status label.
    pub status: StatusField<DisplayText>,
    /// Persistent cartridge load count.
    pub load_count: StatusField<SafeJsonInteger>,
    /// Internal HDD firmware revision.
    pub hdd_firmware: StatusField<DisplayText>,
    /// Cartridge type label.
    pub cartridge_type: StatusField<DisplayText>,
    /// Current write-protection state.
    pub write_protected: StatusField<bool>,
    /// Current temperature in degrees Celsius.
    pub temperature_celsius: StatusField<SafeJsonInteger>,
    /// Total capacity in bytes.
    pub capacity_bytes: StatusField<SafeJsonInteger>,
    /// Used capacity in bytes.
    pub used_bytes: StatusField<SafeJsonInteger>,
    /// Free capacity in bytes.
    pub free_bytes: StatusField<SafeJsonInteger>,
    /// Whether a formatted selected volume is currently mounted.
    pub mounted: StatusField<bool>,
    /// Accumulated bytes read.
    pub bytes_read: StatusField<SafeJsonInteger>,
    /// Accumulated bytes written.
    pub bytes_written: StatusField<SafeJsonInteger>,
    /// Current media-encryption state when proven.
    pub encrypted: StatusField<bool>,
    /// Sanitized support-level status evidence.
    pub support_status: StatusField<ReasonCode>,
    /// Sanitized sense summary, never raw sense bytes.
    pub sense_summary: StatusField<ReasonCode>,
}

/// Complete documented drive status with typed values and per-field
/// unavailable reasons. Unknown semantics remain explicitly absent.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriveStatusDetails {
    /// OEM name distinct from the standard vendor identity.
    pub oem_name: StatusField<DisplayText>,
    /// Standard drive serial number.
    pub serial_number: StatusField<DisplayText>,
    /// Standard product identity.
    pub product: StatusField<DisplayText>,
    /// Standard vendor identity.
    pub vendor: StatusField<DisplayText>,
    /// Standard firmware revision.
    pub firmware_revision: StatusField<DisplayText>,
    /// Optional manufacturing/born-on date.
    pub born_on_date: StatusField<DisplayText>,
    /// Validated product-family label.
    pub product_type: StatusField<DisplayText>,
    /// Validated physical-interface label.
    pub connection_type: StatusField<DisplayText>,
    /// Current operation-mode label.
    pub operation_mode: StatusField<DisplayText>,
    /// Current SATA III maximum-host-speed mode.
    pub sata_mode: StatusField<DisplayText>,
    /// Current drive health/status label.
    pub status: StatusField<DisplayText>,
    /// Persistent load count.
    pub load_count: StatusField<SafeJsonInteger>,
    /// Current drive-error summary.
    pub errors: StatusField<DisplayText>,
    /// Current cam state.
    pub cam_state: StatusField<DisplayText>,
    /// External-drive policy label.
    pub policy: StatusField<DisplayText>,
    /// Current adapter/bus power source.
    pub power_source: StatusField<DisplayText>,
    /// Sanitized support-level status evidence.
    pub support_status: StatusField<ReasonCode>,
    /// Sanitized sense summary, never raw sense bytes.
    pub sense_summary: StatusField<ReasonCode>,
}

/// Renderer-safe drive metadata established by validated protocol evidence.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriveStatus {
    /// Sorted Windows letters proven free for this eligible no-media USB3 dock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_drive_letters: Option<Vec<DriveLetter>>,
    /// Bounded firmware revision reported by standard INQUIRY.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware_revision: Option<DisplayText>,
    /// Bounded product-family label derived from the validated product type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_type: Option<DisplayText>,
    /// Bounded physical-interface label derived from the validated product type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_type: Option<DisplayText>,
    /// Bounded operation-mode label read from MODE page `0x34`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_mode: Option<DisplayText>,
    /// Bounded SATA III maximum-host-speed mode read from MODE page `0x34`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sata_mode: Option<DisplayText>,
    /// Bounded power-source label read from LOG parameter `0x0005`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub power_source: Option<DisplayText>,
    /// Complete status projection used by current hardware discovery.
    pub details: DriveStatusDetails,
}

impl DriveStatus {
    /// Creates a complete identity-only projection for controlled fixtures or
    /// backends that do not supply additional status fields.
    pub fn from_identity(
        vendor: &DisplayText,
        product: &DisplayText,
        serial_number: &DisplayText,
    ) -> Self {
        let details = DriveStatusDetails {
            vendor: StatusField::reported(vendor.clone()),
            product: StatusField::reported(product.clone()),
            serial_number: StatusField::reported(serial_number.clone()),
            ..DriveStatusDetails::default()
        };
        Self {
            details,
            ..Self::default()
        }
    }

    /// Checks every duplicated legacy field against its canonical typed field.
    pub(super) fn has_consistent_legacy_projection(&self) -> bool {
        optional_matches_status(&self.firmware_revision, &self.details.firmware_revision)
            && optional_matches_status(&self.product_type, &self.details.product_type)
            && optional_matches_status(&self.connection_type, &self.details.connection_type)
            && optional_matches_status(&self.operation_mode, &self.details.operation_mode)
            && optional_matches_status(&self.sata_mode, &self.details.sata_mode)
            && optional_matches_status(&self.power_source, &self.details.power_source)
    }
}

/// Requires a legacy duplicate exactly when its canonical typed value exists.
fn optional_matches_status<T: PartialEq>(legacy: &Option<T>, field: &StatusField<T>) -> bool {
    match (legacy.as_ref(), field.reported_value()) {
        (Some(legacy), Some(reported)) => legacy == reported,
        (None, None) => true,
        _ => false,
    }
}
