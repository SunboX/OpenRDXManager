// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict portable model types shared by the native service and Electron boundary.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::error::RdxError;
pub use crate::progress::{CancellationState, OperationAttempt};

mod volume_label;
pub use volume_label::VolumeLabel;
mod confirmation;
pub use confirmation::ConfirmationRequest;
mod device;
pub use device::DeviceSnapshot;
mod status;
pub use status::{DriveStatus, DriveStatusDetails, MediaStatusDetails, StatusField};

/// Validates a bounded ASCII identifier without accepting filesystem syntax.
fn valid_identifier(value: &str, maximum_length: usize) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= maximum_length
        && bytes[0].is_ascii_alphabetic()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-'))
}

/// Validates a stable lower-case kebab-case reason or stage code.
fn valid_reason_code(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// Validates a bounded dotted localization key.
fn valid_message_key(value: &str) -> bool {
    value.len() <= 128
        && !value.is_empty()
        && value.split('.').all(|part| {
            let bytes = part.as_bytes();
            !bytes.is_empty()
                && bytes[0].is_ascii_alphabetic()
                && bytes.iter().all(|byte| byte.is_ascii_alphanumeric())
        })
}

/// Validates a bounded opaque identifier for a specific public token type.
fn validate_opaque_identifier(
    value: String,
    maximum_length: usize,
) -> Result<String, &'static str> {
    if !valid_identifier(&value, maximum_length) {
        return Err("opaque ID must be a bounded identifier");
    }
    Ok(value)
}

/// Opaque renderer-safe RDX device identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DeviceId(String);

impl DeviceId {
    /// Creates an opaque device ID after enforcing the `rdx:` namespace and bounds.
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.len() <= 4
            || value.len() > 128
            || !value
                .as_bytes()
                .get(..4)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"rdx:"))
            || !valid_identifier(&value, 128)
        {
            return Err("device ID must be a bounded rdx: identifier");
        }
        Ok(Self(value))
    }

    /// Returns the opaque identifier without exposing any OS path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    /// Deserializes only a valid opaque RDX identifier.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

macro_rules! define_opaque_identifier {
    ($name:ident, $maximum_length:expr, $type_documentation:literal) => {
        #[doc = $type_documentation]
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates a bounded identifier which cannot be a path, command, or arbitrary parameter bag.
            pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
                validate_opaque_identifier(value.into(), $maximum_length).map(Self)
            }

            /// Returns this opaque identifier's safe string representation.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            /// Deserializes only a bounded opaque identifier of this type's maximum length.
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
            }
        }
    };
}

define_opaque_identifier!(
    OpaqueId,
    128,
    "Opaque 128-byte identifier for renderer-safe media metadata."
);
define_opaque_identifier!(
    OperationId,
    64,
    "Opaque 64-byte identifier assigned to one native operation."
);
define_opaque_identifier!(
    CredentialHandle,
    64,
    "Opaque 64-byte handle supplied by the trusted credential flow."
);
define_opaque_identifier!(
    CredentialId,
    64,
    "Opaque 64-byte identifier for a trusted credential selection."
);
define_opaque_identifier!(
    ConfirmationToken,
    64,
    "Opaque 64-byte main-process confirmation token."
);
define_opaque_identifier!(
    FirmwareFileToken,
    64,
    "Opaque 64-byte file-selection token; it never contains a path."
);
define_opaque_identifier!(
    SupportCorrelationId,
    128,
    "Opaque 128-byte correlation ID for sanitized support diagnostics."
);

/// Stable lower-case kebab-case reason, stage, or error code.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ReasonCode(String);

impl ReasonCode {
    /// Creates a bounded lower-case kebab-case value.
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if !valid_reason_code(&value) {
            return Err("reason code must be lower-case kebab-case");
        }
        Ok(Self(value))
    }

    /// Returns the safe stable code.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ReasonCode {
    /// Deserializes only a stable lower-case kebab-case code.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Bounded localization key controlled by trusted application code.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MessageKey(String);

impl MessageKey {
    /// Creates a bounded dotted message key.
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if !valid_message_key(&value) {
            return Err("message key must be a bounded dotted identifier");
        }
        Ok(Self(value))
    }

    /// Returns the trusted localization key.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for MessageKey {
    /// Deserializes only a bounded dotted message key.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Bounded non-empty display text supplied by validated device metadata.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DisplayText(String);

impl DisplayText {
    /// Creates bounded display text without trimming or silently changing device-reported values.
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 || value.trim() != value {
            return Err("display text must be non-empty, bounded, and trimmed");
        }
        Ok(Self(value))
    }

    /// Returns the validated display text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for DisplayText {
    /// Deserializes only bounded non-empty display text.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Non-negative JSON integer guaranteed to fit JavaScript's exact integer range.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SafeJsonInteger(u64);

impl SafeJsonInteger {
    /// Creates a non-negative integer only when JavaScript can represent it exactly.
    pub const fn new(value: u64) -> Result<Self, &'static str> {
        const MAXIMUM_JAVASCRIPT_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

        if value > MAXIMUM_JAVASCRIPT_SAFE_INTEGER {
            return Err("integer exceeds JavaScript's safe integer range");
        }
        Ok(Self(value))
    }

    /// Returns the exact safe integer value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for SafeJsonInteger {
    /// Deserializes only an integer JavaScript can represent without precision loss.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Monotonic discovery revision assigned by the native service.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DiscoveryRevision(SafeJsonInteger);

impl DiscoveryRevision {
    /// Creates a service revision only when it is exactly representable in JavaScript.
    pub const fn new(value: u64) -> Result<Self, &'static str> {
        match SafeJsonInteger::new(value) {
            Ok(value) => Ok(Self(value)),
            Err(error) => Err(error),
        }
    }

    /// Returns the revision's stable numeric value.
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Reports whether this revision advances beyond an earlier device revision.
    pub const fn is_newer_than(self, earlier: Self) -> bool {
        self.get() > earlier.get()
    }
}

/// Stable high-level operation names shared with the JavaScript schemas.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationKind {
    /// Enumerates manageable RDX devices.
    Scan,
    /// Refreshes status for one revisioned device.
    StatusRefresh,
    /// Enables access using an opaque credential handle.
    AccessEnable,
    /// Disables access for one device.
    AccessDisable,
    /// Creates a credential after trusted confirmation.
    CredentialCreate,
    /// Changes a named credential after trusted confirmation.
    CredentialChange,
    /// Deletes a named credential after trusted confirmation.
    CredentialDelete,
    /// Resets credentials after trusted confirmation.
    CredentialReset,
    /// Configures credentials after trusted confirmation.
    CredentialConfigure,
    /// Runs the documented device self-test.
    SelfTest,
    /// Runs the device LED test with cleanup.
    LedTest,
    /// Runs the host-side write/read test.
    WriteReadTest,
    /// Applies a previously selected opaque firmware file token.
    FirmwareUpdate,
    /// Sets a persisted drive letter.
    DriveLetterSet,
    /// Changes the selected cartridge filesystem label.
    VolumeLabelSet,
    /// Clears a persisted drive letter.
    DriveLetterReset,
    /// Formats selected media after trusted confirmation.
    Format,
    /// Changes fixed/removable drive mode.
    DriveModeSet,
    /// Changes the SATA link mode.
    SataModeSet,
    /// Safely ejects media through the host policy.
    EjectSafe,
    /// Force-ejects media after trusted confirmation.
    EjectForce,
}

/// Stable main-process safety class for a high-level operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskClass {
    /// Read-only discovery and status work.
    ReadOnly,
    /// Routine device operations with bounded recovery.
    Routine,
    /// Reversible device or credential configuration.
    Configuration,
    /// Operations requiring critical preflight attention.
    Critical,
    /// Operations that may irreversibly affect media or credentials.
    Destructive,
}

impl OperationKind {
    /// Returns the exact risk class enforced by the JavaScript main-process safety policy.
    pub const fn risk_class(self) -> RiskClass {
        match self {
            Self::Scan | Self::StatusRefresh => RiskClass::ReadOnly,
            Self::AccessEnable
            | Self::AccessDisable
            | Self::SelfTest
            | Self::LedTest
            | Self::WriteReadTest
            | Self::EjectSafe => RiskClass::Routine,
            Self::CredentialCreate
            | Self::CredentialChange
            | Self::CredentialDelete
            | Self::CredentialConfigure
            | Self::VolumeLabelSet
            | Self::DriveLetterSet
            | Self::DriveLetterReset
            | Self::DriveModeSet
            | Self::SataModeSet => RiskClass::Configuration,
            Self::FirmwareUpdate | Self::EjectForce => RiskClass::Critical,
            Self::CredentialReset | Self::Format => RiskClass::Destructive,
        }
    }
}

/// Safe renderer-visible capability state for one published operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityState {
    /// The operation has passed all current prerequisite checks.
    Available,
    /// A conflicting operation currently owns the device.
    Busy,
    /// The device product does not support this operation.
    UnsupportedProduct,
    /// The running platform does not support this operation.
    UnsupportedPlatform,
    /// The present/no-media state prevents this operation.
    WrongMediaState,
    /// A trusted authentication flow must complete first.
    AuthenticationRequired,
    /// The host process lacks the required privilege.
    InsufficientPermission,
    /// A required host capability or dependency is unavailable.
    HostDependencyMissing,
    /// Evidence is insufficient to enable a privileged operation.
    EvidenceIncomplete,
    /// The platform cannot provide a safe raw transport.
    TransportUnavailable,
    /// Fixture-tested behavior has not yet been verified on physical hardware.
    HardwareUnverified,
}

/// One operation's availability and optional stable explanatory reason.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capability {
    /// Current safe availability state.
    pub state: CapabilityState,
    /// Optional stable reason code suitable for renderer display logic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<ReasonCode>,
}

/// Structured identity used by trusted service code to compare device revisions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceIdentity {
    /// Opaque stable RDX device identifier.
    pub id: DeviceId,
    /// Service-owned revision that must advance when device state changes.
    pub revision: DiscoveryRevision,
}

/// Normalized media-presence state safe for the renderer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MediaState {
    /// No cartridge is currently present.
    NoMedia,
    /// A cartridge is currently present.
    Present,
}

/// Renderer-safe cartridge metadata with no mount path or transport handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Media {
    /// Opaque media identifier.
    pub id: OpaqueId,
    /// Optional bounded vendor-reported serial text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<DisplayText>,
    /// Optional bounded user-visible label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<VolumeLabel>,
    /// Optional reported capacity in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity_bytes: Option<SafeJsonInteger>,
    /// Optional reported used capacity in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used_bytes: Option<SafeJsonInteger>,
    /// Optional writable state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writable: Option<bool>,
    /// Optional encryption state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
    /// Optional bounded filesystem display text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<DisplayText>,
    /// Optional safe media status reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ReasonCode>,
    /// Complete documented cartridge fields with explicit availability.
    pub details: MediaStatusDetails,
}

impl Media {
    /// Checks every duplicated legacy field and reported capacity relationship.
    fn has_consistent_status_details(&self) -> bool {
        let details = &self.details;
        let writable_matches = match (self.writable, details.write_protected.reported_value()) {
            (Some(writable), Some(write_protected)) => writable != *write_protected,
            (None, None) => true,
            _ => false,
        };
        let status_matches = match (self.status.as_ref(), details.status.reported_value()) {
            (Some(status), Some(reported)) => {
                reported.as_str().to_ascii_lowercase().replace(' ', "-") == status.as_str()
            }
            (None, None) => true,
            _ => false,
        };
        let capacities_match = match (
            details.capacity_bytes.reported_value(),
            details.used_bytes.reported_value(),
            details.free_bytes.reported_value(),
        ) {
            (Some(capacity), Some(used), Some(free)) => capacity
                .get()
                .checked_sub(used.get())
                .is_some_and(|expected| expected == free.get()),
            _ => true,
        };
        optional_status_field_matches(&self.serial, &details.serial_number)
            && optional_status_field_matches(&self.capacity_bytes, &details.capacity_bytes)
            && optional_status_field_matches(&self.used_bytes, &details.used_bytes)
            && optional_status_field_matches(&self.encrypted, &details.encrypted)
            && writable_matches
            && status_matches
            && capacities_match
    }
}

/// Requires a legacy duplicate exactly when its canonical typed value exists.
fn optional_status_field_matches<T: PartialEq>(legacy: &Option<T>, field: &StatusField<T>) -> bool {
    match (legacy.as_ref(), field.reported_value()) {
        (Some(legacy), Some(reported)) => legacy == reported,
        (None, None) => true,
        _ => false,
    }
}

/// Single uppercase drive letter accepted by the high-level request contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct DriveLetter(char);

impl DriveLetter {
    /// Creates the one uppercase ASCII letter allowed by the JavaScript contract.
    pub fn new(value: char) -> Result<Self, &'static str> {
        if !value.is_ascii_uppercase() {
            return Err("drive letter must be a single uppercase ASCII letter");
        }
        Ok(Self(value))
    }

    /// Returns the validated uppercase drive letter.
    pub const fn get(self) -> char {
        self.0
    }
}

impl<'de> Deserialize<'de> for DriveLetter {
    /// Deserializes only the single uppercase ASCII letter allowed by the contract.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(char::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

mod filesystem;
pub use filesystem::{Filesystem, FormatPassphrase};

/// RDX fixed/removable mode accepted by a high-level request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DriveMode {
    /// Request fixed-disk presentation.
    Fixed,
    /// Request removable-disk presentation.
    Removable,
}

/// SATA link mode accepted by a high-level request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SataMode {
    /// Limits negotiation to the documented 1.5G/3G range.
    #[serde(rename = "1.5g-3g")]
    OnePointFiveGThreeG,
    /// Enables the documented 3G/6G range.
    #[serde(rename = "3g-6g")]
    ThreeGSixG,
}

/// Strict high-level operation request; it deliberately has no CDB, command, or OS-path field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum OperationRequest {
    /// Enumerates known RDX devices without a caller-controlled target.
    Scan,
    /// Refreshes one revisioned device's status.
    StatusRefresh {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
    },
    /// Enables access through an opaque credential handle.
    AccessEnable {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
        /// Opaque credential handle selected by trusted UI flow.
        credential_handle: CredentialHandle,
    },
    /// Disables access for one device.
    AccessDisable {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
    },
    /// Creates a credential after trusted confirmation.
    CredentialCreate {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
        /// Opaque credential handle selected by trusted UI flow.
        credential_handle: CredentialHandle,
        /// Opaque confirmation token generated by the main process.
        confirmation_token: ConfirmationToken,
    },
    /// Changes a credential after trusted confirmation.
    CredentialChange {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
        /// Opaque credential identifier selected by trusted UI flow.
        credential_id: CredentialId,
        /// Opaque credential handle selected by trusted UI flow.
        credential_handle: CredentialHandle,
        /// Opaque confirmation token generated by the main process.
        confirmation_token: ConfirmationToken,
    },
    /// Deletes a credential after trusted confirmation.
    CredentialDelete {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
        /// Opaque credential identifier selected by trusted UI flow.
        credential_id: CredentialId,
        /// Opaque confirmation token generated by the main process.
        confirmation_token: ConfirmationToken,
    },
    /// Resets credentials after trusted confirmation.
    CredentialReset {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
        /// Opaque confirmation token generated by the main process.
        confirmation_token: ConfirmationToken,
    },
    /// Configures credentials after trusted confirmation.
    CredentialConfigure {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
        /// Opaque confirmation token generated by the main process.
        confirmation_token: ConfirmationToken,
    },
    /// Runs the documented self-test.
    SelfTest {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
    },
    /// Runs the LED test with mandatory native cleanup.
    LedTest {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
    },
    /// Runs the host-side write/read test.
    WriteReadTest {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
    },
    /// Applies firmware chosen by an opaque trusted file token.
    FirmwareUpdate {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
        /// Opaque firmware file token; the path remains main-process owned.
        firmware_file_token: FirmwareFileToken,
    },
    /// Sets a drive letter through trusted platform code.
    DriveLetterSet {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
        /// Single uppercase letter selected by trusted UI validation.
        letter: DriveLetter,
    },
    /// Renames the exact selected mounted cartridge without reformatting.
    VolumeLabelSet {
        /// Service-issued dock identity.
        device_id: DeviceId,
        /// Current revision, including the inserted medium binding.
        device_revision: DiscoveryRevision,
        /// Bounded filesystem label; empty clears the name.
        label: VolumeLabel,
    },
    /// Clears a persisted drive letter.
    DriveLetterReset {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
    },
    /// Formats media after a trusted destructive confirmation.
    Format {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
        /// Requested filesystem policy.
        filesystem: Filesystem,
        /// Transient APFS password, redacted in Debug and zeroed on drop.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<FormatPassphrase>,
        /// Opaque confirmation token generated by the main process.
        confirmation_token: ConfirmationToken,
    },
    /// Changes fixed/removable presentation mode.
    DriveModeSet {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
        /// Requested safe mode value.
        mode: DriveMode,
    },
    /// Changes the SATA link mode.
    SataModeSet {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
        /// Requested safe SATA link policy.
        mode: SataMode,
    },
    /// Safely ejects through host policy.
    EjectSafe {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
    },
    /// Force-ejects after a trusted critical confirmation.
    EjectForce {
        /// Opaque service-issued device ID.
        device_id: DeviceId,
        /// Revision to reject stale requests.
        device_revision: DiscoveryRevision,
        /// Opaque confirmation token generated by the main process.
        confirmation_token: ConfirmationToken,
    },
}

/// Bounded operation progress fraction from zero through one.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Progress(f64);

impl Progress {
    /// Creates a finite progress fraction in the inclusive range from zero through one.
    pub fn new(value: f64) -> Result<Self, &'static str> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err("progress must be finite and between zero and one");
        }
        Ok(Self(value))
    }

    /// Returns the validated progress fraction.
    pub const fn get(self) -> f64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Progress {
    /// Deserializes only a finite progress fraction in the inclusive range from zero through one.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(f64::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl fmt::Display for ReasonCode {
    /// Formats a stable safe reason code.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Strict renderer-safe operation lifecycle event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum OperationEvent {
    /// The service accepted the operation but has not started it.
    Queued {
        /// Opaque operation identifier.
        operation_id: OperationId,
        /// High-level operation kind.
        kind: OperationKind,
        /// Opaque target device ID.
        device_id: DeviceId,
        /// Target revision accepted by the service.
        device_revision: DiscoveryRevision,
        /// Stable lifecycle stage.
        stage: ReasonCode,
        /// Optional trusted localization key.
        #[serde(skip_serializing_if = "Option::is_none")]
        message_key: Option<MessageKey>,
    },
    /// The service started the operation.
    Started {
        /// Opaque operation identifier.
        operation_id: OperationId,
        /// High-level operation kind.
        kind: OperationKind,
        /// Opaque target device ID.
        device_id: DeviceId,
        /// Target revision accepted by the service.
        device_revision: DiscoveryRevision,
        /// Stable lifecycle stage.
        stage: ReasonCode,
        /// Optional trusted localization key.
        #[serde(skip_serializing_if = "Option::is_none")]
        message_key: Option<MessageKey>,
    },
    /// The service made bounded observable progress.
    Progress {
        /// Opaque operation identifier.
        operation_id: OperationId,
        /// High-level operation kind.
        kind: OperationKind,
        /// Opaque target device ID.
        device_id: DeviceId,
        /// Target revision accepted by the service.
        device_revision: DiscoveryRevision,
        /// Stable lifecycle stage.
        stage: ReasonCode,
        /// Validated zero-through-one progress fraction.
        progress: Progress,
        /// Optional bounded whole-file firmware transfer attempt substate.
        #[serde(skip_serializing_if = "Option::is_none")]
        attempt: Option<OperationAttempt>,
        /// Exact cancellation availability at this progress boundary.
        cancellation_state: CancellationState,
        /// Optional trusted localization key.
        #[serde(skip_serializing_if = "Option::is_none")]
        message_key: Option<MessageKey>,
    },
    /// The operation completed safely.
    Succeeded {
        /// Opaque operation identifier.
        operation_id: OperationId,
        /// High-level operation kind.
        kind: OperationKind,
        /// Opaque target device ID.
        device_id: DeviceId,
        /// Target revision accepted by the service.
        device_revision: DiscoveryRevision,
        /// Stable lifecycle stage.
        stage: ReasonCode,
        /// Optional trusted localization key.
        #[serde(skip_serializing_if = "Option::is_none")]
        message_key: Option<MessageKey>,
    },
    /// The operation failed with complete safe error details.
    Failed {
        /// Opaque operation identifier.
        operation_id: OperationId,
        /// High-level operation kind.
        kind: OperationKind,
        /// Opaque target device ID.
        device_id: DeviceId,
        /// Target revision accepted by the service.
        device_revision: DiscoveryRevision,
        /// Safe terminal/current lifecycle stage reached after recovery.
        stage: ReasonCode,
        /// Complete structured safe error without raw diagnostics.
        error: RdxError,
    },
    /// The operation stopped at a declared cancellable stage.
    Cancelled {
        /// Opaque operation identifier.
        operation_id: OperationId,
        /// High-level operation kind.
        kind: OperationKind,
        /// Opaque target device ID.
        device_id: DeviceId,
        /// Target revision accepted by the service.
        device_revision: DiscoveryRevision,
        /// Stable lifecycle stage.
        stage: ReasonCode,
        /// Optional stable cancellation reason.
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<ReasonCode>,
        /// Optional trusted localization key.
        #[serde(skip_serializing_if = "Option::is_none")]
        message_key: Option<MessageKey>,
    },
}
