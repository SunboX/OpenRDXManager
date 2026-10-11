// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Offline migration preparation plus fixed lease-owned raw capture contracts.
//!
//! Preparation, persistence and comparison perform no hardware I/O. The separate
//! capture adapter accepts only a dispatch function from the active lease owner.

pub(crate) mod capture;
pub(crate) mod readback;
pub use readback::MigrationReadback;
mod profile;
mod recovery;
pub use recovery::{MigrationRecoveryInventoryEntry, MigrationRecoverySummary, recovery_inventory};
#[cfg(unix)]
mod storage;
#[cfg(any(target_os = "macos", target_os = "linux", all(unix, test)))]
pub(crate) use storage::manufacturing as manufacturing_backup;
#[cfg(windows)]
#[path = "migration/windows_manufacturing.rs"]
pub(crate) mod manufacturing_backup;
#[cfg(test)]
mod tests;

/// Actual USB-parent identity observed during a single capture lease.
#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationUsbIdentity {
    /// Exact twelve-decimal-digit USB serial.
    pub serial: String,
    /// Nonzero physical location observed on the same USB parent.
    pub location_id: u32,
    /// USB vendor identifier.
    pub vendor_id: u16,
    /// USB product identifier.
    pub product_id: u16,
}

/// Same-lease raw responses, retained without printing opaque unit fields.
#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationCapture {
    /// Independently observed USB-parent properties.
    pub usb: MigrationUsbIdentity,
    /// Standard INQUIRY response.
    pub inquiry: Vec<u8>,
    /// Complete 172-byte factory-info response.
    pub factory: Vec<u8>,
    /// Complete 32-byte USB-identity response.
    pub usb_response: Vec<u8>,
    /// Bounded raw drive LOG SENSE response.
    pub drive_log: Vec<u8>,
    /// Bounded raw MODE SENSE response.
    pub mode_sense: Vec<u8>,
}

/// Fixed diagnostics exclude all captured bytes, serials and storage paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationError {
    /// The captured identity, layout, or state is unsupported or inconsistent.
    InvalidCapture,
    /// The supplied release is not the exact pinned public image.
    InvalidRelease,
    /// The embedded bootstrap or personalized package is inconsistent.
    InvalidBootstrap,
    /// Recovery artifacts could not be durably created or independently verified.
    StorageUnavailable,
    /// The postboot response differs from the saved exposed records.
    ReadbackMismatch,
}

/// The sole service-owned production recovery location.
pub const RECOVERY_ROOT: &str = "/private/var/db/OpenRDXManager/recovery";
/// SHA-256 of the exact unmodified public 1.07 release container.
pub const FINAL_RELEASE_SHA256: &str =
    "1e26a407d5178f1344682798b7ab935f407fe2ce160fb3d03354cf823a951a9e";

impl MigrationError {
    /// Returns a fixed diagnostic, excluding filesystem and device details.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidCapture => "migration-capture-invalid",
            Self::InvalidRelease => "migration-release-invalid",
            Self::InvalidBootstrap => "migration-bootstrap-invalid",
            Self::StorageUnavailable => "migration-private-recovery-unavailable",
            Self::ReadbackMismatch => "migration-readback-mismatch",
        }
    }
}

impl std::fmt::Display for MigrationError {
    /// Formats only the closed diagnostic code.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for MigrationError {}

/// Safely and idempotently provisions the fixed private recovery directory.
///
/// Only a privileged macOS process may create the fixed `OpenRDXManager/recovery`
/// children under the checked root-owned system database directory. Each ancestor
/// is opened without following symlinks; unsafe existing owners/modes are rejected
/// without changing them. New directories use mode 0700 and synced parent entries.
/// No caller may supply a path. Filesystem/platform/privilege failures return the
/// stable [`MigrationError::StorageUnavailable`] code without exposing paths.
pub fn ensure_recovery_root() -> Result<(), MigrationError> {
    #[cfg(target_os = "macos")]
    {
        storage::ensure_fixed_root()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(MigrationError::StorageUnavailable)
    }
}

/// Redacted, point-in-time inspection of one bounded recovery bundle identifier.
///
/// Events are trusted only when all artifacts and the complete journal validate.
/// Integrity is storage consistency, not hardware or executable-content proof.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationRecoveryStatus {
    /// Generated identifier only; never a caller-supplied path or device identity.
    pub bundle_id: String,
    /// Closed milestones, empty whenever integrity could not be established.
    pub events: Vec<MigrationEvent>,
    /// Complete stored evidence passed the pinned offline validation contract.
    pub integrity: bool,
}

/// Inspects the existing fixed privileged root without creating files or hardware.
///
/// Returns at most 64 redacted bundle results. A recognized incomplete bundle is
/// reported with false integrity and no trusted events. Unsafe root ownership,
/// unexpected root entries, excessive inventory or platform/privilege failures
/// return [`MigrationError::StorageUnavailable`]. No records or private hashes
/// are serialized, and no directory is provisioned or permission changed.
pub fn recovery_status() -> Result<Vec<MigrationRecoveryStatus>, MigrationError> {
    #[cfg(target_os = "macos")]
    {
        storage::check_existing_fixed_root()?;
        storage::loader::status(std::path::Path::new(RECOVERY_ROOT), FINAL_RELEASE_SHA256)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(MigrationError::StorageUnavailable)
    }
}

/// Validates captured vendor-0283 identity, layout, raw framing and effective state.
///
/// This performs no I/O and cannot establish capture freshness or physical origin.
/// Returns [`MigrationError::InvalidCapture`] for any unsupported response.
pub fn validate_source_capture(capture: &MigrationCapture) -> Result<(), MigrationError> {
    profile::build_package(capture, b"0283").map(|_| ())
}

/// Requires the exact 62,110-byte published release, without modifying its bytes.
///
/// Returns [`MigrationError::InvalidRelease`] for any other container or revision.
pub fn validate_final_image(image: &[u8]) -> Result<(), MigrationError> {
    if image.len() != 62110 || profile::digest(image) != FINAL_RELEASE_SHA256 {
        return Err(MigrationError::InvalidRelease);
    }
    Ok(())
}

/// Closed milestones; entries never accept caller-provided command or record data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationEvent {
    /// The complete evidence set was synced and independently reopened.
    Prepared,
    /// A new independent attempt copied the receipt-bound original artifacts verbatim.
    RecoveryResumed,
    /// Fresh same-device source identity was checked by the controller.
    SourceRevalidated,
    /// The controller is about to dispatch documented compatibility setup.
    CompatibilitySetupDispatching,
    /// Documented compatibility setup reported its accepted completion status.
    CompatibilitySetupAccepted,
    /// The controller requires the explicit power cycle into the ROM loader.
    AwaitingBootloaderPowerCycle,
    /// The controller requires the explicit power cycle into the bootstrap.
    AwaitingBootstrapPowerCycle,
    /// The controller is about to dispatch its existing source firmware operation.
    SourceTransferDispatching,
    /// The controller observed source firmware operation completion.
    SourceTransferComplete,
    /// The controller is about to request a source reset.
    SourceResetDispatching,
    /// The selected physical location was observed with the expected ROM interfaces.
    RomObserved,
    /// The controller is about to send an erase-capable ROM setup request.
    RomSetupDispatching,
    /// ROM setup was accepted according to the bounded native transport.
    RomSetupAccepted,
    /// The controller is about to start the ROM image transfer.
    RomTransferDispatching,
    /// The full ROM transfer completed; executable-content proof is not implied.
    RomTransferComplete,
    /// The controller is about to request the ROM reset.
    RomResetDispatching,
    /// The native transport reported ROM reset acceptance.
    RomResetAccepted,
    /// Newly supplied bootstrap observations matched the saved exposed records.
    BootstrapReadbackVerified,
    /// The controller started the normal unmodified final release update.
    FinalUpdateStarted,
    /// Every final-release mode04 transfer returned complete SCSI GOOD.
    FinalTransferComplete,
    /// The controller is about to send the final-release mode05 commit once.
    FinalActivationDispatching,
    /// Final-release mode05 returned SCSI GOOD; fresh readback is still required.
    FinalActivationAccepted,
    /// The controller completed its final update and verification flow.
    FinalUpdateVerified,
    /// An uncertain or failed operation requires recovery assessment.
    RecoveryRequired,
}

/// Reopened, immutable recovery material for one exact source identity/location.
///
/// No `Debug` implementation exposes per-unit fields. Successful preparation is
/// neither hardware authorization nor proof of raw SPI or executable contents.
pub struct PreparedMigration {
    capture: MigrationCapture,
    package: [u8; 384],
    bootstrap: Vec<u8>,
    final_image: Vec<u8>,
    directory: std::path::PathBuf,
    #[cfg(unix)]
    store: storage::RecoveryStore,
}

impl PreparedMigration {
    /// Cold-loads the exact saved artifacts from a bounded generated identifier.
    ///
    /// This privileged macOS-only operation uses the existing fixed recovery root;
    /// it never creates, repairs, regenerates or overwrites artifacts. Full receipt,
    /// canonical journal chain, source profile, package, bootstrap and release pins
    /// must validate. The returned instance rejects journal appends to preserve the
    /// original operation evidence. It grants no hardware or changed-port authority.
    /// All cold-load failures return [`MigrationError::StorageUnavailable`].
    pub fn load_existing(bundle_id: &str) -> Result<Self, MigrationError> {
        #[cfg(target_os = "macos")]
        {
            storage::check_existing_fixed_root()?;
            Self::load_inner(
                std::path::Path::new(RECOVERY_ROOT),
                bundle_id,
                FINAL_RELEASE_SHA256,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = bundle_id;
            Err(MigrationError::StorageUnavailable)
        }
    }

    /// Uses identical cold validation with injectable synthetic roots only internally.
    #[cfg(any(target_os = "macos", all(unix, test)))]
    fn load_inner(
        root: &std::path::Path,
        bundle_id: &str,
        release_digest: &str,
    ) -> Result<Self, MigrationError> {
        let (store, artifacts, _) = storage::loader::load(root, bundle_id)?;
        Self::from_store(store, artifacts, release_digest)
    }

    /// Validates, privately persists, fsyncs and independently reopens all artifacts.
    ///
    /// The service supplies [`RECOVERY_ROOT`], safely provisioned through
    /// [`ensure_recovery_root`] after validating the capture and release.
    /// Other roots are rejected; only internal synthetic tests inject temporary
    /// roots. Partial failures remain available for recovery inspection and are
    /// never overwritten. Errors contain no paths or unit bytes. This performs
    /// filesystem I/O only; it never changes or opens hardware.
    pub fn prepare(
        root: &std::path::Path,
        capture: MigrationCapture,
        final_image: &[u8],
    ) -> Result<Self, MigrationError> {
        validate_source_capture(&capture)?;
        validate_final_image(final_image)?;
        if root != std::path::Path::new(RECOVERY_ROOT) {
            return Err(MigrationError::StorageUnavailable);
        }
        ensure_recovery_root()?;
        #[cfg(unix)]
        {
            Self::prepare_inner(root, capture, final_image, FINAL_RELEASE_SHA256)
        }
        #[cfg(not(unix))]
        {
            Err(MigrationError::StorageUnavailable)
        }
    }

    /// Applies the same persistence/readback path to already checked release bytes.
    #[cfg(unix)]
    fn prepare_inner(
        root: &std::path::Path,
        capture: MigrationCapture,
        final_image: &[u8],
        release_digest: &str,
    ) -> Result<Self, MigrationError> {
        let package = profile::build_package(&capture, b"0283")?;
        let bootstrap = profile::personalize(&package)?;
        let artifacts = storage::Artifacts::new(&capture, &package, &bootstrap, final_image)?;
        let (store, reopened) = storage::RecoveryStore::create(root, artifacts)?;
        Self::from_store(store, reopened, release_digest)
    }

    /// Validates derivation while retaining the original independently read bytes.
    #[cfg(unix)]
    fn from_store(
        store: storage::RecoveryStore,
        reopened: storage::Artifacts,
        release_digest: &str,
    ) -> Result<Self, MigrationError> {
        let capture: MigrationCapture = serde_json::from_slice(&reopened.capture)
            .map_err(|_| MigrationError::StorageUnavailable)?;
        let package = profile::build_package(&capture, b"0283")
            .map_err(|_| MigrationError::StorageUnavailable)?;
        let bootstrap =
            profile::personalize(&package).map_err(|_| MigrationError::StorageUnavailable)?;
        if reopened.package != package
            || reopened.bootstrap != bootstrap
            || reopened.final_image.len() != 62110
            || profile::digest(&reopened.final_image) != release_digest
        {
            return Err(MigrationError::StorageUnavailable);
        }
        Ok(Self {
            capture,
            package,
            bootstrap: reopened.bootstrap,
            final_image: reopened.final_image,
            directory: store.directory().to_path_buf(),
            store,
        })
    }

    /// Returns immutable personalized bytes from the verified pinned bootstrap.
    pub fn bootstrap(&self) -> &[u8] {
        &self.bootstrap
    }

    /// Returns immutable raw source evidence; callers must not serialize it to UI.
    pub fn capture(&self) -> &MigrationCapture {
        &self.capture
    }

    /// Returns the exact unmodified final container retained in the recovery store.
    pub fn final_image(&self) -> &[u8] {
        &self.final_image
    }

    /// Returns the private artifact location for privileged recovery references.
    pub fn artifact_directory(&self) -> &std::path::Path {
        &self.directory
    }

    /// Checks a newly captured vendor source against independently reopened evidence.
    ///
    /// The controller obtains the observation immediately before compatibility
    /// setup from the same actual USB parent. This compares supported 0283 layout,
    /// full factory/USB response bytes and reconstructed manufacturing/state fields;
    /// irrelevant raw drive-log fields may change. A saved capture cannot itself
    /// establish freshness. Mismatch returns [`MigrationError::InvalidCapture`];
    /// damaged durable evidence returns [`MigrationError::StorageUnavailable`].
    pub fn verify_source(&self, source: &MigrationCapture) -> Result<(), MigrationError> {
        let package = profile::build_package(source, b"0283")?;
        #[cfg(unix)]
        self.store.reopen()?;
        if source.usb != self.capture.usb
            || source.factory != self.capture.factory
            || source.usb_response != self.capture.usb_response
            || package != self.package
        {
            return Err(MigrationError::InvalidCapture);
        }
        Ok(())
    }

    /// Compares a synthetic revision-0107 semantic profile in offline tests only.
    ///
    /// The real receiver does not implement the vendor READ BUFFER commands. Live
    /// verification must call `verify_records` with the fixed E7 SPI reader.
    /// This helper checks reconstruction properties without claiming wire support.
    /// The pinned receiver enumerates as PID 0005 while its preserved factory USB
    /// record remains PID 0006; serial, vendor and physical location must match.
    /// Returns [`MigrationError::ReadbackMismatch`] on any identity/record mismatch.
    /// Damaged durable evidence returns [`MigrationError::StorageUnavailable`].
    #[cfg(test)]
    #[cfg_attr(not(unix), allow(dead_code))]
    fn verify_readback(&self, readback: &MigrationCapture) -> Result<(), MigrationError> {
        let package = profile::build_package(readback, b"0107")
            .map_err(|_| MigrationError::ReadbackMismatch)?;
        #[cfg(unix)]
        self.store.reopen()?;
        if readback.usb.serial != self.capture.usb.serial
            || readback.usb.location_id != self.capture.usb.location_id
            || readback.usb.vendor_id != self.capture.usb.vendor_id
            || readback.factory != self.capture.factory
            || readback.usb_response != self.capture.usb_response
            || package != self.package
        {
            return Err(MigrationError::ReadbackMismatch);
        }
        Ok(())
    }

    /// Durably appends one fixed event to the separate bounded operation journal.
    ///
    /// Failure closes further appends in this instance and returns
    /// [`MigrationError::StorageUnavailable`]; callers must stop before dispatching
    /// a hardware action whose prerequisite entry could not be saved.
    pub fn journal(&mut self, event: MigrationEvent) -> Result<(), MigrationError> {
        #[cfg(unix)]
        {
            self.store.append(event)
        }
        #[cfg(not(unix))]
        {
            let _ = event;
            Err(MigrationError::StorageUnavailable)
        }
    }
}
