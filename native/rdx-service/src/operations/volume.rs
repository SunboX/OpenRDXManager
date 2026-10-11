// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity-bound host filesystem test and destructive formatting state machines.

use rsa::rand_core::{OsRng, RngCore};

use crate::model::{ConfirmationToken, Filesystem};

/// Maximum payload written by one host filesystem diagnostic.
pub const MAX_WRITE_READ_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_WRITE_READ_BYTES: usize = 64 * 1024;

/// Filesystems whose complete host formatting workflows are documented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileSystem {
    /// Windows NTFS, the documented default on Windows hosts.
    Ntfs,
    /// Cross-platform exFAT quick format.
    ExFat,
    /// Native Linux filesystem personality.
    Linux(Filesystem),
    /// Native macOS format personality.
    MacOs(Filesystem),
}

impl TryFrom<Filesystem> for FileSystem {
    type Error = HostOperationFailure;

    /// Converts closed wire selections while retaining host-specific personalities.
    fn try_from(value: Filesystem) -> Result<Self, Self::Error> {
        Ok(match value {
            Filesystem::Ntfs => Self::Ntfs,
            Filesystem::Exfat => Self::ExFat,
            linux @ (Filesystem::Ext2
            | Filesystem::Ext3
            | Filesystem::Ext4
            | Filesystem::Xfs
            | Filesystem::Btrfs
            | Filesystem::F2fs) => Self::Linux(linux),
            other => Self::MacOs(other),
        })
    }
}

/// Topology classification established from retained native authorities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeTopology {
    /// One unambiguous physical selected RDX disk and its own partitions.
    Simple,
    /// The selected disk participates in host boot, system, or root storage.
    BootOrSystem,
    /// A device-mapper, filter, or other layered parent is involved.
    Layered,
    /// Another physical disk shares one selected volume.
    Shared,
    /// A spanned, striped, mirrored, or multipath volume is involved.
    Spanned,
    /// Complete topology could not be proven.
    Ambiguous,
}

/// Immutable private binding captured from the selected live native authority.
#[derive(Clone, Eq, PartialEq)]
pub struct HostVolumeBinding {
    device_revision: u64,
    device_serial_fingerprint: [u8; 32],
    media_fingerprint: Option<[u8; 32]>,
}

impl HostVolumeBinding {
    /// Creates one service-private exact device, medium, revision, and serial binding.
    #[must_use]
    pub fn new(
        device_revision: u64,
        device_serial_fingerprint: [u8; 32],
        media_fingerprint: Option<[u8; 32]>,
    ) -> Self {
        Self {
            device_revision,
            device_serial_fingerprint,
            media_fingerprint,
        }
    }

    /// Issues one bounded opaque token for this exact service-owned binding.
    pub(crate) fn issue_confirmation_token(&self) -> ConfirmationToken {
        use sha2::{Digest, Sha256};

        let mut digest = Sha256::new();
        digest.update(b"OpenRDXManager/destructive-confirmation/v1\0");
        digest.update(self.device_revision.to_be_bytes());
        digest.update(self.device_serial_fingerprint);
        match self.media_fingerprint {
            Some(media) => {
                digest.update([1]);
                digest.update(media);
            }
            None => digest.update([0]),
        }
        let digest = digest.finalize();
        let encoded = digest[..28]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        ConfirmationToken::new(format!("confirm:{encoded}"))
            .expect("service-issued confirmation is exactly 64 safe bytes")
    }

    /// Validates one opaque token against every exact private binding field.
    pub(crate) fn matches_confirmation(&self, confirmation: &ConfirmationToken) -> bool {
        &self.issue_confirmation_token() == confirmation
    }

    /// Returns a stable lowercase hexadecimal key derived only from validated dock serial.
    pub(crate) fn serial_mapping_key(&self) -> String {
        self.device_serial_fingerprint
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Returns the private current-media fingerprint for same-service validation.
    pub(crate) const fn media_fingerprint(&self) -> Option<[u8; 32]> {
        self.media_fingerprint
    }
}

impl std::fmt::Debug for HostVolumeBinding {
    /// Redacts private device, media, revision, and serial binding evidence.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HostVolumeBinding(<private>)")
    }
}

/// Fresh path-free volume facts derived through the retained authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostVolumeFacts {
    /// Whether an exact cartridge remains inserted.
    pub media_present: bool,
    /// Whether the exact cartridge is writable under host and RDX policy.
    pub writable: bool,
    /// Whether a formatted selected volume is currently mounted.
    pub mounted: bool,
    /// Free bytes proven for the selected mounted filesystem.
    pub free_bytes: u64,
    /// Exact cartridge capacity when known.
    pub capacity_bytes: u64,
    /// Mounted filesystem reported by the host when recognized.
    pub filesystem: Option<FileSystem>,
    /// Complete fail-closed topology classification.
    pub topology: VolumeTopology,
    /// Opaque digest of current authoritative media descriptors, absent with no cartridge.
    pub media_fingerprint: Option<[u8; 32]>,
}

/// Mutation certainty retained across cancellation, timeout, and native errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationCertainty {
    /// No mutation API was invoked.
    NotAttempted,
    /// A native API definitely rejected the requested mutation.
    DefinitelyRejected,
    /// A native API was invoked but completion could not be proven.
    CompletionUnknown,
}

impl MutationCertainty {
    /// Returns the stable renderer-safe certainty code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAttempted => "not-attempted",
            Self::DefinitelyRejected => "definitely-rejected",
            Self::CompletionUnknown => "completion-unknown",
        }
    }
}

/// Cleanup evidence recorded independently from the primary diagnostic result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupState {
    /// No cleanup was required or the exact app-owned file was removed.
    Complete,
    /// Cleanup was definitely rejected and the app-owned file may remain.
    DefinitelyRejected,
    /// Cleanup was attempted but its result cannot be proven.
    CompletionUnknown,
}

impl CleanupState {
    /// Returns the stable renderer-safe cleanup code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::DefinitelyRejected => "definitely-rejected",
            Self::CompletionUnknown => "completion-unknown",
        }
    }
}

/// Sanitized host primitive cause with no native path or command text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostPrimitiveError {
    /// Exact identity, medium, revision, or retained authority changed.
    StaleBinding,
    /// Required media is absent.
    MediaMissing,
    /// Drive-letter configuration requires the cartridge to be ejected.
    MediaPresent,
    /// The cartridge or authenticated session is read-only.
    ReadOnly,
    /// The selected volume is not mounted and formatted.
    NotMounted,
    /// The selected filesystem has insufficient free space.
    InsufficientSpace,
    /// A required bounded host dependency is unavailable.
    DependencyMissing,
    /// Open handles or host policy prevented the action.
    Busy,
    /// The topology is unsafe or incomplete.
    UnsafeTopology,
    /// The supplied confirmation does not match the exact current binding.
    ConfirmationRequired,
    /// A requested drive letter is already owned elsewhere.
    DriveLetterInUse,
    /// A drive-letter preference is not owned by this application and binding.
    MappingNotOwned,
    /// The selected platform does not implement this semantic operation.
    UnsupportedPlatform,
    /// This Manager has no supported OpenRDX installation route for the reported receiver.
    OpenRdxInstallationUnsupported,
    /// The selected dock did not return a complete supported factory capture.
    MigrationCaptureInvalid,
    /// The native controller could not persist or revalidate recovery material.
    MigrationRecoveryUnavailable,
    /// Compatibility staging did not complete with the documented late result.
    MigrationStagingFailed,
    /// The exact ROM loader did not become available after the requested power cycle.
    MigrationBootloaderUnavailable,
    /// The ROM bootstrap transfer or its reset could not be confirmed complete.
    MigrationProgrammingFailed,
    /// Fresh restored identity or state differs from the saved observations.
    MigrationReadbackMismatch,
    /// Exact raw manufacturing data could not be read through the selected lease.
    ManufacturingUnreadable,
    /// Manufacturing data is erased or fails its original four-lane checksum.
    ManufacturingInvalid,
    /// Manufacturing bytes changed after the pre-update capture.
    ManufacturingChanged,
    /// A complete owner-private pre-update backup could not be durably verified.
    ManufacturingBackupUnavailable,
    /// The installed firmware does not implement full-record restoration.
    ManufacturingRestoreUnsupported,
    /// A restore may have changed flash but complete exact readback is unproven.
    ManufacturingRestoreUnknown,
    /// Exact readback bytes did not match the generated payload.
    DataMismatch,
    /// A bounded native operation was cancelled before dispatch.
    Cancelled,
    /// A bounded native operation timed out.
    TimedOut,
    /// Firmware data-out completed without the full requested byte count.
    FirmwareTransferIncomplete,
    /// The dock rejected a firmware command with a parsed device status.
    FirmwareDeviceRejected,
    /// The dock does not implement the requested firmware command opcode.
    FirmwareCommandUnsupported,
    /// The dock rejected the firmware command fields as invalid.
    FirmwareCommandInvalid,
    /// Read-only receiver checks found a verified manufacturing-write reboot interlock.
    FirmwarePowerCycleRequired,
    /// Read-only receiver readiness could not be established before any update write.
    FirmwareReceiverReadinessUnknown,
    /// The dock was not ready to accept the firmware command.
    FirmwareDeviceNotReady,
    /// The dock reported an internal hardware error during firmware transfer.
    FirmwareHardwareFailure,
    /// The dock's data-protection policy rejected the firmware write.
    FirmwareWriteProtected,
    /// The dock repeatedly reported a state change during firmware transfer.
    FirmwareUnitAttention,
    /// The firmware transport could not provide a valid device completion.
    FirmwareTransportUnavailable,
    /// The firmware transport returned structurally contradictory evidence.
    FirmwareTransportInvalid,
    /// The same dock could not be rebound and verified after firmware activation.
    FirmwareReconnectFailed,
    /// The receiver rejected the firmware authentication signature.
    FirmwareSignatureRejected,
    /// Another sanitized host failure occurred.
    Other,
}

impl HostPrimitiveError {
    /// Returns a stable renderer-safe error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StaleBinding => "stale-device-revision",
            Self::MediaMissing => "media-required",
            Self::MediaPresent => "media-must-be-ejected",
            Self::ReadOnly => "media-read-only",
            Self::NotMounted => "volume-not-mounted",
            Self::InsufficientSpace => "insufficient-space",
            Self::DependencyMissing => "host-dependency-missing",
            Self::Busy => "volume-busy",
            Self::UnsafeTopology => "unsafe-volume-topology",
            Self::ConfirmationRequired => "confirmation-required",
            Self::DriveLetterInUse => "drive-letter-in-use",
            Self::MappingNotOwned => "mapping-not-owned",
            Self::UnsupportedPlatform => "unsupported-platform",
            Self::OpenRdxInstallationUnsupported => "firmware-openrdx-installation-unsupported",
            Self::MigrationCaptureInvalid => "firmware-migration-capture-invalid",
            Self::MigrationRecoveryUnavailable => "firmware-migration-recovery-unavailable",
            Self::MigrationStagingFailed => "firmware-migration-staging-failed",
            Self::MigrationBootloaderUnavailable => "firmware-migration-bootloader-unavailable",
            Self::MigrationProgrammingFailed => "firmware-migration-programming-failed",
            Self::MigrationReadbackMismatch => "firmware-migration-readback-mismatch",
            Self::ManufacturingUnreadable => "firmware-manufacturing-unreadable",
            Self::ManufacturingInvalid => "firmware-manufacturing-invalid",
            Self::ManufacturingChanged => "firmware-manufacturing-changed",
            Self::ManufacturingBackupUnavailable => "firmware-manufacturing-backup-unavailable",
            Self::ManufacturingRestoreUnsupported => "firmware-manufacturing-restore-unsupported",
            Self::ManufacturingRestoreUnknown => "manufacturing-outcome-unknown",
            Self::DataMismatch => "data-mismatch",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "operation-timeout",
            Self::FirmwareTransferIncomplete => "firmware-transfer-incomplete",
            Self::FirmwareDeviceRejected => "firmware-device-rejected",
            Self::FirmwareCommandUnsupported => "firmware-command-unsupported",
            Self::FirmwareCommandInvalid => "firmware-command-invalid",
            Self::FirmwarePowerCycleRequired => "firmware-power-cycle-required",
            Self::FirmwareReceiverReadinessUnknown => "firmware-receiver-readiness-unknown",
            Self::FirmwareDeviceNotReady => "firmware-device-not-ready",
            Self::FirmwareHardwareFailure => "firmware-hardware-failure",
            Self::FirmwareWriteProtected => "firmware-write-protected",
            Self::FirmwareUnitAttention => "firmware-unit-attention",
            Self::FirmwareTransportUnavailable => "firmware-transport-unavailable",
            Self::FirmwareTransportInvalid => "firmware-transport-invalid",
            Self::FirmwareReconnectFailed => "firmware-reconnect-failed",
            Self::FirmwareSignatureRejected => "firmware-signature-error",
            Self::Other => "host-operation-failed",
        }
    }
}

/// One native primitive failure with explicit dispatch certainty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimitiveFailure {
    /// Sanitized cause.
    pub error: HostPrimitiveError,
    /// Whether the native mutation may have begun.
    pub certainty: MutationCertainty,
}

impl PrimitiveFailure {
    /// Creates a failure known to precede native mutation dispatch.
    #[must_use]
    pub const fn not_attempted(error: HostPrimitiveError) -> Self {
        Self {
            error,
            certainty: MutationCertainty::NotAttempted,
        }
    }

    /// Creates a completed native rejection.
    #[must_use]
    pub const fn definitely_rejected(error: HostPrimitiveError) -> Self {
        Self {
            error,
            certainty: MutationCertainty::DefinitelyRejected,
        }
    }

    /// Creates a post-dispatch failure whose completion is unknown.
    #[must_use]
    pub const fn completion_unknown(error: HostPrimitiveError) -> Self {
        Self {
            error,
            certainty: MutationCertainty::CompletionUnknown,
        }
    }
}

/// Closed write/read primitive result including cleanup evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteReadPrimitiveResult {
    /// Exact bytes read after close/reopen or the primary file-operation failure.
    pub operation: Result<Vec<u8>, PrimitiveFailure>,
    /// Independent exact-file cleanup result.
    pub cleanup: Result<(), PrimitiveFailure>,
}

/// Closed mutation surface implemented only by service-owned platform handles.
pub trait HostOperations {
    /// Changes a label through the same retained device and medium binding.
    fn set_volume_label_exact(
        &mut self,
        _expected: &HostVolumeBinding,
        _label: &crate::model::VolumeLabel,
    ) -> Result<(), PrimitiveFailure> {
        Err(PrimitiveFailure::not_attempted(
            HostPrimitiveError::UnsupportedPlatform,
        ))
    }

    /// Captures the exact selected device, medium, revision, and serial authority.
    fn binding(&self) -> HostVolumeBinding;

    /// Revalidates exact retained authority and returns fresh path-free facts.
    fn revalidate(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<HostVolumeFacts, PrimitiveFailure>;

    /// Revalidates format-only topology; other operations retain ordinary authority.
    fn revalidate_format(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<HostVolumeFacts, PrimitiveFailure> {
        self.revalidate(expected)
    }

    /// Validates a one-shot token against this exact device/medium/revision binding.
    fn confirmation_matches(
        &self,
        expected: &HostVolumeBinding,
        confirmation: &ConfirmationToken,
    ) -> bool {
        expected.matches_confirmation(confirmation)
    }

    /// Proves the exact selected device departed after a successful eject dispatch.
    fn verify_eject_departure(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<(), PrimitiveFailure>;

    /// Proves authoritative new single-volume filesystem state after layout mutation.
    fn verify_format_rediscovery(
        &mut self,
        expected: &HostVolumeBinding,
        filesystem: FileSystem,
        previous_capacity: u64,
    ) -> Result<(), PrimitiveFailure>;

    /// Checks all tooling and filesystem support before any unmount or mutation.
    fn preflight_format(
        &mut self,
        expected: &HostVolumeBinding,
        filesystem: FileSystem,
    ) -> Result<(), PrimitiveFailure>;

    /// Runs closed create-new/no-follow/write/fsync/close/reopen/read/delete semantics.
    fn write_read_file(
        &mut self,
        expected: &HostVolumeBinding,
        filename: &str,
        bytes: &[u8],
    ) -> Result<WriteReadPrimitiveResult, PrimitiveFailure>;

    /// Flushes and unmounts every exact selected volume without force fallback.
    fn unmount_exact_volumes(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<(), PrimitiveFailure>;

    /// Flushes/unmounts and then ejects while retaining exact mutation authority.
    /// The callback is invoked only after every exact unmount succeeds and
    /// immediately before physical eject dispatch.
    fn safe_eject_exact(
        &mut self,
        expected: &HostVolumeBinding,
        after_unmount: &mut dyn FnMut() -> bool,
    ) -> Result<(), PrimitiveFailure>;

    /// Requests the exact normal host/mechanical eject primitive.
    fn eject_exact(
        &mut self,
        expected: &HostVolumeBinding,
        force: bool,
    ) -> Result<(), PrimitiveFailure>;

    /// Applies one simple supported partition layout with a nonzero MBR signature.
    fn create_single_partition(
        &mut self,
        expected: &HostVolumeBinding,
        mbr_signature: u32,
    ) -> Result<(), PrimitiveFailure>;

    /// Formats the newly created exact partition through the selected host filesystem API.
    fn format_partition(
        &mut self,
        expected: &HostVolumeBinding,
        filesystem: FileSystem,
    ) -> Result<(), PrimitiveFailure>;

    /// Invalidates the live session after any attempted layout mutation.
    fn invalidate_for_rediscovery(&mut self);

    /// Sets one collision-free serial-specific Windows preference.
    fn set_drive_letter_exact(
        &mut self,
        expected: &HostVolumeBinding,
        letter: char,
    ) -> Result<(), PrimitiveFailure>;

    /// Removes only the current application-owned serial-specific preference.
    fn reset_drive_letter_exact(
        &mut self,
        expected: &HostVolumeBinding,
    ) -> Result<(), PrimitiveFailure>;
}

/// Sanitized shared failure from one host operation state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostOperationFailure {
    code: &'static str,
    stage: &'static str,
    certainty: MutationCertainty,
    cleanup: CleanupState,
}

impl HostOperationFailure {
    /// Creates one shared failure from a native primitive boundary.
    #[must_use]
    pub const fn from_primitive(stage: &'static str, failure: PrimitiveFailure) -> Self {
        Self {
            code: failure.error.code(),
            stage,
            certainty: failure.certainty,
            cleanup: CleanupState::Complete,
        }
    }

    /// Creates one preflight rejection before any native mutation.
    #[must_use]
    pub const fn preflight(stage: &'static str, error: HostPrimitiveError) -> Self {
        Self::from_primitive(stage, PrimitiveFailure::not_attempted(error))
    }

    /// Attaches independent cleanup evidence without replacing the primary cause.
    #[must_use]
    pub const fn with_cleanup(mut self, cleanup: CleanupState) -> Self {
        self.cleanup = cleanup;
        self
    }

    /// Returns the stable renderer-safe cause code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the stable stage at which the operation stopped.
    #[must_use]
    pub const fn stage(&self) -> &'static str {
        self.stage
    }

    /// Returns explicit native dispatch certainty.
    #[must_use]
    pub const fn certainty(&self) -> MutationCertainty {
        self.certainty
    }

    /// Returns independent temporary-file cleanup evidence.
    #[must_use]
    pub const fn cleanup(&self) -> CleanupState {
        self.cleanup
    }
}

/// Successful host filesystem diagnostic evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteReadTestResult {
    bytes_tested: usize,
}

impl WriteReadTestResult {
    /// Returns the exact bounded payload length compared successfully.
    #[must_use]
    pub const fn bytes_tested(self) -> usize {
        self.bytes_tested
    }
}

/// Successful destructive format evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormatResult {
    rediscovery_required: bool,
}

/// Service-private observer for causal host stages and safe cancellation gates.
pub(crate) trait HostOperationObserver {
    /// Reports an actually entered stage and returns false only when cancellation won.
    fn reached(&mut self, stage: &'static str, cancellable: bool) -> bool;

    /// Emits one fixed internal diagnostic boundary without changing operation state.
    fn diagnostic(&mut self, _code: &'static str) {}
}

/// Observer used by direct callers that do not expose asynchronous cancellation.
struct UnobservedHostOperation;

impl HostOperationObserver for UnobservedHostOperation {
    /// Always permits the synchronous public wrapper to continue.
    fn reached(&mut self, _stage: &'static str, _cancellable: bool) -> bool {
        true
    }
}

impl FormatResult {
    /// Reports that every prior volume/session object is invalid after layout mutation.
    #[must_use]
    pub const fn rediscovery_required(self) -> bool {
        self.rediscovery_required
    }
}

/// Runs a complete bounded host filesystem write, flush, reopen, compare, and cleanup test.
///
/// # Errors
///
/// Rejects stale, absent, unmounted, read-only, unsafe, or space-constrained media and
/// preserves exact cleanup certainty for failures after file creation.
pub fn run_write_read_test(
    host: &mut impl HostOperations,
) -> Result<WriteReadTestResult, HostOperationFailure> {
    run_write_read_test_observed(host, &mut UnobservedHostOperation)
}

/// Runs the write/read test while exposing only actual safe stage boundaries.
pub(crate) fn run_write_read_test_observed(
    host: &mut impl HostOperations,
    observer: &mut impl HostOperationObserver,
) -> Result<WriteReadTestResult, HostOperationFailure> {
    require_stage(observer, "host-writing", true)?;
    let binding = host.binding();
    let facts = fresh_safe_facts(host, &binding, "preflight", false)?;
    if !facts.mounted {
        return Err(HostOperationFailure::preflight(
            "preflight",
            HostPrimitiveError::NotMounted,
        ));
    }
    if facts.free_bytes < DEFAULT_WRITE_READ_BYTES as u64 {
        return Err(HostOperationFailure::preflight(
            "preflight",
            HostPrimitiveError::InsufficientSpace,
        ));
    }
    require_stage(observer, "host-writing", false)?;
    let (filename, expected) = random_test_material(DEFAULT_WRITE_READ_BYTES);
    let result = host
        .write_read_file(&binding, &filename, &expected)
        .map_err(|failure| HostOperationFailure::from_primitive("write-read", failure))?;
    require_stage(observer, "host-reading", false)?;
    let cleanup = cleanup_state(&result.cleanup);
    require_stage(observer, "host-cleanup", false)?;
    let readback = result.operation.map_err(|failure| {
        HostOperationFailure::from_primitive("write-read", failure).with_cleanup(cleanup)
    })?;
    if readback != expected {
        return Err(
            HostOperationFailure::preflight("compare", HostPrimitiveError::DataMismatch)
                .with_cleanup(cleanup),
        );
    }
    if cleanup != CleanupState::Complete {
        return Err(HostOperationFailure {
            code: "cleanup-incomplete",
            stage: "cleanup",
            certainty: MutationCertainty::CompletionUnknown,
            cleanup,
        });
    }
    Ok(WriteReadTestResult {
        bytes_tested: expected.len(),
    })
}

/// Repartitions and formats one exact disposable cartridge after all fail-closed gates.
///
/// # Errors
///
/// Rejects missing dependencies, unsafe topology, invalid confirmation, unmount
/// failure, or any layout/format uncertainty. Once layout dispatch begins the
/// live session is always invalidated and callers must rediscover.
pub fn partition_and_format(
    host: &mut impl HostOperations,
    filesystem: FileSystem,
    confirmation: &ConfirmationToken,
) -> Result<FormatResult, HostOperationFailure> {
    partition_and_format_observed(host, filesystem, confirmation, &mut UnobservedHostOperation)
}

/// Formats while exposing pre-layout cancellation and actual mutation stages.
pub(crate) fn partition_and_format_observed(
    host: &mut impl HostOperations,
    filesystem: FileSystem,
    confirmation: &ConfirmationToken,
    observer: &mut impl HostOperationObserver,
) -> Result<FormatResult, HostOperationFailure> {
    require_stage(observer, "format-validating", true)?;
    let binding = host.binding();
    require_confirmation(host, &binding, confirmation)?;
    let facts = fresh_format_facts(host, &binding, "preflight")?;
    if facts.capacity_bytes == 0 {
        return Err(HostOperationFailure::preflight(
            "preflight",
            HostPrimitiveError::UnsafeTopology,
        ));
    }
    host.preflight_format(&binding, filesystem)
        .map_err(|failure| HostOperationFailure::from_primitive("preflight", failure))?;
    fresh_format_facts(host, &binding, "unmount")?;
    host.unmount_exact_volumes(&binding)
        .map_err(|failure| HostOperationFailure::from_primitive("unmount", failure))?;
    // Cancellation remains safe after exact unmount but before the first layout write.
    require_stage(observer, "format-validating", true)?;
    fresh_format_facts(host, &binding, "layout")?;
    // This mutex-linearized transition closes cancellation before irreversible dispatch.
    require_stage(observer, "format-writing", false)?;

    let signature = random_nonzero_u32();
    if let Err(failure) = host.create_single_partition(&binding, signature) {
        host.invalidate_for_rediscovery();
        return Err(HostOperationFailure::from_primitive("layout", failure));
    }
    require_stage(observer, "format-finalizing", false)?;
    if let Err(failure) = host.format_partition(&binding, filesystem) {
        host.invalidate_for_rediscovery();
        return Err(HostOperationFailure::from_primitive(
            "format",
            floor_after_layout(failure),
        ));
    }
    require_stage(observer, "format-readback", false)?;
    if let Err(failure) = host.verify_format_rediscovery(&binding, filesystem, facts.capacity_bytes)
    {
        host.invalidate_for_rediscovery();
        return Err(HostOperationFailure::from_primitive(
            "rediscovery",
            floor_after_layout(failure),
        ));
    }
    host.invalidate_for_rediscovery();
    Ok(FormatResult {
        rediscovery_required: true,
    })
}

/// Converts one observer cancellation decision into a pre-dispatch host failure.
fn require_stage(
    observer: &mut impl HostOperationObserver,
    stage: &'static str,
    cancellable: bool,
) -> Result<(), HostOperationFailure> {
    if observer.reached(stage, cancellable) {
        Ok(())
    } else {
        Err(HostOperationFailure::preflight(
            stage,
            HostPrimitiveError::Cancelled,
        ))
    }
}

/// Floors every failure after successful layout dispatch to completion uncertainty.
fn floor_after_layout(failure: PrimitiveFailure) -> PrimitiveFailure {
    PrimitiveFailure::completion_unknown(failure.error)
}

/// Validates an exact one-shot confirmation against the retained binding.
pub(crate) fn require_confirmation(
    host: &impl HostOperations,
    binding: &HostVolumeBinding,
    confirmation: &ConfirmationToken,
) -> Result<(), HostOperationFailure> {
    if host.confirmation_matches(binding, confirmation) {
        Ok(())
    } else {
        Err(HostOperationFailure::preflight(
            "confirmation",
            HostPrimitiveError::ConfirmationRequired,
        ))
    }
}

/// Revalidates and applies common media, write, and topology gates.
pub(crate) fn fresh_safe_facts(
    host: &mut impl HostOperations,
    binding: &HostVolumeBinding,
    stage: &'static str,
    allow_unmounted: bool,
) -> Result<HostVolumeFacts, HostOperationFailure> {
    let facts = host
        .revalidate(binding)
        .map_err(|failure| HostOperationFailure::from_primitive(stage, failure))?;
    validate_safe_facts(facts, stage, allow_unmounted)
}

/// Applies the same safety gates using only the format-specific native proof.
fn fresh_format_facts(
    host: &mut impl HostOperations,
    binding: &HostVolumeBinding,
    stage: &'static str,
) -> Result<HostVolumeFacts, HostOperationFailure> {
    let facts = host
        .revalidate_format(binding)
        .map_err(|failure| HostOperationFailure::from_primitive(stage, failure))?;
    validate_safe_facts(facts, stage, true)
}

/// Rejects absent, read-only, unmounted or non-simple host evidence before mutation.
fn validate_safe_facts(
    facts: HostVolumeFacts,
    stage: &'static str,
    allow_unmounted: bool,
) -> Result<HostVolumeFacts, HostOperationFailure> {
    if !facts.media_present {
        return Err(HostOperationFailure::preflight(
            stage,
            HostPrimitiveError::MediaMissing,
        ));
    }
    if !facts.writable {
        return Err(HostOperationFailure::preflight(
            stage,
            HostPrimitiveError::ReadOnly,
        ));
    }
    if !allow_unmounted && !facts.mounted {
        return Err(HostOperationFailure::preflight(
            stage,
            HostPrimitiveError::NotMounted,
        ));
    }
    if facts.topology != VolumeTopology::Simple {
        return Err(HostOperationFailure::preflight(
            stage,
            HostPrimitiveError::UnsafeTopology,
        ));
    }
    Ok(facts)
}

/// Maps an exact-file cleanup primitive into shared evidence.
fn cleanup_state(cleanup: &Result<(), PrimitiveFailure>) -> CleanupState {
    match cleanup {
        Ok(()) => CleanupState::Complete,
        Err(PrimitiveFailure {
            certainty: MutationCertainty::CompletionUnknown,
            ..
        }) => CleanupState::CompletionUnknown,
        Err(_) => CleanupState::DefinitelyRejected,
    }
}

#[cfg(all(test, feature = "fixtures"))]
mod observer_tests {
    use super::*;
    use crate::platform::fixtures::FixtureHost;

    /// Observer that accepts initial validation but cancels after exact unmount.
    struct CancelAfterUnmount {
        validating_visits: usize,
    }

    impl HostOperationObserver for CancelAfterUnmount {
        /// Cancels on the second still-safe validation boundary.
        fn reached(&mut self, stage: &'static str, cancellable: bool) -> bool {
            if stage == "format-validating" && cancellable {
                self.validating_visits += 1;
                return self.validating_visits == 1;
            }
            true
        }
    }

    /// Cancellation after unmount wins before layout and retains not-attempted certainty.
    #[test]
    fn format_cancellation_between_unmount_and_layout_never_dispatches_layout() {
        let mut host = FixtureHost::ready();
        let confirmation = host.issue_confirmation_token();
        let mut observer = CancelAfterUnmount {
            validating_visits: 0,
        };

        let failure = partition_and_format_observed(
            &mut host,
            FileSystem::ExFat,
            &confirmation,
            &mut observer,
        )
        .unwrap_err();

        assert_eq!(failure.code(), "cancelled");
        assert_eq!(failure.certainty(), MutationCertainty::NotAttempted);
        assert_eq!(host.unmount_count(), 1);
        assert_eq!(host.layout_change_count(), 0);
        assert!(!host.session_invalidated());
    }
}

/// Generates a cryptographically random app-owned basename and unpredictable payload.
fn random_test_material(length: usize) -> (String, Vec<u8>) {
    debug_assert!(length <= MAX_WRITE_READ_BYTES);
    let mut nonce = [0_u8; 16];
    let mut bytes = vec![0_u8; length];
    OsRng.fill_bytes(&mut nonce);
    OsRng.fill_bytes(&mut bytes);
    let suffix = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    (format!(".openrdx-write-read-{suffix}.tmp"), bytes)
}

/// Generates a nonzero random MBR disk signature.
fn random_nonzero_u32() -> u32 {
    loop {
        let value = OsRng.next_u32();
        if value != 0 {
            return value;
        }
    }
}
