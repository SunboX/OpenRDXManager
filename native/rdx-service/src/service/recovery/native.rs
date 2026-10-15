// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! macOS bindings for the closed receipt-owned single-attempt recovery controller.

use super::*;
use crate::firmware::{FirmwareImage, OpenRdxImageMetadata, ProductFamily};
use crate::migration::{FINAL_RELEASE_SHA256, PreparedMigration};
use crate::model::DeviceId;
use crate::platform::macos::MacOsBackend;
use crate::platform::{DeviceRegistry, PlatformBackend, ResolvedDevice};
use crate::service::ServiceExecutionContext;
use rdx_macos_native::{
    HardwareOwnershipGuard, HardwareOwnershipNamespace, RomCandidate, RomSession,
};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::thread;
use std::time::{Duration, Instant};

/// Owns exact saved inputs and native ROM state, never serializable or Debug.
struct NativeAttempt {
    prepared: PreparedMigration,
    image: FirmwareImage,
    target: DeviceId,
    route: RomCandidate,
    context: ServiceExecutionContext,
    rom: Option<RomSession>,
    power_cycle: Option<PowerCycleGate>,
}

/// Proves native process authority before acquiring the existing global owner.
fn acquire_owner() -> Result<(HardwareOwnershipNamespace, HardwareOwnershipGuard), RecoveryError> {
    if !rdx_macos_native::current_process_is_privileged_service() {
        return Err(RecoveryError::PrivilegeRequired);
    }
    let namespace = rdx_macos_native::initialize_hardware_ownership_namespace()
        .map_err(|_| RecoveryError::OwnershipUnavailable)?;
    let guard = rdx_macos_native::try_acquire_hardware_ownership()
        .map_err(|_| RecoveryError::OwnershipUnavailable)?;
    Ok((namespace, guard))
}

/// Parses the exact public release with its existing production integrity validator.
fn final_image(bytes: &[u8]) -> Result<FirmwareImage, RecoveryError> {
    crate::migration::validate_final_image(bytes).map_err(|_| RecoveryError::StorageUnavailable)?;
    // These are the immutable published1.07 facts, not caller-supplied metadata.
    let metadata: OpenRdxImageMetadata = serde_json::from_value(serde_json::json!({
        "containerSha256": FINAL_RELEASE_SHA256,
        "bootRegionSha256": "74ba773b3fed31deaa877a57e5223a871c99e3ec7978d4fa7e3a951c63d9d901",
        "releaseVersion": "1.07"
    }))
    .map_err(|_| RecoveryError::StorageUnavailable)?;
    FirmwareImage::from_openrdx_bytes(bytes.to_vec(), &metadata)
        .map_err(|_| RecoveryError::StorageUnavailable)
}

/// Opens a new attempt only while both global guards remain live until completion.
pub(super) fn recover(
    bundle_id: &str,
    observer: &mut dyn RecoveryObserver,
) -> Result<RecoveryOutcome, RecoveryError> {
    observer.reached(RecoveryStage::Preparing)?;
    let (_namespace, _ownership) = acquire_owner()?;
    recover_owned(
        bundle_id,
        None,
        observer,
        ServiceExecutionContext::privileged_direct_cli(true),
    )
}

/// Returns only current route labels/tokens, never a saved-unit association.
pub(super) fn list_targets() -> Result<Vec<RecoveryTarget>, RecoveryError> {
    let candidates =
        rdx_macos_native::enumerate_rom_candidates().map_err(|_| RecoveryError::RomUnavailable)?;
    Ok(candidates
        .iter()
        .map(|candidate| RecoveryTarget {
            target_token: candidate_token(candidate),
            port_label: format!("USB port 0x{:08X}", candidate.location_id()),
        })
        .collect())
}

/// Acquires standalone ownership before selecting the freshly observed route.
pub(super) fn recover_selected(
    selection: &RecoverySelection,
    observer: &mut dyn RecoveryObserver,
) -> Result<RecoveryOutcome, RecoveryError> {
    observer.reached(RecoveryStage::Preparing)?;
    let (_namespace, _ownership) = acquire_owner()?;
    recover_owned(
        &selection.bundle_id,
        Some(&selection.target_token),
        observer,
        ServiceExecutionContext::privileged_direct_cli(true),
    )
}

/// Uses only trusted caller-held session ownership, with fresh native privilege proof.
pub(super) fn recover_in_service(
    selection: &RecoverySelection,
    observer: &mut dyn RecoveryObserver,
    context: ServiceExecutionContext,
) -> Result<RecoveryOutcome, RecoveryError> {
    if !rdx_macos_native::current_process_is_privileged_service() {
        return Err(RecoveryError::PrivilegeRequired);
    }
    observer.reached(RecoveryStage::Preparing)?;
    recover_owned(
        &selection.bundle_id,
        Some(&selection.target_token),
        observer,
        context,
    )
}

/// Hashes only real registry observations supplied by the native inventory.
fn candidate_token(candidate: &RomCandidate) -> String {
    target_token(candidate.location_id(), candidate.registry_id())
}

/// Keeps source evidence immutable and holds the selected route only in this attempt.
fn recover_owned(
    bundle_id: &str,
    selected_token: Option<&str>,
    observer: &mut dyn RecoveryObserver,
    context: ServiceExecutionContext,
) -> Result<RecoveryOutcome, RecoveryError> {
    observer.ensure_connected()?;
    let prepared = PreparedMigration::begin_recovery_existing(bundle_id)
        .map_err(|_| RecoveryError::StorageUnavailable)?;
    let image = final_image(prepared.final_image())?;
    let target = DeviceRegistry::migration_target_id(prepared.capture())
        .map_err(|_| RecoveryError::StorageUnavailable)?;
    let candidates =
        rdx_macos_native::enumerate_rom_candidates().map_err(|_| RecoveryError::RomUnavailable)?;
    let route = match selected_token {
        Some(token) => *select_observed_target(&candidates, token, candidate_token)?,
        None => {
            // Preserve legacy CLI semantics. Any-port recovery requires an
            // explicitly selected inventory target and physical association.
            if candidates.len() != 1
                || candidates[0].location_id() != prepared.capture().usb.location_id
            {
                return Err(RecoveryError::RomUnavailable);
            }
            candidates[0]
        }
    };
    let mut attempt = NativeAttempt {
        prepared,
        image,
        target,
        route,
        context,
        rom: None,
        power_cycle: None,
    };
    match catch_unwind(AssertUnwindSafe(|| run_sequence(&mut attempt, observer))) {
        Ok(result) => result,
        Err(_) => {
            let _ = attempt.journal(MigrationEvent::RecoveryRequired);
            Err(RecoveryError::RomOperationUnknown)
        }
    }
}

/// Observes the attempt-selected physical port with the original saved unit serial.
fn observe(prepared: &PreparedMigration, location: u32) -> Result<Option<u64>, RecoveryError> {
    let usb = &prepared.capture().usb;
    rdx_macos_native::observe_migration_usb(location, &usb.serial)
        .map_err(|_| RecoveryError::TargetUnavailable)
}

impl RecoveryAttempt for NativeAttempt {
    /// Persists the closed event in the independent copy's journal.
    fn journal(&mut self, event: MigrationEvent) -> Result<(), RecoveryError> {
        self.prepared
            .journal(event)
            .map_err(|_| RecoveryError::StorageUnavailable)
    }

    /// A stale selected epoch/port or invalid feature reply fails before setup.
    fn identify_rom(&mut self) -> Result<(), RecoveryError> {
        let mut rom =
            RomSession::open_selected(&self.route).map_err(|_| RecoveryError::RomUnavailable)?;
        rom.identify(5_000)
            .map_err(|_| RecoveryError::RomUnavailable)?;
        self.rom = Some(rom);
        Ok(())
    }

    /// The native one-attempt state machine prohibits repeat setup after failure.
    fn setup_rom(&mut self) -> Result<(), RecoveryError> {
        let prepared = &self.prepared;
        let location = self.route.location_id();
        let rom = &mut self.rom;
        setup_after_absent_application(
            || observe(prepared, location),
            || {
                rom.as_mut()
                    .ok_or(RecoveryError::RomUnavailable)?
                    .setup(60_000)
                    .map_err(|_| RecoveryError::RomOperationUnknown)
            },
        )
    }

    /// Uses the reopened saved bootstrap, not a regenerated or caller-selected image.
    fn program_rom(&mut self) -> Result<(), RecoveryError> {
        let image = self.prepared.bootstrap();
        let actual = self
            .rom
            .as_mut()
            .ok_or(RecoveryError::RomUnavailable)?
            .program(image, 120_000)
            .map_err(|_| RecoveryError::RomOperationUnknown)?;
        if actual != image.len() {
            return Err(RecoveryError::RomOperationUnknown);
        }
        Ok(())
    }

    /// A failed/partial program never reaches this reset request.
    fn reset_rom(&mut self) -> Result<(), RecoveryError> {
        self.rom
            .as_mut()
            .ok_or(RecoveryError::RomUnavailable)?
            .reset(15_000)
            .map_err(|_| RecoveryError::RomOperationUnknown)
    }

    /// Drop releases report/interface owners without reset or other cleanup IO.
    fn release_rom(&mut self) {
        self.rom = None;
    }

    /// Establishes the observation baseline before the user sees the power-cycle prompt.
    fn arm_power_cycle(&mut self) -> Result<(), RecoveryError> {
        self.power_cycle = Some(PowerCycleGate::new(observe(
            &self.prepared,
            self.route.location_id(),
        )?));
        Ok(())
    }

    /// Requires both the new explicit reply and a returned exact USB application.
    fn await_application(
        &mut self,
        observer: &mut dyn RecoveryObserver,
    ) -> Result<(), RecoveryError> {
        let mut gate = self
            .power_cycle
            .take()
            .ok_or(RecoveryError::OperatorAcknowledgmentRequired)?;
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            observer.ensure_connected()?;
            let acknowledged = !gate.acknowledged && observer.operator_acknowledged()?;
            let current = observe(&self.prepared, self.route.location_id())?;
            // If an application was already visible before the prompt, its
            // unchanged epoch cannot satisfy a physical power-cycle request.
            if gate.observe(current, acknowledged) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(if gate.acknowledged {
                    RecoveryError::TargetUnavailable
                } else {
                    RecoveryError::OperatorAcknowledgmentRequired
                });
            }
            thread::sleep(Duration::from_millis(250));
        }
    }

    /// Retains one fresh target lease across bootstrap verification and final transfer.
    fn finish_release(&mut self, observer: &mut dyn RecoveryObserver) -> Result<(), RecoveryError> {
        let mut backend = MacOsBackend::native_with_context(self.context.duplicate_for_runtime());
        let mut registry = DeviceRegistry::new();
        observer.reached(RecoveryStage::VerifyingBootstrap)?;
        let bootstrap_epoch;
        {
            let mut resolved = open_application(
                &mut backend,
                &mut registry,
                &self.target,
                &self.prepared,
                self.route.location_id(),
                Some(observer),
            )?;
            let result = catch_unwind(AssertUnwindSafe(|| {
                observer.ensure_connected()?;
                verify_application(&mut resolved, &self.prepared, self.route.location_id())?;
                self.prepared
                    .journal(MigrationEvent::BootstrapReadbackVerified)
                    .map_err(|_| RecoveryError::StorageUnavailable)?;
                let (family, revision, media) = resolved
                    .firmware_facts()
                    .map_err(|_| RecoveryError::ReadbackMismatch)?;
                if media {
                    return Err(RecoveryError::ReadbackMismatch);
                }
                self.image
                    .authorize_for_registry(revision, family)
                    .map_err(|_| RecoveryError::ReadbackMismatch)?;
                let epoch = observe(&self.prepared, self.route.location_id())?
                    .ok_or(RecoveryError::TargetUnavailable)?;
                let prepared = &mut self.prepared;
                transfer_once(
                    &self.image,
                    &mut |command| resolved.execute_firmware(command),
                    &mut |event| {
                        prepared
                            .journal(event)
                            .map_err(|_| RecoveryError::StorageUnavailable)
                    },
                    observer,
                )?;
                Ok(epoch)
            }))
            .unwrap_or(Err(RecoveryError::FinalUpdateUnknown));
            if result.is_err() {
                // Persist uncertainty before the live capture is destroyed:
                // macOS may reset/rematch USB when capture ownership ends.
                let _ = self.prepared.journal(MigrationEvent::RecoveryRequired);
            }
            bootstrap_epoch = result?;
        }
        // The receiver schedules reset five100-ms ticks after mode05 GOOD.
        // Fresh identity alone cannot replace that accepted commit result.
        thread::sleep(Duration::from_secs(1));
        observer.reached(RecoveryStage::VerifyingFinalRelease)?;
        await_replacement(
            &self.prepared,
            self.route.location_id(),
            bootstrap_epoch,
            observer,
        )?;
        let mut resolved = open_application(
            &mut backend,
            &mut registry,
            &self.target,
            &self.prepared,
            self.route.location_id(),
            Some(observer),
        )?;
        let result = catch_unwind(AssertUnwindSafe(|| {
            observer.ensure_connected()?;
            verify_application(&mut resolved, &self.prepared, self.route.location_id())?;
            self.prepared
                .journal(MigrationEvent::FinalUpdateVerified)
                .map_err(|_| RecoveryError::StorageUnavailable)
        }))
        .unwrap_or(Err(RecoveryError::ReadbackMismatch));
        if result.is_err() {
            let _ = self.prepared.journal(MigrationEvent::RecoveryRequired);
        }
        result
    }
}

/// Requires a new application epoch after accepted mode05 before final readback.
fn await_replacement(
    prepared: &PreparedMigration,
    location: u32,
    previous: u64,
    observer: &mut dyn RecoveryObserver,
) -> Result<(), RecoveryError> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        observer.ensure_connected()?;
        if observe(prepared, location)?.is_some_and(|current| current != previous) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(RecoveryError::TargetUnavailable);
        }
        thread::sleep(Duration::from_millis(250));
    }
}

/// Obtains the target-retaining discovery probe, never a released reopen recipe.
fn open_application<'registry>(
    backend: &mut MacOsBackend,
    registry: &'registry mut DeviceRegistry,
    target: &DeviceId,
    prepared: &PreparedMigration,
    location: u32,
    mut observer: Option<&mut dyn RecoveryObserver>,
) -> Result<ResolvedDevice<'registry>, RecoveryError> {
    let deadline = Instant::now() + Duration::from_secs(60);
    let binding = loop {
        if let Some(observer) = observer.as_mut() {
            observer.ensure_connected()?;
        }
        if observe(prepared, location)?.is_some() {
            let binding =
                crate::platform::discover_firmware_device_binding(backend, registry, target)
                    .map_err(|_| RecoveryError::TargetUnavailable)?;
            if binding.lease.is_some() {
                break binding;
            }
        }
        if Instant::now() >= deadline {
            return Err(RecoveryError::TargetUnavailable);
        }
        thread::sleep(Duration::from_millis(250));
    };
    let revision = binding
        .report
        .snapshots()
        .iter()
        .find(|snapshot| &snapshot.id == target)
        .map(|snapshot| snapshot.revision)
        .ok_or(RecoveryError::TargetUnavailable)?;
    registry
        .resolve_retained_firmware_lease(
            target,
            revision,
            backend.capabilities(),
            binding.lease.ok_or(RecoveryError::TargetUnavailable)?,
        )
        .map_err(|_| RecoveryError::TargetUnavailable)
}

/// Verifies only fresh same-lease facts and the two entire preserved SPI records.
fn verify_application(
    resolved: &mut ResolvedDevice<'_>,
    prepared: &PreparedMigration,
    location: u32,
) -> Result<(), RecoveryError> {
    let (family, revision, media) = resolved
        .firmware_facts()
        .map_err(|_| RecoveryError::ReadbackMismatch)?;
    if family != ProductFamily::Usb3Sata3 || revision.get() != 107 || media {
        return Err(RecoveryError::ReadbackMismatch);
    }
    let records = resolved
        .migration_readback()
        .map_err(|_| RecoveryError::ReadbackMismatch)?;
    prepared
        .verify_records_at_location(&records, location)
        .map_err(|_| RecoveryError::ReadbackMismatch)
}

/// Independent verification is read-only and cannot produce completed-release status.
pub(super) fn verify_existing(bundle_id: &str) -> Result<(), RecoveryError> {
    let (_namespace, _ownership) = acquire_owner()?;
    let prepared = PreparedMigration::load_existing(bundle_id)
        .map_err(|_| RecoveryError::StorageUnavailable)?;
    let target = DeviceRegistry::migration_target_id(prepared.capture())
        .map_err(|_| RecoveryError::StorageUnavailable)?;
    let mut backend =
        MacOsBackend::native_with_context(ServiceExecutionContext::privileged_direct_cli(true));
    let mut registry = DeviceRegistry::new();
    let location = prepared.capture().usb.location_id;
    let mut resolved = open_application(
        &mut backend,
        &mut registry,
        &target,
        &prepared,
        location,
        None,
    )?;
    verify_application(&mut resolved, &prepared, location)
}
