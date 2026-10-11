// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Documented vendor-0283 first installation, separate from in-place activation.
//!
//! Reference: SunboX/OpenRDX docs/getting-started/installation.md, first-install
//! procedure. The late signature result is staging evidence only; mode 05 is
//! never sent to that source receiver. Programming retains reconstructed unit
//! records, followed by the unmodified final release through its normal receiver.

use super::*;
use crate::migration::{MigrationError, MigrationEvent, PreparedMigration, RECOVERY_ROOT};
use crate::operations::HostPrimitiveError;
use crate::transport::CommandDispatch;

/// Requires the exact public release and researched source family for this route.
pub(super) fn eligible(
    image: &FirmwareImage,
    family: ProductFamily,
    installed: crate::firmware::FirmwareRevision,
) -> bool {
    installed.get() == 283
        && family == ProductFamily::Usb3Sata3
        && image.product() == family
        && image.expected_revision().get() == 107
        && image.signature_evidence()
            == crate::firmware::SignatureEvidence::OpenRdxIntegrityVerified
        && crate::migration::validate_final_image(image.migration_bytes()).is_ok()
}

/// Saves and revalidates source records before the first documented setup command.
pub(super) fn prepare_and_stage(
    resolved: &mut ResolvedDevice<'_>,
    image: &FirmwareImage,
    observer: &mut HostWorkerObserver<'_>,
) -> Result<PreparedMigration, HostOperationFailure> {
    if !observer.reached("firmware-capturing", true) {
        return Err(cancelled_host_failure("firmware-capturing"));
    }
    let capture = resolved
        .migration_capture()
        .map_err(|error| preparation_failure("firmware-capturing", error))?;
    let mut prepared = PreparedMigration::prepare(
        std::path::Path::new(RECOVERY_ROOT),
        capture,
        image.migration_bytes(),
    )
    .map_err(|error| preparation_failure("firmware-capturing", error))?;
    let fresh = resolved
        .migration_capture()
        .map_err(|error| preparation_failure("firmware-capturing", error))?;
    prepared
        .verify_source(&fresh)
        .map_err(|error| preparation_failure("firmware-capturing", error))?;
    let (family, installed, media) = resolved
        .firmware_facts()
        .map_err(|_| preparation_failure("firmware-capturing", MigrationError::InvalidCapture))?;
    if media || !eligible(image, family, installed) {
        return Err(preparation_failure(
            "firmware-capturing",
            MigrationError::InvalidCapture,
        ));
    }
    prepared
        .journal(MigrationEvent::SourceRevalidated)
        .map_err(|error| preparation_failure("firmware-capturing", error))?;
    if !observer.reached("firmware-compatibility-setup", false) {
        return Err(cancelled_host_failure("firmware-compatibility-setup"));
    }
    let result = (|| {
        journal(
            &mut prepared,
            MigrationEvent::CompatibilitySetupDispatching,
            "firmware-compatibility-setup",
        )?;
        // Package validation cross-checks these ten factory bytes against the
        // independently observed USB serial before this request is constructed.
        let serial = std::str::from_utf8(&prepared.capture().factory[16..26]).map_err(|_| {
            failed(
                "firmware-compatibility-setup",
                HostPrimitiveError::MigrationCaptureInvalid,
            )
        })?;
        let authorize =
            crate::protocol::compatibility_receiver_authorization(serial).map_err(|_| {
                failed(
                    "firmware-compatibility-setup",
                    HostPrimitiveError::MigrationCaptureInvalid,
                )
            })?;
        for command in [
            authorize,
            crate::protocol::compatibility_receiver_header_setup(),
        ] {
            if !matches!(
                resolved.execute_firmware(&command),
                CommandDispatch::Succeeded(_)
            ) {
                return Err(failed(
                    "firmware-compatibility-setup",
                    HostPrimitiveError::MigrationStagingFailed,
                ));
            }
        }
        journal(
            &mut prepared,
            MigrationEvent::CompatibilitySetupAccepted,
            "firmware-compatibility-setup",
        )?;
        if !observer.reached("firmware-staging", false) {
            return Err(failed(
                "firmware-staging",
                HostPrimitiveError::MigrationStagingFailed,
            ));
        }
        journal(
            &mut prepared,
            MigrationEvent::SourceTransferDispatching,
            "firmware-staging",
        )?;
        stage_container(image.migration_bytes(), &mut |command| {
            resolved.execute_firmware(command)
        })?;
        journal(
            &mut prepared,
            MigrationEvent::SourceTransferComplete,
            "firmware-staging",
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = prepared.journal(MigrationEvent::RecoveryRequired);
        return Err(error);
    }
    Ok(prepared)
}

/// Requires all full chunks GOOD and only the exact final signature result.
///
/// No partial stream retry, finalizer, reset, or cleanup command is issued.
fn stage_container(
    bytes: &[u8],
    dispatch: &mut impl FnMut(&crate::protocol::Command) -> CommandDispatch,
) -> Result<(), HostOperationFailure> {
    if bytes.len() != 62110 {
        return Err(failed(
            "firmware-staging",
            HostPrimitiveError::MigrationStagingFailed,
        ));
    }
    for (index, chunk) in bytes.chunks(4096).enumerate() {
        let offset = index * 4096;
        let final_chunk = offset + chunk.len() == bytes.len();
        let command = write_buffer(4, offset as u32, chunk).map_err(|_| {
            failed(
                "firmware-staging",
                HostPrimitiveError::MigrationStagingFailed,
            )
        })?;
        let outcome = dispatch(&command);
        let accepted = if final_chunk {
            // This evidence requires the native adapter to observe all 670
            // data-out bytes plus exact final 07/74/08. Certainty remains
            // unknown because staging changed flash; it is not activation.
            matches!(
                outcome,
                CommandDispatch::CompletionUnknown(
                    crate::transport::TransportError::CompatibilityStagingSignature
                )
            )
        } else {
            matches!(outcome, CommandDispatch::Succeeded(_))
        };
        if !accepted {
            return Err(failed(
                "firmware-staging",
                HostPrimitiveError::MigrationStagingFailed,
            ));
        }
    }
    Ok(())
}

/// Retains the staged source lease while the operator performs the first power cycle.
pub(super) fn await_rom(
    prepared: &mut PreparedMigration,
    observer: &mut HostWorkerObserver<'_>,
) -> Result<rdx_macos_native::RomSession, HostOperationFailure> {
    journal(
        prepared,
        MigrationEvent::AwaitingBootloaderPowerCycle,
        "firmware-awaiting-bootloader",
    )?;
    operator_power_cycle(
        observer,
        "firmware-awaiting-bootloader",
        HostPrimitiveError::MigrationBootloaderUnavailable,
    )?;
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        // Enumeration/open is read-only. The exact unique parent and active
        // interfaces must all pass before identify, setup or program is possible.
        match rdx_macos_native::RomSession::open(prepared.capture().usb.location_id) {
            Ok(mut rom) => {
                rom.identify(5_000).map_err(|_| {
                    failed(
                        "firmware-awaiting-bootloader",
                        HostPrimitiveError::MigrationBootloaderUnavailable,
                    )
                })?;
                journal(
                    prepared,
                    MigrationEvent::RomObserved,
                    "firmware-awaiting-bootloader",
                )?;
                return Ok(rom);
            }
            Err(
                rdx_macos_native::NativeError::AccessDenied
                | rdx_macos_native::NativeError::UnsupportedPlatform,
            ) => break,
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(250)),
            Err(_) => break,
        }
    }
    let _ = prepared.journal(MigrationEvent::RecoveryRequired);
    Err(failed(
        "firmware-awaiting-bootloader",
        HostPrimitiveError::MigrationBootloaderUnavailable,
    ))
}

/// Journals each mutation separately and never resets after an incomplete program.
pub(super) fn program_bootstrap(
    prepared: &mut PreparedMigration,
    rom: &mut rdx_macos_native::RomSession,
    observer: &mut HostWorkerObserver<'_>,
) -> Result<(), HostOperationFailure> {
    if !observer.reached("firmware-programming-bootstrap", false) {
        return Err(failed(
            "firmware-programming-bootstrap",
            HostPrimitiveError::MigrationProgrammingFailed,
        ));
    }
    let stage = "firmware-programming-bootstrap";
    let result = (|| {
        journal(prepared, MigrationEvent::RomSetupDispatching, stage)?;
        rom.setup(60_000)
            .map_err(|_| failed(stage, HostPrimitiveError::MigrationProgrammingFailed))?;
        journal(prepared, MigrationEvent::RomSetupAccepted, stage)?;
        journal(prepared, MigrationEvent::RomTransferDispatching, stage)?;
        rom.program(prepared.bootstrap(), 120_000)
            .map_err(|_| failed(stage, HostPrimitiveError::MigrationProgrammingFailed))?;
        journal(prepared, MigrationEvent::RomTransferComplete, stage)?;
        journal(prepared, MigrationEvent::RomResetDispatching, stage)?;
        rom.reset(15_000)
            .map_err(|_| failed(stage, HostPrimitiveError::MigrationProgrammingFailed))?;
        journal(prepared, MigrationEvent::RomResetAccepted, stage)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = prepared.journal(MigrationEvent::RecoveryRequired);
    }
    result
}

/// Pauses until the operator acknowledges this exact published power-cycle step.
///
/// The button is essential even if ROM reset automatically enumerates OpenRDX:
/// seeing an application alone must not start writes while the user is about to
/// follow the still-visible unplug instruction. Arming precedes publication so
/// an immediate click is retained by the same operation control epoch.
fn operator_power_cycle(
    observer: &mut HostWorkerObserver<'_>,
    stage: &'static str,
    cause: HostPrimitiveError,
) -> Result<(), HostOperationFailure> {
    observer
        .control
        .arm_operator_wait(stage)
        .map_err(|_| failed(stage, cause))?;
    if !observer.reached(stage, false) {
        return Err(failed(stage, cause));
    }
    if !observer
        .control
        .wait_for_operator(stage, Duration::from_secs(300))
        .map_err(|_| failed(stage, cause))?
    {
        return Err(failed(stage, cause));
    }
    Ok(())
}

/// Waits for acknowledged return at the exact physical port before SCSI probing.
///
/// The returned discovery lease is retained by the caller through fresh record
/// readback and final release transfer; no release-and-reopen recipe is used.
pub(super) fn await_bootstrap<B: PlatformBackend>(
    worker: &mut HardwareWorker<B>,
    device_id: &crate::model::DeviceId,
    prepared: &mut PreparedMigration,
    observer: &mut HostWorkerObserver<'_>,
) -> Result<crate::platform::FirmwareDiscoveryBinding, HostOperationFailure> {
    let stage = "firmware-awaiting-bootstrap";
    journal(prepared, MigrationEvent::AwaitingBootstrapPowerCycle, stage)?;
    operator_power_cycle(
        observer,
        stage,
        HostPrimitiveError::MigrationReadbackMismatch,
    )?;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let usb = &prepared.capture().usb;
        match rdx_macos_native::observe_migration_usb(usb.location_id, &usb.serial) {
            Ok(Some(_)) => {
                if let Ok(binding) = worker.scan_firmware_binding(device_id)
                    && binding.lease.is_some()
                {
                    return Ok(binding);
                }
            }
            Ok(None) => {}
            // Identity mismatches cannot authorize transport to another dock.
            Err(_) => break,
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    let _ = prepared.journal(MigrationEvent::RecoveryRequired);
    Err(failed(stage, HostPrimitiveError::MigrationReadbackMismatch))
}

/// Maps only bounded preparation diagnostics; no captured bytes enter an error.
fn preparation_failure(stage: &'static str, error: MigrationError) -> HostOperationFailure {
    let cause = match error {
        MigrationError::InvalidCapture | MigrationError::ReadbackMismatch => {
            HostPrimitiveError::MigrationCaptureInvalid
        }
        _ => HostPrimitiveError::MigrationRecoveryUnavailable,
    };
    HostOperationFailure::preflight(stage, cause)
}

/// Preserves unknown mutation state after the source staging barrier.
pub(super) fn failed(stage: &'static str, cause: HostPrimitiveError) -> HostOperationFailure {
    HostOperationFailure::from_primitive(stage, PrimitiveFailure::completion_unknown(cause))
        .with_cleanup(CleanupState::CompletionUnknown)
}

/// Refuses the next mutation when its separate durable journal cannot be written.
pub(super) fn journal(
    prepared: &mut PreparedMigration,
    event: MigrationEvent,
    stage: &'static str,
) -> Result<(), HostOperationFailure> {
    prepared
        .journal(event)
        .map_err(|_| failed(stage, HostPrimitiveError::MigrationRecoveryUnavailable))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{TransportError, TransportResponse};

    /// Real public bytes are eligible only with matching release facts and source.
    #[test]
    fn eligibility_requires_pinned_release_version_and_source_family() {
        let bytes = include_bytes!("../../../../../test/fixtures/OpenRDX-v1-07.bin");
        for (version, expected) in [("1.07", true), ("1.06", false), ("2.83", false)] {
            let metadata = serde_json::from_value(serde_json::json!({
                "containerSha256": crate::migration::FINAL_RELEASE_SHA256,
                "bootRegionSha256": "74ba773b3fed31deaa877a57e5223a871c99e3ec7978d4fa7e3a951c63d9d901",
                "releaseVersion": version,
            })).unwrap();
            let image = FirmwareImage::from_openrdx_bytes(bytes.to_vec(), &metadata).unwrap();
            let source = crate::firmware::FirmwareRevision::new(283).unwrap();
            assert_eq!(
                eligible(&image, ProductFamily::Usb3Sata3, source),
                expected,
                "{version}"
            );
            assert!(!eligible(&image, ProductFamily::Usb2Sata1, source));
            for revision in [1, 106, 107, 282, 284] {
                assert!(!eligible(
                    &image,
                    ProductFamily::Usb3Sata3,
                    crate::firmware::FirmwareRevision::new(revision).unwrap()
                ));
            }
        }
    }

    /// Sends a synthetic native reply through the real macOS certainty converter.
    fn signature(command: &crate::protocol::Command) -> CommandDispatch {
        let mut sense = [0; 18];
        sense[0] = 0x70;
        sense[2] = 7;
        sense[7] = 10;
        sense[12] = 0x74;
        sense[13] = 8;
        let packet = crate::platform::macos::build_scsi_task(command).unwrap();
        crate::platform::macos::convert_scsi_task_completion(
            &packet,
            crate::platform::macos::NativeScsiTaskCompletion::device(
                2,
                crate::platform::macos::SCSI_SERVICE_RESPONSE_TASK_COMPLETE,
                command.data().len() as u32,
                vec![],
                sense.len(),
                sense.to_vec(),
            ),
        )
    }

    /// A final signature result permits only transition, never normal activation.
    #[test]
    fn staging_requires_exact_late_result_and_never_finalizes() {
        for failure_at in 0..=16 {
            let mut calls = 0;
            let result = stage_container(&vec![0; 62110], &mut |command| {
                assert_eq!(&command.cdb()[..3], &[0x3b, 4, 0]);
                let index = calls;
                calls += 1;
                if index == failure_at {
                    signature(command)
                } else {
                    CommandDispatch::Succeeded(TransportResponse::empty())
                }
            });
            assert_eq!(result.is_ok(), failure_at == 15);
            assert_eq!(calls, if failure_at < 15 { failure_at + 1 } else { 16 });
        }
    }

    /// Unqualified sense alone cannot prove the complete final data-out phase.
    #[test]
    fn staging_rejects_signature_without_complete_native_transfer_evidence() {
        let mut sense = [0; 18];
        sense[0] = 0x70;
        sense[2] = 7;
        sense[7] = 10;
        sense[12] = 0x74;
        sense[13] = 8;
        let error =
            TransportError::CheckCondition(crate::protocol::SenseData::parse(&sense).unwrap());
        for outcome in [
            CommandDispatch::DefinitelyRejected(error.clone()),
            CommandDispatch::CompletionUnknown(error),
        ] {
            let mut calls = 0;
            assert!(
                stage_container(&vec![0; 62110], &mut |_| {
                    calls += 1;
                    if calls == 16 {
                        outcome.clone()
                    } else {
                        CommandDispatch::Succeeded(TransportResponse::empty())
                    }
                })
                .is_err()
            );
            assert_eq!(calls, 16);
        }
    }

    /// Partial/unknown writes, including the last one, cannot authorize a power cycle.
    #[test]
    fn every_unknown_staging_reply_stops_without_retry() {
        for failure_at in 0..16 {
            let mut calls = 0;
            assert!(
                stage_container(&vec![0; 62110], &mut |_| {
                    let index = calls;
                    calls += 1;
                    if index == failure_at {
                        CommandDispatch::CompletionUnknown(TransportError::Timeout)
                    } else {
                        CommandDispatch::Succeeded(TransportResponse::empty())
                    }
                })
                .is_err()
            );
            assert_eq!(calls, failure_at + 1);
        }
    }
}
