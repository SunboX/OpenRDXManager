// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production firmware registration and transfer tests using simulated transports.

use super::*;

/// OpenRDX registration reaches exact mode-4/mode-5 transfer and release readback,
/// while vendor receivers and incorrect post-update revisions cannot succeed.
#[test]
fn production_openrdx_update_checks_receiver_and_release_readback() {
    for (
        installed,
        readback,
        reset_delay,
        finalizer_unknown,
        rebind_failures,
        probe_failures,
        transfer_failures,
        nonretryable,
        should_succeed,
    ) in [
        (283, 107, 5, 0, 0, 0, 0, false, false),
        // Every discovery-handle release can rematch the native storage stack,
        // so retrying the subsequent reopen never produces a stable binding.
        (107, 107, 5, 0, 1_000, 0, 0, false, true),
        (107, 107, 0, 0, 1_000, 0, 0, false, true),
        (107, 107, 0, 0, 0, 0, 0, false, true),
        (106, 107, 0, 0, 0, 0, 0, false, true),
        (109, 111, 5, 0, 0, 0, 0, false, true),
        (111, 111, 0, 0, 0, 0, 0, false, true),
        (1, 107, 5, 0, 1, 0, 0, false, true),
        (1, 107, 5, 0, 0, 1, 0, false, true),
        (1, 107, 5, 0, 0, 0, 2, false, false),
        (1, 107, 5, 0, 0, 0, 0, true, false),
        (1, 107, 5, 0, 0, 0, 0, false, true),
        (106, 107, 5, 0, 0, 0, 0, false, true),
        (1, 107, 5, 1, 0, 0, 0, false, true),
        (107, 107, 5, 0, 0, 0, 0, false, true),
        (107, 107, 5, 1, 0, 0, 0, false, true),
        (107, 107, 5, 1, 1, 0, 0, false, true),
        (107, 107, 0, 0, 0, 0, 0, false, true),
        (107, 107, 0, 2, 0, 0, 0, false, false),
        (1, 283, 5, 0, 0, 0, 0, false, false),
    ] {
        let state = Arc::new(Mutex::new(ModePlatformState {
            drive_mode: 1,
            firmware_finalize_unknown: finalizer_unknown,
            firmware_revision: installed,
            firmware_target_revision: readback,
            firmware_target_drive_mode: (installed == 107 && reset_delay == 0).then_some(2),
            firmware_reset_delay: reset_delay,
            // macOS may wait through the entire restart and reuse cached
            // protocol evidence when the release number remains unchanged.
            firmware_cache_discovery: reset_delay == 0,
            firmware_activation_scans: None,
            firmware_rebind_failures: rebind_failures,
            post_reset_opens: None,
            firmware_probe_failures: probe_failures,
            post_reset_inquiries: 0,
            firmware_nonretryable_failure: nonretryable,
            firmware_transfer_failures: transfer_failures,
            manufacturing_fault: Default::default(),
            #[cfg(unix)]
            manufacturing_backups: Vec::new(),
            sata_mode: 2,
            commands: Vec::new(),
        }));
        let mut backend = HardwareServiceBackend::new(
            ServicePlatform::Darwin,
            ModePlatform {
                state: Arc::clone(&state),
            },
        );
        let snapshot = backend.scan_devices().unwrap().remove(0);
        let (bytes, metadata) = if readback == 111 {
            crate::firmware::test_image_for_release("1.11")
        } else {
            crate::firmware::openrdx_test_image()
        };
        let token = FirmwareFileToken::new("firmware:openrdx-update").unwrap();
        backend
            .begin_firmware_registration(
                token.clone(),
                "BIN".to_owned(),
                bytes.len(),
                Some(metadata),
            )
            .unwrap();
        for (index, chunk) in bytes.chunks(4096).enumerate() {
            backend
                .append_firmware_registration(token.clone(), index * 4096, chunk.to_vec())
                .unwrap();
        }
        backend.commit_firmware_registration(token.clone()).unwrap();
        let (sender, receiver) = mpsc::sync_channel(16);
        let operation_id = OperationId::new("op:openrdx-production").unwrap();
        let request = OperationRequest::FirmwareUpdate {
            device_id: snapshot.id,
            device_revision: snapshot.revision,
            firmware_file_token: token,
        };
        backend
            .start_operation(
                operation_id.clone(),
                request.clone(),
                ServiceEventSink::new(sender, crate::service::crash::CrashAdmission::new()),
            )
            .unwrap();
        backend.release_operation(&operation_id).unwrap();
        let mut published = Vec::new();
        loop {
            let event = receiver
                .recv_timeout(Duration::from_secs(40))
                .unwrap()
                .event;
            published.push(event.clone());
            match event {
                crate::model::OperationEvent::Succeeded { .. } => {
                    assert!(should_succeed);
                    break;
                }
                crate::model::OperationEvent::Failed {
                    ref error,
                    ref stage,
                    ..
                } => {
                    assert!(!should_succeed, "Unexpected failure: {event:?}");
                    if installed == 283 {
                        assert_eq!(stage.as_str(), "firmware-validating");
                        assert_eq!(
                            error.code.as_str(),
                            "firmware-openrdx-installation-unsupported",
                            "an unsupported first-install route must retain its specific cause"
                        );
                    }
                    break;
                }
                _ => {}
            }
        }
        // Backend-only success is insufficient: the real service must accept
        // every published lifecycle event without terminating its generation.
        let mut runtime = crate::service::ServiceRuntime::new(
            backend,
            ServiceEventSink::new(
                mpsc::sync_channel(16).0,
                crate::service::crash::CrashAdmission::new(),
            ),
        );
        runtime.active =
            Some(crate::service::ActiveOperation::new(operation_id, &request).unwrap());
        for event in published {
            runtime
                .handle_event(event.clone())
                .unwrap_or_else(|error| panic!("Rejected {event:?}: {error:?}"));
        }
        assert!(runtime.active.is_none());
        let state = state.lock().unwrap();
        let writes = state
            .commands
            .iter()
            .filter(|command| command[0] == 0x3B && matches!(command[1], 4 | 5))
            .collect::<Vec<_>>();
        assert_eq!(
            writes.len(),
            if installed == 283 {
                0
            } else if nonretryable {
                // A terminal mode-4 failure cannot authorize mode-5 activation.
                1
            } else if transfer_failures == 2 {
                // Unavailable invalidates each retained lease. The attempted
                // finalizer must not reach transport through an inactive lease.
                2
            } else if finalizer_unknown == 2 {
                18
            } else {
                17
            },
            "installed={installed} target={readback} transfer_failures={transfer_failures} nonretryable={nonretryable}: {writes:?}"
        );
        if transfer_failures == 2 || nonretryable {
            assert!(writes.iter().all(|command| command[1] == 0x04));
        } else if installed != 283 {
            assert_eq!(&writes.last().unwrap()[..2], &[0x3B, 0x05]);
        }
        if should_succeed {
            if rebind_failures == 1_000 {
                assert_eq!(
                    state.firmware_rebind_failures, 1_000,
                    "verification must retain the probe, never reopen its rematched recipe"
                );
            }
            let finalizer_index = state
                .commands
                .iter()
                .rposition(|command| command.starts_with(&[0x3B, 0x05]))
                .unwrap();
            if readback == 111 {
                assert_eq!(
                    state.commands[finalizer_index + 1..]
                        .iter()
                        .filter(|command| command[0] == 0xe7)
                        .count(),
                    2,
                    "1.11 readback must verify both factory-record halves"
                );
            }
            // A cache hit is never readback proof: opening the exact lease
            // and firmware_facts must each issue fresh standard INQUIRY.
            assert!(
                state.commands[finalizer_index + 1..]
                    .iter()
                    .filter(|command| command.starts_with(&[0x12, 0]))
                    .count()
                    >= 2
            );
        }
    }
}

/// A complete registered image is consumed once and dispatched as exact mode-4/mode-5 commands.
#[test]
fn production_backend_registers_and_dispatches_modern_firmware() {
    let state = Arc::new(Mutex::new(ModePlatformState {
        drive_mode: 1,
        firmware_finalize_unknown: 1,
        firmware_revision: 107,
        firmware_target_revision: 283,
        firmware_target_drive_mode: None,
        firmware_reset_delay: 0,
        firmware_cache_discovery: false,
        firmware_activation_scans: None,
        firmware_rebind_failures: 0,
        post_reset_opens: None,
        firmware_probe_failures: 0,
        post_reset_inquiries: 0,
        firmware_nonretryable_failure: false,
        firmware_transfer_failures: 1,
        manufacturing_fault: Default::default(),
        #[cfg(unix)]
        manufacturing_backups: Vec::new(),
        sata_mode: 2,
        commands: Vec::new(),
    }));
    let mut backend = HardwareServiceBackend::new(
        ServicePlatform::Darwin,
        ModePlatform {
            state: Arc::clone(&state),
        },
    );
    let snapshot = backend.scan_devices().unwrap().remove(0);
    assert_eq!(
        snapshot.capabilities[&OperationKind::FirmwareUpdate].state,
        crate::model::CapabilityState::Available
    );
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("original-inputs/RDX2E__STD__F-0283.bin"),
    )
    .unwrap();
    let token = FirmwareFileToken::new("firmware:hardware-update").unwrap();
    backend
        .begin_firmware_registration(token.clone(), "BIN".to_owned(), bytes.len(), None)
        .unwrap();
    for (index, chunk) in bytes.chunks(4_096).enumerate() {
        backend
            .append_firmware_registration(token.clone(), index * 4_096, chunk.to_vec())
            .unwrap();
    }
    backend.commit_firmware_registration(token.clone()).unwrap();

    let (sender, receiver) = mpsc::sync_channel(16);
    let crashes = crate::service::crash::CrashAdmission::new();
    let operation_id = OperationId::new("op:firmware-production").unwrap();
    backend
        .start_operation(
            operation_id.clone(),
            OperationRequest::FirmwareUpdate {
                device_id: snapshot.id,
                device_revision: snapshot.revision,
                firmware_file_token: token.clone(),
            },
            ServiceEventSink::new(sender, crashes.clone()),
        )
        .unwrap();
    backend.release_operation(&operation_id).unwrap();
    // Signature revalidation, retry and finalizer reconciliation run on the
    // worker; this is not a two-second latency contract. Bound the complete
    // expected sequence once, rather than extending the deadline per event.
    let event_deadline = std::time::Instant::now() + Duration::from_secs(40);
    let events = (0..6)
        .map(|_| {
            receiver
                .recv_timeout(event_deadline.saturating_duration_since(std::time::Instant::now()))
                .expect("signed firmware worker must publish the exact six-event sequence")
                .event
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        events.last(),
        Some(crate::model::OperationEvent::Succeeded { .. })
    ));
    // The terminal event precedes worker ownership release. A queued scan is
    // a deterministic barrier before asserting that the consumed token fails.
    let replay_snapshot = backend.scan_devices().unwrap().remove(0);
    assert_eq!(
        backend
            .start_operation(
                OperationId::new("op:firmware-replay").unwrap(),
                OperationRequest::FirmwareUpdate {
                    device_id: replay_snapshot.id,
                    device_revision: replay_snapshot.revision,
                    firmware_file_token: token,
                },
                ServiceEventSink::new(mpsc::sync_channel(2).0, crashes.clone()),
            )
            .unwrap_err()
            .as_str(),
        "firmware-image-not-registered"
    );
    let commands = &state.lock().unwrap().commands;
    assert_eq!(
        commands
            .iter()
            .filter(|command| command.starts_with(&[0x3B, 0x04]))
            .count(),
        17
    );
    assert_eq!(
        commands
            .iter()
            .filter(|command| command.starts_with(&[0x3B, 0x05]))
            .count(),
        1
    );
    assert!(crashes.observe().is_ok());
}

/// Registration fails closed on legacy format, offset abuse, incompleteness, and invalid images.
#[test]
fn firmware_registration_drops_every_invalid_sequence() {
    let state = Arc::new(Mutex::new(ModePlatformState {
        drive_mode: 1,
        firmware_finalize_unknown: 0,
        firmware_revision: 283,
        firmware_target_revision: 283,
        firmware_target_drive_mode: None,
        firmware_reset_delay: 0,
        firmware_cache_discovery: false,
        firmware_activation_scans: None,
        firmware_rebind_failures: 0,
        post_reset_opens: None,
        firmware_probe_failures: 0,
        post_reset_inquiries: 0,
        firmware_nonretryable_failure: false,
        firmware_transfer_failures: 0,
        manufacturing_fault: Default::default(),
        #[cfg(unix)]
        manufacturing_backups: Vec::new(),
        sata_mode: 2,
        commands: Vec::new(),
    }));
    let mut backend = HardwareServiceBackend::new(
        ServicePlatform::Linux,
        ModePlatform {
            state: Arc::clone(&state),
        },
    );
    let legacy = FirmwareFileToken::new("firmware:legacy").unwrap();
    assert_eq!(
        backend
            .begin_firmware_registration(legacy, "BIP".to_owned(), 4, None)
            .unwrap_err()
            .as_str(),
        "legacy-bip-format-unproven"
    );

    let reordered = FirmwareFileToken::new("firmware:reordered").unwrap();
    backend
        .begin_firmware_registration(reordered.clone(), "BIN".to_owned(), 4, None)
        .unwrap();
    assert_eq!(
        backend
            .append_firmware_registration(reordered.clone(), 1, vec![1, 2])
            .unwrap_err()
            .as_str(),
        "firmware-registration-invalid"
    );
    assert_eq!(
        backend
            .append_firmware_registration(reordered, 0, vec![1, 2])
            .unwrap_err()
            .as_str(),
        "firmware-registration-invalid"
    );

    let incomplete = FirmwareFileToken::new("firmware:incomplete").unwrap();
    backend
        .begin_firmware_registration(incomplete.clone(), "BIN".to_owned(), 4, None)
        .unwrap();
    backend
        .append_firmware_registration(incomplete.clone(), 0, vec![1, 2])
        .unwrap();
    assert_eq!(
        backend
            .commit_firmware_registration(incomplete)
            .unwrap_err()
            .as_str(),
        "firmware-registration-incomplete"
    );

    let invalid = FirmwareFileToken::new("firmware:invalid-image").unwrap();
    backend
        .begin_firmware_registration(invalid.clone(), "BIN".to_owned(), 4, None)
        .unwrap();
    backend
        .append_firmware_registration(invalid.clone(), 0, vec![1, 2, 3, 4])
        .unwrap();
    assert_eq!(
        backend
            .commit_firmware_registration(invalid)
            .unwrap_err()
            .as_str(),
        "firmware-image-invalid"
    );
    assert!(state.lock().unwrap().commands.is_empty());
}

/// The same bounded registration contract is independent of Electron host spelling.
#[test]
fn firmware_registration_is_portable_across_service_platforms() {
    for (index, platform) in [
        ServicePlatform::Darwin,
        ServicePlatform::Linux,
        ServicePlatform::Win32,
    ]
    .into_iter()
    .enumerate()
    {
        let state = Arc::new(Mutex::new(ModePlatformState {
            drive_mode: 1,
            firmware_finalize_unknown: 0,
            firmware_revision: 283,
            firmware_target_revision: 283,
            firmware_target_drive_mode: None,
            firmware_reset_delay: 0,
            firmware_cache_discovery: false,
            firmware_activation_scans: None,
            firmware_rebind_failures: 0,
            post_reset_opens: None,
            firmware_probe_failures: 0,
            post_reset_inquiries: 0,
            firmware_nonretryable_failure: false,
            firmware_transfer_failures: 0,
            manufacturing_fault: Default::default(),
            #[cfg(unix)]
            manufacturing_backups: Vec::new(),
            sata_mode: 2,
            commands: Vec::new(),
        }));
        let mut backend = HardwareServiceBackend::new(platform, ModePlatform { state });
        let snapshot = backend.scan_devices().unwrap().remove(0);
        assert_eq!(
            snapshot.capabilities[&OperationKind::FirmwareUpdate].state,
            crate::model::CapabilityState::Available
        );
        let token = FirmwareFileToken::new(format!("firmware:portable-{index}")).unwrap();
        backend
            .begin_firmware_registration(token.clone(), "BIN".to_owned(), 4, None)
            .unwrap();
        backend.abort_firmware_registration(&token).unwrap();
    }
}
