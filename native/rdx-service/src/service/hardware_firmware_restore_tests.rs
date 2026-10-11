// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vendor-image restoration through the installed OpenRDX receiver.

use super::*;
use crate::service::runtime_loop::drain_backend_signals;

/// A vendor image still needs the installed receiver's delayed activation wait.
/// Exercise the real registration, worker, service, and publication contracts;
/// the only substitute is the physical transport and its reset observations.
#[test]
fn vendor_restore_waits_for_openrdx_receiver_activation_before_readback() {
    for (installed, target, unknown_finalizers, succeeds) in [
        (107, 283, 0, true),
        (106, 283, 0, true),
        (1, 283, 0, true),
        (107, 283, 1, true),
        (107, 106, 0, false),
    ] {
        let state = Arc::new(Mutex::new(ModePlatformState {
            drive_mode: 1,
            firmware_finalize_unknown: unknown_finalizers,
            firmware_revision: installed,
            firmware_target_revision: target,
            firmware_target_drive_mode: None,
            firmware_reset_delay: 5,
            firmware_cache_discovery: true,
            firmware_activation_scans: None,
            firmware_rebind_failures: 1_000,
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
            ServicePlatform::Darwin,
            ModePlatform {
                state: Arc::clone(&state),
            },
        );
        let snapshot = backend.scan_devices().unwrap().remove(0);
        let bytes = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../original-inputs/RDX2E__STD__F-0283.bin"),
        )
        .unwrap();
        let token = FirmwareFileToken::new("firmware:vendor-restore").unwrap();
        backend
            .begin_firmware_registration(token.clone(), "BIN".to_owned(), bytes.len(), None)
            .unwrap();
        for (index, chunk) in bytes.chunks(4096).enumerate() {
            backend
                .append_firmware_registration(token.clone(), index * 4096, chunk.to_vec())
                .unwrap();
        }
        backend.commit_firmware_registration(token.clone()).unwrap();
        let (sender, receiver) = mpsc::sync_channel(16);
        let crashes = crate::service::crash::CrashAdmission::new();
        let sink = ServiceEventSink::new(sender, crashes.clone());
        let mut runtime = crate::service::ServiceRuntime::new(backend, sink.clone());
        let initial = runtime.list_devices().unwrap();
        let operation_id = OperationId::new("op:vendor-restore").unwrap();
        let request = OperationRequest::FirmwareUpdate {
            device_id: snapshot.id.clone(),
            device_revision: snapshot.revision,
            firmware_file_token: token,
        };
        runtime.active =
            Some(crate::service::ActiveOperation::new(operation_id.clone(), &request).unwrap());
        runtime
            .backend
            .start_operation(operation_id.clone(), request, sink)
            .unwrap();
        runtime.backend.release_operation(&operation_id).unwrap();
        let deadline = Instant::now() + Duration::from_secs(40);
        let mut output = Vec::new();
        while runtime.active.is_some() {
            assert!(Instant::now() < deadline, "restoration did not finish");
            drain_backend_signals(&mut runtime, &receiver, &crashes, &mut output).unwrap();
            if runtime.active.is_some() {
                assert_eq!(runtime.list_devices().unwrap(), initial);
            }
            thread::sleep(Duration::from_millis(10));
        }
        let mut reader = std::io::Cursor::new(output);
        let mut frames = Vec::new();
        while let Some(frame) = crate::service::framing::read_frame(&mut reader).unwrap() {
            frames.push(frame);
        }
        let terminal = &frames.last().unwrap()["event"];
        assert_eq!(
            terminal["state"],
            if succeeds { "succeeded" } else { "failed" },
            "installed={installed} target={target}: {terminal}"
        );
        let inventory = runtime.list_devices().unwrap();
        if succeeds {
            assert_eq!(inventory["devices"][0]["drive"]["firmwareRevision"], "0283");
            let published = &frames[frames.len() - 2]["event"];
            assert_eq!(published["type"], "list");
            assert_eq!(published["devices"], inventory["devices"]);
        } else {
            assert_eq!(
                inventory, initial,
                "incorrect readback cannot publish success"
            );
        }
        let state = state.lock().unwrap();
        #[cfg(unix)]
        assert_eq!(
            state.manufacturing_backups.len(),
            1,
            "vendor firmware also requires a durable pre-update backup"
        );
        assert_eq!(state.firmware_rebind_failures, 1_000);
        let writes = state
            .commands
            .iter()
            .filter(|cdb| cdb[0] == 0x3B)
            .collect::<Vec<_>>();
        assert_eq!(
            writes.len(),
            17,
            "reconnect must not resend a committed image"
        );
        assert_eq!(&writes.last().unwrap()[..2], &[0x3B, 0x05]);
    }
}
