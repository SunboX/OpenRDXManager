// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Concurrent public inventory reads during the real firmware worker lifecycle.

use super::*;
use crate::service::runtime_loop::drain_backend_signals;

/// A status reader must never see a private reconnect scan under an old list revision.
#[test]
fn firmware_reconnect_keeps_public_inventory_stable_until_terminal_publication() {
    let state = Arc::new(Mutex::new(ModePlatformState {
        drive_mode: 1,
        firmware_finalize_unknown: 0,
        firmware_revision: 107,
        firmware_target_revision: 107,
        firmware_target_drive_mode: Some(2),
        firmware_reset_delay: 0,
        firmware_cache_discovery: true,
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
    let mut backend = HardwareServiceBackend::new(ServicePlatform::Darwin, ModePlatform { state });
    let snapshot = backend.scan_devices().unwrap().remove(0);
    let (bytes, metadata) = crate::firmware::openrdx_test_image();
    let token = FirmwareFileToken::new("firmware:inventory-update").unwrap();
    backend
        .begin_firmware_registration(token.clone(), "BIN".to_owned(), bytes.len(), Some(metadata))
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
    let operation_id = OperationId::new("op:inventory-update").unwrap();
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
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut output = Vec::new();
    let mut reads_while_active = 0;
    while runtime.active.is_some() {
        assert!(Instant::now() < deadline, "firmware worker did not finish");
        drain_backend_signals(&mut runtime, &receiver, &crashes, &mut output).unwrap();
        let listed = runtime
            .list_devices()
            .expect("an ordinary status read must not terminate the service during reconnect");
        if runtime.active.is_some() {
            assert_eq!(
                listed, initial,
                "private reconnect observations are not public inventory events"
            );
            reads_while_active += 1;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(reads_while_active > 1);
    let final_list = runtime.list_devices().unwrap();
    assert!(
        final_list["listRevision"].as_u64().unwrap() > initial["listRevision"].as_u64().unwrap()
    );
    assert_eq!(
        final_list["devices"][0]["drive"]["operationMode"],
        "Fixed disk"
    );
    let mut reader = std::io::Cursor::new(output);
    let mut frames = Vec::new();
    while let Some(frame) = crate::service::framing::read_frame(&mut reader).unwrap() {
        frames.push(frame);
    }
    assert_eq!(frames.last().unwrap()["event"]["state"], "succeeded");
    let inventory = &frames[frames.len() - 2]["event"];
    assert_eq!(inventory["type"], "list");
    assert_eq!(inventory["listRevision"], final_list["listRevision"]);
    assert_eq!(inventory["devices"], final_list["devices"]);
}
