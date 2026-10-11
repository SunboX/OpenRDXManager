// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Closed Linux mappings and explicitly opted-in read-only physical preflight.

use super::*;

/// The factory reads and receiver queries must reach the native semantic boundary.
#[test]
fn factory_record_and_interlock_queries_have_read_only_native_mappings() {
    for command in [
        crate::protocol::openrdx_manufacturing_record_first(),
        crate::protocol::openrdx_manufacturing_record_second(),
        crate::protocol::openrdx_manufacturing_restore_capability(),
        crate::protocol::openrdx_serial_capability(),
    ] {
        for timeout in [1, 30_000, 300_000] {
            let command = command.clone().with_timeout_ms(timeout).unwrap();
            let packet = build_sg_io(&command).unwrap();
            assert_eq!(packet.risk, RiskClass::ReadOnly);
            assert!(native_operation(&packet).is_ok());
            let mut sense = vec![0; 18];
            sense[0] = 0x70;
            sense[2] = 5;
            sense[7] = 10;
            sense[12] = 0x24;
            let rejected = NativeSgCompletion::device(
                SgIoStatus::new(2, 1, 0, 0, DRIVER_SENSE, SG_INFO_CHECK),
                command.data().len() as i32,
                command.data().to_vec(),
                sense.len(),
                sense,
            );
            assert!(matches!(
                convert_sg_completion(&packet, rejected),
                CommandDispatch::DefinitelyRejected(_)
            ));
        }
    }
}

/// Supporting fixed reads must not accidentally authorize factory writes or other TI reads.
#[test]
fn factory_mutations_and_unmapped_reads_remain_rejected() {
    for command in [
        crate::protocol::openrdx_operational_state_record(),
        crate::protocol::openrdx_manufacturing_sector_chunk(2).unwrap(),
        crate::protocol::compatibility_receiver_header_setup(),
    ] {
        let packet = build_sg_io(&command).unwrap();
        assert_eq!(packet.risk, RiskClass::Critical);
        assert!(matches!(
            native_operation(&packet),
            Err(rdx_linux_native::NativeError::InvalidRequest)
        ));
    }
}

/// Reads an explicitly selected empty dock twice through production discovery and binding.
/// Never registers an image, backs up/restores records, or transfers/finalizes firmware.
#[test]
#[ignore = "Requires explicit OPENRDX_READ_ONLY_DEVICE_ID and exclusive physical dock access"]
fn connected_linux_manufacturing_preflight_read_only() {
    let id = crate::model::DeviceId::new(
        std::env::var("OPENRDX_READ_ONLY_DEVICE_ID").expect("explicit selected dock ID"),
    )
    .unwrap();
    let privileged = rdx_linux_native::current_process_is_privileged_service();
    assert!(
        privileged,
        "explicit physical read requires a privileged process"
    );
    let mut backend = LinuxBackend::native_with_context(
        ServiceExecutionContext::privileged_direct_cli(privileged),
    );
    let mut registry = crate::platform::DeviceRegistry::new();
    crate::platform::discover_validated_device_report(&mut backend, &mut registry).unwrap();
    let snapshot = registry
        .snapshot(&id)
        .expect("selected dock must be discovered");
    let mut resolved = registry
        .resolve(&mut backend, &id, snapshot.revision)
        .unwrap();
    let (_, installed, media_present) = resolved.firmware_facts().unwrap();
    assert!(!media_present, "cartridge bay must be empty");
    let first = resolved
        .manufacturing_record()
        .expect("complete first factory-record read");
    let second = resolved
        .manufacturing_record()
        .expect("complete repeated factory-record read");
    first
        .verify(&second)
        .expect("factory records must remain identical");
    if matches!(installed.get(), 110 | 111) {
        for command in [
            crate::protocol::openrdx_manufacturing_restore_capability(),
            crate::protocol::openrdx_serial_capability(),
        ] {
            assert!(
                resolved
                    .execute_firmware(&command)
                    .response()
                    .is_some_and(|response| response.data().is_empty()),
                "receiver interlock query must succeed"
            );
        }
    }
    resolved
        .revalidate_identity()
        .expect("same exact dock must remain bound");
    println!(
        "Repeated 256-byte factory reads and applicable receiver queries passed; hardware writes=0"
    );
}

/// Exercises the real private host backup gate on one explicitly selected empty dock.
/// Device commands remain read-only; the only writes are the retained recovery files.
#[test]
#[ignore = "Requires explicit OPENRDX_READ_ONLY_DEVICE_ID; saves a private host backup"]
fn connected_linux_manufacturing_backup_preflight() {
    let id = crate::model::DeviceId::new(
        std::env::var("OPENRDX_READ_ONLY_DEVICE_ID").expect("explicit selected dock ID"),
    )
    .unwrap();
    let privileged = rdx_linux_native::current_process_is_privileged_service();
    assert!(
        privileged,
        "physical backup preflight requires privileged process authority"
    );
    let mut backend = LinuxBackend::native_with_context(
        ServiceExecutionContext::privileged_direct_cli(privileged),
    );
    let mut registry = crate::platform::DeviceRegistry::new();
    crate::platform::discover_validated_device_report(&mut backend, &mut registry).unwrap();
    let snapshot = registry
        .snapshot(&id)
        .expect("selected dock must be discovered");
    let mut resolved = registry
        .resolve(&mut backend, &id, snapshot.revision)
        .unwrap();
    let (_, _, media_present) = resolved.firmware_facts().unwrap();
    assert!(!media_present, "cartridge bay must be empty");
    let record = resolved
        .manufacturing_record()
        .expect("complete factory-record read");
    backend
        .backup_manufacturing_record(&id, record.bytes())
        .expect("durable private host backup");
    let entries = backend
        .manufacturing_backups(&id)
        .expect("verified host inventory");
    let entry = entries
        .iter()
        .find(|entry| entry.device_id == id)
        .expect("selected dock's retained backup");
    let loaded = backend
        .load_manufacturing_backup(&entry.backup_id)
        .expect("independent backup readback");
    assert_eq!(loaded.bytes.as_ref(), record.bytes());
    record
        .verify(
            &resolved
                .manufacturing_record()
                .expect("same-lease read after saving"),
        )
        .unwrap();
    println!(
        "Complete private backup, independent file readback and same-lease dock comparison passed; device writes=0"
    );
}
