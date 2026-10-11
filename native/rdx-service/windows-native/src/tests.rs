// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::sync::atomic::{AtomicUsize, Ordering};

mod formatted_volume;

use super::endpoint::{
    NamespaceOwnership, PipeInstancePolicy, named_pipe_client_access_contract, protected_pipe_sddl,
};
use super::{
    AuthorityEvidence, DataDirection, DeviceIdentityProof, NativeError, Readiness, ResourceCloser,
    ResourceGuard, ScsiOperation, ServiceIdentityEvidence, ServiceRuntimeEvidence,
    ServiceStatusQueryAction, ServiceStatusQueryResult, StorageDeviceIdentity, VolumeExtent,
    VolumeInventory, VolumeMembership, VolumeMutationIo, VolumeMutationOutcome, VolumeRecord,
    VolumeTopology, WindowsServiceLifecycle, WindowsServiceState, aligned_transfer_layout,
    bounded_returned_length, classify_volume_probe, decode_recipe, drive_letters_from_multi_sz,
    exact_endpoint_service_binary_path, exact_service_binary_path, execute_safe_dismount,
    mount_paths_from_multi_sz, parse_adapter_descriptor, service_status_query_action,
    volume_extent_buffer_length, volume_extents_contain_disk, volume_extents_from_bytes,
};

static RESOURCE_CLOSE_COUNT: AtomicUsize = AtomicUsize::new(0);
static VOLUME_CLOSE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// SCM lifecycle gates all connection work and drains ownership before STOPPED.
#[test]
fn windows_service_lifecycle_publishes_exact_states_and_closes_admission_on_stop() {
    let lifecycle = WindowsServiceLifecycle::new(8).expect("bounded service lifecycle");
    let starting = lifecycle.snapshot();
    assert_eq!(starting.state(), WindowsServiceState::StartPending);
    assert_eq!(
        (starting.active_connections(), starting.served_connections()),
        (0, 0)
    );
    assert!(!starting.accepts_stop_or_shutdown());

    assert_eq!(
        lifecycle.mark_running(),
        Err(NativeError::AccessDenied),
        "SCM RUNNING cannot precede the first authoritative pipe instance"
    );
    lifecycle
        .mark_endpoint_bound()
        .expect("authoritative first pipe instance is retained");

    lifecycle
        .mark_running()
        .expect("SCM registration completed");
    assert_eq!(lifecycle.snapshot().state(), WindowsServiceState::Running);
    assert!(lifecycle.snapshot().accepts_stop_or_shutdown());
    let connection = lifecycle
        .begin_connection()
        .expect("running service admits bounded connection ownership");
    assert_eq!(lifecycle.snapshot().active_connections(), 1);

    assert!(lifecycle.request_stop());
    assert!(!lifecycle.request_stop(), "stop is idempotent");
    let stopping = lifecycle.snapshot();
    assert_eq!(stopping.state(), WindowsServiceState::StopPending);
    assert!(!stopping.accepts_stop_or_shutdown());
    assert_eq!(
        lifecycle.begin_connection().unwrap_err(),
        NativeError::AccessDenied,
        "no work may be admitted after STOP/SHUTDOWN"
    );
    assert_eq!(lifecycle.finish(0), Err(NativeError::Busy));

    drop(connection);
    lifecycle
        .finish(0)
        .expect("all connection ownership drained");
    let stopped = lifecycle.snapshot();
    assert_eq!(stopped.state(), WindowsServiceState::Stopped);
    assert_eq!(stopped.active_connections(), 0);
    assert_eq!(stopped.win32_exit_code(), 0);
}

/// The eight-instance limit is concurrent; sequential sessions do not retire the service.
#[test]
fn windows_service_admits_eighth_ninth_and_later_sequential_sessions() {
    let lifecycle = WindowsServiceLifecycle::new(8).expect("bounded service lifecycle");
    lifecycle
        .mark_endpoint_bound()
        .expect("authoritative first pipe instance is retained");
    lifecycle.mark_running().expect("running service");

    for expected in 1..=12 {
        let connection = lifecycle
            .begin_connection()
            .expect("later sequential session remains available");
        assert_eq!(lifecycle.snapshot().active_connections(), 1);
        assert_eq!(lifecycle.snapshot().served_connections(), expected);
        drop(connection);
    }

    let concurrent = (0..8)
        .map(|_| {
            lifecycle
                .begin_connection()
                .expect("bounded concurrent slot")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        lifecycle.begin_connection().unwrap_err(),
        NativeError::ResourceLimit
    );
    drop(concurrent);
    lifecycle
        .begin_connection()
        .expect("released concurrent capacity remains reusable");
}

/// The interactive manager receives only duplex client rights, never server creation.
#[test]
fn named_pipe_client_mask_excludes_every_server_creation_right() {
    let access = named_pipe_client_access_contract();

    assert_ne!(access.mask & access.read_data, 0);
    assert_ne!(access.mask & access.write_data, 0);
    assert_ne!(access.mask & access.synchronize, 0);
    assert_eq!(access.mask & access.create_pipe_instance, 0);
    assert_eq!(access.mask & access.generic_write, 0);
    let sddl = protected_pipe_sddl("S-1-5-21-1-2-3-1001");
    assert!(sddl.contains("(A;;0x00100183;;;S-1-5-21-1-2-3-1001)"));
    assert!(!sddl.contains("(A;;GA;;;S-1-5-21-1-2-3-1001)"));
}

/// Rolling pending instances keep authoritative namespace ownership across sessions.
#[test]
fn named_pipe_listener_retains_first_instance_state_across_accepted_sessions() {
    let mut ownership = NamespaceOwnership::new();

    assert_eq!(
        ownership.pending_policy(),
        PipeInstancePolicy::FirstExclusive
    );
    assert!(ownership.authority_retained());
    assert_eq!(ownership.competing_claim(), Err(NativeError::AccessDenied));
    ownership.roll_after_accept().unwrap();
    assert_eq!(ownership.pending_policy(), PipeInstancePolicy::Additional);
    assert!(ownership.authority_retained());
    assert_eq!(ownership.competing_claim(), Err(NativeError::AccessDenied));
    ownership.roll_after_accept().unwrap();
    assert!(ownership.authority_retained());
    ownership.stop();
    assert!(!ownership.authority_retained());
    assert_eq!(ownership.competing_claim(), Ok(()));
    assert_eq!(ownership.roll_after_accept(), Err(NativeError::Cancelled));
}

struct FakeCloser;

impl ResourceCloser<u32> for FakeCloser {
    fn close(_resource: u32) {
        RESOURCE_CLOSE_COUNT.fetch_add(1, Ordering::SeqCst);
    }
}

struct FakeVolumeCloser;

impl ResourceCloser<u32> for FakeVolumeCloser {
    fn close(_resource: u32) {
        VOLUME_CLOSE_COUNT.fetch_add(1, Ordering::SeqCst);
    }
}

struct FakeVolumeMutationIo {
    scans: VecDeque<Result<VolumeInventory, NativeError>>,
    events: Vec<&'static str>,
    retained_results: VecDeque<Result<(), NativeError>>,
    lock_result: Result<(), NativeError>,
    dismount_result: Result<(), NativeError>,
}

impl FakeVolumeMutationIo {
    fn new(scans: impl IntoIterator<Item = Result<VolumeInventory, NativeError>>) -> Self {
        Self {
            scans: scans.into_iter().collect(),
            events: Vec::new(),
            retained_results: VecDeque::from([Ok(())]),
            lock_result: Ok(()),
            dismount_result: Ok(()),
        }
    }
}

impl VolumeMutationIo for FakeVolumeMutationIo {
    fn revalidate_parent(&mut self) -> Result<(), NativeError> {
        self.events.push("parent");
        Ok(())
    }

    fn scan_complete(&mut self) -> Result<VolumeInventory, NativeError> {
        self.events.push("scan");
        self.scans
            .pop_front()
            .unwrap_or(Err(NativeError::EnumerationFailed))
    }

    fn revalidate_retained_volumes(&mut self) -> Result<(), NativeError> {
        self.events.push("retained");
        self.retained_results.pop_front().unwrap_or(Ok(()))
    }

    fn lock_retained_volumes(&mut self) -> Result<(), NativeError> {
        self.events.push("lock");
        self.lock_result
    }

    fn dismount_retained_volumes(&mut self) -> Result<(), NativeError> {
        self.events.push("dismount");
        self.dismount_result
    }
}

fn volume_record(
    key: &str,
    disk_number: u32,
    partition_number: u32,
    letter: char,
    target: bool,
) -> VolumeRecord {
    VolumeRecord::new(
        key.encode_utf16().collect(),
        VolumeTopology {
            storage: StorageDeviceIdentity {
                device_type: 7,
                device_number: disk_number,
                partition_number,
            },
            extents: vec![VolumeExtent {
                disk_number,
                starting_offset: i64::from(partition_number) * 1_048_576,
                extent_length: 8_388_608,
            }],
        },
        vec![letter],
        target,
    )
    .expect("complete fake volume record")
}

fn complete_volume_inventory(reverse: bool) -> VolumeInventory {
    let mut records = vec![
        volume_record("volume-system", 0, 1, 'C', false),
        volume_record("volume-rdx", 7, 1, 'E', true),
    ];
    if reverse {
        records.reverse();
    }
    VolumeInventory::new(records).expect("complete fake inventory")
}

/// Repeated scans tolerate enumeration order while keeping mutation immediately guarded.
#[test]
fn safe_dismount_runs_only_after_two_equal_complete_scans() {
    let retained = complete_volume_inventory(false);
    let mut io = FakeVolumeMutationIo::new([
        Ok(complete_volume_inventory(true)),
        Ok(complete_volume_inventory(false)),
    ]);

    assert_eq!(
        execute_safe_dismount(&mut io, &retained, 'E'),
        VolumeMutationOutcome::Succeeded,
    );
    assert_eq!(
        io.events,
        [
            "parent", "scan", "parent", "scan", "parent", "retained", "parent", "lock", "retained",
            "parent", "dismount",
        ]
    );
}

/// Any appearance, disappearance, topology change, or mount remap stops before mutation.
#[test]
fn safe_dismount_rejects_complete_inventory_drift_without_mutation() {
    let retained = complete_volume_inventory(false);
    let appeared = VolumeInventory::new(vec![
        volume_record("volume-system", 0, 1, 'C', false),
        volume_record("volume-rdx", 7, 1, 'E', true),
        volume_record("volume-new", 9, 1, 'F', false),
    ])
    .expect("appeared inventory");
    let disappeared = VolumeInventory::new(vec![volume_record("volume-rdx", 7, 1, 'E', true)])
        .expect("disappeared inventory");
    let remapped = VolumeInventory::new(vec![
        volume_record("volume-system", 0, 1, 'C', false),
        volume_record("volume-rdx", 7, 1, 'F', true),
    ])
    .expect("remapped inventory");
    let topology_changed = VolumeInventory::new(vec![
        volume_record("volume-system", 0, 1, 'C', false),
        volume_record("volume-rdx", 7, 2, 'E', true),
    ])
    .expect("changed topology inventory");

    for changed in [appeared, disappeared, remapped, topology_changed] {
        let mut io = FakeVolumeMutationIo::new([Ok(complete_volume_inventory(false)), Ok(changed)]);

        assert_eq!(
            execute_safe_dismount(&mut io, &retained, 'E'),
            VolumeMutationOutcome::NotAttempted(NativeError::DeviceRemoved),
        );
        assert!(!io.events.contains(&"lock"));
        assert!(!io.events.contains(&"dismount"));
    }
}

/// An uninspectable candidate or stale selected association cannot reach a mutation call.
#[test]
fn safe_dismount_fails_closed_for_busy_scan_and_wrong_selected_mount() {
    let retained = complete_volume_inventory(false);
    let mut busy = FakeVolumeMutationIo::new([Err(NativeError::Busy)]);
    assert_eq!(
        execute_safe_dismount(&mut busy, &retained, 'E'),
        VolumeMutationOutcome::NotAttempted(NativeError::Busy),
    );
    assert_eq!(busy.events, ["parent", "scan"]);

    let mut wrong_mount = FakeVolumeMutationIo::new([
        Ok(complete_volume_inventory(false)),
        Ok(complete_volume_inventory(false)),
    ]);
    assert_eq!(
        execute_safe_dismount(&mut wrong_mount, &retained, 'F'),
        VolumeMutationOutcome::NotAttempted(NativeError::DeviceRemoved),
    );
    assert!(!wrong_mount.events.contains(&"lock"));
    assert!(!wrong_mount.events.contains(&"dismount"));
}

/// A changed original pinned handle fails before any lock or dismount request.
#[test]
fn safe_dismount_revalidates_retained_handles_before_mutation() {
    let retained = complete_volume_inventory(false);
    let mut io = FakeVolumeMutationIo::new([
        Ok(complete_volume_inventory(false)),
        Ok(complete_volume_inventory(false)),
    ]);
    io.retained_results = VecDeque::from([Err(NativeError::DeviceRemoved)]);

    assert_eq!(
        execute_safe_dismount(&mut io, &retained, 'E'),
        VolumeMutationOutcome::NotAttempted(NativeError::DeviceRemoved),
    );
    assert!(!io.events.contains(&"lock"));
    assert!(!io.events.contains(&"dismount"));
}

/// The locked handle topology is queried again immediately before dismount.
#[test]
fn safe_dismount_revalidates_locked_handles_before_dismount() {
    let retained = complete_volume_inventory(false);
    let mut io = FakeVolumeMutationIo::new([
        Ok(complete_volume_inventory(false)),
        Ok(complete_volume_inventory(false)),
    ]);
    io.retained_results = VecDeque::from([Ok(()), Err(NativeError::DeviceRemoved)]);

    assert_eq!(
        execute_safe_dismount(&mut io, &retained, 'E'),
        VolumeMutationOutcome::NotAttempted(NativeError::DeviceRemoved),
    );
    assert!(io.events.contains(&"lock"));
    assert!(!io.events.contains(&"dismount"));
}

/// A dismount API failure is ambiguous only after every validation and lock succeeded.
#[test]
fn safe_dismount_preserves_post_call_completion_uncertainty() {
    let retained = complete_volume_inventory(false);
    let mut io = FakeVolumeMutationIo::new([
        Ok(complete_volume_inventory(false)),
        Ok(complete_volume_inventory(false)),
    ]);
    io.dismount_result = Err(NativeError::TimedOut);

    assert_eq!(
        execute_safe_dismount(&mut io, &retained, 'E'),
        VolumeMutationOutcome::CompletionUnknown(NativeError::TimedOut),
    );
    assert_eq!(io.events.last(), Some(&"dismount"));
}

/// A successful status query trusts the initialized structure, never bytes-needed output.
#[test]
fn successful_service_status_query_ignores_bytes_needed() {
    for bytes_needed in [0, 1, 36, u32::MAX] {
        assert_eq!(
            service_status_query_action(ServiceStatusQueryResult::Success, bytes_needed, 36),
            ServiceStatusQueryAction::Accept,
        );
    }
}

/// Only a coherent bounded insufficient-buffer failure may request one larger query.
#[test]
fn failed_service_status_query_retries_only_documented_bounded_size() {
    assert_eq!(
        service_status_query_action(ServiceStatusQueryResult::InsufficientBuffer, 72, 36,),
        ServiceStatusQueryAction::Retry(72),
    );
    for bytes_needed in [0, 35, 36, 8_193, u32::MAX] {
        assert_eq!(
            service_status_query_action(
                ServiceStatusQueryResult::InsufficientBuffer,
                bytes_needed,
                36,
            ),
            ServiceStatusQueryAction::Reject,
        );
    }
    for bytes_needed in [0, 72, u32::MAX] {
        assert_eq!(
            service_status_query_action(ServiceStatusQueryResult::Failure, bytes_needed, 36),
            ServiceStatusQueryAction::Reject,
        );
    }
}

/// Returns complete evidence for the expected service owning the current process.
fn bound_service_evidence() -> ServiceIdentityEvidence {
    let status = ServiceRuntimeEvidence {
        running: true,
        process_id: 42,
        own_process: true,
    };
    ServiceIdentityEvidence {
        installed: true,
        current_pid: 42,
        status_before: status,
        status_after: status,
        config_stable: true,
        demand_start: true,
        binary_matches: true,
        token_local_service: true,
    }
}

/// Running registration metadata is not authority when another process owns it.
#[test]
fn elevated_gui_and_unrelated_running_service_are_not_authorized() {
    let mut service = bound_service_evidence();
    service.status_before.process_id = 99;
    service.status_after.process_id = 99;
    let evidence = AuthorityEvidence {
        service,
        process_elevated: true,
        exact_device_access: false,
    };

    assert!(!evidence.current_process_authorized());
}

/// Configuration churn, wrong runtime token/type, and PID churn all fail closed.
#[test]
fn unstable_or_wrong_runtime_service_evidence_fails_closed() {
    let base = bound_service_evidence();
    let mut variants = [base; 6];
    variants[0].config_stable = false;
    variants[1].token_local_service = false;
    variants[2].status_before.own_process = false;
    variants[2].status_after.own_process = false;
    variants[3].status_after.process_id = 99;
    variants[4].demand_start = false;
    variants[5].binary_matches = false;

    for service in variants {
        let evidence = AuthorityEvidence {
            service,
            process_elevated: false,
            exact_device_access: false,
        };
        assert!(!evidence.current_process_authorized());
    }
}

/// The expected running service process is authorized without conflating elevation.
#[test]
fn current_verified_service_process_is_authorized() {
    let evidence = AuthorityEvidence {
        service: bound_service_evidence(),
        process_elevated: false,
        exact_device_access: false,
    };

    assert!(evidence.current_process_authorized());
    let readiness = Readiness::from_authority(true, evidence);
    assert!(readiness.adapter_available());
    assert!(readiness.service_installed());
    assert!(readiness.service_running());
    assert!(readiness.current_process_authorized());
}

/// Direct authority requires both token proof and exact device-access proof.
#[test]
fn direct_process_authority_requires_both_independent_proofs() {
    let mut service = bound_service_evidence();
    service.status_before.running = false;
    service.status_after.running = false;
    for (process_elevated, exact_device_access, expected) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (true, true, true),
    ] {
        let evidence = AuthorityEvidence {
            service,
            process_elevated,
            exact_device_access,
        };
        assert_eq!(evidence.current_process_authorized(), expected);
    }
}

/// Service configuration accepts one argument-free local absolute executable path only.
#[test]
fn service_binary_path_parser_rejects_relative_remote_and_argument_forms() {
    assert_eq!(
        exact_service_binary_path(r#""C:\Program Files\OpenRDX\openrdx-hardware.exe""#),
        Some(r"C:\Program Files\OpenRDX\openrdx-hardware.exe")
    );
    assert_eq!(
        exact_service_binary_path(r"D:\OpenRDX\openrdx-hardware.exe"),
        Some(r"D:\OpenRDX\openrdx-hardware.exe")
    );
    assert_eq!(
        exact_service_binary_path(r"\\?\C:\OpenRDX\openrdx-hardware.exe"),
        Some(r"\\?\C:\OpenRDX\openrdx-hardware.exe")
    );

    for rejected in [
        "",
        "openrdx-hardware.exe",
        r".\openrdx-hardware.exe",
        r"%ProgramFiles%\OpenRDX\openrdx-hardware.exe",
        r"\\server\share\openrdx-hardware.exe",
        r#""C:\OpenRDX\openrdx-hardware.exe" --service"#,
        r"C:\Program Files\OpenRDX\openrdx-hardware.exe",
    ] {
        assert_eq!(exact_service_binary_path(rejected), None);
    }
}

/// Endpoint service configuration accepts only the exact production argument suffix.
#[test]
fn endpoint_service_command_parser_requires_fixed_named_pipe_mode() {
    assert_eq!(
        exact_endpoint_service_binary_path(
            r#""C:\Program Files\OpenRDX\openrdx-hardware.exe" --service-mode named-pipe --protocol-version 1"#
        ),
        Some(r"C:\Program Files\OpenRDX\openrdx-hardware.exe")
    );
    for rejected in [
        r#""C:\OpenRDX\openrdx-hardware.exe""#,
        r#""C:\OpenRDX\openrdx-hardware.exe" --service-mode stdio --protocol-version 1"#,
        r#""C:\OpenRDX\openrdx-hardware.exe" --service-mode named-pipe --protocol-version 1 extra"#,
        r#"\\server\share\openrdx-hardware.exe --service-mode named-pipe --protocol-version 1"#,
    ] {
        assert_eq!(exact_endpoint_service_binary_path(rejected), None);
    }
}

/// Moving and early-returning an owned native resource closes it exactly once.
#[test]
fn resource_guard_closes_exactly_once_on_error_paths() {
    RESOURCE_CLOSE_COUNT.store(0, Ordering::SeqCst);

    fn fail_after_move(resource: ResourceGuard<u32, FakeCloser>) -> Result<(), &'static str> {
        let _moved = resource;
        Err("injected failure")
    }

    let guard = ResourceGuard::<u32, FakeCloser>::new(42);
    assert_eq!(fail_after_move(guard), Err("injected failure"));
    assert_eq!(RESOURCE_CLOSE_COUNT.load(Ordering::SeqCst), 1);
}

/// A retained exact instance rejects disk-number reuse, remapping, and handle replacement.
#[test]
fn exact_identity_proof_rejects_hotplug_reuse_and_swap() {
    let recipe = decode_recipe(OsStr::new(
        "win1:00000007:00550053004200530054004F0052005C005200440058",
    ))
    .expect("exact opaque recipe");
    let proof = DeviceIdentityProof::new(recipe, 7).expect("initial exact handle");

    assert_eq!(proof.revalidate(r"USBSTOR\RDX", 7, 7), Ok(()));
    assert_eq!(
        proof.revalidate(r"USBSTOR\OTHER", 7, 7),
        Err(NativeError::DeviceRemoved)
    );
    assert_eq!(
        proof.revalidate(r"USBSTOR\RDX", 8, 7),
        Err(NativeError::DeviceRemoved)
    );
    assert_eq!(
        proof.revalidate(r"USBSTOR\RDX", 7, 8),
        Err(NativeError::DeviceRemoved)
    );
}

/// Complete inspection distinguishes one exact target volume from unrelated media.
#[test]
fn volume_probe_fails_closed_for_uninspectable_and_ambiguous_candidates() {
    let target = VolumeTopology {
        storage: StorageDeviceIdentity {
            device_type: 7,
            device_number: 7,
            partition_number: 1,
        },
        extents: vec![VolumeExtent {
            disk_number: 7,
            starting_offset: 1_048_576,
            extent_length: 8_388_608,
        }],
    };
    assert_eq!(
        classify_volume_probe(Ok(target.clone()), 7),
        Ok(VolumeMembership::Target(target))
    );
    assert_eq!(
        classify_volume_probe(Err(NativeError::Busy), 7),
        Err(NativeError::Busy)
    );
    assert_eq!(
        classify_volume_probe(Err(NativeError::DeviceRemoved), 7),
        Err(NativeError::DeviceRemoved)
    );

    let unrelated = VolumeTopology {
        storage: StorageDeviceIdentity {
            device_type: 7,
            device_number: 8,
            partition_number: 1,
        },
        extents: vec![VolumeExtent {
            disk_number: 8,
            starting_offset: 1_048_576,
            extent_length: 8_388_608,
        }],
    };
    assert_eq!(
        classify_volume_probe(Ok(unrelated), 7),
        Ok(VolumeMembership::Unrelated)
    );

    let unrelated_spanned = VolumeTopology {
        storage: StorageDeviceIdentity {
            device_type: 7,
            device_number: 8,
            partition_number: 1,
        },
        extents: vec![
            VolumeExtent {
                disk_number: 8,
                starting_offset: 1_048_576,
                extent_length: 8_388_608,
            },
            VolumeExtent {
                disk_number: 9,
                starting_offset: 2_048_576,
                extent_length: 4_194_304,
            },
        ],
    };
    assert_eq!(
        classify_volume_probe(Ok(unrelated_spanned), 7),
        Err(NativeError::EnumerationFailed)
    );

    let inconsistent = VolumeTopology {
        storage: StorageDeviceIdentity {
            device_type: 7,
            device_number: 8,
            partition_number: 1,
        },
        extents: vec![VolumeExtent {
            disk_number: 9,
            starting_offset: 1_048_576,
            extent_length: 8_388_608,
        }],
    };
    assert_eq!(
        classify_volume_probe(Ok(inconsistent), 7),
        Err(NativeError::EnumerationFailed)
    );

    let spanned = VolumeTopology {
        storage: StorageDeviceIdentity {
            device_type: 7,
            device_number: 7,
            partition_number: 1,
        },
        extents: vec![
            VolumeExtent {
                disk_number: 7,
                starting_offset: 1_048_576,
                extent_length: 8_388_608,
            },
            VolumeExtent {
                disk_number: 8,
                starting_offset: 2_048_576,
                extent_length: 4_194_304,
            },
        ],
    };
    assert_eq!(
        classify_volume_probe(Ok(spanned), 7),
        Err(NativeError::EnumerationFailed)
    );
}

/// A retained handle's full storage and extent snapshot must remain byte-for-byte stable.
#[test]
fn retained_volume_topology_rejects_changes_and_extent_reordering() {
    let snapshot = VolumeTopology {
        storage: StorageDeviceIdentity {
            device_type: 7,
            device_number: 7,
            partition_number: 1,
        },
        extents: vec![
            VolumeExtent {
                disk_number: 7,
                starting_offset: 1_048_576,
                extent_length: 8_388_608,
            },
            VolumeExtent {
                disk_number: 7,
                starting_offset: 9_437_184,
                extent_length: 4_194_304,
            },
        ],
    };
    assert_eq!(snapshot.revalidate(&snapshot), Ok(()));

    let mut changed = snapshot.clone();
    changed.extents[0].extent_length -= 512;
    assert_eq!(
        snapshot.revalidate(&changed),
        Err(NativeError::DeviceRemoved)
    );

    let mut reordered = snapshot.clone();
    reordered.extents.reverse();
    assert_eq!(
        snapshot.revalidate(&reordered),
        Err(NativeError::DeviceRemoved)
    );

    let mut renumbered = snapshot.clone();
    renumbered.storage.partition_number = 2;
    assert_eq!(
        snapshot.revalidate(&renumbered),
        Err(NativeError::DeviceRemoved)
    );
}

/// Resize arithmetic accepts the documented extent count and rejects hostile bounds.
#[test]
fn volume_extent_resize_is_checked_and_bounded() {
    assert_eq!(volume_extent_buffer_length(1, 8, 24, 65_536), Ok(32));
    assert_eq!(volume_extent_buffer_length(2, 8, 24, 65_536), Ok(56));
    assert_eq!(
        volume_extent_buffer_length(0, 8, 24, 65_536),
        Err(NativeError::EnumerationFailed)
    );
    assert_eq!(
        volume_extent_buffer_length(u32::MAX, 8, 24, 65_536),
        Err(NativeError::ResourceLimit)
    );
    assert_eq!(
        volume_extent_buffer_length(3_000, 8, 24, 65_536),
        Err(NativeError::ResourceLimit)
    );
}

/// Authorized fake volume handles remain pinned until the whole lease set drops.
#[test]
fn pinned_volume_resources_close_only_with_the_lease_set() {
    VOLUME_CLOSE_COUNT.store(0, Ordering::SeqCst);
    let pinned = vec![
        ResourceGuard::<u32, FakeVolumeCloser>::new(10),
        ResourceGuard::<u32, FakeVolumeCloser>::new(11),
    ];

    assert_eq!(VOLUME_CLOSE_COUNT.load(Ordering::SeqCst), 0);
    assert_eq!(pinned.len(), 2);
    drop(pinned);
    assert_eq!(VOLUME_CLOSE_COUNT.load(Ordering::SeqCst), 2);
}

/// Only the exact versioned disk/UTF-16 recipe is accepted as reopen authority.
#[test]
fn opaque_recipe_decoder_rejects_paths_and_malformed_lengths() {
    let decoded = decode_recipe(OsStr::new(
        "win1:00000007:00550053004200530054004F0052005C005200440058",
    ))
    .expect("exact opaque recipe");

    assert_eq!(decoded.disk_number, 7);
    assert_eq!(decoded.instance_id, r"USBSTOR\RDX");
    assert_eq!(
        decode_recipe(OsStr::new(r"\\.\PhysicalDrive7")),
        Err(NativeError::InvalidRequest)
    );
    assert_eq!(
        decode_recipe(OsStr::new("win1:00000007:005")),
        Err(NativeError::InvalidRequest)
    );
}

/// Semantic operations encode exact private CDBs without exposing raw submission.
#[test]
fn semantic_operation_encoding_is_exact_and_redacted() {
    let request = ScsiOperation::firmware_chunk(0x012345, vec![0xA5; 17])
        .expect("bounded firmware operation")
        .with_timeout_seconds(41)
        .expect("bounded timeout")
        .into_request()
        .expect("private request");

    assert_eq!(
        &request.cdb[..usize::from(request.cdb_length)],
        &[0x3B, 0x04, 0, 0x01, 0x23, 0x45, 0, 0, 17, 0]
    );
    assert_eq!(request.direction, DataDirection::ToDevice);
    assert_eq!(request.timeout_seconds, 41);
    assert_eq!(request.sense_capacity, 0xFC);
    assert_eq!(
        format!("{:?}", ScsiOperation::led_test(true)),
        "ScsiOperation(<private>)"
    );
}

/// Volume extent parsing is alignment-independent and rejects hostile counts.
#[test]
fn volume_extent_parser_checks_stride_truncation_and_overflow() {
    let mut bytes = vec![0_u8; 8 + 2 * 24];
    bytes[..4].copy_from_slice(&2_u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&3_u32.to_le_bytes());
    bytes[16..24].copy_from_slice(&1_048_576_i64.to_le_bytes());
    bytes[24..32].copy_from_slice(&8_388_608_i64.to_le_bytes());
    bytes[32..36].copy_from_slice(&7_u32.to_le_bytes());
    bytes[40..48].copy_from_slice(&9_437_184_i64.to_le_bytes());
    bytes[48..56].copy_from_slice(&4_194_304_i64.to_le_bytes());

    assert_eq!(volume_extents_contain_disk(&bytes, 8, 24, 7), Ok(true));
    assert_eq!(volume_extents_contain_disk(&bytes, 8, 24, 5), Ok(false));
    assert_eq!(
        volume_extents_from_bytes(&bytes, 8, 24, 0, 8, 16),
        Ok(vec![
            VolumeExtent {
                disk_number: 3,
                starting_offset: 1_048_576,
                extent_length: 8_388_608,
            },
            VolumeExtent {
                disk_number: 7,
                starting_offset: 9_437_184,
                extent_length: 4_194_304,
            },
        ])
    );
    assert_eq!(
        volume_extents_contain_disk(&bytes[..35], 8, 24, 7),
        Err(NativeError::EnumerationFailed)
    );

    bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        volume_extents_contain_disk(&bytes, usize::MAX - 1, 24, 7),
        Err(NativeError::ResourceLimit)
    ));
}

/// Native byte counts cannot authorize a slice beyond the supplied allocation.
#[test]
fn returned_native_length_is_bounded_before_slice_construction() {
    assert_eq!(bounded_returned_length(32, 64, 8), Ok(32));
    assert_eq!(
        bounded_returned_length(7, 64, 8),
        Err(NativeError::EnumerationFailed)
    );
    assert_eq!(
        bounded_returned_length(65, 64, 8),
        Err(NativeError::EnumerationFailed)
    );
}

/// Adapter limits and alignment arithmetic reject malformed or oversized inputs.
#[test]
fn adapter_descriptor_and_transfer_alignment_are_bounded() {
    let mut descriptor = vec![0_u8; 32];
    descriptor[0..4].copy_from_slice(&20_u32.to_le_bytes());
    descriptor[4..8].copy_from_slice(&32_u32.to_le_bytes());
    descriptor[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    descriptor[16..20].copy_from_slice(&63_u32.to_le_bytes());
    let constraints = parse_adapter_descriptor(&descriptor).expect("bounded descriptor");

    let layout = aligned_transfer_layout(0x1003, 17, constraints).expect("aligned transfer");
    assert_eq!(layout.allocation_length, 80);
    assert_eq!(layout.data_offset, 61);
    assert_eq!((0x1003 + layout.data_offset) & 63, 0);

    descriptor[16..20].copy_from_slice(&5_u32.to_le_bytes());
    assert_eq!(
        parse_adapter_descriptor(&descriptor),
        Err(NativeError::EnumerationFailed)
    );
    descriptor[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        parse_adapter_descriptor(&descriptor),
        Err(NativeError::ResourceLimit)
    );
    descriptor[4..8].copy_from_slice(&33_u32.to_le_bytes());
    assert_eq!(
        parse_adapter_descriptor(&descriptor),
        Err(NativeError::EnumerationFailed)
    );
    assert_eq!(
        aligned_transfer_layout(usize::MAX - 1, 17, constraints),
        Err(NativeError::ResourceLimit)
    );
}

/// Drive-letter mapping rejects unterminated MULTI_SZ and normalizes roots only.
#[test]
fn drive_letter_multi_sz_parser_is_bounded_and_normalized() {
    let valid = [
        'z' as u16,
        ':' as u16,
        '\\' as u16,
        0,
        'C' as u16,
        ':' as u16,
        '\\' as u16,
        0,
        'C' as u16,
        ':' as u16,
        '\\' as u16,
        0,
        0,
    ];

    assert_eq!(drive_letters_from_multi_sz(&valid), Ok(vec!['C', 'Z']));
    assert_eq!(
        drive_letters_from_multi_sz(&valid[..valid.len() - 1]),
        Err(NativeError::EnumerationFailed)
    );
    assert_eq!(drive_letters_from_multi_sz(&[0]), Ok(Vec::new()));

    let folder = "C:\\RDX\\Cartridge\\"
        .encode_utf16()
        .chain([0, 0])
        .collect::<Vec<_>>();
    assert_eq!(
        mount_paths_from_multi_sz(&folder),
        Ok(vec!["C:\\RDX\\Cartridge\\".encode_utf16().collect()])
    );
    assert_eq!(drive_letters_from_multi_sz(&folder), Ok(Vec::new()));
}

mod layout;
mod locked_layout;
