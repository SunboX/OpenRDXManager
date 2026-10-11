// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Linux registry format transition regressions; no hardware is touched.

use super::*;

/// The entire registry pipeline accepts its own unmount and blank partition exactly once.
#[cfg(target_os = "linux")]
#[test]
fn confirmed_linux_format_continues_after_its_own_unmount_and_layout() {
    let mut backend = SwapBackend::new(None).with_host_mutations();
    let state = Arc::clone(&backend.state);
    state.lock().unwrap().windows_layout = true;
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .unwrap()
        .remove(0);
    let mut resolved = registry
        .resolve(&mut backend, &snapshot.id, snapshot.revision)
        .unwrap();
    let confirmation = resolved.issue_host_mutation_confirmation().unwrap();
    let filesystem = FileSystem::Linux(rdx_service::model::Filesystem::Ext4);
    rdx_service::operations::partition_and_format(&mut resolved, filesystem, &confirmation)
        .expect("the retained confirmed cartridge survives our mount and layout changes");
    let binding = resolved.binding();
    assert!(resolved.format_partition(&binding, filesystem).is_err());
    let fixture = state.lock().unwrap();
    assert_eq!(fixture.format_calls, 1);
    assert_eq!(
        fixture.opens, 2,
        "discovery and resolution only; never reopen mid-format"
    );
}

/// Each Linux continuation rejects medium/dock/host drift and permanently invalidates its lease.
#[cfg(target_os = "linux")]
#[test]
fn linux_format_continuations_reject_identity_drift_and_external_remounts() {
    for after_layout in [false, true] {
        for case in 0..9 {
            let mut backend = SwapBackend::new(None).with_host_mutations();
            let state = Arc::clone(&backend.state);
            state.lock().unwrap().windows_layout = true;
            let mut registry = DeviceRegistry::new();
            let snapshot = discover_validated_devices(&mut backend, &mut registry)
                .unwrap()
                .remove(0);
            let mut resolved = registry
                .resolve(&mut backend, &snapshot.id, snapshot.revision)
                .unwrap();
            let binding = resolved.binding();
            resolved.unmount_exact_volumes(&binding).unwrap();
            if after_layout {
                resolved.create_single_partition(&binding, 1).unwrap();
            }
            let original = state.lock().unwrap().host_override.unwrap();
            {
                let mut fixture = state.lock().unwrap();
                match case {
                    0 => fixture.host_override.as_mut().unwrap().capacity_bytes += 512,
                    1 => {
                        fixture.host_override.as_mut().unwrap().media_fingerprint = Some([0x33; 32])
                    }
                    2 => {
                        fixture.host_override.as_mut().unwrap().topology =
                            VolumeTopology::BootOrSystem
                    }
                    3 => fixture.host_override.as_mut().unwrap().writable = false,
                    4 => fixture.host_override.as_mut().unwrap().media_present = false,
                    5 => fixture.current.incarnation = 2,
                    6 => fixture.current.serial = "9999999999",
                    7 => fixture.host_override.as_mut().unwrap().mounted = true,
                    8 => {
                        fixture.host_override.as_mut().unwrap().filesystem = Some(FileSystem::ExFat)
                    }
                    _ => unreachable!(),
                }
            }
            let filesystem = FileSystem::Linux(rdx_service::model::Filesystem::Ext4);
            let failure = if after_layout {
                resolved.format_partition(&binding, filesystem).unwrap_err()
            } else {
                resolved.revalidate_format(&binding).unwrap_err()
            };
            assert_eq!(
                failure.error,
                HostPrimitiveError::StaleBinding,
                "layout={after_layout} case={case}"
            );
            state.lock().unwrap().host_override = Some(original);
            assert!(
                resolved.format_partition(&binding, filesystem).is_err(),
                "drift permanently invalidates"
            );
            assert_eq!(state.lock().unwrap().format_calls, 0);
        }
    }
}

/// An external unmount never authorizes the format-specific mount-state normalization.
#[cfg(target_os = "linux")]
#[test]
fn linux_format_transition_requires_our_successful_unmount() {
    let mut backend = SwapBackend::new(None).with_host_mutations();
    let state = Arc::clone(&backend.state);
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .unwrap()
        .remove(0);
    let mut resolved = registry
        .resolve(&mut backend, &snapshot.id, snapshot.revision)
        .unwrap();
    let binding = resolved.binding();
    let original = resolved.revalidate(&binding).unwrap();
    state.lock().unwrap().host_override = Some(HostVolumeFacts {
        mounted: false,
        filesystem: None,
        free_bytes: 0,
        ..original
    });
    assert_eq!(
        resolved.revalidate_format(&binding).unwrap_err().error,
        HostPrimitiveError::StaleBinding
    );
    assert_eq!(state.lock().unwrap().format_calls, 0);
}

/// Only a format continuation tolerates our unmount; ordinary operations keep strict binding.
#[cfg(target_os = "linux")]
#[test]
fn linux_format_unmount_proof_cannot_authorize_an_ordinary_operation() {
    let mut backend = SwapBackend::new(None).with_host_mutations();
    let state = Arc::clone(&backend.state);
    state.lock().unwrap().windows_layout = true;
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .unwrap()
        .remove(0);
    let mut resolved = registry
        .resolve(&mut backend, &snapshot.id, snapshot.revision)
        .unwrap();
    let binding = resolved.binding();
    resolved.unmount_exact_volumes(&binding).unwrap();
    assert!(resolved.revalidate_format(&binding).is_ok());
    assert!(resolved.revalidate(&binding).is_err());
    assert!(resolved.revalidate_format(&binding).is_err());
    assert_eq!(state.lock().unwrap().format_calls, 0);
}

/// Layout authorization is consumed before mkfs and cannot dispatch it twice.
#[cfg(target_os = "linux")]
#[test]
fn linux_layout_continuation_is_required_and_consumed_once() {
    for create_layout in [false, true] {
        let mut backend = SwapBackend::new(None).with_host_mutations();
        let state = Arc::clone(&backend.state);
        state.lock().unwrap().windows_layout = true;
        let mut registry = DeviceRegistry::new();
        let snapshot = discover_validated_devices(&mut backend, &mut registry)
            .unwrap()
            .remove(0);
        let mut resolved = registry
            .resolve(&mut backend, &snapshot.id, snapshot.revision)
            .unwrap();
        let binding = resolved.binding();
        resolved.unmount_exact_volumes(&binding).unwrap();
        if create_layout {
            resolved.create_single_partition(&binding, 1).unwrap();
        }
        let filesystem = FileSystem::Linux(rdx_service::model::Filesystem::Ext4);
        assert_eq!(
            resolved.format_partition(&binding, filesystem).is_ok(),
            create_layout
        );
        assert!(resolved.format_partition(&binding, filesystem).is_err());
        assert_eq!(
            state.lock().unwrap().format_calls,
            usize::from(create_layout)
        );
    }
}

/// A failed native unmount cannot create the format-specific continuation.
#[test]
fn failed_linux_unmount_never_authorizes_layout_or_format() {
    let mut backend = SwapBackend::new(None).with_host_mutations();
    let state = Arc::clone(&backend.state);
    {
        let mut fixture = state.lock().unwrap();
        fixture.windows_layout = true;
        fixture.unmount_fails = true;
    }
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .unwrap()
        .remove(0);
    let mut resolved = registry
        .resolve(&mut backend, &snapshot.id, snapshot.revision)
        .unwrap();
    let binding = resolved.binding();
    let original = resolved.revalidate(&binding).unwrap();
    assert_eq!(
        resolved.unmount_exact_volumes(&binding).unwrap_err().error,
        HostPrimitiveError::Busy
    );
    state.lock().unwrap().host_override = Some(HostVolumeFacts {
        mounted: false,
        filesystem: None,
        free_bytes: 0,
        ..original
    });
    assert!(resolved.revalidate_format(&binding).is_err());
    assert!(resolved.create_single_partition(&binding, 1).is_err());
    assert_eq!(state.lock().unwrap().format_calls, 0);
}
