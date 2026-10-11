// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::sync::{Arc, Mutex};

use rdx_service::host::DeviceInterface;
use rdx_service::operations::{
    FileSystem, HostOperations, HostPrimitiveError, HostVolumeFacts, PrimitiveFailure,
    VolumeTopology,
};
use rdx_service::platform::{
    CandidateDevice, CandidateLease, CandidateMetadata, DeviceRegistry, PlatformBackend,
    PlatformCapabilities, PlatformDeviceHandle, PlatformError, discover_validated_devices,
};
use rdx_service::protocol::Command;
use rdx_service::transport::{CommandDispatch, TransportError, TransportResponse};

/// One physical target currently occupying the fixture locator.
struct PhysicalTarget {
    incarnation: u64,
    serial: &'static str,
}

/// Shared hotplug and handle-accounting state independent of any opened lease.
struct SwapState {
    current: PhysicalTarget,
    replacement: PhysicalTarget,
    swap_after_dispatch: Option<usize>,
    dispatches: usize,
    opens: usize,
    active_handles: usize,
    maximum_active_handles: usize,
    host_fact_reads: usize,
    identity_probe_sets: usize,
    safe_eject_calls: usize,
    ejected: bool,
    filesystem: FileSystem,
    completed_format: Option<FileSystem>,
    format_facts: Option<HostVolumeFacts>,
    host_topology: VolumeTopology,
    windows_layout: bool,
    host_override: Option<HostVolumeFacts>,
    format_calls: usize,
    #[cfg(target_os = "linux")]
    unmount_fails: bool,
}

/// Backend whose one locator can be atomically rebound to another physical target.
struct SwapBackend {
    candidates: Vec<CandidateDevice>,
    host_mutations: bool,
    state: Arc<Mutex<SwapState>>,
}

impl SwapBackend {
    /// Creates one candidate and a different replacement target at its locator.
    fn new(swap_after_dispatch: Option<usize>) -> Self {
        Self {
            candidates: vec![
                CandidateDevice::new(
                    "candidate-a",
                    "/private/device/lease-test",
                    CandidateMetadata::new(
                        Some("TANDBERG".to_owned()),
                        Some("RDX".to_owned()),
                        None,
                        Some(DeviceInterface::Usb3),
                    ),
                )
                .expect("bounded fixture candidate"),
            ],
            host_mutations: false,
            state: Arc::new(Mutex::new(SwapState {
                current: PhysicalTarget {
                    incarnation: 1,
                    serial: "7820999743",
                },
                replacement: PhysicalTarget {
                    incarnation: 2,
                    // Even a replacement reporting identical protocol identity
                    // must not satisfy the old OS-instance reopen recipe.
                    serial: "7820999743",
                },
                swap_after_dispatch,
                dispatches: 0,
                opens: 0,
                active_handles: 0,
                maximum_active_handles: 0,
                host_fact_reads: 0,
                identity_probe_sets: 0,
                safe_eject_calls: 0,
                ejected: false,
                filesystem: FileSystem::Ntfs,
                completed_format: None,
                format_facts: None,
                host_topology: VolumeTopology::Simple,
                windows_layout: false,
                host_override: None,
                format_calls: 0,
                #[cfg(target_os = "linux")]
                unmount_fails: false,
            })),
        }
    }

    /// Enables exact host-volume evidence for mutation-capable resolution tests.
    fn with_host_mutations(mut self) -> Self {
        self.host_mutations = true;
        self
    }

    /// Rebinds the locator immediately, simulating removal plus path reuse.
    fn replace_now(&self) {
        let mut state = self.state.lock().expect("swap state remains available");
        state.current = PhysicalTarget {
            incarnation: state.replacement.incarnation,
            serial: state.replacement.serial,
        };
    }
}

impl PlatformBackend for SwapBackend {
    fn capabilities(&self) -> PlatformCapabilities {
        PlatformCapabilities::try_new(
            true,
            true,
            self.host_mutations,
            self.host_mutations,
            false,
            false,
            false,
            false,
        )
        .expect("fixture capabilities are consistent")
    }

    fn enumerate_candidates(&mut self) -> Result<Vec<CandidateDevice>, PlatformError> {
        Ok(std::mem::take(&mut self.candidates))
    }

    fn open_candidate(
        &mut self,
        candidate: &CandidateDevice,
    ) -> Result<CandidateLease, PlatformError> {
        if candidate.token() != "candidate-a" {
            return Err(PlatformError::DeviceUnavailable);
        }
        let incarnation = {
            let mut state = self.state.lock().expect("swap state remains available");
            state.opens += 1;
            if state.current.incarnation != 1 {
                return Err(PlatformError::DeviceUnavailable);
            }
            state.active_handles += 1;
            state.maximum_active_handles = state.maximum_active_handles.max(state.active_handles);
            state.current.incarnation
        };
        Ok(CandidateLease::new(SwapHandle {
            incarnation,
            state: Arc::clone(&self.state),
        }))
    }
}

/// One RAII handle pinned to the incarnation observed by the atomic open.
struct SwapHandle {
    incarnation: u64,
    state: Arc<Mutex<SwapState>>,
}

impl PlatformDeviceHandle for SwapHandle {
    fn execute(&mut self, command: &Command) -> CommandDispatch {
        let mut state = self.state.lock().expect("swap state remains available");
        if state.current.incarnation != self.incarnation {
            return CommandDispatch::NotSent(TransportError::DeviceRemoved);
        }
        let serial = state.current.serial;
        if matches!(command.cdb(), [0x12, 0, 0, 0, 0xFE, 0]) {
            state.identity_probe_sets += 1;
        }
        let outcome = exact_probe_response(command, serial);
        state.dispatches += 1;
        if state.swap_after_dispatch == Some(state.dispatches) {
            state.current = PhysicalTarget {
                incarnation: state.replacement.incarnation,
                serial: state.replacement.serial,
            };
        }
        outcome
    }

    /// Reports one stable cartridge while counting authoritative native reads.
    fn host_volume_facts(&mut self) -> Result<HostVolumeFacts, PrimitiveFailure> {
        // Keep one guard for the aggregate: field temporaries live until the
        // struct expression ends and a second lock would deadlock the fixture.
        let mut state = self.state.lock().expect("swap state remains available");
        state.host_fact_reads += 1;
        if let Some(facts) = state.host_override {
            return Ok(facts);
        }
        Ok(HostVolumeFacts {
            media_present: true,
            writable: true,
            mounted: true,
            free_bytes: 319_900_000_000,
            capacity_bytes: 320_000_000_000,
            filesystem: Some(state.filesystem),
            topology: state.host_topology,
            media_fingerprint: Some([0x52; 32]),
        })
    }

    /// Supplies isolated format-only facts while ordinary evidence remains unchanged.
    fn host_format_volume_facts(&mut self) -> Result<HostVolumeFacts, PrimitiveFailure> {
        let facts = self.state.lock().expect("fixture state").format_facts;
        match facts {
            Some(facts) => Ok(facts),
            None => self.host_volume_facts(),
        }
    }

    /// Models macOS's single native layout/format/verified-readback result.
    fn create_single_partition(&mut self, _signature: u32) -> Result<(), PrimitiveFailure> {
        let mut state = self.state.lock().expect("fixture state");
        if state.windows_layout {
            state.host_override = Some(HostVolumeFacts {
                media_present: true,
                writable: true,
                mounted: false,
                free_bytes: 0,
                capacity_bytes: 320_000_000_000,
                filesystem: None,
                topology: VolumeTopology::Simple,
                media_fingerprint: Some([0x52; 32]),
            });
            return Ok(());
        }
        let filesystem = FileSystem::MacOs(rdx_service::model::Filesystem::Hfs);
        state.filesystem = filesystem;
        state.completed_format = Some(filesystem);
        Ok(())
    }

    /// Acknowledges the native result only for its exact verified filesystem.
    fn format_partition(&mut self, filesystem: FileSystem) -> Result<(), PrimitiveFailure> {
        {
            let mut state = self.state.lock().expect("fixture state");
            if state.windows_layout {
                state.format_calls += 1;
                state.completed_format = Some(filesystem);
                return Ok(());
            }
        }
        if self.completed_format() == Some(filesystem) {
            Ok(())
        } else {
            Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::StaleBinding,
            ))
        }
    }

    /// Models a preflight that reads only prerequisites, not a filesystem write.
    fn preflight_format(&mut self, _filesystem: FileSystem) -> Result<(), PrimitiveFailure> {
        Ok(())
    }

    /// Models a Linux dismount that changes only mount/filesystem presentation.
    fn unmount_exact_volumes(&mut self) -> Result<(), PrimitiveFailure> {
        #[cfg(target_os = "linux")]
        {
            let mut state = self.state.lock().expect("fixture state");
            if state.unmount_fails {
                return Err(PrimitiveFailure::not_attempted(HostPrimitiveError::Busy));
            }
            if state.windows_layout {
                state.host_override = Some(HostVolumeFacts {
                    mounted: false,
                    filesystem: None,
                    free_bytes: 0,
                    media_present: true,
                    writable: true,
                    capacity_bytes: 320_000_000_000,
                    topology: VolumeTopology::Simple,
                    media_fingerprint: Some([0x52; 32]),
                });
            }
        }
        Ok(())
    }

    /// Exposes only a result already verified by the combined native boundary.
    fn completed_format(&self) -> Option<FileSystem> {
        let state = self.state.lock().expect("fixture state");
        if state.windows_layout {
            None
        } else {
            state.completed_format
        }
    }

    /// Consumes exact native readback once, matching the macOS completion contract.
    fn verify_format_rediscovery(
        &mut self,
        filesystem: FileSystem,
        capacity: u64,
    ) -> Result<(), PrimitiveFailure> {
        let mut state = self.state.lock().expect("fixture state");
        if state.completed_format == Some(filesystem) && capacity == 320_000_000_000 {
            state.completed_format = None;
            Ok(())
        } else {
            Err(PrimitiveFailure::completion_unknown(
                HostPrimitiveError::StaleBinding,
            ))
        }
    }

    /// Simulates one combined host unmount and mechanical eject dispatch.
    fn safe_eject_exact(
        &mut self,
        after_unmount: &mut dyn FnMut() -> bool,
    ) -> Result<(), PrimitiveFailure> {
        if !after_unmount() {
            return Err(PrimitiveFailure::completion_unknown(
                HostPrimitiveError::Cancelled,
            ));
        }
        let mut state = self.state.lock().expect("swap state remains available");
        state.safe_eject_calls += 1;
        state.ejected = true;
        Ok(())
    }

    /// Proves the fixture target departed after the exact eject dispatch.
    fn verify_eject_departure(&mut self) -> Result<(), PrimitiveFailure> {
        if self
            .state
            .lock()
            .expect("swap state remains available")
            .ejected
        {
            Ok(())
        } else {
            Err(PrimitiveFailure::not_attempted(
                HostPrimitiveError::TimedOut,
            ))
        }
    }
}

impl Drop for SwapHandle {
    fn drop(&mut self) {
        let mut state = self.state.lock().expect("swap state remains available");
        state.active_handles -= 1;
    }
}

/// Returns one literal response for each exact service-owned discovery command.
fn exact_probe_response(command: &Command, serial: &str) -> CommandDispatch {
    let bytes = match command.cdb() {
        [0x12, 0, 0, 0, 0xFE, 0] => standard_inquiry(),
        [0x12, 1, 0x83, 0, 0xFE, 0] => device_identification(serial),
        [0x5A, 0, 0x31, 0, 0, 0, 0, 0, 0xFE, 0] => capability_page(),
        _ => return CommandDispatch::NotSent(TransportError::Unavailable),
    };
    CommandDispatch::Succeeded(
        TransportResponse::new(bytes).expect("fixture responses remain bounded"),
    )
}

/// Builds a complete standard inquiry response for one supported dock family.
fn standard_inquiry() -> Vec<u8> {
    let mut bytes = vec![b' '; 43];
    bytes[0] = 0;
    bytes[4] = 38;
    bytes[8..16].copy_from_slice(b"TANDBERG");
    bytes[16..32].copy_from_slice(b"RDX             ");
    bytes[32..36].copy_from_slice(b"0283");
    bytes[36] = 0x35;
    bytes[37..40].copy_from_slice(b"RDX");
    bytes[40] = 2;
    bytes[41] = 0x08;
    bytes[42] = 0x10;
    bytes
}

/// Builds the fixed-layout VPD identity response for one ten-byte serial.
fn device_identification(serial: &str) -> Vec<u8> {
    let mut bytes = vec![b' '; 42];
    bytes[0] = 0;
    bytes[1] = 0x83;
    bytes[2..4].copy_from_slice(&38_u16.to_be_bytes());
    bytes[8..16].copy_from_slice(b"TANDBERG");
    bytes[16..32].copy_from_slice(b"RDX             ");
    bytes[32..42].copy_from_slice(serial.as_bytes());
    bytes
}

/// Builds the smallest structurally complete capability page.
fn capability_page() -> Vec<u8> {
    vec![0x00, 0x0B, 0, 0, 0, 0, 0, 0, 0x31, 0x03, 0, 0, 0x18]
}

/// The actual confirmed pipeline tolerates its own EFI-to-RAW change exactly once.
#[cfg(windows)]
#[test]
fn confirmed_windows_format_continues_after_its_own_layout_change() {
    let mut backend = SwapBackend::new(None).with_host_mutations();
    let state = Arc::clone(&backend.state);
    {
        let mut fixture = state.lock().unwrap();
        fixture.windows_layout = true;
        fixture.host_topology = VolumeTopology::BootOrSystem;
        fixture.format_facts = Some(HostVolumeFacts {
            media_present: true,
            writable: true,
            mounted: false,
            free_bytes: 0,
            capacity_bytes: 320_000_000_000,
            filesystem: None,
            topology: VolumeTopology::Simple,
            media_fingerprint: Some([0x52; 32]),
        });
    }
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .unwrap()
        .remove(0);
    let mut resolved = registry
        .resolve(&mut backend, &snapshot.id, snapshot.revision)
        .unwrap();
    let confirmation = resolved.issue_host_mutation_confirmation().unwrap();
    rdx_service::operations::partition_and_format(&mut resolved, FileSystem::Ntfs, &confirmation)
        .unwrap();
    let binding = resolved.binding();
    assert!(
        resolved
            .format_partition(&binding, FileSystem::Ntfs)
            .is_err()
    );
    assert_eq!(state.lock().unwrap().format_calls, 1);
}

/// Successful layout handoff never permits a different cartridge, dock or system role.
#[cfg(windows)]
#[test]
fn windows_layout_continuation_rejects_drift_and_is_one_shot() {
    for case in 0..8 {
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
        if case != 7 {
            resolved.create_single_partition(&binding, 1).unwrap();
        }
        {
            let mut fixture = state.lock().unwrap();
            match case {
                0 => fixture.host_override.as_mut().unwrap().capacity_bytes += 512,
                1 => fixture.host_override.as_mut().unwrap().media_fingerprint = Some([0x33; 32]),
                2 => {
                    fixture.host_override.as_mut().unwrap().topology = VolumeTopology::BootOrSystem
                }
                3 => fixture.host_override.as_mut().unwrap().writable = false,
                4 => {
                    let facts = fixture.host_override.as_mut().unwrap();
                    facts.media_present = false;
                    facts.media_fingerprint = None;
                }
                5 => fixture.current.incarnation = 2,
                6 => fixture.current.serial = "9999999999",
                7 => {}
                _ => unreachable!(),
            }
        }
        assert!(
            resolved
                .format_partition(&binding, FileSystem::Ntfs)
                .is_err(),
            "case {case}"
        );
        assert!(
            resolved
                .format_partition(&binding, FileSystem::Ntfs)
                .is_err(),
            "one shot {case}"
        );
        assert_eq!(state.lock().unwrap().format_calls, 0, "case {case}");
    }
}

/// Format-only proof neither changes ordinary topology nor survives a medium swap.
#[cfg(windows)]
#[test]
fn format_only_facts_preserve_ordinary_topology_and_exact_medium_identity() {
    let mut backend = SwapBackend::new(None).with_host_mutations();
    let state = Arc::clone(&backend.state);
    state.lock().unwrap().host_topology = VolumeTopology::BootOrSystem;
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .unwrap()
        .remove(0);
    let mut resolved = registry
        .resolve(&mut backend, &snapshot.id, snapshot.revision)
        .unwrap();
    let binding = resolved.binding();
    // Consume the one-shot resolution facts before requesting fresh proof.
    resolved.revalidate(&binding).unwrap();
    let ordinary = resolved.revalidate(&binding).unwrap();
    assert_eq!(ordinary.topology, VolumeTopology::BootOrSystem);
    let format = HostVolumeFacts {
        mounted: false,
        free_bytes: 0,
        topology: VolumeTopology::Simple,
        ..ordinary
    };
    state.lock().unwrap().format_facts = Some(format);
    assert_eq!(resolved.revalidate_format(&binding).unwrap(), format);
    assert_eq!(
        resolved.revalidate(&binding).unwrap(),
        ordinary,
        "format evidence must not authorize another operation"
    );
    state.lock().unwrap().format_facts = Some(HostVolumeFacts {
        media_fingerprint: Some([0x33; 32]),
        ..format
    });
    assert_eq!(
        resolved.revalidate_format(&binding).unwrap_err().error,
        HostPrimitiveError::StaleBinding
    );
    state.lock().unwrap().format_facts = Some(format);
    assert_eq!(
        resolved.revalidate_format(&binding).unwrap_err().error,
        HostPrimitiveError::StaleBinding,
        "a changed medium permanently invalidates the lease"
    );
}

/// A verified filesystem change must not be compared to pre-format discovery.
#[test]
fn combined_native_format_consumes_exact_completion_after_filesystem_change() {
    let mut backend = SwapBackend::new(None).with_host_mutations();
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .unwrap()
        .remove(0);
    let mut resolved = registry
        .resolve(&mut backend, &snapshot.id, snapshot.revision)
        .unwrap();
    let binding = resolved.binding();
    let filesystem = FileSystem::MacOs(rdx_service::model::Filesystem::Hfs);
    resolved.create_single_partition(&binding, 1).unwrap();
    resolved
        .format_partition(&binding, filesystem)
        .expect("combined native completion survives intentional filesystem change");
    resolved
        .verify_format_rediscovery(&binding, filesystem, 320_000_000_000)
        .unwrap();
    assert!(
        resolved
            .verify_format_rediscovery(&binding, filesystem, 320_000_000_000)
            .is_err(),
        "completion proof is one shot"
    );
}

/// Missing or differently selected native completion cannot bypass stale proof.
#[test]
fn combined_completion_never_admits_unverified_or_wrong_filesystem() {
    for complete in [None, Some(FileSystem::ExFat)] {
        let mut backend = SwapBackend::new(None).with_host_mutations();
        let mut registry = DeviceRegistry::new();
        let snapshot = discover_validated_devices(&mut backend, &mut registry)
            .unwrap()
            .remove(0);
        let mut resolved = registry
            .resolve(&mut backend, &snapshot.id, snapshot.revision)
            .unwrap();
        let binding = resolved.binding();
        let filesystem = FileSystem::MacOs(rdx_service::model::Filesystem::Hfs);
        {
            let mut state = backend.state.lock().unwrap();
            state.filesystem = filesystem;
            state.completed_format = complete;
        }
        assert_eq!(
            resolved
                .format_partition(&binding, filesystem)
                .unwrap_err()
                .error,
            HostPrimitiveError::StaleBinding
        );
    }
}

/// Native completion cannot reactivate a resolution invalidated after dispatch.
#[test]
fn combined_completion_cannot_bypass_invalidated_registry_binding() {
    let mut backend = SwapBackend::new(None).with_host_mutations();
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .unwrap()
        .remove(0);
    let mut resolved = registry
        .resolve(&mut backend, &snapshot.id, snapshot.revision)
        .unwrap();
    let binding = resolved.binding();
    let filesystem = FileSystem::MacOs(rdx_service::model::Filesystem::Hfs);
    resolved.create_single_partition(&binding, 1).unwrap();
    resolved.invalidate_for_rediscovery();
    assert_eq!(
        resolved
            .format_partition(&binding, filesystem)
            .unwrap_err()
            .error,
        HostPrimitiveError::StaleBinding
    );
}

/// A hotplug between probes invalidates the open lease and publishes no hybrid identity.
#[test]
fn path_swap_between_discovery_probes_fails_and_closes_the_candidate_lease() {
    for swap_after_dispatch in [1, 2] {
        let mut backend = SwapBackend::new(Some(swap_after_dispatch));
        let state = Arc::clone(&backend.state);
        let mut registry = DeviceRegistry::new();

        let snapshots = discover_validated_devices(&mut backend, &mut registry)
            .expect("candidate-local removal leaves an empty authoritative set");

        assert!(snapshots.is_empty());
        let state = state.lock().expect("swap state remains available");
        assert_eq!(state.opens, 1);
        assert_eq!(state.maximum_active_handles, 1);
        assert_eq!(state.active_handles, 0);
    }
}

/// Resolution opens once, revalidates on that handle, and retains it through use.
#[test]
fn resolve_and_use_are_pinned_to_one_live_handle_across_path_reuse() {
    let mut backend = SwapBackend::new(None);
    let state = Arc::clone(&backend.state);
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .expect("initial discovery succeeds")
        .remove(0);

    let mut resolved = registry
        .resolve(&mut backend, &snapshot.id, snapshot.revision)
        .expect("resolution opens and revalidates one current handle");
    assert_eq!(resolved.id(), &snapshot.id);
    assert_eq!(resolved.revision(), snapshot.revision);
    backend.replace_now();

    assert_eq!(
        resolved
            .revalidate_identity()
            .expect_err("reuse after resolution invalidates the pinned handle"),
        PlatformError::StaleDeviceBinding
    );
    assert_eq!(state.lock().expect("swap state remains available").opens, 2);
    drop(resolved);
    assert_eq!(
        state
            .lock()
            .expect("swap state remains available")
            .active_handles,
        0
    );
}

/// Resolution reuses the host facts obtained by same-handle validation instead
/// of performing a second read that can release an exclusive platform lease.
#[test]
fn mutation_resolution_reads_host_facts_once_per_open_handle() {
    let mut backend = SwapBackend::new(None).with_host_mutations();
    let state = Arc::clone(&backend.state);
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .expect("initial mutation-capable discovery succeeds")
        .remove(0);
    let discovery_reads = state
        .lock()
        .expect("swap state remains available")
        .host_fact_reads;
    assert_eq!(discovery_reads, 1);

    let resolved = registry
        .resolve(&mut backend, &snapshot.id, snapshot.revision)
        .expect("mutation resolution retains its validated host authority");

    let resolution_reads = state
        .lock()
        .expect("swap state remains available")
        .host_fact_reads;
    assert_eq!(resolution_reads, 2);
    drop(resolved);
}

/// Safe eject consumes the atomic resolution proof without probing the same
/// retained SCSI lease a second time.
#[test]
fn safe_eject_reuses_the_immediate_preflight_without_duplicate_identity_probe() {
    let mut backend = SwapBackend::new(None).with_host_mutations();
    let state = Arc::clone(&backend.state);
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .expect("initial mutation-capable discovery succeeds")
        .remove(0);
    let mut resolved = registry
        .resolve(&mut backend, &snapshot.id, snapshot.revision)
        .expect("mutation resolution retains its validated host authority");
    let probes_before_eject = state
        .lock()
        .expect("swap state remains available")
        .identity_probe_sets;

    rdx_service::operations::safe_eject(&mut resolved)
        .expect("one fresh preflight authorizes the retained exact eject authority");
    drop(resolved);

    let state = state.lock().expect("swap state remains available");
    assert_eq!(state.identity_probe_sets, probes_before_eject);
    assert_eq!(state.safe_eject_calls, 1);
    assert!(state.ejected);
}

/// The low-level exact eject boundary fails closed without a one-shot fresh preflight proof.
#[test]
fn safe_eject_exact_rejects_dispatch_without_an_immediate_preflight() {
    let mut backend = SwapBackend::new(None).with_host_mutations();
    let state = Arc::clone(&backend.state);
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .expect("initial mutation-capable discovery succeeds")
        .remove(0);
    let mut resolved = registry
        .resolve(&mut backend, &snapshot.id, snapshot.revision)
        .expect("mutation resolution retains its validated host authority");
    let binding = resolved.binding();

    let failure = resolved
        .safe_eject_exact(&binding, &mut || true)
        .expect_err("the native boundary cannot manufacture its own stale preflight proof");
    drop(resolved);

    assert_eq!(failure.error, HostPrimitiveError::StaleBinding);
    assert_eq!(
        state
            .lock()
            .expect("swap state remains available")
            .safe_eject_calls,
        0
    );
}

/// A different OS instance present before resolution fails even with identical protocol identity.
#[test]
fn path_reuse_before_resolution_rejects_the_stored_authorization() {
    let mut backend = SwapBackend::new(None);
    let state = Arc::clone(&backend.state);
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .expect("initial discovery succeeds")
        .remove(0);
    backend.replace_now();

    assert_eq!(
        registry
            .resolve(&mut backend, &snapshot.id, snapshot.revision)
            .expect_err("stored identity cannot authorize a replacement device"),
        PlatformError::DeviceUnavailable
    );
    let state = state.lock().expect("swap state remains available");
    assert_eq!(state.opens, 2);
    assert_eq!(state.maximum_active_handles, 1);
    assert_eq!(state.active_handles, 0);
}

#[cfg(target_os = "linux")]
#[path = "platform_live_lease/linux_format.rs"]
mod linux_format;
