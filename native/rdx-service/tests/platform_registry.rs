use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rdx_service::host::DeviceInterface;
use rdx_service::model::{CapabilityState, DriveLetter, OperationKind};
use rdx_service::operations::{
    FileSystem, HostOperations, HostPrimitiveError, HostVolumeFacts, PrimitiveFailure,
    VolumeTopology,
};
#[cfg(target_os = "macos")]
use rdx_service::platform::macos::MacOsBackend;
use rdx_service::platform::{
    CandidateDevice, CandidateLease, CandidateMetadata, DeviceRegistry, DiscoveryProbe,
    PlatformBackend, PlatformCapabilities, PlatformDeviceHandle, PlatformError,
    discover_validated_device_report, discover_validated_devices,
};
use rdx_service::protocol::{Command, RdxFeaturePage, parse_rdx_inquiry_identity};
use rdx_service::service::{ServiceDescriptor, ServiceMode, ServicePlatform};
use rdx_service::transport::{CommandDispatch, TransportError, TransportResponse};

#[path = "platform_registry/discovery_diagnostics.rs"]
mod discovery_diagnostics;
#[path = "platform_registry/media_refresh.rs"]
mod media_refresh;

/// Modern update support comes from the proven product path, never the cartridge-flash bit.
#[test]
fn modern_firmware_capability_is_independent_of_cartridge_flash_bit() {
    let mut backend = FixtureBackend::new(vec![
        candidate("mask-set", "/dev/sg2", "7820999743"),
        candidate("mask-clear", "/dev/sg3", "7820999744"),
    ])
    .with_responses(
        "mask-set",
        complete_responses_with_masks("7820999743", 0x08, 0x10),
    )
    .with_responses(
        "mask-clear",
        complete_responses_with_masks("7820999744", 0x00, 0x10),
    );
    let mut registry = DeviceRegistry::new();

    let snapshots = discover_validated_devices(&mut backend, &mut registry)
        .expect("both exact identities remain discoverable");

    assert_eq!(snapshots.len(), 2);
    for snapshot in snapshots {
        let firmware = &snapshot.capabilities[&OperationKind::FirmwareUpdate];
        assert_eq!(firmware.state, CapabilityState::Available);
        assert!(firmware.reason.is_none());
    }
}

/// A missing OEM/date/drive decoder must not regress the original Manager's status fields.
#[test]
fn status_projection_decodes_reference_drive_identity_and_log_fields() {
    let mut responses = complete_responses("7820999743");
    let mut standard = standard_inquiry(0x35, 0x08, 0x10);
    standard[40] = 7;
    responses.insert(DiscoveryProbe::StandardInquiry, response(standard));

    let mut identification = device_identification("7820999743");
    identification.resize(50, b' ');
    identification[2..4].copy_from_slice(&46_u16.to_be_bytes());
    identification[42..50].copy_from_slice(b"20260829");
    responses.insert(
        DiscoveryProbe::DeviceIdentification,
        response(identification),
    );
    responses.insert(
        DiscoveryProbe::DriveStatus,
        response(complete_drive_status_page()),
    );

    let mut backend =
        FixtureBackend::new(vec![candidate("complete-status", "/dev/sg2", "7820999743")])
            .with_responses("complete-status", responses);
    let snapshot = discover_validated_devices(&mut backend, &mut DeviceRegistry::new())
        .expect("complete original Manager evidence remains discoverable")
        .remove(0);
    let details = &snapshot.drive.details;

    assert_eq!(
        details
            .oem_name
            .reported_value()
            .map(|value| value.as_str()),
        Some("Imation")
    );
    assert_eq!(
        details
            .born_on_date
            .reported_value()
            .map(|value| value.as_str()),
        Some("20260829")
    );
    assert_eq!(
        details.status.reported_value().map(|value| value.as_str()),
        Some("Good")
    );
    assert_eq!(
        details.load_count.reported_value().map(|value| value.get()),
        Some(42)
    );
    assert_eq!(
        details.errors.reported_value().map(|value| value.as_str()),
        Some("None")
    );
    assert_eq!(
        details
            .cam_state
            .reported_value()
            .map(|value| value.as_str()),
        Some("Home")
    );
}

/// Legacy product identity remains disabled because no `.BIP` container sample is evidenced.
#[test]
fn legacy_firmware_capability_remains_evidence_incomplete() {
    let mut responses = complete_responses("7820999743");
    responses.insert(
        DiscoveryProbe::StandardInquiry,
        response(standard_inquiry(0x00, 0x08, 0x10)),
    );
    let mut backend = FixtureBackend::new(vec![candidate_with_metadata(
        "legacy",
        "/dev/sg2",
        CandidateMetadata::new(
            Some("TANDBERG".to_owned()),
            Some("RDX".to_owned()),
            Some("7820999743".to_owned()),
            Some(DeviceInterface::Legacy),
        ),
    )])
    .with_responses("legacy", responses);
    let snapshot = discover_validated_devices(&mut backend, &mut DeviceRegistry::new())
        .unwrap()
        .remove(0);
    let firmware = &snapshot.capabilities[&OperationKind::FirmwareUpdate];
    assert_eq!(firmware.state, CapabilityState::EvidenceIncomplete);
    assert_eq!(
        firmware.reason.as_ref().map(|reason| reason.as_str()),
        Some("legacy-bip-format-unproven")
    );
}

/// Exact SATA III identity, current page value, and no-media evidence authorize both setters.
#[test]
fn mode_capabilities_publish_only_from_exact_current_evidence() {
    let mut responses = complete_responses("7820999743");
    let mut inquiry = standard_inquiry(0x39, 0x08, 0x10);
    inquiry[36] = 0x39;
    responses.insert(DiscoveryProbe::StandardInquiry, response(inquiry));
    let mut mode_page = operation_mode_page();
    mode_page[14] = 2;
    responses.insert(DiscoveryProbe::OperationMode, response(mode_page));
    let sata_candidate = candidate_with_metadata(
        "sata-mode",
        "/dev/sg2",
        CandidateMetadata::new(
            Some("TANDBERG".to_owned()),
            Some("RDX".to_owned()),
            Some("7820999743".to_owned()),
            Some(DeviceInterface::Sata3),
        ),
    );
    let mut backend =
        FixtureBackend::new(vec![sata_candidate]).with_responses("sata-mode", responses);
    let mut registry = DeviceRegistry::new();

    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .unwrap()
        .remove(0);

    assert_eq!(
        snapshot.capabilities[&OperationKind::DriveModeSet].state,
        CapabilityState::Available
    );
    assert_eq!(
        snapshot.capabilities[&OperationKind::SataModeSet].state,
        CapabilityState::Available
    );
    assert_eq!(
        snapshot
            .drive
            .sata_mode
            .as_ref()
            .map(|value| value.as_str()),
        Some("1.5g-3g")
    );
    assert_eq!(
        snapshot
            .drive
            .details
            .sata_mode
            .reported_value()
            .map(|value| value.as_str()),
        Some("1.5g-3g")
    );
}

include!("platform_registry/fixture.rs");

#[test]
fn current_media_is_revision_bound_and_admits_unverified_host_software() {
    let mut backend =
        FixtureBackend::new(vec![candidate("current-media", "/dev/sg2", "7820999743")])
            .with_responses("current-media", complete_responses("7820999743"))
            .with_media([0xA5; 32], 1_000_000_000);
    let mut registry = DeviceRegistry::new();
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .expect("authoritative cartridge facts are discoverable")
        .into_iter()
        .next()
        .expect("current device is published");
    assert_eq!(
        snapshot.media_state,
        rdx_service::model::MediaState::Present
    );
    let media = snapshot.media.expect("current media metadata is present");
    assert_eq!(
        media
            .capacity_bytes
            .map(rdx_service::model::SafeJsonInteger::get),
        Some(1_000_000_000)
    );
    assert_eq!(media.writable, Some(true));
    assert_eq!(media.details.mounted.reported_value(), Some(&true));
    for kind in [
        OperationKind::EjectSafe,
        OperationKind::EjectForce,
        OperationKind::Format,
        OperationKind::WriteReadTest,
    ] {
        assert_eq!(
            snapshot.capabilities[&kind].state,
            CapabilityState::Available
        );
    }
    for kind in [
        OperationKind::DriveLetterSet,
        OperationKind::DriveLetterReset,
    ] {
        assert_eq!(
            snapshot.capabilities[&kind].state,
            CapabilityState::WrongMediaState
        );
        assert_eq!(
            snapshot.capabilities[&kind]
                .reason
                .as_ref()
                .map(|reason| reason.as_str()),
            Some("media-must-be-ejected")
        );
    }
}

/// Inserted media must trigger every read-only status command used by the original Manager.
#[test]
fn inserted_media_runs_cartridge_identity_status_and_temperature_probes() {
    let mut backend = FixtureBackend::new(vec![candidate(
        "cartridge-probes",
        "/dev/sg2",
        "7820999743",
    )])
    .with_responses("cartridge-probes", complete_responses("7820999743"))
    .with_media([0xA5; 32], 320_067_338_240);

    let snapshots = discover_validated_devices(&mut backend, &mut DeviceRegistry::new())
        .expect("optional cartridge probes preserve the validated dock");
    assert_eq!(snapshots.len(), 1);
    let commands = backend
        .calls()
        .into_iter()
        .map(|(_, _, cdb)| cdb)
        .collect::<Vec<_>>();

    assert!(commands.contains(&vec![0x12, 1, 0xC0, 0, 0xFE, 0]));
    assert!(commands.contains(&vec![0x12, 1, 0xC2, 0x02, 0x00, 0]));
    assert!(commands.contains(&vec![0x4D, 0, 0x21, 0, 0, 0, 0, 0, 0xFE, 0,]));
    assert!(commands.contains(&vec![0x4D, 0, 0x0D, 0, 0, 0, 0, 0, 0xFE, 0,]));
}

/// Complete cartridge evidence must replace every placeholder shown in the status UI.
#[test]
fn status_projection_decodes_reference_cartridge_identity_and_telemetry() {
    let mut responses = complete_responses("7820999743");
    responses.insert(
        DiscoveryProbe::MediaIdentification,
        response(media_identification_page()),
    );
    responses.insert(DiscoveryProbe::MediaDevice, response(media_device_page()));
    responses.insert(
        DiscoveryProbe::CartridgeStatus,
        response(cartridge_status_page()),
    );
    responses.insert(DiscoveryProbe::Temperature, response(temperature_page()));
    let mut backend = FixtureBackend::new(vec![candidate(
        "complete-cartridge-status",
        "/dev/sg2",
        "7820999743",
    )])
    .with_responses("complete-cartridge-status", responses)
    .with_media([0xA5; 32], 320_067_338_240);

    let snapshot = discover_validated_devices(&mut backend, &mut DeviceRegistry::new())
        .expect("complete cartridge status remains discoverable")
        .remove(0);
    serde_json::to_value(&snapshot).expect("complete status snapshot remains contract-valid");
    let media = snapshot.media.expect("inserted cartridge is published");
    let details = &media.details;

    assert_eq!(
        media.serial.as_ref().map(|value| value.as_str()),
        Some("CART-SERIAL-0001")
    );
    assert_eq!(
        details.vendor.reported_value().map(|value| value.as_str()),
        Some("Imation")
    );
    assert_eq!(
        details.model.reported_value().map(|value| value.as_str()),
        Some("RDX 320GB")
    );
    assert_eq!(
        details.status.reported_value().map(|value| value.as_str()),
        Some("Good")
    );
    assert_eq!(
        details.load_count.reported_value().map(|value| value.get()),
        Some(12)
    );
    assert_eq!(
        details
            .hdd_firmware
            .reported_value()
            .map(|value| value.as_str()),
        Some("FW1234")
    );
    assert_eq!(
        details
            .cartridge_type
            .reported_value()
            .map(|value| value.as_str()),
        Some("Disk")
    );
    assert_eq!(
        details
            .temperature_celsius
            .reported_value()
            .map(|value| value.get()),
        Some(39)
    );
    assert_eq!(
        details.bytes_read.reported_value().map(|value| value.get()),
        Some(5_678_000_000)
    );
    assert_eq!(
        details
            .bytes_written
            .reported_value()
            .map(|value| value.get()),
        Some(1_234_000_000)
    );
}

#[test]
fn enumeration_is_not_validation_and_only_complete_exact_probe_evidence_is_published() {
    let valid = candidate("candidate-a", "/dev/sg2", "7820999743");
    let incomplete = candidate("candidate-b", "/dev/sg3", "7820999744");
    let mut backend = FixtureBackend::new(vec![valid, incomplete])
        .with_responses("candidate-a", complete_responses("7820999743"))
        .with_responses(
            "candidate-b",
            BTreeMap::from([(
                DiscoveryProbe::StandardInquiry,
                response(standard_inquiry(0x35, 0x08, 0x10)),
            )]),
        );
    let mut registry = DeviceRegistry::new();

    let snapshots = discover_validated_devices(&mut backend, &mut registry)
        .expect("one complete candidate remains discoverable");

    assert_eq!(snapshots.len(), 1);
    let snapshot = &snapshots[0];
    assert_eq!(snapshot.vendor.as_str(), "TANDBERG");
    assert_eq!(snapshot.product.as_str(), "RDX");
    assert_eq!(snapshot.serial.as_str(), "7820999743");
    assert_eq!(
        snapshot
            .drive
            .firmware_revision
            .as_ref()
            .map(|value| value.as_str()),
        Some("0283")
    );
    assert_eq!(
        snapshot
            .drive
            .product_type
            .as_ref()
            .map(|value| value.as_str()),
        Some("USB 3 / SATA III")
    );
    assert_eq!(
        snapshot
            .drive
            .connection_type
            .as_ref()
            .map(|value| value.as_str()),
        Some("USB 3")
    );
    assert_eq!(
        snapshot
            .drive
            .operation_mode
            .as_ref()
            .map(|value| value.as_str()),
        Some("Fixed disk")
    );
    assert_eq!(
        snapshot
            .drive
            .power_source
            .as_ref()
            .map(|value| value.as_str()),
        Some("Power adapter")
    );
    assert_eq!(
        snapshot.capabilities[&OperationKind::StatusRefresh].state,
        CapabilityState::Available
    );
    assert!(snapshot.id.as_str().starts_with("rdx:"));
    assert_eq!(snapshot.id.as_str().len(), 68);
    assert!(!snapshot.id.as_str().contains("7820999743"));
    assert!(!snapshot.id.as_str().contains("sg2"));

    let published = serde_json::to_string(&snapshots).expect("snapshots serialize");
    assert!(!published.contains("/dev/"));
    assert!(!published.contains("candidate-a"));

    let expected_calls = [
        ("candidate-a", DiscoveryProbe::StandardInquiry),
        ("candidate-a", DiscoveryProbe::DeviceIdentification),
        ("candidate-a", DiscoveryProbe::CapabilityPage),
        ("candidate-a", DiscoveryProbe::OperationMode),
        ("candidate-a", DiscoveryProbe::DriveStatus),
        ("candidate-b", DiscoveryProbe::StandardInquiry),
        ("candidate-b", DiscoveryProbe::DeviceIdentification),
    ];
    let calls = backend.calls();
    assert_eq!(
        calls
            .iter()
            .map(|(token, probe, _)| (token.as_str(), *probe))
            .collect::<Vec<_>>(),
        expected_calls
    );
    assert_eq!(calls[0].2, [0x12, 0, 0, 0, 0xFE, 0]);
    assert_eq!(calls[1].2, [0x12, 1, 0x83, 0, 0xFE, 0]);
    assert_eq!(calls[2].2, [0x5A, 0, 0x31, 0, 0, 0, 0, 0, 0xFE, 0]);
    assert_eq!(calls[3].2, [0x5A, 0, 0x34, 0, 0, 0, 0, 0, 0xFE, 0]);
    assert_eq!(calls[4].2, [0x4D, 0, 0x20, 0, 0, 0, 0, 0, 0xFE, 0]);
}

/// Global non-invasive readiness must not freeze later exact-candidate probes.
#[test]
fn transport_unavailable_startup_can_hotplug_and_resolve_repeatedly() {
    let mut backend = FixtureBackend::new(Vec::new());
    backend.capabilities =
        PlatformCapabilities::try_new(true, false, false, false, false, false, false, false)
            .expect("discovery-only startup capabilities are consistent");
    let mut registry = DeviceRegistry::new();

    assert!(
        discover_validated_devices(&mut backend, &mut registry)
            .expect("empty discovery-only startup scan remains valid")
            .is_empty()
    );

    backend.candidates = vec![candidate("hotplugged", "/dev/sg2", "7820999743")];
    backend
        .responses
        .insert("hotplugged".to_owned(), complete_responses("7820999743"));
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .expect("later exact candidate is probed independently")
        .into_iter()
        .next()
        .expect("hotplugged candidate is published");

    for _ in 0..2 {
        let mut resolved = registry
            .resolve(&mut backend, &snapshot.id, snapshot.revision)
            .expect("private reopen recipe remains reusable");
        resolved
            .revalidate_identity()
            .expect("same exact candidate remains valid");
    }
}

/// The complete proof captured while opening an operation lease is already
/// fresh and must not be repeated before the first host mutation preflight.
#[test]
fn first_host_revalidation_reuses_atomic_resolution_evidence() {
    let media_fingerprint = [0xA5; 32];
    let mut registry = DeviceRegistry::new();
    let mut backend = complete_backend(&[("candidate-a", "/dev/sg2", "7820999743")])
        .with_media(media_fingerprint, 320_000_000_000);
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .expect("fixture discovery succeeds")
        .remove(0);
    let mut resolved = registry
        .resolve(&mut backend, &snapshot.id, snapshot.revision)
        .expect("exact candidate resolution succeeds");
    let calls_after_resolution = backend.calls().len();
    let binding = resolved.binding();

    let facts = resolved
        .revalidate(&binding)
        .expect("resolution-time host evidence remains current for first preflight");

    assert_eq!(facts.media_fingerprint, Some(media_fingerprint));
    assert_eq!(
        backend.calls().len(),
        calls_after_resolution,
        "first preflight must not emit a duplicate SCSI proof sequence"
    );

    resolved
        .revalidate(&binding)
        .expect("later preflights still perform fresh retained-lease validation");
    assert!(
        backend.calls().len() > calls_after_resolution,
        "resolution evidence must be consumed exactly once"
    );
}

/// A matcher-allocation failure is dynamic per scan; retry on the same backend
/// observes hotplug and preserves the prior committed generation on failure.
#[test]
fn matcher_allocation_failures_retry_and_preserve_committed_devices() {
    let mut registry = DeviceRegistry::new();
    let mut backend = complete_backend(&[("initial", "/dev/sg2", "7820999743")]);
    backend.fail_matching_allocation_once();

    assert_eq!(
        discover_validated_devices(&mut backend, &mut registry),
        Err(PlatformError::EnumerationFailed)
    );
    assert!(registry.snapshots().is_empty());
    assert_eq!(backend.enumeration_calls, 1);
    assert_eq!(backend.refresh_commits, 0);
    assert_eq!(backend.refresh_aborts, 1);

    let original = discover_validated_devices(&mut backend, &mut registry)
        .expect("retry observes the still-pending candidate");
    let original_generation = registry.generation();
    assert_eq!(original.len(), 1);
    assert_eq!(backend.enumeration_calls, 2);

    backend.fail_matching_allocation_once();
    assert_eq!(
        discover_validated_devices(&mut backend, &mut registry),
        Err(PlatformError::EnumerationFailed)
    );
    assert_eq!(registry.snapshots(), original);
    assert_eq!(registry.generation(), original_generation);
    assert_eq!(backend.enumeration_calls, 3);

    assert!(
        discover_validated_devices(&mut backend, &mut registry)
            .expect("a later successful empty scan removes the unplugged device")
            .is_empty()
    );
    assert_eq!(backend.enumeration_calls, 4);
    assert!(registry.snapshots().is_empty());
}

/// The production macOS wrapper's successful null iterator is an authoritative
/// empty generation, so it removes the last previously committed device.
#[cfg(target_os = "macos")]
#[test]
fn successful_null_native_iterator_removes_last_committed_generation() {
    let mut registry = DeviceRegistry::new();
    let mut initial = complete_backend(&[("initial", "/dev/sg2", "7820999743")]);
    let original = discover_validated_devices(&mut initial, &mut registry)
        .expect("initial fixture generation commits");
    let original_generation = registry.generation();
    assert_eq!(original.len(), 1);

    rdx_macos_native::succeed_next_matching_without_iterator_for_test();
    let mut native = MacOsBackend::native();
    let removed = discover_validated_devices(&mut native, &mut registry)
        .expect("successful null iterator commits an empty generation");

    assert!(removed.is_empty());
    assert!(registry.snapshots().is_empty());
    assert_ne!(registry.generation(), original_generation);
}

/// A matching registry hint only permits the complete raw admission proof; a
/// spoofed identity remains absent from the committed device registry.
#[test]
fn rdx_like_registry_hint_reaches_inquiry_but_spoof_fails_final_validation() {
    let spoof = candidate("spoof", "/dev/sg2", "7820999743");
    let mut response_bytes = standard_inquiry(0x35, 0x08, 0x10);
    response_bytes[8..16].copy_from_slice(b"GENERIC ");
    let mut identification = device_identification("7820999743");
    identification[8..16].copy_from_slice(b"GENERIC ");
    let mut backend = FixtureBackend::new(vec![spoof]).with_responses(
        "spoof",
        BTreeMap::from([
            (DiscoveryProbe::StandardInquiry, response(response_bytes)),
            (
                DiscoveryProbe::DeviceIdentification,
                response(identification),
            ),
            (DiscoveryProbe::CapabilityPage, response(capability_page())),
        ]),
    );
    let mut registry = DeviceRegistry::new();

    assert!(
        discover_validated_devices(&mut backend, &mut registry)
            .expect("a candidate-local identity rejection is a successful scan")
            .is_empty()
    );
    assert_eq!(
        backend
            .calls()
            .iter()
            .map(|(_, probe, _)| *probe)
            .collect::<Vec<_>>(),
        [
            DiscoveryProbe::StandardInquiry,
            DiscoveryProbe::DeviceIdentification,
            DiscoveryProbe::CapabilityPage,
        ]
    );
}

#[test]
fn unchanged_devices_keep_ids_revisions_and_generation_when_enumeration_reorders() {
    let mut registry = DeviceRegistry::new();
    let mut first = complete_backend(&[
        ("candidate-a", "/dev/sg2", "7820999743"),
        ("candidate-b", "/dev/sg3", "7820999744"),
    ]);
    let original = discover_validated_devices(&mut first, &mut registry)
        .expect("initial complete discovery succeeds");
    let original_generation = registry.generation();

    let mut reordered = complete_backend(&[
        ("fresh-token-b", "/dev/sg3", "7820999744"),
        ("fresh-token-a", "/dev/sg2", "7820999743"),
    ]);
    let refreshed = discover_validated_devices(&mut reordered, &mut registry)
        .expect("reordered complete discovery succeeds");

    assert_eq!(refreshed, original);
    assert_eq!(registry.generation(), original_generation);
    let first = refreshed
        .first()
        .expect("reordered inventory still has both devices");
    let mut resolved = registry
        .resolve(&mut reordered, &first.id, first.revision)
        .expect("unchanged replacement refreshes its private reopen recipe");
    resolved
        .revalidate_identity()
        .expect("refreshed recipe retains the exact current handle");
}

/// Cross-field claims must never overstate host mutation or privilege readiness.
#[test]
fn platform_capabilities_reject_contradictions_and_expose_truthful_fields() {
    assert_eq!(
        PlatformCapabilities::try_new(true, false, true, false, false, false, false, false),
        Err(PlatformError::InconsistentCapabilities)
    );
    assert_eq!(
        PlatformCapabilities::try_new(true, true, false, true, false, false, false, false),
        Err(PlatformError::InconsistentCapabilities)
    );
    assert_eq!(
        PlatformCapabilities::try_new(true, true, true, false, true, false, false, false),
        Err(PlatformError::InconsistentCapabilities)
    );
    assert_eq!(
        PlatformCapabilities::try_new(false, true, false, false, false, false, false, false),
        Err(PlatformError::InconsistentCapabilities)
    );
    assert_eq!(
        PlatformCapabilities::try_new(true, false, false, false, false, false, false, true),
        Err(PlatformError::InconsistentCapabilities)
    );

    let capabilities =
        PlatformCapabilities::try_new(true, true, true, true, false, true, true, false)
            .expect("internally consistent capabilities");
    assert!(capabilities.discovery_available());
    assert!(capabilities.transport_available());
    assert!(capabilities.privileged());
    assert!(capabilities.safe_eject_available());
    assert!(!capabilities.force_eject_available());
    assert!(capabilities.format_available());
    assert!(capabilities.drive_letter_available());
    assert!(!capabilities.hardware_verified());
}

/// Malicious enumeration hints are rejected before the service sends any probe.
#[test]
fn hostile_unicode_control_and_oversized_metadata_fail_closed_before_io() {
    let valid = candidate("candidate-valid", "/dev/sg2", "7820999743");
    let unicode = candidate_with_metadata(
        "candidate-unicode",
        "/dev/sg3",
        CandidateMetadata::new(
            Some("TANDBERG💣".to_owned()),
            Some("RDX".to_owned()),
            Some("7820999744".to_owned()),
            Some(DeviceInterface::Usb3),
        ),
    );
    let control = candidate_with_metadata(
        "candidate-control",
        "/dev/sg4",
        CandidateMetadata::new(
            Some("TANDBERG".to_owned()),
            Some("RDX".to_owned()),
            Some("78209\n9745".to_owned()),
            Some(DeviceInterface::Usb3),
        ),
    );
    let oversized = candidate_with_metadata(
        "candidate-oversized",
        "/dev/sg5",
        CandidateMetadata::new(
            Some("TANDBERG".to_owned()),
            Some("R".repeat(129)),
            Some("7820999746".to_owned()),
            Some(DeviceInterface::Usb3),
        ),
    );
    let mut backend = FixtureBackend::new(vec![valid, unicode, control, oversized])
        .with_responses("candidate-valid", complete_responses("7820999743"))
        .with_responses("candidate-unicode", complete_responses("7820999744"))
        .with_responses("candidate-control", complete_responses("7820999745"))
        .with_responses("candidate-oversized", complete_responses("7820999746"));
    let mut registry = DeviceRegistry::new();

    let snapshots = discover_validated_devices(&mut backend, &mut registry)
        .expect("invalid hints reject candidates without failing valid discovery");

    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].serial.as_str(), "7820999743");
    assert!(
        backend
            .calls()
            .iter()
            .all(|(token, _, _)| token == "candidate-valid")
    );
}

/// Path reuse, removal, movement, and capability drift invalidate old authorization.
#[test]
fn replacement_removal_and_capability_changes_reject_stale_resolutions() {
    let mut registry = DeviceRegistry::new();
    let mut initial = complete_backend(&[("candidate-a", "/dev/sg2", "7820999743")]);
    let original = discover_validated_devices(&mut initial, &mut registry)
        .expect("initial discovery succeeds")
        .remove(0);
    let mut original_resolution = registry
        .resolve(&mut initial, &original.id, original.revision)
        .expect("current identity resolves");
    original_resolution
        .revalidate_identity()
        .expect("fresh resolution revalidates through its retained handle");
    drop(original_resolution);

    let mut reused_path = complete_backend(&[("candidate-b", "/dev/sg2", "7820999744")]);
    let replacement = discover_validated_devices(&mut reused_path, &mut registry)
        .expect("replacement discovery succeeds")
        .remove(0);
    assert_ne!(replacement.id, original.id);
    assert_eq!(
        registry
            .resolve(&mut reused_path, &original.id, original.revision)
            .expect_err("retired identity cannot be replayed"),
        PlatformError::StaleDeviceRevision
    );

    let mut removed = FixtureBackend::new(Vec::new());
    discover_validated_devices(&mut removed, &mut registry).expect("removal scan succeeds");
    assert_eq!(
        registry
            .resolve(&mut removed, &replacement.id, replacement.revision)
            .expect_err("removed identity cannot be replayed"),
        PlatformError::StaleDeviceRevision
    );

    let mut reinserted_backend = complete_backend(&[("candidate-a2", "/dev/sg2", "7820999743")]);
    let reinserted = discover_validated_devices(&mut reinserted_backend, &mut registry)
        .expect("reinserted device is rediscovered")
        .remove(0);
    assert_eq!(reinserted.id, original.id);
    assert!(reinserted.revision.is_newer_than(original.revision));
    let mut reinserted_resolution = registry
        .resolve(&mut reinserted_backend, &reinserted.id, reinserted.revision)
        .expect("reinserted current revision resolves");
    reinserted_resolution
        .revalidate_identity()
        .expect("reinserted binding remains live");
    drop(reinserted_resolution);

    let mut moved_backend = complete_backend(&[("candidate-a3", "/dev/sg9", "7820999743")]);
    let moved = discover_validated_devices(&mut moved_backend, &mut registry)
        .expect("same identity at a new private locator is rediscovered")
        .remove(0);
    assert_eq!(moved.id, reinserted.id);
    assert!(moved.revision.is_newer_than(reinserted.revision));
    let mut moved_resolution = registry
        .resolve(&mut moved_backend, &moved.id, moved.revision)
        .expect("moved current binding resolves");
    moved_resolution
        .revalidate_identity()
        .expect("moved binding remains live on its exact handle");
    drop(moved_resolution);
    let mut changed_capability = complete_backend(&[("candidate-a4", "/dev/sg9", "7820999743")]);
    changed_capability.capabilities =
        PlatformCapabilities::try_new(true, true, true, true, true, true, true, true)
            .expect("hardware-verified fixture matrix is consistent");
    let changed = discover_validated_devices(&mut changed_capability, &mut registry)
        .expect("capability drift is accepted as a new binding")
        .remove(0);
    assert!(changed.revision.is_newer_than(moved.revision));
    let mut current_resolution = registry
        .resolve(&mut changed_capability, &changed.id, changed.revision)
        .expect("latest binding resolves");
    current_resolution
        .revalidate_identity()
        .expect("latest binding remains live");
    let resolution_diagnostics = format!("{current_resolution:?}");
    drop(current_resolution);

    let mut other_registry = DeviceRegistry::new();
    let mut other_backend = complete_backend(&[("other", "/dev/sg9", "7820999743")]);
    discover_validated_devices(&mut other_backend, &mut other_registry)
        .expect("second independent registry discovers same identity");
    let diagnostics = format!("{registry:?} {other_registry:?} {resolution_diagnostics}");
    assert!(!diagnostics.contains("/dev/"));
    assert!(!diagnostics.contains("7820999743"));
}

#[path = "platform_registry/closure.rs"]
mod platform_registry_closure;
