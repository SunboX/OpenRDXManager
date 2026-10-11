// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[path = "drive_letters.rs"]
mod drive_letters;

/// Windows host readiness admits drive-letter changes only for a media-empty USB3 dock.
#[test]
fn drive_letter_capability_is_usb3_only_before_media_arrival() {
    let legacy = candidate_with_metadata(
        "legacy",
        "/private/legacy",
        CandidateMetadata::new(
            Some("TANDBERG".to_owned()),
            Some("RDX".to_owned()),
            Some("7820999742".to_owned()),
            Some(DeviceInterface::Legacy),
        ),
    );
    let mut legacy_responses = complete_responses("7820999742");
    legacy_responses.insert(
        DiscoveryProbe::StandardInquiry,
        response(standard_inquiry(0, 0x08, 0x10)),
    );
    let mut backend = FixtureBackend::new(vec![
        candidate("usb3", "/private/usb3", "7820999741"),
        legacy,
    ])
    .with_responses("usb3", complete_responses("7820999741"))
    .with_responses("legacy", legacy_responses);
    let mut registry = DeviceRegistry::new();

    let devices = discover_validated_devices(&mut backend, &mut registry).unwrap();
    let usb3 = devices
        .iter()
        .find(|device| device.serial.as_str() == "7820999741")
        .unwrap();
    let legacy = devices
        .iter()
        .find(|device| device.serial.as_str() == "7820999742")
        .unwrap();
    for kind in [
        OperationKind::DriveLetterSet,
        OperationKind::DriveLetterReset,
    ] {
        assert_eq!(usb3.capabilities[&kind].state, CapabilityState::Available);
        assert_eq!(
            legacy.capabilities[&kind].state,
            CapabilityState::UnsupportedProduct
        );
    }
}

/// Enumeration ambiguity and fixed resource bounds reject before any device I/O.
#[test]
fn duplicate_candidates_and_candidate_limit_preserve_the_authoritative_set() {
    let mut registry = DeviceRegistry::new();
    let mut initial = complete_backend(&[("initial", "/dev/sg1", "7820999741")]);
    let original = discover_validated_devices(&mut initial, &mut registry)
        .expect("initial registry population succeeds");
    let original_generation = registry.generation();

    let mut duplicate = FixtureBackend::new(vec![
        candidate("duplicate-a", "/dev/sg2", "7820999742"),
        candidate("duplicate-b", "/dev/sg2", "7820999743"),
    ]);
    assert_eq!(
        discover_validated_devices(&mut duplicate, &mut registry),
        Err(PlatformError::DuplicateCandidate)
    );
    assert!(duplicate.calls().is_empty());
    assert_eq!(registry.snapshots(), original);
    assert_eq!(registry.generation(), original_generation);
    assert_eq!(duplicate.refresh_commits, 0);
    assert_eq!(duplicate.refresh_aborts, 1);

    let too_many = (0..=rdx_service::platform::MAX_CANDIDATE_DEVICES)
        .map(|index| {
            candidate(
                &format!("candidate-{index}"),
                &format!("/private/device/{index}"),
                "7820999742",
            )
        })
        .collect();
    let mut oversized = FixtureBackend::new(too_many);
    assert_eq!(
        discover_validated_devices(&mut oversized, &mut registry),
        Err(PlatformError::TooManyCandidates)
    );
    assert!(oversized.calls().is_empty());
    assert_eq!(registry.snapshots(), original);
    assert_eq!(registry.generation(), original_generation);
    assert_eq!(oversized.refresh_commits, 0);
    assert_eq!(oversized.refresh_aborts, 1);
}

/// Backend reopen recipes publish only with a successful registry transaction.
#[test]
fn candidate_refresh_commit_follows_successful_registry_replacement() {
    let mut backend = complete_backend(&[("candidate", "/dev/sg2", "7820999743")]);
    let mut registry = DeviceRegistry::new();

    discover_validated_devices(&mut backend, &mut registry).expect("scan succeeds");

    assert_eq!(backend.refresh_commits, 1);
    assert_eq!(backend.refresh_aborts, 0);
}

/// Duplicate proven serials are ambiguous even when private locators differ.
#[test]
fn duplicate_validated_serials_reject_the_whole_replacement_atomically() {
    let mut registry = DeviceRegistry::new();
    let mut initial = complete_backend(&[("initial", "/dev/sg1", "7820999741")]);
    let original = discover_validated_devices(&mut initial, &mut registry)
        .expect("initial registry population succeeds");
    let original_generation = registry.generation();
    let mut ambiguous = complete_backend(&[
        ("ambiguous-a", "/dev/sg2", "7820999742"),
        ("ambiguous-b", "/dev/sg3", "7820999742"),
    ]);

    assert_eq!(
        discover_validated_devices(&mut ambiguous, &mut registry),
        Err(PlatformError::DuplicateDeviceSerial)
    );
    assert_eq!(registry.snapshots(), original);
    assert_eq!(registry.generation(), original_generation);
}

/// The backend owns static discovery support; the generic transaction always
/// delegates so a cached capability snapshot cannot hide a later scan.
#[test]
fn backend_discovery_support_and_transport_readiness_do_not_freeze_scans() {
    let pending = candidate("pending", "/private/device/pending", "7820999743");
    let mut unavailable = FixtureBackend::new(vec![pending]);
    unavailable.capabilities =
        PlatformCapabilities::try_new(false, false, false, false, false, false, false, false)
            .expect("fully unavailable is internally consistent");
    let mut registry = DeviceRegistry::new();
    assert_eq!(
        discover_validated_devices(&mut unavailable, &mut registry),
        Err(PlatformError::DiscoveryUnavailable)
    );
    assert_eq!(unavailable.enumeration_calls, 1);
    assert_eq!(unavailable.candidates.len(), 1);
    assert_eq!(
        PlatformError::DiscoveryUnavailable.to_string(),
        "discovery-unavailable"
    );

    unavailable.capabilities =
        PlatformCapabilities::try_new(true, false, false, false, false, false, false, false)
            .expect("enumeration without transport is internally consistent");
    assert!(
        discover_validated_devices(&mut unavailable, &mut registry)
            .expect("candidate-local transport failure leaves a valid empty scan")
            .is_empty()
    );
    assert!(unavailable.candidates.is_empty());
    assert_eq!(unavailable.enumeration_calls, 2);
    assert_eq!(unavailable.calls().len(), 1);
}

/// Unsupported, contradictory, and malformed device replies never establish identity.
#[test]
fn exact_identity_and_capability_evidence_fail_closed_per_candidate() {
    let candidates = vec![
        candidate("valid", "/dev/sg1", "7820999741"),
        candidate("unsupported", "/dev/sg2", "7820999742"),
        candidate("mismatch", "/dev/sg3", "7820999743"),
        candidate("bad-capability", "/dev/sg4", "7820999744"),
        candidate("control", "/dev/sg5", "7820999745"),
    ];
    let mut unsupported = standard_inquiry(0x35, 0x08, 0x10);
    unsupported[36] = 0x20;
    let mut mismatched_id = device_identification("7820999743");
    mismatched_id[16..32].copy_from_slice(b"OTHER           ");
    let mut wrong_capability = capability_page();
    wrong_capability[8] = 0x32;
    let mut control_id = device_identification("7820999745");
    control_id[32] = b'\n';

    let mut backend = FixtureBackend::new(candidates)
        .with_responses("valid", complete_responses("7820999741"))
        .with_responses(
            "unsupported",
            BTreeMap::from([
                (DiscoveryProbe::StandardInquiry, response(unsupported)),
                (
                    DiscoveryProbe::DeviceIdentification,
                    response(device_identification("7820999742")),
                ),
                (DiscoveryProbe::CapabilityPage, response(capability_page())),
            ]),
        )
        .with_responses(
            "mismatch",
            BTreeMap::from([
                (
                    DiscoveryProbe::StandardInquiry,
                    response(standard_inquiry(0x35, 0x08, 0x10)),
                ),
                (
                    DiscoveryProbe::DeviceIdentification,
                    response(mismatched_id),
                ),
                (DiscoveryProbe::CapabilityPage, response(capability_page())),
            ]),
        )
        .with_responses(
            "bad-capability",
            BTreeMap::from([
                (
                    DiscoveryProbe::StandardInquiry,
                    response(standard_inquiry(0x35, 0x08, 0x10)),
                ),
                (
                    DiscoveryProbe::DeviceIdentification,
                    response(device_identification("7820999744")),
                ),
                (DiscoveryProbe::CapabilityPage, response(wrong_capability)),
            ]),
        )
        .with_responses(
            "control",
            BTreeMap::from([
                (
                    DiscoveryProbe::StandardInquiry,
                    response(standard_inquiry(0x35, 0x08, 0x10)),
                ),
                (DiscoveryProbe::DeviceIdentification, response(control_id)),
                (DiscoveryProbe::CapabilityPage, response(capability_page())),
            ]),
        );
    let mut registry = DeviceRegistry::new();

    let discovered = discover_validated_devices(&mut backend, &mut registry)
        .expect("candidate-local proof failures do not hide a valid device");

    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].serial.as_str(), "7820999741");
}

/// Every truncated discovery response is rejected without indexing panics.
#[test]
fn discovery_parsers_reject_all_truncated_prefixes_without_panicking() {
    let standard = standard_inquiry(0x35, 0x08, 0x10);
    let identification = device_identification("7820999743");
    for length in 0..standard.len() {
        assert!(parse_rdx_inquiry_identity(&standard[..length], &identification).is_err());
    }
    for length in 0..identification.len() {
        assert!(parse_rdx_inquiry_identity(&standard, &identification[..length]).is_err());
    }
    let capability = capability_page();
    for length in 0..capability.len() {
        assert!(RdxFeaturePage::parse(&capability[..length]).is_err());
    }
}

/// Service software readiness is independent from truthful physical verification metadata.
#[test]
fn service_descriptor_maps_platform_truth_without_enabling_fake_hardware() {
    let unverified =
        PlatformCapabilities::try_new(true, true, true, true, false, true, true, false)
            .expect("unverified native matrix is consistent");
    let descriptor =
        ServiceDescriptor::from_platform_capabilities(ServicePlatform::Darwin, unverified);
    assert_eq!(descriptor.mode(), ServiceMode::Native);
    assert!(descriptor.privileged());
    assert_eq!(descriptor.platform_capability_state(), "available");
    assert_eq!(descriptor.platform_capability_reason(), None);
    assert!(!descriptor.hardware_verified());

    let verified = PlatformCapabilities::try_new(true, true, true, true, false, true, true, true)
        .expect("verified native matrix is consistent");
    let descriptor =
        ServiceDescriptor::from_platform_capabilities(ServicePlatform::Darwin, verified);
    assert_eq!(descriptor.platform_capability_state(), "available");
    assert_eq!(descriptor.platform_capability_reason(), None);
    assert!(descriptor.hardware_verified());

    let no_adapter =
        PlatformCapabilities::try_new(false, false, false, false, false, false, false, false)
            .expect("fully unavailable matrix is consistent");
    let descriptor =
        ServiceDescriptor::from_platform_capabilities(ServicePlatform::Darwin, no_adapter);
    assert_eq!(descriptor.mode(), ServiceMode::NoDevice);
    assert!(!descriptor.privileged());
    assert_eq!(
        descriptor.platform_capability_state(),
        "transport-unavailable"
    );
}
