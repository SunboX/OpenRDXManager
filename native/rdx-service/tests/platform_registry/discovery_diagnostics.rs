// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sanitized discovery-diagnostic integration tests.

use super::*;

/// Firmware readback bypasses only the selected dock's otherwise valid host cache.
#[test]
fn firmware_refresh_reprobes_only_the_updated_dock() {
    let candidates = || {
        vec![
            candidate("dock-a", "/dev/sg2", "7820999743"),
            candidate("dock-b", "/dev/sg3", "7820999744"),
        ]
    };
    let mut backend = FixtureBackend::new(candidates())
        .with_responses("dock-a", complete_responses("7820999743"))
        .with_responses("dock-b", complete_responses("7820999744"));
    let mut registry = DeviceRegistry::new();
    let initial = discover_validated_devices(&mut backend, &mut registry).unwrap();
    let target = initial
        .iter()
        .find(|dock| dock.serial.as_str() == "7820999743")
        .unwrap();
    backend.refreshed_facts = Some(backend.facts);
    for token in ["dock-a", "dock-b"] {
        let mut inquiry = standard_inquiry(0x35, 0x08, 0x10);
        inquiry[32..36].copy_from_slice(b"0284");
        backend
            .responses
            .get_mut(token)
            .unwrap()
            .insert(DiscoveryProbe::StandardInquiry, response(inquiry));
    }
    backend.candidates = candidates();
    let cached = discover_validated_devices(&mut backend, &mut registry).unwrap();
    assert!(
        cached
            .iter()
            .all(|dock| dock.drive.firmware_revision.as_ref().unwrap().as_str() == "0283")
    );
    assert_eq!(
        backend.open_calls, 2,
        "ordinary refresh does not seize either dock"
    );
    backend.candidates = candidates();
    let fresh = rdx_service::platform::discover_firmware_device_report(
        &mut backend,
        &mut registry,
        &target.id,
    )
    .unwrap();
    assert_eq!(backend.open_calls, 3, "only the selected dock is reprobed");
    for dock in fresh.snapshots() {
        if dock.id == target.id {
            assert_eq!(
                dock.drive.firmware_revision.as_ref().unwrap().as_str(),
                "0284"
            );
            assert_ne!(dock.revision, target.revision);
            registry
                .resolve(&mut backend, &dock.id, dock.revision)
                .expect("fresh readback matches the refreshed binding");
        } else {
            assert_eq!(
                dock.drive.firmware_revision.as_ref().unwrap().as_str(),
                "0283"
            );
        }
    }
}

#[test]
fn candidate_rejections_are_counted_without_exposing_tokens_or_locators() {
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

    let report = discover_validated_device_report(&mut backend, &mut registry)
        .expect("candidate-local rejection keeps the scan successful");

    assert_eq!(report.snapshots().len(), 1);
    assert_eq!(report.diagnostics().candidate_count(), 2);
    assert_eq!(report.diagnostics().accepted_count(), 1);
    assert_eq!(
        report.diagnostics().rejections(),
        &[("candidate-vpd83-inquiry-failed", 1)]
    );
    let diagnostics = serde_json::to_string(report.diagnostics()).expect("diagnostics serialize");
    assert!(!diagnostics.contains("candidate-b"));
    assert!(!diagnostics.contains("/dev/sg3"));
}

/// Each mandatory failure preserves the original successful-prefix probe order.
#[test]
fn mandatory_discovery_failures_identify_stage_without_extra_dispatch() {
    let required = [
        DiscoveryProbe::StandardInquiry,
        DiscoveryProbe::DeviceIdentification,
        DiscoveryProbe::CapabilityPage,
    ];
    let codes = [
        "candidate-standard-inquiry-failed",
        "candidate-vpd83-inquiry-failed",
        "candidate-mode31-probe-failed",
    ];
    for (index, failed) in required.into_iter().enumerate() {
        let mut replies = complete_responses("7820999743");
        replies.remove(&failed);
        let mut backend = FixtureBackend::new(vec![candidate(
            "private-token",
            "/private/path",
            "7820999743",
        )])
        .with_responses("private-token", replies);
        let report =
            discover_validated_device_report(&mut backend, &mut DeviceRegistry::new()).unwrap();
        assert_eq!(report.diagnostics().rejections(), &[(codes[index], 1)]);
        let calls = backend.calls.lock().unwrap();
        assert_eq!(
            calls.iter().map(|(_, probe, _)| *probe).collect::<Vec<_>>(),
            required[..=index]
        );
        assert_eq!(backend.open_calls, 1);
    }
}

/// Parsing still follows all three mandatory reads, and optional reads do not rescue malformed proof.
#[test]
fn required_identity_and_feature_parsing_keep_exact_dispatch_order() {
    for (probe, code) in [
        (
            DiscoveryProbe::StandardInquiry,
            "candidate-inquiry-identity-invalid",
        ),
        (
            DiscoveryProbe::DeviceIdentification,
            "candidate-inquiry-identity-invalid",
        ),
        (DiscoveryProbe::CapabilityPage, "candidate-mode31-invalid"),
    ] {
        let mut replies = complete_responses("7820999743");
        replies.insert(probe, response(vec![0]));
        let mut backend =
            FixtureBackend::new(vec![candidate("opaque", "/private/path", "7820999743")])
                .with_responses("opaque", replies);
        let report =
            discover_validated_device_report(&mut backend, &mut DeviceRegistry::new()).unwrap();
        assert_eq!(report.diagnostics().rejections(), &[(code, 1)]);
        assert_eq!(
            backend
                .calls
                .lock()
                .unwrap()
                .iter()
                .map(|(_, probe, _)| *probe)
                .collect::<Vec<_>>(),
            [
                DiscoveryProbe::StandardInquiry,
                DiscoveryProbe::DeviceIdentification,
                DiscoveryProbe::CapabilityPage
            ]
        );
    }
}

/// All native open stages use the same unchanged aggregate shape and account every candidate once.
#[test]
fn closed_native_open_stages_are_private_counted_and_read_without_reopening() {
    use rdx_service::platform::DiscoveryFailure;
    for stage in [
        DiscoveryFailure::RegistryRecipe,
        DiscoveryFailure::Prefilter,
        DiscoveryFailure::RegistryOpen,
        DiscoveryFailure::MediaMap,
        DiscoveryFailure::Unmount,
        DiscoveryFailure::WorkerAcquisition,
    ] {
        let mut backend = FixtureBackend::new(vec![candidate(
            "opaque-private-id",
            "/private/secret",
            "7820999743",
        )])
        .with_open_failure("opaque-private-id", PlatformError::NativeBoundaryFailure)
        .with_open_stage(stage);
        let report =
            discover_validated_device_report(&mut backend, &mut DeviceRegistry::new()).unwrap();
        assert_eq!(report.diagnostics().candidate_count(), 1);
        assert_eq!(report.diagnostics().accepted_count(), 0);
        assert_eq!(report.diagnostics().rejections(), &[(stage.code(), 1)]);
        assert_eq!(backend.open_calls, 1);
        assert!(backend.calls.lock().unwrap().is_empty());
        let encoded = serde_json::to_string(report.diagnostics()).unwrap();
        for private in [
            "opaque-private-id",
            "/private/secret",
            "7820999743",
            "NativeBoundaryFailure",
        ] {
            assert!(!encoded.contains(private));
        }
        assert!(
            stage
                .code()
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        );
        assert!(stage.code().len() <= 128);
    }
}

/// Malformed metadata never opens transport; a successful candidate ignores stale open diagnostics.
#[test]
fn metadata_failure_and_success_preserve_admission_and_candidate_accounting() {
    let invalid = candidate_with_metadata(
        "bad",
        "/private/bad",
        CandidateMetadata::new(Some("bad\nmetadata".into()), None, None, None),
    );
    let valid = candidate("good", "/private/good", "7820999743");
    let mut backend = FixtureBackend::new(vec![invalid, valid])
        .with_responses("good", complete_responses("7820999743"))
        .with_open_stage(rdx_service::platform::DiscoveryFailure::Unmount);
    let report =
        discover_validated_device_report(&mut backend, &mut DeviceRegistry::new()).unwrap();
    assert_eq!(
        report.diagnostics().rejections(),
        &[("candidate-metadata-invalid", 1)]
    );
    assert_eq!(report.diagnostics().candidate_count(), 2);
    assert_eq!(report.diagnostics().accepted_count(), 1);
    assert_eq!(backend.open_calls, 1);
    assert_eq!(backend.refresh_commits, 1);
    assert_eq!(backend.refresh_aborts, 0);
}

/// Required identity corroboration and host evidence failures precede optional status probes.
#[test]
fn identity_and_required_host_checks_publish_closed_rejections() {
    let mut host_failure =
        FixtureBackend::new(vec![candidate("dock", "/private/dock", "7820999743")])
            .with_responses("dock", complete_responses("7820999743"));
    host_failure.host_facts_failure = Some(PrimitiveFailure::not_attempted(
        HostPrimitiveError::DependencyMissing,
    ));
    let mut media_failure =
        FixtureBackend::new(vec![candidate("dock", "/private/dock", "7820999743")])
            .with_responses("dock", complete_responses("7820999743"));
    media_failure.facts.media_present = true;
    media_failure.facts.media_fingerprint = None;
    let mismatch = FixtureBackend::new(vec![candidate("dock", "/private/dock", "7820999743")])
        .with_responses("dock", complete_responses("7820999744"));
    let interface = candidate_with_metadata(
        "dock",
        "/private/dock",
        CandidateMetadata::new(
            Some("TANDBERG".into()),
            Some("RDX".into()),
            None,
            Some(DeviceInterface::Legacy),
        ),
    );
    let interface_failure = FixtureBackend::new(vec![interface])
        .with_responses("dock", complete_responses("7820999743"));
    for (mut backend, code) in [
        (host_failure, "candidate-host-facts-failed"),
        (media_failure, "candidate-host-media-evidence-invalid"),
        (mismatch, "candidate-inquiry-metadata-mismatch"),
        (interface_failure, "candidate-interface-mismatch"),
    ] {
        let report =
            discover_validated_device_report(&mut backend, &mut DeviceRegistry::new()).unwrap();
        assert_eq!(report.diagnostics().rejections(), &[(code, 1)]);
        assert_eq!(
            backend
                .calls
                .lock()
                .unwrap()
                .iter()
                .map(|(_, probe, _)| *probe)
                .collect::<Vec<_>>(),
            [
                DiscoveryProbe::StandardInquiry,
                DiscoveryProbe::DeviceIdentification,
                DiscoveryProbe::CapabilityPage
            ]
        );
        assert_eq!(backend.open_calls, 1);
    }
}

/// Missing optional telemetry remains an accepted dock, never a mandatory rejection.
#[test]
fn optional_status_failures_preserve_accepted_candidate_evidence() {
    let mut replies = complete_responses("7820999743");
    replies.remove(&DiscoveryProbe::OperationMode);
    replies.remove(&DiscoveryProbe::DriveStatus);
    let mut backend = FixtureBackend::new(vec![candidate("dock", "/private/dock", "7820999743")])
        .with_responses("dock", replies);
    let report =
        discover_validated_device_report(&mut backend, &mut DeviceRegistry::new()).unwrap();
    assert_eq!(report.snapshots().len(), 1);
    assert_eq!(report.diagnostics().accepted_count(), 1);
    assert!(report.diagnostics().rejections().is_empty());
    assert_eq!(
        backend
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|(_, probe, _)| *probe)
            .collect::<Vec<_>>(),
        [
            DiscoveryProbe::StandardInquiry,
            DiscoveryProbe::DeviceIdentification,
            DiscoveryProbe::CapabilityPage,
            DiscoveryProbe::OperationMode,
            DiscoveryProbe::DriveStatus
        ]
    );
}
