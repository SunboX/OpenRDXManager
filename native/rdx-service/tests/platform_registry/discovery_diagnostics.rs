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
        &[("candidate-validation-failed", 1)]
    );
    let diagnostics = serde_json::to_string(report.diagnostics()).expect("diagnostics serialize");
    assert!(!diagnostics.contains("candidate-b"));
    assert!(!diagnostics.contains("/dev/sg3"));
}
