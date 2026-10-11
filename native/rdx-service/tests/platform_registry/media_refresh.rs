// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cartridge metadata and non-disruptive refresh integration tests.

use super::*;

/// Builds complete dock and cartridge probe responses for binding tests.
fn complete_media_responses(serial: &str) -> BTreeMap<DiscoveryProbe, CommandDispatch> {
    let mut responses = complete_responses(serial);
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
    responses
}

#[test]
fn mounted_candidate_is_reported_separately_without_exposing_native_authority() {
    let mounted = candidate("mounted-rdx", "/dev/disk-private", "7820999743");
    let mut backend = FixtureBackend::new(vec![mounted])
        .with_open_failure("mounted-rdx", PlatformError::DeviceBusy);
    let report = discover_validated_device_report(&mut backend, &mut DeviceRegistry::new())
        .expect("mounted media remains a successful non-mutating scan outcome");

    assert!(report.snapshots().is_empty());
    assert_eq!(report.diagnostics().rejections(), &[("media-mounted", 1)]);
    let diagnostics = serde_json::to_string(report.diagnostics()).unwrap();
    assert!(!diagnostics.contains("mounted-rdx"));
    assert!(!diagnostics.contains("/dev/disk-private"));
}

#[test]
fn changed_media_reopens_once_for_protocol_status_then_refreshes_non_disruptively() {
    let mut registry = DeviceRegistry::new();
    let mut backend = complete_backend(&[("initial", "/dev/sg2", "7820999743")]);
    let initial = discover_validated_devices(&mut backend, &mut registry)
        .expect("initial protocol validation succeeds")
        .remove(0);
    assert_eq!(initial.media_state, rdx_service::model::MediaState::NoMedia);
    assert_eq!(backend.open_calls, 1);

    backend.candidates = vec![candidate(
        "refresh-current",
        "/private/generation-2",
        "7820999743",
    )];
    backend.refreshed_facts = FixtureBackend::new(Vec::new())
        .with_refreshed_media([0xC3; 32], 320_067_338_240)
        .refreshed_facts;
    backend.facts = backend
        .refreshed_facts
        .expect("configured refresh facts are present");
    backend.responses.insert(
        "refresh-current".to_owned(),
        complete_responses("7820999743"),
    );
    let refreshed = discover_validated_devices(&mut backend, &mut registry)
        .expect("same dock refreshes from non-disruptive host facts")
        .remove(0);

    assert_eq!(backend.open_calls, 2);
    assert_eq!(
        refreshed.media_state,
        rdx_service::model::MediaState::Present
    );
    assert_eq!(
        refreshed
            .media
            .as_ref()
            .and_then(|media| media.capacity_bytes)
            .map(rdx_service::model::SafeJsonInteger::get),
        Some(320_067_338_240)
    );
    assert_eq!(
        refreshed
            .media
            .as_ref()
            .and_then(|media| media.filesystem.as_ref())
            .map(|filesystem| filesystem.as_str()),
        Some("ntfs")
    );
    assert_eq!(
        refreshed.capabilities[&OperationKind::EjectSafe].state,
        CapabilityState::Available
    );
    assert_eq!(
        refreshed.capabilities[&OperationKind::FirmwareUpdate].state,
        CapabilityState::WrongMediaState
    );

    let refreshed_generation = registry.generation();
    backend.candidates = vec![candidate(
        "refresh-later",
        "/private/generation-3",
        "7820999743",
    )];
    let unchanged = discover_validated_devices(&mut backend, &mut registry)
        .expect("private generation recipe changes preserve physical continuity")
        .remove(0);
    assert_eq!(backend.open_calls, 2);
    assert_eq!(unchanged.revision, refreshed.revision);
    assert_eq!(registry.generation(), refreshed_generation);
}

#[test]
fn mutable_capacity_and_telemetry_do_not_invalidate_the_same_live_binding() {
    let mut registry = DeviceRegistry::new();
    let mut backend = FixtureBackend::new(vec![candidate(
        "mutable-telemetry",
        "/dev/sg2",
        "7820999743",
    )])
    .with_responses("mutable-telemetry", complete_media_responses("7820999743"))
    .with_media([0xC4; 32], 320_067_338_240);
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .expect("initial mounted-cartridge discovery succeeds")
        .remove(0);

    backend.facts.free_bytes -= 4_096;
    backend
        .responses
        .get_mut("mutable-telemetry")
        .unwrap()
        .insert(
            DiscoveryProbe::Temperature,
            response(vec![0x0D, 0, 0, 6, 0, 0, 0, 2, 0, 40]),
        );

    let mut resolved = registry
        .resolve(&mut backend, &snapshot.id, snapshot.revision)
        .expect("free-space and temperature changes retain the same binding");
    resolved
        .revalidate_identity()
        .expect("repeated same-handle proof ignores mutable telemetry");
}

#[test]
fn unmounted_media_never_claims_zero_free_or_full_capacity() {
    let mut registry = DeviceRegistry::new();
    let mut backend =
        FixtureBackend::new(vec![candidate("unmounted-media", "/dev/sg2", "7820999743")])
            .with_responses("unmounted-media", complete_media_responses("7820999743"))
            .with_media([0xC6; 32], 320_067_338_240);
    backend.facts.mounted = false;
    backend.facts.free_bytes = 0;
    backend.facts.filesystem = None;

    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .expect("unmounted cartridge discovery remains valid")
        .remove(0);
    let published = serde_json::to_value(snapshot.media).unwrap();

    assert_eq!(
        published["details"]["capacityBytes"],
        serde_json::json!({"availability":"reported","value":320_067_338_240_u64})
    );
    assert_eq!(
        published["details"]["usedBytes"],
        serde_json::json!({"availability":"unavailable","reason":"media-not-mounted"})
    );
    assert_eq!(
        published["details"]["freeBytes"],
        serde_json::json!({"availability":"unavailable","reason":"media-not-mounted"})
    );
    assert!(published["usedBytes"].is_null());
}

#[test]
fn changed_cartridge_identity_still_invalidates_the_live_binding() {
    let mut registry = DeviceRegistry::new();
    let mut backend = FixtureBackend::new(vec![candidate(
        "changed-media-identity",
        "/dev/sg2",
        "7820999743",
    )])
    .with_responses(
        "changed-media-identity",
        complete_media_responses("7820999743"),
    )
    .with_media([0xC5; 32], 320_067_338_240);
    let snapshot = discover_validated_devices(&mut backend, &mut registry)
        .expect("initial cartridge identity is validated")
        .remove(0);

    let mut changed_identity = media_device_page();
    changed_identity[0x32] = b'X';
    backend
        .responses
        .get_mut("changed-media-identity")
        .unwrap()
        .insert(DiscoveryProbe::MediaDevice, response(changed_identity));

    assert_eq!(
        registry
            .resolve(&mut backend, &snapshot.id, snapshot.revision)
            .expect_err("different cartridge identity must fail closed"),
        PlatformError::StaleDeviceBinding
    );
}

/// Optional telemetry failures retain the validated candidate and publish an
/// explicit bounded reason for every unavailable drive and cartridge field.
#[test]
fn optional_status_probe_failure_preserves_candidate_and_field_reasons() {
    let mut responses = complete_responses("7820999743");
    responses.remove(&DiscoveryProbe::OperationMode);
    responses.remove(&DiscoveryProbe::DriveStatus);
    let mut backend = FixtureBackend::new(vec![candidate(
        "optional-status-failure",
        "/dev/sg2",
        "7820999743",
    )])
    .with_responses("optional-status-failure", responses)
    .with_media([0x5A; 32], 1_000_000_000);
    let mut registry = DeviceRegistry::new();

    let snapshots = discover_validated_devices(&mut backend, &mut registry)
        .expect("optional telemetry never rejects a validated candidate");
    assert_eq!(snapshots.len(), 1);
    let published = serde_json::to_value(&snapshots[0]).unwrap();
    assert_eq!(
        published["drive"]["details"]["operationMode"],
        serde_json::json!({"availability":"unavailable","reason":"status-probe-unavailable"})
    );
    assert_eq!(
        published["drive"]["details"]["status"],
        serde_json::json!({"availability":"unavailable","reason":"status-probe-unavailable"})
    );
    assert_eq!(
        published["drive"]["details"]["firmwareRevision"],
        serde_json::json!({"availability":"reported","value":"0283"})
    );
    assert_eq!(
        published["media"]["details"]["capacityBytes"],
        serde_json::json!({"availability":"reported","value":1_000_000_000_u64})
    );
    assert_eq!(
        published["media"]["details"]["status"],
        serde_json::json!({"availability":"unavailable","reason":"status-probe-unavailable"})
    );
    assert!(!published.to_string().contains("/dev/"));
}

#[test]
fn current_temperature_and_unavailable_sensor_reach_the_renderer_truthfully() {
    for current in [0, 39, 255] {
        let mut responses = complete_media_responses("7820999743");
        responses.insert(
            DiscoveryProbe::Temperature,
            response(vec![
                0x0D, 0, 0, 12, 0, 0, 0x43, 2, 0, current, 0, 1, 0x43, 2, 0, 255,
            ]),
        );
        let mut backend =
            FixtureBackend::new(vec![candidate("temperature", "/dev/sg2", "7820999743")])
                .with_responses("temperature", responses)
                .with_media([0xC7; 32], 320_067_338_240);
        let snapshot = discover_validated_devices(&mut backend, &mut DeviceRegistry::new())
            .expect("temperature decoding must not reject the dock")
            .remove(0);
        let published = serde_json::to_value(snapshot.media).unwrap();
        let expected = if current == 255 {
            serde_json::json!({"availability":"unavailable","reason":"not-reported"})
        } else {
            serde_json::json!({"availability":"reported","value":current})
        };
        assert_eq!(published["details"]["temperatureCelsius"], expected);
    }
}

/// Verifies vendor-padded telemetry is published by the normal discovery path.
#[test]
fn vendor_padded_cartridge_status_reaches_the_public_device_snapshot() {
    let mut page = cartridge_status_page();
    for code in 11_u16..14 {
        page.extend_from_slice(&code.to_be_bytes());
        page.extend_from_slice(&[0x60, 4, 0, 0, 0, 0]);
    }
    assert_eq!(page.len(), 0x72);
    page.extend_from_slice(&[0, 0]);
    page[2..4].copy_from_slice(&0x70_u16.to_be_bytes());
    let mut responses = complete_media_responses("7820999743");
    responses.insert(DiscoveryProbe::CartridgeStatus, response(page));
    let mut backend =
        FixtureBackend::new(vec![candidate("vendor-padding", "/dev/sg2", "7820999743")])
            .with_responses("vendor-padding", responses)
            .with_media([0xD3; 32], 320_067_338_240);
    let snapshot = discover_validated_devices(&mut backend, &mut DeviceRegistry::new())
        .expect("vendor padding does not reject the dock")
        .remove(0);
    let published = serde_json::to_value(snapshot.media).unwrap();
    for (field, value) in [
        ("status", serde_json::json!("Good")),
        ("loadCount", serde_json::json!(12)),
        ("bytesRead", serde_json::json!(5_678_000_000_u64)),
        ("bytesWritten", serde_json::json!(1_234_000_000_u64)),
        ("writeProtected", serde_json::json!(false)),
    ] {
        assert_eq!(
            published["details"][field],
            serde_json::json!({"availability":"reported","value":value}),
            "{field}"
        );
    }
}
