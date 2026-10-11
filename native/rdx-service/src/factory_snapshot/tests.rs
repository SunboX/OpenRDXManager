// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Synthetic collector fixtures contain no physical dock data.

use std::collections::VecDeque;
use std::fs;

use super::*;

const SERIAL: &str = "001234567890";

/// Builds one complete synthetic response sequence with fixed private fields.
fn responses() -> VecDeque<(SnapshotRead, Vec<u8>)> {
    let mut inquiry = vec![0; 43];
    inquiry[4] = 38;
    inquiry[8..16].copy_from_slice(b"TANDBERG");
    inquiry[16..32].copy_from_slice(b"RDX             ");
    inquiry[32..36].copy_from_slice(b"0283");
    let mut factory = vec![0; 172];
    factory[16..26].copy_from_slice(&SERIAL.as_bytes()[2..]);
    factory[28] = 6;
    let usb = vec![0; 32];
    let log = vec![0x20, 0, 0, 8, 0, 1, 0, 4, 0x12, 0x34, 0x56, 0x78];
    let mode = vec![0, 13, 0, 0, 0, 0, 0, 0, 0x34, 5, 0, 0, 2, 0, 0];
    VecDeque::from([
        (SnapshotRead::Inquiry, inquiry.clone()),
        (SnapshotRead::FactoryInfo, factory),
        (SnapshotRead::UsbIdentity, usb),
        (SnapshotRead::DriveLog, log),
        (SnapshotRead::ModeSense, mode),
        (SnapshotRead::Inquiry, inquiry),
    ])
}

/// Captures against an exact ordered script, never a live native transport.
fn capture(
    path: &Path,
    script: &mut VecDeque<(SnapshotRead, Vec<u8>)>,
) -> Result<(), SnapshotError> {
    capture_to_file(
        SERIAL,
        UsbIdentity {
            location_id: 0x01000000,
            vendor_id: 0x1a5a,
            product_id: 6,
        },
        path,
        SnapshotPurpose::MigrationSource,
        &mut |read| {
            let (expected, bytes) = script.pop_front().expect("unexpected command");
            assert_eq!(read, expected);
            Ok(bytes)
        },
    )
    .map_err(|failure| failure.error)
}

/// All fixed responses and derived values survive in an owner-only new file.
#[test]
fn complete_same_lease_snapshot_is_private_and_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("snapshot.json");
    let mut script = responses();
    capture(&path, &mut script).unwrap();
    assert!(script.is_empty());
    let bytes = fs::read(&path).unwrap();
    assert!(bytes.len() < 4096);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["kind"], "openrdx-vendor-0283-semantic-snapshot");
    assert_eq!(value["device"]["usbSerial"], SERIAL);
    assert_eq!(value["device"]["usbLocationId"], 0x01000000);
    assert_eq!(value["device"]["usbVendorId"], 0x1a5a);
    assert_eq!(value["device"]["usbProductId"], 6);
    assert_eq!(value["loadCount"], 0x12345678);
    assert_eq!(value["operationMode"], 2);
    assert_eq!(value["factoryInfoHex"].as_str().unwrap().len(), 344);
    assert_eq!(value["usbIdentityHex"].as_str().unwrap().len(), 64);
    assert_eq!(
        value["rawResponses"]["driveLogHex"].as_str().unwrap().len(),
        24
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

/// Every partial or malformed reply fails before creating a snapshot file.
#[test]
fn partial_or_inconsistent_responses_never_create_output() {
    for index in 0..6 {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("snapshot.json");
        let mut script = responses();
        script[index].1.pop();
        assert!(capture(&path, &mut script).is_err(), "reply {index}");
        assert!(!path.exists(), "reply {index}");
    }
}

/// Revision and final identity guards reject before output, without guessing.
#[test]
fn wrong_revision_and_changed_final_identity_fail_closed() {
    for index in [0, 5] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("snapshot.json");
        let mut script = responses();
        script[index].1[32..36].copy_from_slice(b"0107");
        assert!(capture(&path, &mut script).is_err());
        assert!(!path.exists());
        if index == 0 {
            assert_eq!(script.len(), 5);
        }
    }
}

/// A conflicting factory serial is never attributed to the selected USB unit.
#[test]
fn factory_identity_conflict_never_creates_output() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("snapshot.json");
    let mut script = responses();
    script[1].1[16] = b'9';
    assert!(capture(&path, &mut script).is_err());
    assert!(!path.exists());
}

/// An existing file is preserved and rejected before any native read is needed.
#[test]
fn duplicate_output_is_never_replaced_or_read_from_hardware() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("snapshot.json");
    fs::write(&path, b"existing private evidence").unwrap();
    let mut script = responses();
    assert_eq!(
        capture(&path, &mut script),
        Err(SnapshotError::OutputUnavailable)
    );
    assert_eq!(script.len(), 6);
    assert_eq!(fs::read(path).unwrap(), b"existing private evidence");
}

/// A dangling symlink cannot redirect or receive any private evidence.
#[cfg(unix)]
#[test]
fn symlink_output_is_rejected_before_reads() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("snapshot.json");
    let target = directory.path().join("uncreated.json");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let mut script = responses();
    assert_eq!(
        capture(&path, &mut script),
        Err(SnapshotError::OutputUnavailable)
    );
    assert_eq!(script.len(), 6);
    assert!(!target.exists());
}

/// Missing counters, unsupported modes and transport errors cannot create output.
#[test]
fn missing_semantics_and_failed_transport_never_create_output() {
    for (index, offset, value) in [(3, 5, 2), (4, 12, 0), (4, 12, 4)] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("snapshot.json");
        let mut script = responses();
        script[index].1[offset] = value;
        assert!(capture(&path, &mut script).is_err());
        assert!(!path.exists());
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("snapshot.json");
    let result = capture_to_file(
        SERIAL,
        UsbIdentity {
            location_id: 1,
            vendor_id: 1,
            product_id: 1,
        },
        &path,
        SnapshotPurpose::MigrationSource,
        &mut |_| Err(SnapshotError::Native(NativeFailureKind::AccessDenied)),
    );
    assert_eq!(
        result.map_err(|failure| failure.error),
        Err(SnapshotError::Native(NativeFailureKind::AccessDenied))
    );
    assert!(!path.exists());
}

/// Every injected read failure identifies its exact stage without file or payload.
#[test]
fn each_read_failure_reports_a_fixed_stage_and_native_kind() {
    for (failed_index, expected_stage) in [
        "inquiry-initial",
        "read-factory-info",
        "read-usb-identity-buffer",
        "read-drive-log",
        "read-mode-sense",
        "inquiry-final",
    ]
    .into_iter()
    .enumerate()
    {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("snapshot.json");
        let mut script = responses();
        let mut calls = 0;
        let failure = capture_to_file(
            SERIAL,
            UsbIdentity {
                location_id: 1,
                vendor_id: 1,
                product_id: 1,
            },
            &path,
            SnapshotPurpose::MigrationSource,
            &mut |read| {
                let (expected, bytes) = script.pop_front().unwrap();
                assert_eq!(read, expected);
                let index = calls;
                calls += 1;
                if index == failed_index {
                    Err(SnapshotError::Native(NativeFailureKind::InvalidRequest))
                } else {
                    Ok(bytes)
                }
            },
        )
        .unwrap_err();
        let mut output = Vec::new();
        failure.write_to(&mut output).unwrap();
        assert!(output.len() < 384);
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["code"], "snapshot-read-transport-unavailable");
        assert_eq!(value["stage"], expected_stage);
        assert_eq!(value["nativeError"], "invalid-request");
        assert_eq!(calls, failed_index + 1);
        assert!(!path.exists());
        assert!(!String::from_utf8(output).unwrap().contains(SERIAL));
    }
}

/// Missing or duplicate exact identities never select a first-match fallback.
#[test]
fn exact_unique_target_is_required() {
    assert_eq!(
        select_unique_serial(SERIAL, [Some("009999999999")]),
        Err(SnapshotError::TargetMissing)
    );
    assert_eq!(
        select_unique_serial(SERIAL, [Some(SERIAL), Some(SERIAL)]),
        Err(SnapshotError::TargetAmbiguous)
    );
    assert_eq!(select_unique_serial(SERIAL, [None, Some(SERIAL)]), Ok(1));
    assert_eq!(
        select_unique_serial("*", [Some(SERIAL)]),
        Err(SnapshotError::InvalidArguments)
    );
}

/// CLI parsing accepts only one explicit serial and absolute new output path.
#[test]
fn cli_rejects_wildcards_missing_and_combined_options() {
    for arguments in [
        vec![],
        vec!["--usb-serial", "*", "--output", "/tmp/snapshot.json"],
        vec!["--usb-serial", SERIAL, "--output", "relative.json"],
        vec!["--usb-serial", SERIAL],
        vec![
            "--usb-serial",
            SERIAL,
            "--output",
            "/tmp/snapshot.json",
            "--scan",
        ],
        vec![
            "--usb-serial",
            SERIAL,
            "--usb-serial",
            SERIAL,
            "--output",
            "/tmp/snapshot.json",
        ],
    ] {
        assert!(parse_arguments(arguments.into_iter().map(OsString::from)).is_err());
    }
}

/// Readback is an explicit separate purpose; it cannot silently become source evidence.
#[test]
fn restoration_readback_requires_explicit_flag_and_exact_revision() {
    let output = std::env::temp_dir().join("openrdx-synthetic-readback.json");
    let output = output.to_str().expect("test output is UTF-8");
    let arguments = parse_arguments(
        ["--usb-serial", SERIAL, "--output", output, "--readback"]
            .into_iter()
            .map(OsString::from),
    );
    assert!(
        arguments.is_ok(),
        "Read-only restoration verification is not available"
    );
    assert_eq!(
        arguments.unwrap().purpose,
        SnapshotPurpose::RestorationReadback
    );
    assert!(
        parse_arguments(
            [
                "--usb-serial",
                SERIAL,
                "--output",
                "/tmp/readback.json",
                "--readback",
                "--readback"
            ]
            .into_iter()
            .map(OsString::from),
        )
        .is_err()
    );
    for revision in [b"0283", b"0106", b"0107"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("readback.json");
        let mut script = responses();
        script[0].1[32..36].copy_from_slice(revision);
        script[5].1[32..36].copy_from_slice(revision);
        let result = capture_to_file(
            SERIAL,
            UsbIdentity {
                location_id: 1,
                vendor_id: 0x1a5a,
                product_id: 6,
            },
            &path,
            SnapshotPurpose::RestorationReadback,
            &mut |read| {
                let (expected, bytes) = script.pop_front().unwrap();
                assert_eq!(read, expected);
                Ok(bytes)
            },
        );
        if revision == b"0107" {
            result.unwrap();
            assert!(script.is_empty());
            let value: serde_json::Value =
                serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            assert_eq!(value["kind"], "openrdx-0107-restoration-readback");
            assert_eq!(value["device"]["inquiryRevision"], "0107");
        } else {
            assert_eq!(
                result.unwrap_err().error,
                SnapshotError::ReadbackRevisionMismatch
            );
            assert_eq!(script.len(), 5);
            assert!(!path.exists());
        }
    }
}
