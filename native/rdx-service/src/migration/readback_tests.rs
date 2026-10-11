// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Synthetic fixed-command and complete-record readback regressions.

use super::*;
use crate::transport::{TransportError, TransportResponse};

/// Builds independent synthetic source records and the expected OpenRDX observation.
fn fixture() -> (super::super::MigrationCapture, MigrationReadback) {
    let source = super::super::tests::capture();
    let package = super::super::profile::build_package(&source, b"0283").unwrap();
    let mut usb = source.usb.clone();
    usb.product_id = 5;
    let mut inquiry = source.inquiry.clone();
    inquiry.resize(64, 0);
    inquiry[32..36].copy_from_slice(b"0107");
    let readback = MigrationReadback {
        usb,
        inquiry,
        manufacturing: package[64..320].to_vec(),
        state: package[320..].to_vec(),
    };
    (source, readback)
}

/// Supplies only the five exact responses expected by the OpenRDX reader.
fn responses(readback: &MigrationReadback) -> Vec<Vec<u8>> {
    vec![
        readback.inquiry.clone(),
        readback.manufacturing[..128].to_vec(),
        readback.manufacturing[128..].to_vec(),
        readback.state.clone(),
        readback.inquiry.clone(),
    ]
}

/// Regression: the OpenRDX receiver never receives unsupported vendor READ BUFFER.
#[test]
fn reads_fixed_flash_ranges_with_equal_inquiry_before_and_after() {
    let (_, expected) = fixture();
    let mut data = responses(&expected);
    let mut cdbs = Vec::new();
    let actual = collect(expected.usb.clone(), &mut |command| {
        cdbs.push(command.cdb().to_vec());
        CommandDispatch::Succeeded(TransportResponse::new(data.remove(0)).unwrap())
    })
    .unwrap();
    assert_eq!(cdbs[1], [0xe7, 0, 3, 0xe0, 0, 128]);
    assert_eq!(cdbs[2], [0xe7, 0, 3, 0xe0, 128, 128]);
    assert_eq!(cdbs[3], [0xe7, 0, 3, 0xf0, 0, 64]);
    assert_eq!(cdbs[0], cdbs[4]);
    assert_eq!(actual.manufacturing, expected.manufacturing);
    assert_eq!(actual.state, expected.state);
}

/// A failed, incomplete, or changed observation stops the read sequence immediately.
#[test]
fn rejects_failed_short_and_changed_reads() {
    for failed in 0..5 {
        let (_, expected) = fixture();
        let mut data = responses(&expected);
        let mut calls = 0;
        assert!(
            collect(expected.usb, &mut |_| {
                calls += 1;
                if calls == failed + 1 {
                    CommandDispatch::CompletionUnknown(TransportError::Timeout)
                } else {
                    CommandDispatch::Succeeded(TransportResponse::new(data.remove(0)).unwrap())
                }
            })
            .is_err()
        );
        assert_eq!(calls, failed + 1);
        let (_, expected) = fixture();
        let mut data = responses(&expected);
        data[failed].pop();
        assert!(
            collect(expected.usb, &mut |_| {
                CommandDispatch::Succeeded(TransportResponse::new(data.remove(0)).unwrap())
            })
            .is_err()
        );
    }
    let (_, expected) = fixture();
    let mut data = responses(&expected);
    data[4][1] ^= 1;
    assert!(
        collect(expected.usb, &mut |_| {
            CommandDispatch::Succeeded(TransportResponse::new(data.remove(0)).unwrap())
        })
        .is_err()
    );
}

/// Source/vendor identity never causes private OpenRDX commands to be dispatched.
#[test]
fn rejects_vendor_revision_before_spi_reads() {
    let (_, mut expected) = fixture();
    expected.inquiry[32..36].copy_from_slice(b"0283");
    let mut calls = 0;
    assert!(
        collect(expected.usb, &mut |_| {
            calls += 1;
            CommandDispatch::Succeeded(TransportResponse::new(expected.inquiry.clone()).unwrap())
        })
        .is_err()
    );
    assert_eq!(calls, 1);
}

/// Complete record comparison includes every opaque and reserved reconstructed byte.
#[test]
#[cfg(unix)]
fn all_saved_record_bytes_and_physical_identity_must_match() {
    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::tempdir().unwrap();
    // macOS temp paths may begin with the /var symlink; production rejects links.
    let root = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (source, mut actual) = fixture();
    let final_image = vec![0x42; 62110];
    let release_digest = super::super::profile::digest(&final_image);
    let prepared =
        PreparedMigration::prepare_inner(&root, source, &final_image, &release_digest).unwrap();
    assert!(prepared.verify_records(&actual).is_ok());
    for index in 0..256 {
        actual.manufacturing[index] ^= 1;
        assert_eq!(
            prepared.verify_records(&actual),
            Err(MigrationError::ReadbackMismatch)
        );
        actual.manufacturing[index] ^= 1;
    }
    for index in 0..64 {
        actual.state[index] ^= 1;
        assert_eq!(
            prepared.verify_records(&actual),
            Err(MigrationError::ReadbackMismatch)
        );
        actual.state[index] ^= 1;
    }
    actual.usb.location_id ^= 1;
    assert_eq!(
        prepared.verify_records(&actual),
        Err(MigrationError::ReadbackMismatch)
    );
    actual.usb.location_id ^= 1;
    actual.usb.serial.replace_range(11..12, "8");
    assert_eq!(
        prepared.verify_records(&actual),
        Err(MigrationError::ReadbackMismatch)
    );
}

/// An explicitly selected attempt port never rewrites or relaxes the original identity.
#[test]
#[cfg(unix)]
fn selected_attempt_location_is_exact_without_changing_saved_capture() {
    let (_temporary, prepared) = super::super::tests::prepared_fixture();
    let (_, mut actual) = fixture();
    let saved_location = prepared.capture().usb.location_id;
    let selected_location = saved_location + 1;
    actual.usb.location_id = selected_location;
    assert!(prepared.verify_records(&actual).is_err());
    assert!(
        prepared
            .verify_records_at_location(&actual, selected_location)
            .is_ok()
    );
    for wrong in [0, saved_location, selected_location + 1] {
        assert_eq!(
            prepared.verify_records_at_location(&actual, wrong),
            Err(MigrationError::ReadbackMismatch)
        );
    }
    actual.manufacturing[10] ^= 1;
    assert!(
        prepared
            .verify_records_at_location(&actual, selected_location)
            .is_err()
    );
    actual.manufacturing[10] ^= 1;
    actual.usb.serial.replace_range(11..12, "8");
    assert!(
        prepared
            .verify_records_at_location(&actual, selected_location)
            .is_err()
    );
    assert_eq!(prepared.capture().usb.location_id, saved_location);
}
