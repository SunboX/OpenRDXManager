// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Synthetic diagnostics tests: no handles, device requests or payload capture.

use super::*;

const INQUIRY: [u8; 6] = [0x12, 0, 0, 0, 0xFE, 0];
const DOWNLOAD: [u8; 10] = [0x3B, 4, 0, 0, 0, 0, 0, 0x10, 0, 0];

/// The default-disabled state never reserves even an otherwise safe observation.
#[test]
fn disabled_and_unknown_headers_are_not_recorded() {
    assert!(CaptureState::new(false).reserve(&INQUIRY, 1, 254).is_none());
    for cdb in [
        vec![],
        vec![0; 17],
        vec![0xAA; 10],
        vec![0xA2; 12],
        vec![0xB5; 12],
        vec![0x3B, 4, 1, 0, 0, 0, 0, 0x10, 0, 0],
    ] {
        assert!(!allowed_header(&cdb, 0, 4096));
    }
    assert!(!allowed_header(&INQUIRY, 0, 254));
    assert!(!allowed_header(&INQUIRY, 1, 255));
    assert!(!allowed_header(&DOWNLOAD, 0, 4097));
    assert!(!allowed_header(&DOWNLOAD, 0, 0));
}

/// Expected read and firmware headers retain actual padding and field mismatches.
#[test]
fn header_shapes_are_closed_but_not_silently_repaired() {
    assert!(allowed_header(&[0x12, 1, 0x83, 0, 0xFE, 0], 1, 254));
    for opcode in [0x4D, 0x5A] {
        assert!(allowed_header(
            &[opcode, 0, 0xC0, 0, 0, 0, 0, 0, 0xFE, 0],
            1,
            254
        ));
    }
    let mut padded = DOWNLOAD.to_vec();
    padded.extend_from_slice(&[0, 0]);
    let record = CaptureState::new(true).reserve(&padded, 0, 670).unwrap();
    assert_eq!(record.frame, "3B0400000000001000000000");
    padded[11] = 1;
    assert!(!allowed_header(&padded, 0, 670));
    assert!(allowed_header(&[0x3B, 5, 0, 0, 0, 0, 0, 0, 0, 0], 2, 0));
    assert!(!allowed_header(&[0x3B, 5, 0, 0, 0, 0, 0, 0, 0, 0], 0, 0));
}

/// Read polling cannot exhaust the separate bounded firmware observation quota.
#[test]
fn quotas_and_sequences_are_bounded() {
    let state = CaptureState::new(true);
    for expected in 1..=128 {
        assert_eq!(state.reserve(&INQUIRY, 1, 254).unwrap().sequence, expected);
    }
    assert!(state.reserve(&INQUIRY, 1, 254).is_none());
    for expected in 129..=256 {
        assert_eq!(
            state.reserve(&DOWNLOAD, 0, 4096).unwrap().sequence,
            expected
        );
    }
    assert!(state.reserve(&DOWNLOAD, 0, 4096).is_none());
}

/// Only bounded standard sense codes and illegal-request field pointers survive.
#[test]
fn sense_decoding_never_exposes_raw_data() {
    let mut fixed = [0xAA; 252];
    fixed[0] = 0xF0;
    fixed[2] = 5;
    fixed[7] = 10;
    fixed[12] = 0x24;
    fixed[13] = 0;
    fixed[15] = 0xCB;
    fixed[16] = 0;
    fixed[17] = 7;
    assert_eq!(
        decode_sense(2, 18, &fixed),
        "{\"format\":112,\"code\":5,\"asc\":36,\"ascq\":0,\"field\":{\"inHeader\":true,\"offset\":7,\"bit\":3}}"
    );
    assert_eq!(decode_sense(0, 252, &fixed), "null");
    assert_eq!(decode_sense(2, 13, &fixed), "null");
    assert_eq!(decode_sense(2, 252, &fixed[..7]), "null");
    fixed[7] = 5;
    assert_eq!(decode_sense(2, 252, &fixed), "null");
    assert_eq!(
        decode_sense(2, 8, &[0x72, 5, 0x24, 0, 0, 0, 0, 0]),
        "{\"format\":114,\"code\":5,\"asc\":36,\"ascq\":0,\"field\":null}"
    );
    assert_eq!(decode_sense(2, 8, &[0x7F; 8]), "null");
}

/// The exact single-line wire envelope consists solely of approved metadata.
#[test]
fn serialized_submit_is_small_and_deterministic() {
    let record = CaptureState::new(true).reserve(&INQUIRY, 1, 254).unwrap();
    let line = record.line("submit", "pending", "null", "null", "null", 0, 0, "null");
    assert_eq!(
        line,
        "openrdx-hardware: spti-v1 {\"v\":1,\"seq\":1,\"phase\":\"submit\",\"frame\":\"12000000FE00\",\"dir\":1,\"requested\":254,\"completed\":null,\"status\":null,\"sense\":null,\"reported\":0,\"copied\":0,\"returned\":null,\"host\":\"pending\"}\n"
    );
    assert!(line.len() < 512);
}
