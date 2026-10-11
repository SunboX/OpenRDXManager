// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vendor v2.83 LOG page framing described by the implementation reference at 0x08000614.

use rdx_service::protocol::parse_log_page;

/// Reconstructs the vendor's zero-filled 0x74-byte allocation and fourteen records.
///
/// Counter values are illustrative; framing follows the original firmware builder.
fn vendor_cartridge_page() -> Vec<u8> {
    let mut bytes = vec![0x21, 0, 0, 0x70];
    for code in 0_u16..14 {
        let width = if code == 0 { 2 } else { 4 };
        let value = match code {
            1 => 21_u32,
            5 => 95,
            6 => 2_170,
            _ => 0,
        };
        bytes.extend_from_slice(&code.to_be_bytes());
        bytes.extend_from_slice(&[0x60, width as u8]);
        bytes.extend_from_slice(&value.to_be_bytes()[4 - width..]);
    }
    assert_eq!(bytes.len(), 0x72);
    bytes.extend_from_slice(&[0, 0]);
    bytes
}

/// Verifies every record survives the original firmware's reserved zero tail.
#[test]
fn original_firmware_cartridge_padding_preserves_all_parameters() {
    let page = parse_log_page(&vendor_cartridge_page()).expect("vendor's reserved tail is valid");
    assert_eq!(page.parameters().len(), 14);
    for (code, expected) in [(0, 0), (1, 21), (5, 95), (6, 2_170), (8, 0)] {
        assert_eq!(
            page.find(code).and_then(|parameter| parameter.uint32()),
            Some(expected)
        );
    }
}

/// Keeps incomplete and malformed replies outside the bounded compatibility case.
#[test]
fn compatibility_does_not_accept_truncation_or_nonzero_trailing_data() {
    let bytes = vendor_cartridge_page();
    for end in 0..bytes.len() {
        assert!(
            parse_log_page(&bytes[..end]).is_err(),
            "accepted truncated prefix {end}"
        );
    }
    for offset in [0x72, 0x73] {
        let mut invalid = bytes.clone();
        invalid[offset] = 1;
        assert!(parse_log_page(&invalid).is_err());
    }
    let mut overrun = bytes.clone();
    overrun[0x6D] = 7;
    assert!(
        parse_log_page(&overrun).is_err(),
        "padding must not forgive an oversized parameter"
    );
    let mut wrong_page = bytes.clone();
    wrong_page[0] = 0x20;
    assert!(
        parse_log_page(&wrong_page).is_err(),
        "drive pages do not have this reserved tail"
    );
    for tail_length in [1, 3] {
        let mut wrong_tail = bytes[..0x72].to_vec();
        wrong_tail.resize(0x72 + tail_length, 0);
        let length = (wrong_tail.len() - 4) as u16;
        wrong_tail[2..4].copy_from_slice(&length.to_be_bytes());
        assert!(parse_log_page(&wrong_tail).is_err());
    }
}
