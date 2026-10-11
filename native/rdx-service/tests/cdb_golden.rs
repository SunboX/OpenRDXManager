// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_service::protocol::endian::{MAX_U24, u16_be, u24_be, u32_be};
use rdx_service::protocol::{
    DEFAULT_TIMEOUT_MS, DataDirection, InquiryPage, MAX_TIMEOUT_MS, ProtocolBuildError, inquiry,
    led_test, log_sense, mode_select, mode_sense, security_in, security_out, self_test, unit_reset,
    write_buffer,
};

#[test]
fn exact_diagnostic_commands_match_reference_bytes() {
    let self_test = self_test();
    assert_eq!(self_test.cdb(), &[0x1D, 0x04, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(self_test.direction(), DataDirection::None);
    assert_eq!(self_test.data(), &[] as &[u8]);

    let led_on = led_test(true);
    assert_eq!(led_on.cdb(), &[0x1D, 0x00, 0x00, 0x00, 0x08, 0x00]);
    assert_eq!(led_on.data_out(), &[0x80, 0x00, 0x00, 0x04, 0, 0, 0, 0]);
    assert_eq!(led_on.direction(), DataDirection::ToDevice);

    let led_off = led_test(false);
    assert_eq!(led_off.cdb(), &[0x1D, 0x00, 0x00, 0x00, 0x08, 0x00]);
    assert_eq!(led_off.data_out(), &[0x80, 0x00, 0x00, 0x04, 0, 0, 0, 1]);
    assert_eq!(led_off.direction(), DataDirection::ToDevice);

    let reset = unit_reset();
    assert_eq!(reset.cdb(), &[0x1D, 0x05, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(reset.direction(), DataDirection::None);
    assert_eq!(reset.data(), &[] as &[u8]);
}

/// Factory capture is limited to two complete fixed read-only responses.
#[test]
fn exact_migration_record_reads_match_vendor_0283_layout() {
    for (command, buffer_id, length) in [
        (rdx_service::protocol::vendor_0283_factory_info(), 2, 172),
        (rdx_service::protocol::vendor_0283_usb_identity(), 10, 32),
    ] {
        assert_eq!(
            command.cdb(),
            &[0x3C, 2, buffer_id, 0, 0, 0, 0, 0, length, 0]
        );
        assert_eq!(command.direction(), DataDirection::FromDevice);
        assert_eq!(command.data_in_capacity(), usize::from(length));
        assert!(command.data_out().is_empty());
    }
}

#[test]
fn exact_status_read_commands_match_reference_bytes() {
    let drive = log_sense(0x20).expect("drive LOG SENSE page is proven");
    assert_eq!(
        drive.cdb(),
        &[0x4D, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0x00]
    );
    assert_eq!(drive.direction(), DataDirection::FromDevice);
    assert_eq!(drive.data_in_capacity(), 0xFE);
    assert_eq!(drive.data_out(), &[] as &[u8]);

    let cartridge = log_sense(0x21).expect("cartridge LOG SENSE page is proven");
    assert_eq!(
        cartridge.cdb(),
        &[0x4D, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0x00]
    );

    let temperature = log_sense(0x0D).expect("temperature LOG SENSE page is proven");
    assert_eq!(
        temperature.cdb(),
        &[0x4D, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0x00]
    );

    let media_identification = inquiry(InquiryPage::MediaIdentification);
    assert_eq!(
        media_identification.cdb(),
        &[0x12, 0x01, 0xC0, 0x00, 0xFE, 0x00]
    );
    assert_eq!(media_identification.data_in_capacity(), 0xFE);

    let media_device = inquiry(InquiryPage::MediaDevice);
    assert_eq!(media_device.cdb(), &[0x12, 0x01, 0xC2, 0x02, 0x00, 0x00]);
    assert_eq!(media_device.data_in_capacity(), 0x200);

    for page in [0x31, 0x33, 0x34] {
        let command = mode_sense(page).expect("documented RDX MODE page is proven");
        let mut expected = [0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE, 0x00];
        expected[2] = page;
        assert_eq!(command.cdb(), expected);
        assert_eq!(command.direction(), DataDirection::FromDevice);
        assert_eq!(command.data_in_capacity(), 0xFE);
    }
}

#[test]
fn mode_select_preserves_page_data_and_builds_consistent_lengths() {
    // Complete minimum page 0x34 layout: the operation-mode field is
    // page-relative byte 4 and the maximum host SATA speed is byte 6.
    let sense_payload = [
        0x00, 0x0D, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0xB4, 0x05, 0x00, 0x00, 0x02, 0x00, 0x03,
    ];

    let saved = mode_select(&sense_payload, true).expect("well-formed page 0x34 response");
    assert_eq!(saved.cdb(), &[0x55, 0x11, 0, 0, 0, 0, 0, 0, 0x0F, 0]);
    assert_eq!(
        saved.data_out(),
        &[
            0x00, 0x00, 0x00, 0x10, 0, 0, 0, 0, 0xB4, 0x05, 0x00, 0x00, 0x02, 0x00, 0x03
        ]
    );
    assert_eq!(saved.direction(), DataDirection::ToDevice);

    let volatile = mode_select(&sense_payload, false).expect("well-formed page 0x34 response");
    assert_eq!(volatile.cdb(), &[0x55, 0x10, 0, 0, 0, 0, 0, 0, 0x0F, 0]);
}

#[test]
fn mode_select_accepts_only_complete_reference_minimum_page_layouts() {
    let fixtures: &[&[u8]] = &[
        // Page 0x31 byte 4 carries the skip-eject/auto-reload bits.
        &[0x00, 0x0B, 0, 0x10, 0, 0, 0, 0, 0x31, 0x03, 0, 0, 0x18],
        // Page 0x33 byte 3 carries the eject-polling field.
        &[0x00, 0x0A, 0, 0x10, 0, 0, 0, 0, 0xB3, 0x02, 0, 1],
        // Page 0x34 bytes 4 and 6 carry mode and speed fields.
        &[0x00, 0x0D, 0, 0x10, 0, 0, 0, 0, 0xB4, 0x05, 0, 0, 2, 0, 3],
    ];

    for fixture in fixtures {
        let command = mode_select(fixture, false).expect("complete page layout");
        let mut expected = fixture.to_vec();
        expected[0..3].fill(0);
        assert_eq!(command.data_out(), expected);
        assert_eq!(command.cdb()[7..9], (fixture.len() as u16).to_be_bytes());
    }
}

#[test]
fn exact_security_protocol_in_commands_match_observed_directional_selectors() {
    for selector in [0x0010_u16, 0x0020, 0x0021] {
        let query = security_in(selector).expect("observed SECURITY PROTOCOL IN selector");
        let selector_bytes = selector.to_be_bytes();
        assert_eq!(
            query.cdb(),
            &[
                0xA2,
                0x20,
                selector_bytes[0],
                selector_bytes[1],
                0,
                0,
                0x00,
                0x00,
                0x10,
                0x00,
                0,
                0
            ]
        );
        assert_eq!(query.direction(), DataDirection::FromDevice);
        assert_eq!(query.data_in_capacity(), 0x1000);
    }
}

#[test]
fn security_protocol_out_fails_closed_without_bounded_descriptor_evidence() {
    let descriptor = [0xC1, 0x00, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD];

    for selector in [0x0020, 0x0021] {
        assert!(matches!(
            security_out(selector, &descriptor),
            Err(ProtocolBuildError::UnsupportedSecuritySelector(value)) if value == selector
        ));
    }

    let observed = security_out(0x0010, &descriptor)
        .expect_err("observed selector must not emit without bounded descriptor semantics");
    assert!(matches!(
        &observed,
        ProtocolBuildError::SecurityOutEvidenceIncomplete(0x0010)
    ));
}

#[test]
fn exact_firmware_boundaries_match_reference_commands() {
    let first = write_buffer(0x04, 0, &[0; 0x1000]).expect("first 4 KiB chunk");
    assert_eq!(
        first.cdb(),
        &[0x3B, 0x04, 0, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0]
    );
    assert_eq!(first.direction(), DataDirection::ToDevice);
    assert_eq!(first.data_out().len(), 0x1000);

    let last = write_buffer(0x04, 0xF000, &[0; 0x029E]).expect("final data chunk");
    assert_eq!(
        last.cdb(),
        &[0x3B, 0x04, 0, 0x00, 0xF0, 0x00, 0x00, 0x02, 0x9E, 0]
    );

    let finalize = write_buffer(0x05, 0xF29E, &[]).expect("zero-length finalize");
    assert_eq!(
        finalize.cdb(),
        &[0x3B, 0x05, 0, 0x00, 0xF2, 0x9E, 0x00, 0x00, 0x00, 0]
    );
    assert_eq!(finalize.direction(), DataDirection::None);
    assert_eq!(finalize.data(), &[] as &[u8]);
}

#[test]
fn endian_helpers_cover_zero_middle_and_maximum_values() {
    assert_eq!(u16_be(0xA10B), [0xA1, 0x0B]);
    assert_eq!(u24_be(0).expect("zero is representable"), [0, 0, 0]);
    assert_eq!(
        u24_be(0x12A0F3).expect("middle value is representable"),
        [0x12, 0xA0, 0xF3]
    );
    assert_eq!(
        u24_be(MAX_U24).expect("maximum is representable"),
        [0xFF, 0xFF, 0xFF]
    );
    assert!(matches!(
        u24_be(MAX_U24 + 1),
        Err(ProtocolBuildError::ValueOutOfRange { field: "u24", .. })
    ));
    assert_eq!(u32_be(0x90A0B0C0), [0x90, 0xA0, 0xB0, 0xC0]);
}

#[test]
fn builder_allowlists_reject_unproven_pages_selectors_and_modes() {
    for page in [0x00, 0x1F, 0x22, 0xFF] {
        assert!(matches!(
            log_sense(page),
            Err(ProtocolBuildError::UnsupportedLogPage(value)) if value == page
        ));
    }
    for page in [0x00, 0x20, 0x32, 0x35, 0xFF] {
        assert!(matches!(
            mode_sense(page),
            Err(ProtocolBuildError::UnsupportedModePage(value)) if value == page
        ));
    }
    for selector in [0x0000, 0x000F, 0x0011, 0x001F, 0x0022, 0xFFFF] {
        assert!(matches!(
            security_in(selector),
            Err(ProtocolBuildError::UnsupportedSecuritySelector(value)) if value == selector
        ));
        assert!(matches!(
            security_out(selector, &[0xC1; 8]),
            Err(ProtocolBuildError::UnsupportedSecuritySelector(value)) if value == selector
        ));
    }
    for mode in [0x00, 0x02, 0x03, 0x06, 0x07, 0x0F, 0xFF] {
        assert!(matches!(
            write_buffer(mode, 0, &[1]),
            Err(ProtocolBuildError::UnsupportedWriteBufferMode(value)) if value == mode
        ));
    }
}

#[test]
fn mode_select_rejects_short_inconsistent_and_unproven_payloads() {
    assert!(matches!(
        mode_select(&[0; 9], true),
        Err(ProtocolBuildError::PayloadTooShort { .. })
    ));

    let wrong_total = [0x00, 0x0B, 0, 0, 0, 0, 0, 0, 0x34, 0x02, 0, 0];
    assert!(matches!(
        mode_select(&wrong_total, true),
        Err(ProtocolBuildError::PayloadLengthMismatch { .. })
    ));

    let block_descriptor_overrun = [0x00, 0x0A, 0, 0, 0, 0, 0x00, 0x04, 0x34, 0x02, 0, 0];
    assert!(matches!(
        mode_select(&block_descriptor_overrun, true),
        Err(ProtocolBuildError::PayloadLengthMismatch { .. })
    ));

    let unsupported_page = [0x00, 0x0A, 0, 0, 0, 0, 0, 0, 0xB2, 0x02, 0, 0];
    assert!(matches!(
        mode_select(&unsupported_page, true),
        Err(ProtocolBuildError::UnsupportedModePage(0x32))
    ));

    let page_length_overrun = [0x00, 0x0A, 0, 0, 0, 0, 0, 0, 0x34, 0x03, 0, 0];
    assert!(matches!(
        mode_select(&page_length_overrun, true),
        Err(ProtocolBuildError::PayloadLengthMismatch { .. })
    ));

    let zero_length_page = [0x00, 0x08, 0, 0, 0, 0, 0, 0, 0x31, 0x00];
    assert!(matches!(
        mode_select(&zero_length_page, true),
        Err(ProtocolBuildError::PayloadTooShort { .. })
    ));

    let truncated_pages: &[(&[u8], usize, usize)] = &[
        (&[0x00, 0x0A, 0, 0, 0, 0, 0, 0, 0x31, 0x02, 0, 0], 3, 2),
        (&[0x00, 0x09, 0, 0, 0, 0, 0, 0, 0x33, 0x01, 0], 2, 1),
        (
            &[0x00, 0x0C, 0, 0, 0, 0, 0, 0, 0x34, 0x04, 0, 0, 2, 0],
            5,
            4,
        ),
    ];
    for (fixture, minimum, actual) in truncated_pages {
        assert!(matches!(
            mode_select(fixture, true),
            Err(ProtocolBuildError::PayloadTooShort {
                minimum: reported_minimum,
                actual: reported_actual,
                ..
            }) if reported_minimum == *minimum && reported_actual == *actual
        ));
    }

    let subpage_format = [0x00, 0x0D, 0, 0, 0, 0, 0, 0, 0xF4, 0x05, 0, 0, 2, 0, 3];
    assert!(matches!(
        mode_select(&subpage_format, true),
        Err(ProtocolBuildError::UnsupportedModeSubpage(0x34))
    ));

    let oversized = vec![0; usize::from(u16::MAX) + 1];
    assert!(matches!(
        mode_select(&oversized, false),
        Err(ProtocolBuildError::PayloadTooLarge { .. })
    ));
}

#[test]
fn data_bearing_builders_reject_payload_cdb_inconsistency() {
    assert!(matches!(
        security_out(0x0020, &[]),
        Err(ProtocolBuildError::UnsupportedSecuritySelector(0x0020))
    ));
    assert!(matches!(
        write_buffer(0x04, 0, &[]),
        Err(ProtocolBuildError::WriteBufferPayloadMismatch { mode: 0x04, .. })
    ));
    assert!(matches!(
        write_buffer(0x05, 0, &[1]),
        Err(ProtocolBuildError::WriteBufferPayloadMismatch { mode: 0x05, .. })
    ));

    assert!(matches!(
        write_buffer(0x04, MAX_U24 + 1, &[1]),
        Err(ProtocolBuildError::ValueOutOfRange {
            field: "offset",
            ..
        })
    ));

    let oversized = vec![0; MAX_U24 as usize + 1];
    assert!(matches!(
        write_buffer(0x04, 0, &oversized),
        Err(ProtocolBuildError::PayloadTooLarge { .. })
    ));
}

#[test]
fn command_timeout_is_explicit_and_bounded_without_changing_cdb_bytes() {
    let base = self_test();
    assert_eq!(base.timeout_ms(), DEFAULT_TIMEOUT_MS);

    let shortest = base
        .clone()
        .with_timeout_ms(1)
        .expect("one millisecond is representable");
    assert_eq!(shortest.timeout_ms(), 1);
    assert_eq!(shortest.cdb(), base.cdb());

    let longest = base
        .clone()
        .with_timeout_ms(MAX_TIMEOUT_MS)
        .expect("maximum bounded timeout is accepted");
    assert_eq!(longest.timeout_ms(), MAX_TIMEOUT_MS);
    assert_eq!(longest.cdb(), base.cdb());

    assert!(matches!(
        base.clone().with_timeout_ms(0),
        Err(ProtocolBuildError::TimeoutOutOfRange { milliseconds: 0 })
    ));
    assert!(matches!(
        base.with_timeout_ms(MAX_TIMEOUT_MS + 1),
        Err(ProtocolBuildError::TimeoutOutOfRange { .. })
    ));
}
