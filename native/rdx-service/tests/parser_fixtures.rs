// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_service::protocol::{
    EvidenceStatus, InboundSecurityDescriptor, LogParameterMeaning,
    MAX_INBOUND_SECURITY_AGGREGATE_LENGTH, MAX_INBOUND_SECURITY_DESCRIPTOR_LENGTH,
    MAX_LOG_PAGE_LENGTH, MAX_MODE_PAGE_LENGTH, MAX_SENSE_DATA_LENGTH,
    OutboundSecurityDescriptorLayout, RdxFeaturePage, SecurityEvidence, SecurityOperation,
    SenseData, parse_cartridge_identity, parse_inbound_security_descriptors, parse_log_page,
    parse_temperature_celsius,
};

/// Builds a complete cartridge identity pair.
fn cartridge_identity_fixtures() -> (Vec<u8>, Vec<u8>) {
    let mut identification = vec![0, 0xC0, 0, 0, 0];
    for field in [
        "320000",
        "1",
        "HDD MODEL",
        "HDD-SERIAL-000000001",
        "Imation",
        "RDX 320GB",
        "CART-SERIAL-0001",
        "TEST-CARTRIDGE",
    ] {
        identification.extend_from_slice(field.as_bytes());
        identification.push(0);
    }
    let identification_length = u16::try_from(identification.len() - 4).unwrap();
    identification[2..4].copy_from_slice(&identification_length.to_be_bytes());

    let mut device = vec![b' '; 0x62];
    device[0] = 0;
    device[1] = 0xC2;
    device[2..4].copy_from_slice(&0x5E_u16.to_be_bytes());
    device[0x32..0x3A].copy_from_slice(b"FW1234  ");
    (identification, device)
}

#[test]
fn cartridge_identity_and_temperature_decode_only_complete_reference_layouts() {
    let (identification, device) = cartridge_identity_fixtures();
    let identity =
        parse_cartridge_identity(&identification, &device).expect("complete cartridge identity");
    assert_eq!(identity.vendor(), "Imation");
    assert_eq!(identity.model(), "RDX 320GB");
    assert_eq!(identity.serial(), "CART-SERIAL-0001");
    assert_eq!(identity.hdd_firmware(), "FW1234");

    let temperature = [0x0D, 0, 0, 6, 0, 0, 0, 2, 0, 39];
    assert_eq!(parse_temperature_celsius(&temperature), Ok(Some(39)));

    for end in 0..identification.len() {
        assert!(parse_cartridge_identity(&identification[..end], &device).is_err());
    }
    for end in 0..device.len() {
        assert!(parse_cartridge_identity(&identification, &device[..end]).is_err());
    }
    for end in 0..temperature.len() {
        assert!(parse_temperature_celsius(&temperature[..end]).is_err());
    }

    let mut wrong_page = identification.clone();
    wrong_page[1] = 0xC1;
    assert!(parse_cartridge_identity(&wrong_page, &device).is_err());
    let mut non_printable = identification.clone();
    let vendor_offset = non_printable
        .windows(7)
        .position(|bytes| bytes == b"Imation")
        .expect("fixture vendor exists");
    non_printable[vendor_offset] = 0x1F;
    assert!(parse_cartridge_identity(&non_printable, &device).is_err());
}

#[test]
fn cartridge_identity_accepts_exact_c2_inquiry_allocation_truncation() {
    let mut identification = vec![0, 0xC0, 0, 0];
    for field in [
        "Cartridge:",
        "2542EAB0",
        "HDD MODEL",
        "HDD-SERIAL",
        "Imation",
        "RDX-320",
        "CART-SERIAL",
        "LOT",
    ] {
        identification.extend_from_slice(field.as_bytes());
        identification.push(0);
    }
    let identification_length = u16::try_from(identification.len() - 4).unwrap();
    identification[2..4].copy_from_slice(&identification_length.to_be_bytes());

    let mut device = vec![0; 0x200];
    device[1] = 0xC2;
    device[2..4].copy_from_slice(&0x0200_u16.to_be_bytes());
    device[0x32..0x3A].copy_from_slice(b"AM0P1A  ");

    let identity = parse_cartridge_identity(&identification, &device)
        .expect("the exact original 0x0200 allocation retains all identity fields");
    assert_eq!(identity.vendor(), "Imation");
    assert_eq!(identity.model(), "RDX-320");
    assert_eq!(identity.serial(), "CART-SERIAL");
    assert_eq!(identity.hdd_firmware(), "AM0P1A");

    device.pop();
    assert!(parse_cartridge_identity(&identification, &device).is_err());
}

/// Builds one descriptor with a big-endian body length and repeated body byte.
fn descriptor_fixture(id: u8, flags: u8, body_len: usize, body_byte: u8) -> Vec<u8> {
    let body_len = u16::try_from(body_len).expect("test descriptor length fits u16");
    let mut fixture = vec![
        id,
        flags,
        body_len.to_be_bytes()[0],
        body_len.to_be_bytes()[1],
    ];
    fixture.extend(vec![body_byte; usize::from(body_len)]);
    fixture
}

#[test]
fn parses_bounded_log_parameters_without_inventing_unknown_meanings() {
    let fixture = [
        0x20, 0x00, 0x00, 0x0E, // page header, fourteen bytes of parameters
        0x00, 0x04, 0x40, 0x04, 0x00, 0x00, 0x00, 0x03, // connection type
        0x12, 0x34, 0xA5, 0x02, 0xDE, 0xAD, // unknown metadata
    ];

    let page = parse_log_page(&fixture).expect("complete page 0x20 fixture");
    assert_eq!(page.page_code(), 0x20);
    assert_eq!(page.evidence(), EvidenceStatus::ImplementationReference);
    assert_eq!(page.framing_evidence(), EvidenceStatus::Documented);
    assert_eq!(page.parameters().len(), 2);

    let known = &page.parameters()[0];
    assert_eq!(known.code(), 0x0004);
    assert_eq!(known.control(), 0x40);
    assert_eq!(known.value(), &[0x00, 0x00, 0x00, 0x03]);
    assert_eq!(
        known.meaning(),
        Some(LogParameterMeaning::DriveConnectionType)
    );
    assert_eq!(known.evidence(), EvidenceStatus::ImplementationReference);
    assert_eq!(known.uint32(), Some(3));

    let unknown = &page.parameters()[1];
    assert_eq!(unknown.code(), 0x1234);
    assert_eq!(unknown.control(), 0xA5);
    assert_eq!(unknown.value(), &[0xDE, 0xAD]);
    assert_eq!(unknown.meaning(), None);
    assert_eq!(unknown.evidence(), EvidenceStatus::Incomplete);
    assert_eq!(unknown.uint32(), Some(0xDEAD));
}

#[test]
fn log_parser_preserves_duplicates_and_lookup_uses_the_reference_last_match_policy() {
    let fixture = [
        0x20, 0, 0, 16, // page header
        0, 4, 0, 4, 0, 0, 0, 1, // first connection type
        0, 4, 0, 4, 0, 0, 0, 3, // later duplicate
    ];
    let page = parse_log_page(&fixture).expect("complete duplicate fixture");

    assert_eq!(page.parameters().len(), 2);
    assert_eq!(page.parameters()[0].uint32(), Some(1));
    assert_eq!(page.parameters()[1].uint32(), Some(3));
    assert_eq!(
        page.find(4).and_then(|parameter| parameter.uint32()),
        Some(3)
    );
}

#[test]
fn log_parser_rejects_short_oversized_and_inconsistent_inputs_without_panicking() {
    let complete = [0x21, 0, 0, 8, 0, 10, 0, 4, 0, 0, 0, 3];
    for end in 0..complete.len() {
        assert!(
            parse_log_page(&complete[..end]).is_err(),
            "accepted prefix {end}"
        );
    }
    assert!(parse_log_page(&complete).is_ok());

    assert!(parse_log_page(&[0x20, 0, 0, 7, 0, 1, 0, 4, 0xAA]).is_err());
    assert!(parse_log_page(&[0x22, 0, 0, 0]).is_err());
    assert!(parse_log_page(&[0x60, 0, 0, 0]).is_err());
    for extra in 1..=8 {
        let mut oversized = vec![0; MAX_LOG_PAGE_LENGTH + extra];
        oversized[0] = 0x20;
        assert!(parse_log_page(&oversized).is_err());
    }
}

#[test]
fn feature_page_round_trip_changes_only_reference_fields() {
    let original = [
        0x00, 0x0D, 0x7A, 0x10, 0, 0, 0, 0, // MODE parameter header
        0xB4, 0x05, 0xA1, 0xB2, 0xDA, 0xC3, 0x02, // PS + page 0x34
    ];
    let mut page = RdxFeaturePage::parse(&original).expect("complete RDX feature page");
    assert_eq!(page.page_code(), 0x34);
    assert_eq!(page.evidence(), EvidenceStatus::ImplementationReference);
    assert_eq!(page.operation_mode(), Some(2));
    assert_eq!(page.max_host_sata_speed(), Some(2));
    assert_eq!(page.as_bytes(), &original);

    page.set_operation_mode(3).expect("operation mode");
    let mut expected = original;
    expected[12] = 0xDB;
    assert_eq!(page.as_bytes(), &expected);

    page.set_max_host_sata_speed(3).expect("SATA host speed");
    expected[14] = 3;
    assert_eq!(page.into_bytes(), expected);
}

#[test]
fn mode_parser_rejects_short_oversized_and_inconsistent_inputs_without_panicking() {
    let complete = [0x00, 0x0D, 0, 0x10, 0, 0, 0, 0, 0x34, 5, 0, 0, 2, 0, 3];
    for end in 0..complete.len() {
        assert!(
            RdxFeaturePage::parse(&complete[..end]).is_err(),
            "accepted prefix {end}"
        );
    }
    assert!(RdxFeaturePage::parse(&complete).is_ok());

    let wrong_total = [0x00, 0x0C, 0, 0x10, 0, 0, 0, 0, 0x34, 5, 0, 0, 2, 0, 3];
    assert!(RdxFeaturePage::parse(&wrong_total).is_err());
    let page_overrun = [0x00, 0x0D, 0, 0x10, 0, 0, 0, 0, 0x34, 6, 0, 0, 2, 0, 3];
    assert!(RdxFeaturePage::parse(&page_overrun).is_err());
    let block_overrun = [0x00, 0x0D, 0, 0x10, 0, 0, 0, 8, 0x34, 5, 0, 0, 2, 0, 3];
    assert!(RdxFeaturePage::parse(&block_overrun).is_err());
    let unsupported_page = [0x00, 0x08, 0, 0, 0, 0, 0, 0, 0x32, 0];
    assert!(RdxFeaturePage::parse(&unsupported_page).is_err());
    let subpage = [0x00, 0x08, 0, 0, 0, 0, 0, 0, 0x74, 0];
    assert!(RdxFeaturePage::parse(&subpage).is_err());

    for extra in 1..=8 {
        let mut oversized = vec![0; MAX_MODE_PAGE_LENGTH + extra];
        oversized[8] = 0x34;
        assert!(RdxFeaturePage::parse(&oversized).is_err());
    }
}

#[test]
fn inbound_security_parser_accepts_only_independently_verified_layouts() {
    let layouts = [(0xC0, 0x4C), (0xC1, 0x10), (0xC1, 0x80)];
    for (id, body_len) in layouts {
        let fixture = descriptor_fixture(id, 0x07, body_len, id ^ 0x5A);
        let descriptor = InboundSecurityDescriptor::parse(&fixture).expect("inbound descriptor");
        assert_eq!(descriptor.id(), id);
        assert_eq!(descriptor.flags(), 0x07);
        assert_eq!(descriptor.body_len(), body_len);
        assert_eq!(
            descriptor.evidence(),
            EvidenceStatus::ImplementationReference
        );
    }

    for (id, outbound_body_len) in [
        (0xC1, 0x70),
        (0xC2, 0x44),
        (0xC3, 0x28),
        (0xC4, 0x44),
        (0xC5, 4),
    ] {
        let outbound =
            OutboundSecurityDescriptorLayout::for_id(id).expect("outbound serialization layout");
        assert_eq!(outbound.id(), id);
        assert_eq!(outbound.body_len(), outbound_body_len);
        assert_eq!(
            outbound.layout_evidence(),
            SecurityEvidence::ImplementationReference
        );
        assert_eq!(outbound.write_evidence(), SecurityEvidence::Incomplete);

        let fixture = descriptor_fixture(id, 0, outbound_body_len, 0xA5);
        assert!(InboundSecurityDescriptor::parse(&fixture).is_err());
    }

    for body_len in [0x37, 0x38, 0x39] {
        let c5 = descriptor_fixture(0xC5, 0, body_len, 0x5A);
        assert!(InboundSecurityDescriptor::parse(&c5).is_err());
        assert!(parse_inbound_security_descriptors(&c5).is_err());
    }
    let mut tailed_c5 = descriptor_fixture(0xC5, 0, 0x38, 0xA5);
    tailed_c5.push(0xFF);
    assert!(InboundSecurityDescriptor::parse(&tailed_c5).is_err());
    assert!(parse_inbound_security_descriptors(&tailed_c5).is_err());

    assert_eq!(
        SecurityEvidence::for_operation(SecurityOperation::DisplayCredentialPolicy),
        SecurityEvidence::Documented
    );
    assert_eq!(
        SecurityEvidence::for_operation(SecurityOperation::ParseInboundDescriptor),
        SecurityEvidence::ImplementationReference
    );
    assert_eq!(
        SecurityEvidence::for_operation(SecurityOperation::CreateCredential),
        SecurityEvidence::Incomplete
    );
}

#[test]
fn inbound_security_aggregate_is_bounded_and_preserves_descriptor_order() {
    let fixtures = [
        descriptor_fixture(0xC0, 1, 0x4C, 0x10),
        descriptor_fixture(0xC1, 2, 0x10, 0x20),
    ];
    let aggregate: Vec<u8> = fixtures.iter().flatten().copied().collect();
    let descriptors = parse_inbound_security_descriptors(&aggregate).expect("inbound aggregate");
    assert_eq!(descriptors.len(), 2);
    assert_eq!(
        descriptors
            .iter()
            .map(InboundSecurityDescriptor::id)
            .collect::<Vec<_>>(),
        [0xC0, 0xC1]
    );

    let complete = descriptor_fixture(0xC1, 0, 0x80, 0x5A);
    for end in 0..complete.len() {
        assert!(
            InboundSecurityDescriptor::parse(&complete[..end]).is_err(),
            "descriptor parser accepted prefix {end}"
        );
        assert!(
            parse_inbound_security_descriptors(&complete[..end]).is_err(),
            "aggregate parser accepted prefix {end}"
        );
    }
    assert!(InboundSecurityDescriptor::parse(&complete).is_ok());
    assert!(parse_inbound_security_descriptors(&complete).is_ok());

    assert!(InboundSecurityDescriptor::parse(&descriptor_fixture(0xC0, 0, 4, 0)).is_err());
    assert!(InboundSecurityDescriptor::parse(&descriptor_fixture(0xC1, 0, 0x11, 0)).is_err());
    assert!(InboundSecurityDescriptor::parse(&descriptor_fixture(0xC5, 0, 4, 0)).is_err());

    for extra in 1..=8 {
        let oversized = vec![0; MAX_INBOUND_SECURITY_DESCRIPTOR_LENGTH + extra];
        assert!(InboundSecurityDescriptor::parse(&oversized).is_err());
        let aggregate = vec![0; MAX_INBOUND_SECURITY_AGGREGATE_LENGTH + extra];
        assert!(parse_inbound_security_descriptors(&aggregate).is_err());
    }
}

#[test]
fn inbound_security_debug_redacts_sensitive_descriptor_material() {
    let mut fixture = vec![0xC1, 7, 0, 0x10];
    fixture.extend_from_slice(b"TOP_SECRET_VALUE");
    let descriptor = InboundSecurityDescriptor::parse(&fixture).expect("short C1 descriptor");

    let debug = format!("{descriptor:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("TOP_SECRET_VALUE"));
    assert!(!debug.contains("84, 79, 80"));
}

#[test]
fn sense_parser_retains_raw_fields_but_publishes_only_stable_sanitized_codes() {
    let signature = [
        0x70, 0, 0x07, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x74, 0x08, 0, 0, 0, 0,
    ];
    let sense = SenseData::parse(&signature).expect("complete fixed-format sense");
    assert_eq!(sense.raw_key(), 0x07);
    assert_eq!(sense.asc(), 0x74);
    assert_eq!(sense.ascq(), 0x08);
    assert_eq!(sense.code(), "firmware-signature-error");
    assert_eq!(sense.evidence(), EvidenceStatus::ImplementationReference);

    let descriptor_format = [0x72, 0x05, 0x20, 0x01, 0, 0, 0, 0];
    let generic = SenseData::parse(&descriptor_format).expect("complete descriptor-format sense");
    assert_eq!(
        (generic.raw_key(), generic.asc(), generic.ascq()),
        (5, 0x20, 1)
    );
    assert_eq!(generic.code(), "scsi-check-condition");
    assert_eq!(generic.evidence(), EvidenceStatus::Incomplete);
}

#[test]
fn sense_parser_rejects_short_oversized_and_inconsistent_inputs_without_panicking() {
    let complete = [0x72, 0x07, 0x74, 0x08, 0, 0, 0, 0];
    for end in 0..complete.len() {
        assert!(
            SenseData::parse(&complete[..end]).is_err(),
            "accepted prefix {end}"
        );
    }
    assert!(SenseData::parse(&complete).is_ok());

    let inconsistent = [0x70, 0, 7, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x74, 8];
    assert!(SenseData::parse(&inconsistent).is_err());
    assert!(SenseData::parse(&[0x60, 0, 0, 0, 0, 0, 0, 0]).is_err());

    for extra in 1..=8 {
        let oversized = vec![0; MAX_SENSE_DATA_LENGTH + extra];
        assert!(SenseData::parse(&oversized).is_err());
    }
}

/// Builds standard temperature parameters independently of their wire order.
fn temperature_parameters(current: Option<u8>, reference: u8) -> Vec<u8> {
    let mut page = vec![0x0D, 0, 0, 6, 0, 1, 0x43, 2, 0, reference];
    if let Some(current) = current {
        page.extend_from_slice(&[0, 0, 0x43, 2, 0, current]);
        page[3] = 12;
    }
    page
}

#[test]
fn temperature_uses_current_parameter_and_preserves_real_zero() {
    for current in [0, 28, 39] {
        assert_eq!(
            parse_temperature_celsius(&temperature_parameters(Some(current), 65)),
            Ok(Some(current))
        );
    }
    assert_eq!(
        parse_temperature_celsius(&temperature_parameters(Some(255), 65)),
        Ok(None)
    );
    assert!(parse_temperature_celsius(&temperature_parameters(None, 65)).is_err());
}

#[test]
fn temperature_rejects_malformed_or_ambiguous_parameters() {
    let complete = temperature_parameters(Some(39), 65);
    for end in 0..complete.len() {
        assert!(parse_temperature_celsius(&complete[..end]).is_err());
    }
    let mut invalid_length = complete.clone();
    invalid_length[13] = 1;
    assert!(parse_temperature_celsius(&invalid_length).is_err());
    let mut duplicate = complete.clone();
    duplicate.extend_from_slice(&[0, 0, 0x43, 2, 0, 42]);
    duplicate[3] = 18;
    assert!(parse_temperature_celsius(&duplicate).is_err());
    let mut reserved = complete.clone();
    reserved[14] = 1;
    assert!(parse_temperature_celsius(&reserved).is_err());
}
