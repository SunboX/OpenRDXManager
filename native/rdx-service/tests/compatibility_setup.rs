// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Offline parity with the public OpenRDX compatibility installation procedure.

use rdx_service::model::RiskClass;
use rdx_service::platform::macos::build_scsi_task;
use rdx_service::protocol::{
    DataDirection, ProtocolBuildError, compatibility_receiver_authorization,
    compatibility_receiver_header_setup, write_buffer,
};

/// The script's literal mode/buffer/offset framing and serial transform stay exact.
#[test]
fn compatibility_setup_matches_public_script_wire_bytes() {
    let authorization = compatibility_receiver_authorization("0123456789").unwrap();
    assert_eq!(authorization.cdb(), &[0x3b, 2, 0x80, 0, 0, 0, 0, 0, 10, 0]);
    assert_eq!(
        authorization.data_out(),
        &[0, 0, 0x67, 0x99, 0x11, 0x73, 0x32, 0xf6, 0x25, 0x8e]
    );
    assert_eq!(authorization.direction(), DataDirection::ToDevice);
    assert_eq!(authorization.timeout_ms(), 15_000);
    assert_eq!(format!("{authorization:?}"), "Command(<private>)");
    let header = compatibility_receiver_header_setup();
    assert_eq!(header.cdb(), &[0x3b, 2, 0x82, 2, 0x0f, 0xf8, 0, 0, 2, 0]);
    assert_eq!(header.data_out(), &[0, 0]);
    assert_eq!(header.direction(), DataDirection::ToDevice);
    assert_eq!(header.timeout_ms(), 15_000);
}

/// Serial selection is strict and never silently trims or rewrites identity.
#[test]
fn compatibility_setup_rejects_malformed_serial_without_opening_general_mode_two() {
    for serial in [
        "",
        "012345678",
        "01234567890",
        " 0123456789",
        "0123456789 ",
        "012345678\n",
        "01234567\u{7f}9",
        "01234567é",
    ] {
        assert!(matches!(
            compatibility_receiver_authorization(serial),
            Err(ProtocolBuildError::InvalidCompatibilitySerial)
        ));
    }
    assert!(compatibility_receiver_authorization("ABCD E~xyZ").is_ok());
    assert!(matches!(
        write_buffer(2, 0x020ff8, &[0, 0]),
        Err(ProtocolBuildError::UnsupportedWriteBufferMode(2))
    ));
}

/// Both closed setup mutations retain critical risk through the macOS classifier.
#[test]
fn compatibility_setup_maps_to_critical_bounded_native_tasks() {
    for (command, length) in [
        (
            compatibility_receiver_authorization("0123456789").unwrap(),
            10,
        ),
        (compatibility_receiver_header_setup(), 2),
    ] {
        let task = build_scsi_task(&command).unwrap();
        assert_eq!(task.risk(), RiskClass::Critical);
        assert_eq!(task.transfer_length(), length);
        assert_eq!(task.timeout_ms(), 15_000);
    }
}
