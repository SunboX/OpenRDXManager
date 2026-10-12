// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! No-device regression boundary for an authenticated peer that sends no frame.
use rdx_service::{
    endpoint::HandshakeDeadlineReader,
    service::{
        NoDeviceBackend, ServiceExecutionContext, ServiceExit, ServicePlatform,
        ServiceProtocolError, run_framed_service_with_context,
    },
};
use std::{io::Cursor, time::Duration};

/// Clean EOF before any protocol byte is an ordinary session end with no response.
#[test]
fn authenticated_empty_eof_ends_without_handshake_or_hardware_requests() {
    let reader = HandshakeDeadlineReader::new(
        Cursor::new(Vec::<u8>::new()),
        Duration::from_secs(2),
        |_, _| Ok(()),
    )
    .unwrap();
    let mut output = Vec::new();
    let exit = run_framed_service_with_context(
        NoDeviceBackend::new(ServicePlatform::Darwin),
        reader,
        &mut output,
        ServiceExecutionContext::authenticated_platform_endpoint(true),
    )
    .unwrap();
    assert_eq!(exit, ServiceExit::EndOfInput);
    assert!(output.is_empty());
}

/// A partial header or partial/invalid payload is not an authentication-only EOF.
#[test]
fn authenticated_partial_or_invalid_frames_remain_protocol_failures() {
    let cases = [
        vec![0],
        vec![0, 0, 0],
        vec![0, 0, 0, 1],
        vec![0, 0, 0, 1, b'{'],
    ];
    for bytes in cases {
        let reader =
            HandshakeDeadlineReader::new(Cursor::new(bytes), Duration::from_secs(2), |_, _| Ok(()))
                .unwrap();
        let mut output = Vec::new();
        let result = run_framed_service_with_context(
            NoDeviceBackend::new(ServicePlatform::Darwin),
            reader,
            &mut output,
            ServiceExecutionContext::authenticated_platform_endpoint(true),
        );
        assert!(matches!(result, Err(ServiceProtocolError::MalformedFrame)));
        assert!(output.is_empty());
    }
}
