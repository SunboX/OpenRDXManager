// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use serde_json::json;
use std::{net::Shutdown, os::unix::net::UnixStream, time::Duration};

/// A real EOF must revoke before a full channel can block terminal enqueue behind a valid message.
#[test]
fn session_admission_real_eof_revokes_before_terminal_enqueue() {
    let (mut reader, mut writer) = UnixStream::pair().unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    let admission = SessionAdmission::fixture();
    let reader_admission = admission.clone();
    let task = thread::spawn(move || read_loop(&mut reader, sender, reader_admission));
    write_frame(
        &mut writer,
        &json!({"type":"handshake-request","protocolVersion":1}),
    )
    .unwrap();
    writer.shutdown(Shutdown::Write).unwrap();
    // The channel still contains the valid unadmitted handshake. The reader's
    // terminal send cannot complete until this test later drains that channel.
    assert!(admission.wait_revoked());
    assert!(matches!(
        receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
        InputSignal::Message(_)
    ));
    assert!(matches!(
        receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
        InputSignal::End
    ));
    task.join().unwrap();
}

/// A valid queued handshake cannot enter after real EOF is observed ahead of terminal enqueue.
#[test]
fn session_admission_real_eof_refuses_queued_unadmitted_message() {
    let (mut reader, mut writer) = UnixStream::pair().unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    let admission = SessionAdmission::fixture();
    let reader_admission = admission.clone();
    let task = thread::spawn(move || read_loop(&mut reader, sender, reader_admission));
    write_frame(
        &mut writer,
        &json!({"type":"handshake-request","protocolVersion":1}),
    )
    .unwrap();
    writer.shutdown(Shutdown::Write).unwrap();
    assert!(admission.wait_revoked());
    let (event_sender, events) = mpsc::sync_channel(1);
    let crashes = CrashAdmission::new();
    let sink = ServiceEventSink::new(event_sender, crashes.clone());
    let mut runtime = ServiceRuntime::new(
        super::super::NoDeviceBackend::new(super::super::ServicePlatform::Darwin),
        sink,
    );
    let mut output = Vec::new();
    assert_eq!(
        service_loop(
            &mut runtime,
            &receiver,
            &events,
            &crashes,
            &mut output,
            &admission
        ),
        Ok(ServiceExit::EndOfInput)
    );
    assert!(output.is_empty());
    assert!(!runtime.handshaken);
    drop(receiver);
    task.join().unwrap();
}

/// A partial frame after valid queued input revokes before publishing its exact terminal error.
#[test]
fn session_admission_real_partial_frame_revokes_before_terminal_enqueue() {
    let (mut reader, mut writer) = UnixStream::pair().unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    let admission = SessionAdmission::fixture();
    let observer = admission.clone();
    let task = thread::spawn(move || read_loop(&mut reader, sender, observer));
    write_frame(
        &mut writer,
        &json!({"type":"handshake-request","protocolVersion":1}),
    )
    .unwrap();
    writer.write_all(&[0, 0]).unwrap();
    writer.shutdown(Shutdown::Write).unwrap();
    assert!(admission.wait_revoked());
    assert!(matches!(
        receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
        InputSignal::Message(_)
    ));
    assert!(matches!(
        receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
        InputSignal::Failure(ServiceProtocolError::MalformedFrame)
    ));
    task.join().unwrap();
}
