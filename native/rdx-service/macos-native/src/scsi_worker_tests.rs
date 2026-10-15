// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::io::Cursor;

use super::*;

/// A removed Child handle does not prove a killed-but-unreaped capture owner exited.
#[test]
fn release_requires_proven_child_termination_even_after_lost_reply() {
    for reply in [
        Ok((FRAME_ACK, Vec::new())),
        Err(NativeError::TransportUnavailable),
    ] {
        assert_eq!(
            release_outcome(reply.clone(), Ok(()), true),
            Err(NativeError::TimedOut)
        );
        assert_eq!(release_outcome(reply, Ok(()), false), Ok(()));
    }
}

/// Only fixed compatibility shapes survive the IPC boundary; no offset is accepted.
#[test]
fn compatibility_setup_worker_frames_are_closed() {
    let authorization = [0, 0, 0x67, 0x99, 0x11, 0x73, 0x32, 0xf6, 0x25, 0x8e];
    for (operation, length) in [(24, 10), (25, 0)] {
        let mut request = ffi::ScsiRequest {
            operation,
            timeout_ms: 15_000,
            data_length: length,
            ..ffi::ScsiRequest::default()
        };
        if operation == 24 {
            request.data[..10].copy_from_slice(&authorization);
        }
        let payload = encode_request(request);
        assert!(decode_request(&payload).is_ok());
        for index in [12, 16] {
            let mut changed = payload.clone();
            changed[index] = 1;
            assert!(decode_request(&changed).is_err());
        }
        if operation == 24 {
            let mut changed = payload.clone();
            changed[17] = 1;
            assert!(decode_request(&changed).is_err());
            changed = payload.clone();
            changed[19] = 0x55 ^ 0x1f;
            assert!(decode_request(&changed).is_err());
        }
    }
}

/// Restore framing rejects mutations to fixed fields or the desired record checksum.
#[test]
fn manufacturing_restore_worker_frames_are_closed() {
    for operation in [33, 34] {
        assert!(operation_allowed(false, operation));
        assert!(!operation_allowed(true, operation));
    }
    let probe = ffi::ScsiRequest {
        operation: 33,
        timeout_ms: 30000,
        ..ffi::ScsiRequest::default()
    };
    let payload = encode_request(probe);
    assert!(decode_request(&payload).is_ok());
    for index in [12, 16] {
        let mut invalid = payload.clone();
        invalid[index] = 1;
        assert!(decode_request(&invalid).is_err());
    }
    let mut request = ffi::ScsiRequest {
        operation: 34,
        timeout_ms: 30000,
        data_length: 528,
        ..ffi::ScsiRequest::default()
    };
    request.data[..8].copy_from_slice(b"RDXMFG01");
    request.data[16..272].fill(0xff);
    request.data[272..276].copy_from_slice(&[0x78, 0x56, 0x34, 0x12]);
    let payload = encode_request(request);
    assert!(decode_request(&payload).is_ok());
    for index in [
        12,
        16,
        17,
        17 + 12,
        17 + 13,
        17 + 14,
        17 + 15,
        17 + 272,
        17 + 527,
    ] {
        let mut invalid = payload.clone();
        invalid[index] ^= 1;
        assert!(decode_request(&invalid).is_err());
    }
    let mut damaged_current = payload.clone();
    damaged_current[17 + 16] = 0;
    assert!(decode_request(&damaged_current).is_ok());
    let mut erased_desired = payload.clone();
    erased_desired[17 + 272..].fill(0xff);
    assert!(decode_request(&erased_desired).is_err());
    assert!(decode_request(&payload[..payload.len() - 1]).is_err());
}

/// Serial worker framing independently refuses arbitrary chunk bounds, modes, and payloads.
#[test]
fn serial_worker_frames_are_closed() {
    for operation in [
        ScsiOperation::openrdx_serial_capability(),
        ScsiOperation::openrdx_mechanism_diagnostics(),
    ] {
        let payload = encode_request(operation.into_request());
        assert!(decode_request(&payload).is_ok());
        for index in [12, 16] {
            let mut invalid = payload.clone();
            invalid[index] = 1;
            assert!(decode_request(&invalid).is_err());
        }
    }
    let mut payload = encode_request(
        ScsiOperation::openrdx_manufacturing_sector_chunk(31)
            .unwrap()
            .into_request(),
    );
    assert!(decode_request(&payload).is_ok());
    payload[12] = 32;
    assert!(decode_request(&payload).is_err());
    payload[12] = 31;
    payload[16] = 1;
    assert!(decode_request(&payload).is_err());
    let mut data = vec![0; 280];
    data[..8].copy_from_slice(b"RDXSER01");
    data[12] = 1;
    data[14..24].copy_from_slice(b"0123456789");
    data[24..].fill(0xff);
    let payload = encode_request(
        ScsiOperation::openrdx_set_serial(data)
            .unwrap()
            .into_request(),
    );
    assert!(decode_request(&payload).is_ok());
    for index in [12, 16, 17, 17 + 12, 17 + 13, 17 + 14, 17 + 24] {
        let mut invalid = payload.clone();
        invalid[index] = 0xfe;
        assert!(decode_request(&invalid).is_err());
    }
}

/// Framing rejects an oversized length before allocating its payload.
#[test]
fn oversized_frame_is_rejected() {
    let mut bytes = Vec::from(*MAGIC);
    bytes.extend_from_slice(&[FRAME_COMMAND, 0, 0, 0]);
    bytes.extend_from_slice(&((MAX_FRAME_BYTES + 1) as u32).to_le_bytes());

    assert_eq!(
        read_frame(&mut Cursor::new(bytes)),
        Err(NativeError::ResourceLimit)
    );
}

/// Request framing round-trips a closed eject operation without padding.
#[test]
fn request_round_trip_preserves_eject_operation() {
    let request = ScsiOperation::eject_media().into_request();
    let decoded = decode_request(&encode_request(request)).expect("valid request");

    assert_eq!(decoded.operation, 21);
    assert_eq!(decoded.data_length, 0);
    assert_eq!(decoded.save_pages, 0);
}

/// Factory commands survive the worker boundary with no caller payload.
#[test]
fn factory_read_request_frames_are_closed() {
    for operation in [
        ScsiOperation::vendor_0283_factory_info(),
        ScsiOperation::vendor_0283_usb_identity(),
        ScsiOperation::openrdx_manufacturing_record_first(),
        ScsiOperation::openrdx_manufacturing_record_second(),
        ScsiOperation::openrdx_operational_state_record(),
    ] {
        let payload = encode_request(operation.into_request());
        assert!(decode_request(&payload).is_ok());
        for index in [12, 16] {
            let mut changed = payload.clone();
            changed[index] = 1;
            assert!(decode_request(&changed).is_err());
        }
        let mut with_data = payload.clone();
        with_data[8..12].copy_from_slice(&1_u32.to_le_bytes());
        with_data.push(0);
        assert!(decode_request(&with_data).is_err());
    }
    let mut unknown = encode_request(ScsiOperation::vendor_0283_usb_identity().into_request());
    unknown[..4].copy_from_slice(&35_u32.to_le_bytes());
    assert!(decode_request(&unknown).is_err());
}

/// A response's closed shape is checked before reading its declared payload.
#[test]
fn parent_response_headers_are_closed_before_payload_wait() {
    assert!(response_length_allowed(FRAME_READY, FRAME_READY, 0));
    assert!(!response_length_allowed(FRAME_READY, FRAME_READY, 1));
    assert!(!response_length_allowed(FRAME_ACK, FRAME_RESPONSE, 2));
    assert!(!response_length_allowed(FRAME_RESPONSE, FRAME_ERROR, 1));
    assert!(!response_length_allowed(FRAME_RESPONSE, FRAME_RESPONSE, 19));
    assert!(!response_length_allowed(
        FRAME_RESPONSE,
        FRAME_RESPONSE,
        MAX_FRAME_BYTES
    ));
    assert!(response_length_allowed(
        FRAME_RESPONSE,
        FRAME_RESPONSE,
        20 + ffi::MAX_TRANSFER_BYTES + ffi::MAX_SENSE_BYTES
    ));
}

/// Completion framing retains bounded device data and sense lengths.
#[test]
fn completion_round_trip_is_bounded() {
    let completion = Completion::Device {
        scsi_status: 2,
        service_response: 2,
        transferred_length: 3,
        data: vec![1, 2, 3],
        sense_reported_length: 2,
        sense: vec![4, 5],
    };

    assert_eq!(
        decode_completion(&encode_completion(&completion)),
        Ok(completion)
    );
}

/// A flushed native failure followed by worker death is lost at the current boundary.
#[test]
fn startup_preserves_precleanup_native_breadcrumb_on_child_eof() {
    use std::process::{Command, Stdio};
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg("printf '%s\n' '{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"usb-capture-device\",\"nativeStatus\":3,\"nativeCodeKind\":\"nserror\",\"nativeCode\":42}' >&2; exit 3")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    let mut diagnostics = crate::scsi_worker_startup::StartupDiagnostics::new(child.stderr.take());
    diagnostics.nonblocking().unwrap();
    crate::scsi_worker_startup::reset();
    let mut worker = MacScsiWorkerLease {
        input: child.stdin.take().map(WorkerPipe::Standard),
        output: child.stdout.take().map(WorkerPipe::Standard),
        diagnostics,
        child: Some(WorkerProcess::Standard(child)),
    };
    crate::scsi_worker_io::nonblocking(worker.output.as_ref().unwrap()).unwrap();
    assert_eq!(
        worker.read_frame(FRAME_READY, Instant::now() + Duration::from_secs(1)),
        Err(NativeError::TransportUnavailable)
    );
    let code = crate::take_last_worker_startup_failure()
        .map_or("candidate-worker-acquisition-failed", |failure| {
            failure.code()
        });
    assert_eq!(code, "candidate-worker-usb-capture-device-access-denied");
}

/// Spawns only a disposable shell fixture with no worker/device entrypoint or native probe.
fn startup_fixture(script: &str) -> MacScsiWorkerLease {
    crate::scsi_worker_startup::reset();
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut diagnostics = crate::scsi_worker_startup::StartupDiagnostics::new(child.stderr.take());
    diagnostics.nonblocking().unwrap();
    let worker = MacScsiWorkerLease {
        input: child.stdin.take().map(WorkerPipe::Standard),
        output: child.stdout.take().map(WorkerPipe::Standard),
        child: Some(WorkerProcess::Standard(child)),
        diagnostics,
    };
    crate::scsi_worker_io::nonblocking(worker.input.as_ref().unwrap()).unwrap();
    crate::scsi_worker_io::nonblocking(worker.output.as_ref().unwrap()).unwrap();
    worker
}

/// An intermediate legacy failure followed by READY is successful and clears stale evidence.
#[test]
fn startup_real_child_success_clears_legacy_failure() {
    let mut worker = startup_fixture(
        "printf '%s\n' '{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"legacy-create-plugin\",\"nativeStatus\":2,\"nativeCodeKind\":\"ioreturn\",\"nativeCode\":-1}' >&2; printf 'RDXSCSI1\\002\\000\\000\\000\\000\\000\\000\\000'",
    );
    assert_eq!(
        worker.read_frame(FRAME_READY, Instant::now() + Duration::from_secs(1)),
        Ok((FRAME_READY, vec![]))
    );
    worker.diagnostics.success();
    assert!(crate::take_last_worker_startup_failure().is_none());
    worker.terminate_child();
    assert!(worker.child.is_none());
}

/// Stderr chatter larger than pipe capacity is drained without filling stdout or extending time.
#[test]
fn startup_real_child_chatter_is_bounded_and_does_not_block_ready() {
    let mut worker = startup_fixture(
        "i=0; while [ $i -lt 5000 ]; do printf '%s\n' 'not-a-diagnostic-secret' >&2; i=$((i+1)); done; printf 'RDXSCSI1\\002\\000\\000\\000\\000\\000\\000\\000'",
    );
    assert_eq!(
        worker.read_frame(FRAME_READY, Instant::now() + Duration::from_secs(2)),
        Ok((FRAME_READY, vec![]))
    );
    worker.diagnostics.success();
    assert!(crate::take_last_worker_startup_failure().is_none());
    worker.terminate_child();
    assert!(worker.child.is_none());
}

/// Stderr EOF is removed from poll and a silent stdout retains the original absolute deadline.
#[test]
fn startup_real_child_stderr_eof_and_silence_are_bounded() {
    let mut worker = startup_fixture("exec 2>&-; exec /bin/sleep 2");
    let started = Instant::now();
    assert_eq!(
        worker.read_frame(FRAME_READY, started + Duration::from_millis(50)),
        Err(NativeError::TimedOut)
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        crate::take_last_worker_startup_failure().unwrap().code(),
        "candidate-worker-init-read-timed-out"
    );
    assert!(worker.child.is_none());
}

/// Arbitrary/unknown stderr never relaxes malformed stdout framing or publishes child text.
#[test]
fn startup_real_child_malicious_diagnostic_does_not_change_protocol_rejection() {
    let mut worker = startup_fixture(
        "printf '%s\n' '{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"/dev/secret\",\"nativeStatus\":3,\"nativeCodeKind\":\"nserror\",\"nativeCode\":42}' >&2; printf 'BADMAGIC\\002\\000\\000\\000\\000\\000\\000\\000'",
    );
    assert_eq!(
        worker.read_frame(FRAME_READY, Instant::now() + Duration::from_secs(1)),
        Err(NativeError::InvalidRequest)
    );
    assert_eq!(
        crate::take_last_worker_startup_failure().unwrap().code(),
        "candidate-worker-init-frame-invalid"
    );
    assert!(worker.child.is_none());
}

/// Missing child pipes drop safely before stderr is nonblocking and reap only the retained child.
#[test]
fn startup_missing_pipes_never_reads_blocking_stderr_during_drop() {
    crate::scsi_worker_startup::reset();
    let child = Command::new("/bin/sleep")
        .arg("2")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let identity = crate::synthetic_candidate_for_test().rematch_identity();
    let started = Instant::now();
    assert!(matches!(
        MacScsiWorkerLease::initialize_child(child, &identity),
        Err(NativeError::TransportUnavailable)
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        crate::take_last_worker_startup_failure().unwrap().code(),
        "candidate-worker-process-pipes-transport-unavailable"
    );
}

/// A failed setup fcntl carries its immediate errno and Drop never drains a blocking pipe.
#[test]
fn startup_failed_nonblocking_setup_is_bounded_and_preserves_errno() {
    crate::scsi_worker_startup::reset();
    let child = Command::new("/bin/sleep")
        .arg("2")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let identity = crate::synthetic_candidate_for_test().rematch_identity();
    let started = Instant::now();
    assert!(matches!(
        MacScsiWorkerLease::initialize_child_with(child, &identity, |_| Err(
            std::io::Error::from_raw_os_error(libc::EBADF)
        )),
        Err(NativeError::TransportUnavailable)
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        crate::take_last_worker_startup_failure().unwrap().code(),
        "candidate-worker-process-nonblocking-bad-fd"
    );
}

/// A closed init input is classified before the original failed-write termination/reap.
#[test]
fn startup_real_child_init_write_failure_is_classified_before_kill() {
    crate::scsi_worker_startup::reset();
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg("exec 0<&-; printf closed >&2; exec /bin/sleep 2")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.as_mut().unwrap();
    crate::scsi_worker_io::nonblocking(stderr).unwrap();
    let mut marker = [0; 6];
    crate::scsi_worker_io::read_exact(stderr, &mut marker, Instant::now() + Duration::from_secs(1))
        .unwrap();
    assert_eq!(&marker, b"closed");
    let identity = crate::synthetic_candidate_for_test().rematch_identity();
    assert!(matches!(
        MacScsiWorkerLease::initialize_child(child, &identity),
        Err(NativeError::TransportUnavailable)
    ));
    assert_eq!(
        crate::take_last_worker_startup_failure().unwrap().code(),
        "candidate-worker-init-write-transport-unavailable"
    );
}

/// The production startup helper accepts READY while preserving the zero-diagnostic success path.
#[test]
fn startup_production_initializer_accepts_ready_without_stale_evidence() {
    crate::scsi_worker_startup::parent_failure("process-spawn", NativeError::Other);
    crate::scsi_worker_startup::reset();
    let identity = crate::synthetic_candidate_for_test().rematch_identity();
    // Consume the whole INIT, including identity: a small nonblocking pipe can accept only
    // a strict prefix before its reader drains. READY never precedes complete request admission.
    let frame_bytes = HEADER_BYTES + encode_identity(&identity).len();
    let child = Command::new("/bin/sh").arg("-c")
        .arg(format!("dd bs=1 count={frame_bytes} of=/dev/null 2>/dev/null; printf 'RDXSCSI1\\002\\000\\000\\000\\000\\000\\000\\000'; exec /bin/sleep 2"))
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut worker = MacScsiWorkerLease::initialize_child(child, &identity).unwrap();
    assert!(crate::take_last_worker_startup_failure().is_none());
    worker.terminate_child();
    assert!(worker.child.is_none());
}

/// Fresh current-call metadata survives actual child EOF without changing the original result.
#[test]
fn startup_real_child_fresh_error_eof_and_ready_keep_native_semantics() {
    let evidence = "{\"diagnostic\":\"interface-init-evidence\",\"status\":10,\"domain\":1,\"code\":9,\"reason\":1,\"underDomain\":2,\"underCode\":21}";
    let legacy = "{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"usb-open-interface\",\"nativeStatus\":10,\"nativeCodeKind\":\"nserror\",\"nativeCode\":3758097097}";
    let script = format!("printf '%s\\n' '{evidence}' '{legacy}' >&2; exit 3");
    let mut worker = startup_fixture(&script);
    assert_eq!(
        worker.read_frame(FRAME_READY, Instant::now() + Duration::from_secs(1)),
        Err(NativeError::TransportUnavailable)
    );
    assert_eq!(
        crate::take_last_worker_startup_failure().unwrap().code(),
        "candidate-worker-usb-interface-fresh-super-init-under-posix-permission"
    );
    worker.terminate_child();
    assert!(worker.child.is_none());
    let script = format!(
        "printf '%s\\n' '{evidence}' '{legacy}' >&2; printf 'RDXSCSI1\\002\\000\\000\\000\\000\\000\\000\\000'"
    );
    let mut worker = startup_fixture(&script);
    assert_eq!(
        worker.read_frame(FRAME_READY, Instant::now() + Duration::from_secs(1)),
        Ok((FRAME_READY, vec![]))
    );
    worker.diagnostics.success();
    assert!(crate::take_last_worker_startup_failure().is_none());
    worker.terminate_child();
    assert!(worker.child.is_none());
}

/// Partial reserved evidence at genuine child EOF is invalid, never an accepted or stale cause.
#[test]
fn startup_real_child_partial_fresh_stderr_eof_is_invalid() {
    let partial = "{\"diagnostic\":\"interface-init-evidence\",\"status\":10,\"domain\":1";
    let old = "{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"usb-open-interface\",\"nativeStatus\":10,\"nativeCodeKind\":\"nserror\",\"nativeCode\":3758097097}";
    let fresh = "{\"diagnostic\":\"interface-init-evidence\",\"status\":10,\"domain\":1,\"code\":9,\"reason\":1,\"underDomain\":2,\"underCode\":21}";
    let partial_old = "{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"usb-open-interface\",\"nativeStatus\":";
    for script in [
        format!("printf '%s' '{partial}' >&2; exit 3"),
        format!("printf '%s\\n' '{old}' >&2; printf '%s' '{partial}' >&2; exit 3"),
        format!("printf '%s\\n' '{fresh}' >&2; printf '%s' '{partial_old}' >&2; exit 3"),
    ] {
        let mut worker = startup_fixture(&script);
        assert_eq!(
            worker.read_frame(FRAME_READY, Instant::now() + Duration::from_secs(1)),
            Err(NativeError::TransportUnavailable)
        );
        assert_eq!(
            crate::take_last_worker_startup_failure().unwrap().code(),
            "candidate-worker-usb-interface-fresh-evidence-invalid"
        );
        worker.terminate_child();
        assert!(worker.child.is_none());
    }
}
