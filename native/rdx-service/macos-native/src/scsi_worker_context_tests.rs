// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// Uses an actual retained child and real bounded pipes; no fixture can grant GUI/root authority.
fn fixture(script: &str) -> MacScsiWorkerLease {
    let mut child = Command::new("/bin/sh")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut worker = MacScsiWorkerLease {
        input: child.stdin.take().map(WorkerPipe::Standard),
        output: child.stdout.take().map(WorkerPipe::Standard),
        diagnostics: crate::scsi_worker_startup::StartupDiagnostics::new(child.stderr.take()),
        child: Some(WorkerProcess::Standard(child)),
    };
    worker.diagnostics.nonblocking().unwrap();
    crate::scsi_worker_io::nonblocking_io(worker.input.as_ref().unwrap()).unwrap();
    crate::scsi_worker_io::nonblocking_io(worker.output.as_ref().unwrap()).unwrap();
    worker
}

/// Hands only this actual test child's three pipes into the real parent preflight implementation.
fn protocol_fixture(mode: &str, marker: &std::path::Path) -> MacScsiWorkerLease {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "scsi_worker::context::tests::context_child_fixture",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("OPENRDX_TEST_CONTEXT_MODE", mode)
        .env("OPENRDX_TEST_CONTEXT_MARKER", marker)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut worker = MacScsiWorkerLease {
        input: child.stdin.take().map(WorkerPipe::Standard),
        output: child.stdout.take().map(WorkerPipe::Standard),
        diagnostics: crate::scsi_worker_startup::StartupDiagnostics::new(child.stderr.take()),
        child: Some(WorkerProcess::Standard(child)),
    };
    worker.diagnostics.nonblocking().unwrap();
    crate::scsi_worker_io::nonblocking_io(worker.input.as_ref().unwrap()).unwrap();
    crate::scsi_worker_io::nonblocking_io(worker.output.as_ref().unwrap()).unwrap();
    // Consume only this test harness's bounded prelude, never a production protocol exception.
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut prelude = Vec::new();
    while !prelude.ends_with(b"OPENRDX_TEST_CONTEXT_START\n") {
        assert!(prelude.len() < 256);
        let mut byte = [0];
        crate::scsi_worker_io::read_exact_observed(
            worker.output.as_mut().unwrap(),
            &mut byte,
            deadline,
            Some(&mut worker.diagnostics),
        )
        .unwrap();
        prelude.push(byte[0]);
    }
    worker
}

/// Partial/malformed/silent/EOF children must never reach even the parent initializer admission.
#[test]
fn real_child_context_refusal_never_admits_ack_or_initializer() {
    for script in [
        "exec /bin/sleep 2",
        "printf RDXSCSI1; exec /bin/sleep 2",
        "printf malformed; exit 0",
        "exit 0",
    ] {
        let mut worker = fixture(script);
        let expected = WorkerExpectation::fixture_for_pid(worker.child.as_ref().unwrap().id());
        let mut admitted = 0;
        let started = Instant::now();
        let result = worker.prove_context(&expected, started + Duration::from_millis(40), |_| {
            admitted += 1;
            Ok(())
        });
        assert!(result.is_err(), "proof refusal required");
        assert_eq!(admitted, 0, "no ACK or initializer after missing proof");
        drop(worker);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}

/// Full private handshake proves ordering and flag restoration, without authenticating synthetic data.
#[test]
fn real_child_context_proof_ack_then_init_share_one_deadline() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("initializer");
    let mut worker = protocol_fixture("valid", &marker);
    let expected = WorkerExpectation::fixture_for_pid(worker.child.as_ref().unwrap().id());
    let deadline = Instant::now() + Duration::from_secs(1);
    worker
        .prove_context(&expected, deadline, |owned| {
            owned.acknowledge_context(deadline)
        })
        .unwrap();
    assert!(!marker.exists(), "ACK alone must not initialize");
    let identity = crate::synthetic_candidate_for_test().rematch_identity();
    let mut worker = worker.finish_initialization(&identity, deadline).unwrap();
    worker.wait_for_child_exit(deadline).unwrap();
    assert_eq!(
        std::fs::read_to_string(marker).unwrap(),
        "initialized-after-proof-ack-and-restoration"
    );
}

/// Proof consumes the same absolute INIT budget; no later READY phase receives a reset timeout.
#[test]
fn real_child_context_slow_proof_does_not_reset_ready_deadline() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("budget");
    let mut worker = protocol_fixture("slow", &marker);
    let expected = WorkerExpectation::fixture_for_pid(worker.child.as_ref().unwrap().id());
    let started = Instant::now();
    let deadline = started + Duration::from_millis(600);
    worker
        .prove_context(&expected, deadline, |owned| {
            owned.acknowledge_context(deadline)
        })
        .unwrap();
    let identity = crate::synthetic_candidate_for_test().rematch_identity();
    assert!(matches!(
        worker.finish_initialization(&identity, deadline),
        Err(NativeError::TimedOut)
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
}

/// Exact owned identity, credentials, session and fixed framing refusals all keep initializer count zero.
#[test]
fn real_child_context_malformed_identity_and_late_deadline_never_initialize() {
    let directory = tempfile::tempdir().unwrap();
    for mode in [
        "wrong-pid",
        "wrong-ppid",
        "wrong-uid",
        "wrong-gid",
        "wrong-auid",
        "wrong-asid",
        "wrong-session",
        "bad-magic",
        "oversized",
        "partial",
        "eof",
        "silent",
        "stderr",
    ] {
        let marker = directory.path().join(mode);
        let mut worker = protocol_fixture(mode, &marker);
        let expected = WorkerExpectation::fixture_for_pid(worker.child.as_ref().unwrap().id());
        let started = Instant::now();
        let deadline = started + Duration::from_millis(60);
        let mut acks = 0;
        assert!(
            worker
                .prove_context(&expected, deadline, |_| {
                    acks += 1;
                    Ok(())
                })
                .is_err(),
            "{mode}"
        );
        assert_eq!(acks, 0, "{mode}");
        assert!(!marker.exists(), "{mode}");
        let expected_code = match mode {
            "bad-magic" | "oversized" => "candidate-worker-context-proof-invalid",
            "partial" | "silent" | "stderr" => "candidate-worker-context-proof-timed-out",
            "eof" => "candidate-worker-context-proof-transport-unavailable",
            _ => "candidate-worker-context-proof-access-denied",
        };
        assert_eq!(
            crate::take_last_worker_startup_failure().unwrap().code(),
            expected_code,
            "{mode}"
        );
        drop(worker);
        assert!(started.elapsed() < Duration::from_secs(1), "{mode}");
    }
    let marker = directory.path().join("expired-after-proof");
    let mut worker = protocol_fixture("valid", &marker);
    let expected = WorkerExpectation::fixture_for_pid(worker.child.as_ref().unwrap().id());
    let deadline = Instant::now() + Duration::from_millis(100);
    assert_eq!(
        worker.prove_context(&expected, deadline, |owned| {
            owned.acknowledge_context(Instant::now())
        }),
        Err(NativeError::TimedOut)
    );
    assert!(!marker.exists());
}

/// A saturated child stdin makes the one-shot gate ACK fail immediately, never poll until init timeout.
#[test]
fn context_ack_saturated_pipe_is_one_nonblocking_attempt() {
    let directory = tempfile::tempdir().unwrap();
    let mut worker = protocol_fixture("blocked", &directory.path().join("blocked"));
    let input = worker.input.as_mut().unwrap();
    let bytes = [0u8; 4096];
    let fill_deadline = Instant::now() + Duration::from_secs(1);
    loop {
        assert!(Instant::now() < fill_deadline, "bounded pipe fill");
        match input.write(&bytes) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("fill: {error}"),
        }
    }
    let started = Instant::now();
    let owner = crate::MacWorkerFactory::fixture_owner();
    let deadline = started + Duration::from_secs(15);
    assert_eq!(
        owner
            .factory()
            .fixture_admit(deadline, || Ok(()), || worker.acknowledge_context(deadline)),
        Err(NativeError::TransportUnavailable)
    );
    owner.revoke();
    assert!(started.elapsed() < Duration::from_millis(100));
}

/// Prior real child init-read progress cannot mask a failed context request or one-shot ACK.
#[test]
fn real_child_context_phase_refusals_publish_exact_consumed_codes() {
    let directory = tempfile::tempdir().unwrap();
    let mut worker = protocol_fixture("write-fail", &directory.path().join("write-fail"));
    let expected = WorkerExpectation::fixture_for_pid(worker.child.as_ref().unwrap().id());
    assert_eq!(
        worker.prove_context(
            &expected,
            Instant::now() + Duration::from_secs(1),
            |_| panic!("no ACK")
        ),
        Err(NativeError::TransportUnavailable)
    );
    assert_eq!(
        crate::take_last_worker_startup_failure().unwrap().code(),
        "candidate-worker-context-request-transport-unavailable"
    );
    let mut worker = protocol_fixture("block-ack", &directory.path().join("block-ack"));
    let expected = WorkerExpectation::fixture_for_pid(worker.child.as_ref().unwrap().id());
    let owner = crate::MacWorkerFactory::fixture_owner();
    let deadline = Instant::now() + Duration::from_secs(1);
    assert_eq!(
        worker.prove_context(&expected, deadline, |child| {
            let input = child.input.as_mut().unwrap();
            loop {
                assert!(Instant::now() < deadline, "bounded pipe fill");
                match input.write(&[0; 4096]) {
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => panic!("fill: {error}"),
                }
            }
            owner.factory().fixture_admit(
                deadline,
                || Ok(()),
                || child.acknowledge_context(deadline),
            )
        }),
        Err(NativeError::TransportUnavailable)
    );
    assert_eq!(
        crate::take_last_worker_startup_failure().unwrap().code(),
        "candidate-worker-context-ack-transport-unavailable"
    );
}

/// A real proof can finish while native validation stalls, but revoke still prevents ACK and INIT.
#[test]
fn real_child_context_revoked_during_final_validation_has_zero_initializer() {
    use std::sync::mpsc;
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("revoked");
    let mut worker = protocol_fixture("valid", &marker);
    let expected = WorkerExpectation::fixture_for_pid(worker.child.as_ref().unwrap().id());
    let owner = crate::MacWorkerFactory::fixture_owner();
    let factory = owner.factory();
    let (entered, ready) = mpsc::sync_channel(0);
    let (release, resume) = mpsc::sync_channel(0);
    let thread = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        worker.prove_context(&expected, deadline, |child| {
            factory.fixture_admit(
                deadline,
                || {
                    entered.send(()).unwrap();
                    resume.recv_timeout(Duration::from_secs(2)).unwrap();
                    Ok(())
                },
                || child.acknowledge_context(deadline),
            )
        })
    });
    ready.recv_timeout(Duration::from_secs(2)).unwrap();
    owner.revoke();
    assert_eq!(
        owner.factory().ensure_active(),
        Err(NativeError::AccessDenied)
    );
    release.send(()).unwrap();
    assert_eq!(thread.join().unwrap(), Err(NativeError::AccessDenied));
    assert!(!marker.exists());
}

/// Actual public spawn ownership and GUI initialization share pipes, proof, failure Drop and reap.
#[cfg(feature = "test-hooks")]
#[test]
fn native_owned_spawn_context_handoff_and_failed_proof_cleanup() {
    let identity = crate::synthetic_candidate_for_test().rematch_identity();
    for bad in [false, true] {
        let (process, _source_guard) = crate::worker_process::context_process_fixture(bad);
        let pid = process.child.id();
        let expected = WorkerExpectation::fixture_for_pid(pid);
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut acks = 0;
        let result = MacScsiWorkerLease::initialize_gui_process(
            process,
            &expected,
            &identity,
            deadline,
            |worker| {
                acks += 1;
                worker.acknowledge_context(deadline)
            },
        );
        if bad {
            assert!(matches!(result, Err(NativeError::AccessDenied)));
            assert_eq!(acks, 0);
        } else {
            let mut worker = result.unwrap();
            worker.wait_for_child_exit(deadline).unwrap();
            assert_eq!(acks, 1);
        }
        let mut status = 0;
        // SAFETY: read-only WNOHANG proof about this test's actual completed child;
        // the owned lease above must already have reaped it, never an arbitrary selected process.
        assert_eq!(
            unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}

/// Private malicious/test role uses real stdio and real PID; it never invokes IOKit or a device command.
#[test]
fn context_child_fixture() {
    let Ok(mode) = std::env::var("OPENRDX_TEST_CONTEXT_MODE") else {
        return;
    };
    let marker = std::env::var_os("OPENRDX_TEST_CONTEXT_MARKER").unwrap();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let input = stdin.lock();
    let mut output = stdout.lock();
    eprintln!("{{\"diagnostic\":\"worker-startup\",\"stage\":\"init-read\",\"status\":0}}");
    if mode == "write-fail" {
        // SAFETY: only this isolated test child's own standard input is closed before its marker.
        unsafe {
            libc::close(0);
        }
    }
    output.write_all(b"OPENRDX_TEST_CONTEXT_START\n").unwrap();
    output.flush().unwrap();
    if mode == "write-fail" || mode == "blocked" {
        thread::sleep(Duration::from_secs(2));
        std::process::exit(4);
    }
    let mut input = RolePipe(&input);
    let mut output = RolePipe(&output);
    let mut flags = StdioFlags::nonblocking(&input, &output).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    if mode == "valid" || mode == "slow" {
        let result = child_preflight(&mut input, &mut output, deadline, |expected| {
            if mode == "slow" {
                thread::sleep(Duration::from_millis(300));
            }
            Ok(WorkerContext::matching_fixture(expected))
        });
        let Ok((FRAME_INIT, payload)) = result else {
            std::process::exit(3);
        };
        assert_eq!(payload.len(), IDENTITY_BYTES);
        flags.restore().unwrap();
        if mode == "slow" {
            thread::sleep(Duration::from_millis(500));
        }
        // SAFETY: getter inspects only this test child's retained standard input/output descriptors.
        unsafe {
            assert_eq!(
                libc::fcntl(input.as_raw_fd(), libc::F_GETFL) & libc::O_NONBLOCK,
                0
            );
            assert_eq!(
                libc::fcntl(output.as_raw_fd(), libc::F_GETFL) & libc::O_NONBLOCK,
                0
            );
        }
        std::fs::write(marker, "initialized-after-proof-ack-and-restoration").unwrap();
        write_frame(&mut output, FRAME_READY, &[]).unwrap();
        std::process::exit(0);
    }
    let (_, bytes) = read_bounded(
        &mut input,
        deadline,
        &[(
            FRAME_CONTEXT_REQUEST,
            crate::worker_context::EXPECTATION_BYTES,
        )],
    )
    .unwrap();
    let expected = WorkerExpectation::decode(&bytes).unwrap();
    let mut payload = WorkerContext::matching_fixture(&expected).encode();
    if mode.starts_with("wrong-") || mode == "block-ack" {
        let word = match mode.as_str() {
            "wrong-pid" => 6,
            "wrong-ppid" => 7,
            "wrong-uid" => 2,
            "wrong-gid" => 4,
            "wrong-auid" => 8,
            "wrong-asid" => 14,
            _ => 16,
        };
        if mode != "block-ack" {
            payload[word * 4..word * 4 + 4].copy_from_slice(&9876_u32.to_le_bytes());
        }
        write_bounded(&mut output, FRAME_CONTEXT_PROOF, &payload, deadline).unwrap();
    } else if mode == "oversized" {
        let mut header = [0; HEADER_BYTES];
        header[..8].copy_from_slice(MAGIC);
        header[8] = FRAME_CONTEXT_PROOF;
        header[12..16].copy_from_slice(&8193_u32.to_le_bytes());
        output.write_all(&header).unwrap();
        output.flush().unwrap();
    } else if mode == "partial" {
        output.write_all(b"RDXSCSI1").unwrap();
        output.flush().unwrap();
    } else if mode == "bad-magic" {
        output.write_all(&[42; HEADER_BYTES]).unwrap();
        output.flush().unwrap();
    } else if mode == "eof" {
        std::process::exit(0);
    } else if mode == "stderr" {
        for _ in 0..1024 {
            eprintln!("private-context-detail-must-not-be-published");
        }
    }
    // Let the real parent's absolute deadline/refusal cleanup terminate this exact child.
    thread::sleep(Duration::from_secs(2));
    std::process::exit(4);
}
