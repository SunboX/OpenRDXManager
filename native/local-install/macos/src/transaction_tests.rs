// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

/// Exact foreign-label bootstrap failures must survive the private socket response.
#[test]
fn registration_response_preserves_foreign_job_failure() {
    let (mut client, mut supervisor) = UnixStream::pair().unwrap();
    let detail = "foreign or legacy signed registration reappeared during installation";
    write_preparation_failure(&mut supervisor, detail).unwrap();
    drop(supervisor);
    let error = read_registration_result(&mut client).unwrap_err();
    assert!(error.contains(detail), "{error}");
    assert!(
        error.contains("privileged access remains disabled"),
        "{error}"
    );
}

/// Unknown, empty, truncated, oversized or malformed frames cannot confirm registration.
#[test]
fn registration_response_refuses_invalid_failure_frames() {
    for bytes in [
        vec![b'N', 4, 1],
        vec![b'N', 0, 1, 0xff],
        vec![b'N', 0, 3, b'x'],
        vec![b'N', 0],
        vec![b'N', 0, 0],
        vec![b'N'],
        vec![b'Z'],
        vec![],
    ] {
        let (mut client, mut supervisor) = UnixStream::pair().unwrap();
        supervisor.write_all(&bytes).unwrap();
        drop(supervisor);
        let error = read_registration_result(&mut client).unwrap_err();
        assert!(error.contains("registration"), "{error}");
        assert!(
            error.contains("privileged access remains disabled"),
            "{error}"
        );
    }
}

/// Long Unicode diagnostics remain valid and bounded while registration stays refused.
#[test]
fn registration_response_bounds_overlong_utf8_diagnostics() {
    let (mut client, mut supervisor) = UnixStream::pair().unwrap();
    write_preparation_failure(&mut supervisor, &"α".repeat(1100)).unwrap();
    drop(supervisor);
    let error = read_registration_result(&mut client).unwrap_err();
    assert!(error.contains(&"α".repeat(512)), "{error}");
    assert!(!error.contains(&"α".repeat(513)), "{error}");
}

/// Registration keeps the single-byte Y success response without waiting for EOF.
#[test]
fn registration_response_keeps_single_byte_success() {
    let (mut client, mut supervisor) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    supervisor.write_all(b"Y").unwrap();
    read_registration_result(&mut client).unwrap();
}

/// Missing Installer stdio must never place ownership/protocol handles below fd3.
#[test]
fn missing_standard_streams_cannot_become_lease_or_ready_handles() {
    for missing in ["1", "all"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "transaction::tests::stdio_reservation_isolated_child",
                "--nocapture",
            ])
            .env("OPENRDX_TEST_MISSING_STDIO", missing)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "missing={missing}, status={}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// Self-exec fixture closes only its own stdio and exercises real fd replacement.
#[test]
fn stdio_reservation_isolated_child() {
    let close_stderr = match std::env::var("OPENRDX_TEST_MISSING_STDIO").as_deref() {
        Ok("1") => false,
        Ok("all") => true,
        _ => return,
    };
    let directory = tempfile::tempdir().unwrap();
    let evidence_fd = unsafe { libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 3) };
    assert!(evidence_fd >= 3);
    let mut evidence = unsafe { File::from_raw_fd(evidence_fd) };
    let existing_stderr = evidence.metadata().unwrap();
    unsafe {
        libc::close(0);
        libc::close(1);
    }
    if close_stderr {
        unsafe {
            libc::close(2);
        }
    }
    let _guards = reserve_missing_standard_descriptors().unwrap();
    let stderr_check_fd = unsafe { libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 3) };
    assert!(stderr_check_fd >= 3);
    let retained_stderr = unsafe { File::from_raw_fd(stderr_check_fd) }
        .metadata()
        .unwrap();
    let present_stream_unchanged = close_stderr
        || (existing_stderr.dev() == retained_stderr.dev()
            && existing_stderr.ino() == retained_stderr.ino());
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(directory.path().join("lease"))
        .unwrap();
    openrdx_macos_local_install::acquire_file_lock(&lease).unwrap();
    let original = lease.metadata().unwrap();
    let (mut ready_parent, mut ready_child) = UnixStream::pair().unwrap();
    let critical_fds_above_stdio = [
        lease.as_raw_fd(),
        ready_parent.as_raw_fd(),
        ready_child.as_raw_fd(),
    ]
    .iter()
    .all(|descriptor| *descriptor >= 3);
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    for descriptor in [0, 1, 2] {
        assert!(unsafe { libc::dup2(null.as_raw_fd(), descriptor) } >= 0);
    }
    let held = lease.metadata().unwrap();
    let lease_unchanged =
        held.is_file() && held.dev() == original.dev() && held.ino() == original.ino();
    ready_parent
        .set_read_timeout(Some(Duration::from_millis(50)))
        .ok();
    let sent = ready_child.write_all(b"Y").is_ok();
    let mut ready = [0];
    let protocol_unchanged = sent && ready_parent.read_exact(&mut ready).is_ok() && ready == [b'Y'];
    writeln!(evidence, "lease_fd={}, above_stdio={critical_fds_above_stdio}, lease_unchanged={lease_unchanged}, protocol_unchanged={protocol_unchanged}, existing_stderr_unchanged={present_stream_unchanged}", lease.as_raw_fd()).unwrap();
    fs::remove_dir_all(directory.path()).unwrap();
    // Exit directly: this isolated fixture intentionally replaced standard
    // descriptor slots, so its test harness must not flush inherited streams.
    unsafe {
        libc::_exit(
            if critical_fds_above_stdio
                && lease_unchanged
                && protocol_unchanged
                && present_stream_unchanged
            {
                0
            } else {
                1
            },
        );
    }
}

/// Foreign files remain refused while the diagnostic identifies retained fd state.
#[test]
fn lease_recheck_reports_protected_descriptor_failure_with_metadata() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let file = tempfile::NamedTempFile::new().unwrap();
    let lease = Lease(file.as_file().try_clone().unwrap());
    let error = lease.recheck(file.path().to_str().unwrap()).unwrap_err();
    assert!(
        error.contains("retained lease protection failed"),
        "{error}"
    );
    assert!(
        error.contains(&format!("fd={}", lease.0.as_raw_fd())),
        "{error}"
    );
    assert!(error.contains("mode/uid/gid/links=Ok("), "{error}");
    assert!(error.contains("foreign-owned"), "{error}");
}

/// Darwin accepts inherit nonblocking mode; commit follows content verification.
#[test]
fn accepted_transaction_waits_for_commit_after_client_verification() {
    let directory = tempfile::tempdir().unwrap();
    let listener = UnixListener::bind(directory.path().join("transaction.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut client = UnixStream::connect(directory.path().join("transaction.sock")).unwrap();
    let (mut accepted, _) = listener.accept().unwrap();
    let flags = unsafe { libc::fcntl(accepted.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    assert_ne!(
        flags & libc::O_NONBLOCK,
        0,
        "Darwin accepted socket must reproduce inherited nonblocking mode"
    );
    let writer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(50));
        client.write_all(b"C").unwrap();
    });
    let admitted = read_commit_message(&mut accepted).unwrap();
    writer.join().unwrap();
    assert!(
        admitted,
        "commit was dropped before client verification completed"
    );
}

/// Blocking the retained peer still rejects EOF and every non-commit byte.
#[test]
fn transaction_commit_read_refuses_closed_or_invalid_client() {
    for bytes in [b"".as_slice(), b"N", b"Y"] {
        let (mut supervisor, mut client) = UnixStream::pair().unwrap();
        supervisor.set_nonblocking(true).unwrap();
        client.write_all(bytes).unwrap();
        if bytes.is_empty() {
            drop(client);
            assert!(!matches!(read_commit_message(&mut supervisor), Ok(true)));
        } else {
            assert!(!read_commit_message(&mut supervisor).unwrap());
        }
    }
}

/// The private fork socket must preserve the root supervisor's failure cause.
#[test]
fn preparation_response_preserves_bounded_supervisor_failure() {
    let (mut parent, mut child) = UnixStream::pair().unwrap();
    let detail = "daemon ownership changed before quiescence";
    child.write_all(b"N").unwrap();
    child
        .write_all(&(detail.len() as u16).to_be_bytes())
        .unwrap();
    child.write_all(detail.as_bytes()).unwrap();
    drop(child);
    let error = read_preparation_result(&mut parent).unwrap_err();
    assert!(error.contains(detail), "{error}");
}

/// The existing single-byte success response requires no EOF or extra frame.
#[test]
fn preparation_response_keeps_existing_single_byte_success() {
    let (mut parent, mut child) = UnixStream::pair().unwrap();
    parent
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    child.write_all(b"Y").unwrap();
    read_preparation_result(&mut parent).unwrap();
}

/// Sender truncation preserves UTF-8 and the exact bounded wire length.
#[test]
fn preparation_failure_frame_truncates_at_utf8_boundary() {
    let (mut parent, mut child) = UnixStream::pair().unwrap();
    let detail = format!("{}üextra", "x".repeat(1023));
    write_preparation_failure(&mut child, &detail).unwrap();
    drop(child);
    let mut bytes = Vec::new();
    parent.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes[0], b'N');
    let length = usize::from(u16::from_be_bytes([bytes[1], bytes[2]]));
    assert_eq!(length, 1023);
    assert_eq!(bytes.len(), length + 3);
    assert_eq!(
        String::from_utf8(bytes[3..].to_vec()).unwrap(),
        "x".repeat(1023)
    );
}

/// Oversized, malformed, incomplete and unknown frames never admit replacement.
#[test]
fn preparation_response_refuses_invalid_failure_frames() {
    for bytes in [
        vec![b'N', 4, 1],
        vec![b'N', 0, 1, 0xff],
        vec![b'N', 0, 3, b'x'],
        vec![b'N', 0, 0],
        vec![b'Z'],
        vec![],
    ] {
        let (mut parent, mut child) = UnixStream::pair().unwrap();
        child.write_all(&bytes).unwrap();
        drop(child);
        let error = read_preparation_result(&mut parent).unwrap_err();
        assert!(error.contains("replacement is refused"), "{error}");
    }
}
