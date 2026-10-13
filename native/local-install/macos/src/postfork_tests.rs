// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Isolated actual-fork ACL/descriptor fixture without system setup or hardware access.

use super::*;

unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
    fn acl_free(pointer: *mut libc::c_void) -> libc::c_int;
}

/// Return exact raw ACL retrieval errno alongside the production ACL-only verdict.
fn inspect(file: &File) -> String {
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
    let raw_errno = unsafe { *libc::__error() };
    let had_acl = !acl.is_null();
    if had_acl {
        unsafe { acl_free(acl) };
    }
    let checked = rdx_local_trust::verify_descriptor_acl(file);
    let metadata = file.metadata().unwrap();
    format!(
        "fd={}, raw_acl={had_acl}, raw_errno={raw_errno}, checked={checked:?}, inode={}:{} mode={:o}",
        file.as_raw_fd(),
        metadata.dev(),
        metadata.ino(),
        metadata.mode()
    )
}

/// Exercise shared ACL verification on actual retained inodes in a detached fork.
#[test]
fn actual_fork_retains_acl_and_lock_through_detachment() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "transaction::postfork_tests::postfork_isolated_child",
            "--nocapture",
        ])
        .env("OPENRDX_TEST_POSTFORK", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Self-exec confines fork/setsid/stdio replacement to one disposable test process.
#[test]
fn postfork_isolated_child() {
    if std::env::var("OPENRDX_TEST_POSTFORK").as_deref() != Ok("1") {
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(temporary.path().join("lease"))
        .unwrap();
    let root_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open("/usr/bin/true")
        .unwrap();
    rdx_local_trust::verify_protected_descriptor(&root_file).unwrap();
    openrdx_macos_local_install::acquire_file_lock(&lease).unwrap();
    // Exercise actual readonly OS subprocess/ACL boundaries before fork, as
    // prepare does after acquiring leases. No registration action is requested.
    rdx_local_trust::verify_protected_directory(Path::new("/Library")).unwrap();
    for registration in [Registration::Local, Registration::Previous] {
        let _ = registration_evidence(registration);
    }
    let original = lease.metadata().unwrap();
    let baseline = inspect(&lease);
    let (mut parent, mut child) = UnixStream::pair().unwrap();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        drop(parent);
        let result = (|| -> Result<(), String> {
            writeln!(child, "afterfork {}", inspect(&lease)).unwrap();
            assert!(unsafe { libc::setsid() } >= 0);
            writeln!(child, "aftersetsid {}", inspect(&lease)).unwrap();
            let null = File::options()
                .read(true)
                .write(true)
                .open("/dev/null")
                .unwrap();
            for fd in [0, 1, 2] {
                assert!(unsafe { libc::dup2(null.as_raw_fd(), fd) } >= 0);
            }
            writeln!(child, "afterdup2 {}", inspect(&lease)).unwrap();
            rdx_local_trust::verify_descriptor_acl(&lease).map_err(|error| error.to_string())?;
            rdx_local_trust::verify_protected_descriptor(&root_file)
                .map_err(|error| error.to_string())?;
            for registration in [Registration::Local, Registration::Previous] {
                let probe = registration_evidence(registration);
                writeln!(
                    child,
                    "afterdup2 readonly-probe {}={:?}",
                    registration.label(),
                    probe.as_ref().map(|value| value.is_some())
                )
                .unwrap();
                probe?;
            }
            let retained = lease.metadata().unwrap();
            assert_eq!(
                (retained.dev(), retained.ino()),
                (original.dev(), original.ino())
            );
            let contender = File::options()
                .read(true)
                .write(true)
                .open(temporary.path().join("lease"))
                .unwrap();
            assert!(openrdx_macos_local_install::acquire_file_lock(&contender).is_err());
            Ok(())
        })();
        writeln!(child, "result={result:?}").unwrap();
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) };
    }
    drop(child);
    let mut evidence = String::new();
    parent.read_to_string(&mut evidence).unwrap();
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(status, 0, "baseline={baseline}\n{evidence}");
    eprintln!("baseline={baseline}\n{evidence}");
}
