// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Isolated actual-fork ACL/descriptor fixture without system setup or hardware access.

use super::*;

unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
    fn acl_free(pointer: *mut libc::c_void) -> libc::c_int;
}

/// Return exact raw ACL retrieval errno alongside the production ACL-only verdict.
fn inspect(file: &File) -> Result<String, String> {
    // Preserve the FIRST production call verdict; a repeated raw diagnostic
    // read must not replace a transient original syscall failure.
    let checked = rdx_local_trust::verify_descriptor_acl(file);
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
    let raw_errno = unsafe { *libc::__error() };
    let had_acl = !acl.is_null();
    if had_acl {
        unsafe { acl_free(acl) };
    }
    let metadata = file.metadata().unwrap();
    let evidence = format!(
        "fd={}, raw_acl={had_acl}, raw_errno={raw_errno}, checked={checked:?}, inode={}:{} mode={:o}",
        file.as_raw_fd(),
        metadata.dev(),
        metadata.ino(),
        metadata.mode()
    );
    checked.map_err(|_| evidence.clone())?;
    Ok(evidence)
}

/// Read ONLY an explicit public test inventory, then preflight the fixed installed tree.
/// The environment input exists solely in this cfg(test) isolated fixture and
/// grants no IPC/enrollment authority. Never use an elevated process for it.
fn installed_fixture() -> Option<rdx_local_trust::RuntimeInventory> {
    let source = std::env::var_os("OPENRDX_TEST_PUBLIC_INSTALLED_INVENTORY")?;
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "public inventory fixture requires ordinary user"
    );
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)
        .unwrap()
        .take(rdx_local_trust::MAX_INVENTORY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    let record = rdx_local_trust::parse_inventory(&bytes, "macos").unwrap();
    let app = Path::new("/Applications/OpenRDXManager.app");
    let required = rdx_local_trust::protected_runtime_handle_requirement(app, &record).unwrap()
        as libc::rlim_t;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    assert!(required <= limit.rlim_max && required <= 8192);
    if required > limit.rlim_cur {
        limit.rlim_cur = required;
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    }
    rdx_local_trust::verify_protected_tree_ownership(app, &record).unwrap();
    eprintln!(
        "beforefork fixed-installed-tree ownership=Ok handles-required={required} effective-uid={}",
        unsafe { libc::geteuid() }
    );
    Some(record)
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
    let installed = installed_fixture();
    for registration in [Registration::Local, Registration::Previous] {
        let _ = registration_evidence(registration);
    }
    let original = lease.metadata().unwrap();
    let baseline = inspect(&lease).unwrap();
    let (mut parent, mut child) = UnixStream::pair().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        drop(parent);
        let result = (|| -> Result<(), String> {
            writeln!(child, "afterfork {}", inspect(&lease)?).unwrap();
            assert!(unsafe { libc::setsid() } >= 0);
            writeln!(child, "aftersetsid {}", inspect(&lease)?).unwrap();
            let null = File::options()
                .read(true)
                .write(true)
                .open("/dev/null")
                .unwrap();
            for fd in [0, 1, 2] {
                assert!(unsafe { libc::dup2(null.as_raw_fd(), fd) } >= 0);
            }
            writeln!(child, "afterdup2 {}", inspect(&lease)?).unwrap();
            rdx_local_trust::verify_descriptor_acl(&lease).map_err(|error| error.to_string())?;
            rdx_local_trust::verify_protected_descriptor(&root_file)
                .map_err(|error| error.to_string())?;
            if let Some(record) = &installed {
                let checked = rdx_local_trust::verify_protected_tree_ownership(
                    Path::new("/Applications/OpenRDXManager.app"),
                    record,
                );
                writeln!(
                    child,
                    "afterdup2 fixed-installed-tree ownership={checked:?}"
                )
                .unwrap();
                checked.map_err(|error| error.to_string())?;
            }
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
    let mut evidence = Vec::new();
    let received = (|| -> Result<(), String> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("postfork test deadline expired".into());
            }
            parent
                .set_read_timeout(Some(remaining))
                .map_err(|error| error.to_string())?;
            let mut bytes = [0; 4096];
            let count = parent.read(&mut bytes).map_err(|error| error.to_string())?;
            if count == 0 {
                return Ok(());
            }
            if evidence.len() + count > 16384 {
                return Err("postfork test evidence exceeds bound".into());
            }
            evidence.extend_from_slice(&bytes[..count]);
        }
    })();
    if received.is_err() {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    let evidence = String::from_utf8_lossy(&evidence);
    assert!(
        received.is_ok(),
        "baseline={baseline}\n{evidence}\n{received:?}"
    );
    assert_eq!(status, 0, "baseline={baseline}\n{evidence}");
    eprintln!("baseline={baseline}\n{evidence}");
}
