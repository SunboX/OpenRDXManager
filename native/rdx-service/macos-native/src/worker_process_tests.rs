// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::{ffi::CString, path::Path, process::Command};

/// Calls only the feature/test-gated primitive; supplied fixture paths cannot mint GUI authority.
pub(super) fn spawn_fixture(
    program: &Path,
    arguments: &[String],
    fail_step: u32,
) -> Result<SpawnedProcess, NativeError> {
    use std::os::unix::ffi::OsStrExt;
    let program = CString::new(program.as_os_str().as_bytes()).unwrap();
    let words: Vec<_> = std::iter::once(program.clone())
        .chain(arguments.iter().map(|s| CString::new(s.as_str()).unwrap()))
        .collect();
    let argv: Vec<_> = words
        .iter()
        .map(|s| s.as_ptr().cast_mut())
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect();
    let environment = [c"LANG=C".as_ptr().cast_mut(), std::ptr::null_mut()];
    let mut output = SpawnOutput::empty();
    // SAFETY: test-only C call borrows terminated owned strings and transfers output only on success.
    let status = unsafe {
        rdx_macos_test_spawn_worker(
            program.as_ptr(),
            argv.as_ptr(),
            environment.as_ptr(),
            fail_step,
            &mut output,
        )
    };
    if status != ffi::STATUS_OK {
        assert_eq!(output.pid, -1);
        assert_eq!(output.input_fd, -1);
        assert_eq!(output.output_fd, -1);
        assert_eq!(output.error_fd, -1);
        return Err(crate::status_error(status));
    }
    output.take()
}

/// Polls one retained fixture under a fixed absolute deadline; RAII covers every failed assertion.
fn wait(child: &mut OwnedSpawnedChild, deadline: Instant) -> ExitStatus {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Err(error) if error.kind() != io::ErrorKind::Interrupted => {
                panic!("wait failed: {error}")
            }
            _ => {}
        }
        assert!(Instant::now() < deadline, "fixture wait deadline");
        thread::sleep(Duration::from_millis(5));
    }
}

/// Builds a tiny owned C process so Rust runtime SIGPIPE adjustment cannot hide spawn semantics.
pub(super) fn fixture_program(directory: &Path) -> std::path::PathBuf {
    let source = directory.join("fixture.c");
    std::fs::write(&source, include_str!("worker_process_fixture.c")).unwrap();
    let executable = directory.join("fixture");
    let result = Command::new("/usr/bin/clang")
        .args(["-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .status()
        .unwrap();
    assert!(result.success());
    executable
}

/// The same real owned non-CLOEXEC descriptor that leaked through stdlib must be absent here.
#[test]
fn public_spawn_closes_unrelated_fd_and_preserves_owned_pipes_status_and_signals() {
    let directory = tempfile::tempdir().unwrap();
    let executable = fixture_program(directory.path());
    let token = tempfile::tempfile().unwrap();
    // SAFETY: this owned fixture descriptor remains live; only its own CLOEXEC flag is cleared.
    assert_eq!(
        unsafe { libc::fcntl(token.as_raw_fd(), libc::F_SETFD, 0) },
        0
    );
    let process = spawn_fixture(
        &executable,
        &["contract".into(), token.as_raw_fd().to_string()],
        0,
    )
    .unwrap();
    let SpawnedProcess {
        mut input,
        mut output,
        mut error,
        mut child,
    } = process;
    let pid = child.pid;
    for fd in [input.as_raw_fd(), output.as_raw_fd(), error.as_raw_fd()] {
        assert!(fd >= 3);
        // SAFETY: getters inspect only retained fixture descriptors.
        unsafe {
            assert_ne!(libc::fcntl(fd, libc::F_GETFD) & libc::FD_CLOEXEC, 0);
            assert_eq!(libc::fcntl(fd, libc::F_GETFL) & libc::O_NONBLOCK, 0);
        }
    }
    input.write_all(b"pipe-ok\n").unwrap();
    drop(input);
    let status = wait(&mut child, Instant::now() + Duration::from_secs(2));
    assert_eq!(status.code(), Some(37));
    assert_eq!(child.try_wait().unwrap(), Some(status));
    child
        .kill(Instant::now() + Duration::from_millis(500))
        .unwrap(); // Cached reaped state must not issue another signal.
    let mut stdout = String::new();
    output.read_to_string(&mut stdout).unwrap();
    assert_eq!(
        stdout,
        format!("pid={pid} pipe-ok sigpipe-default mask-empty env-exact\n")
    );
    let mut stderr = String::new();
    error.read_to_string(&mut stderr).unwrap();
    assert_eq!(stderr, "stderr-ok\n");
}

/// Failed native setup transfers no PID or descriptor and never inspects an undefined spawn PID.
#[test]
fn public_spawn_partial_setup_and_missing_target_return_no_ownership() {
    // There are 24 fallible setup/spawn steps: three pipes, six normalization calls,
    // two initializers, three dup2 + six close actions, three attributes, and spawn.
    for fail_step in 1..=24 {
        assert!(
            spawn_fixture(Path::new("/bin/cat"), &[], fail_step).is_err(),
            "step {fail_step}"
        );
    }
    assert!(spawn_fixture(Path::new("/nonexistent/openrdx-fixture"), &[], 0).is_err());
}

/// Actual owned children can be killed/reaped under bounds, and pre-handoff failure Drop stays armed.
#[test]
fn public_spawn_early_drop_and_owned_kill_are_bounded() {
    let process = spawn_fixture(Path::new("/bin/sleep"), &["10".into()], 0).unwrap();
    let SpawnedProcess {
        input,
        output,
        error,
        mut child,
    } = process;
    drop((input, output, error));
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut interrupted = 0;
    child
        .kill_with(deadline, |owned| {
            if interrupted < 3 {
                interrupted += 1;
                Err(io::Error::from_raw_os_error(libc::EINTR))
            } else {
                owned.try_wait()
            }
        })
        .unwrap();
    assert_eq!(interrupted, 3);
    let status = wait(&mut child, Instant::now() + Duration::from_secs(1));
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    let started = Instant::now();
    drop(spawn_fixture(Path::new("/bin/sleep"), &["10".into()], 0).unwrap());
    assert!(started.elapsed() < Duration::from_secs(1));
}

/// Isolates std-slot and deliberate external-reaper fixtures from the test runner's descriptors/latch.
#[test]
fn public_spawn_missing_standard_slots_and_ownership_loss_are_isolated() {
    let directory = tempfile::tempdir().unwrap();
    let executable = fixture_program(directory.path());
    for mode in (0..8)
        .map(|n| n.to_string())
        .chain(["lost".into(), "signals".into()])
    {
        let report = directory.path().join(format!("report-{mode}"));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "worker_process::tests::isolated_process_fixture",
                "--test-threads=1",
            ])
            .env("OPENRDX_TEST_SPAWN_MODE", &mode)
            .env("OPENRDX_TEST_SPAWN_FIXTURE", &executable)
            .env("OPENRDX_TEST_SPAWN_REPORT", &report)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "isolated {mode}");
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let grace = Instant::now() + Duration::from_millis(500);
                while Instant::now() < grace {
                    if child.try_wait().ok().flatten().is_some() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                panic!("isolated fixture timeout");
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(std::fs::read_to_string(report).unwrap(), "passed");
    }
}

/// Internal subprocess-only fixture; environment selection exists only inside cfg(test).
#[test]
fn isolated_process_fixture() {
    let Ok(mode) = std::env::var("OPENRDX_TEST_SPAWN_MODE") else {
        return;
    };
    let report = std::env::var_os("OPENRDX_TEST_SPAWN_REPORT").unwrap();
    if mode == "lost" {
        let SpawnedProcess {
            input,
            output,
            error,
            mut child,
        } = spawn_fixture(Path::new("/usr/bin/true"), &[], 0).unwrap();
        drop((input, output, error));
        let deadline = Instant::now() + Duration::from_secs(2);
        // Deliberately simulate a forbidden competing waiter on our *actual* child, then prove
        // ECHILD irreversibly disarms the owner. The child is already reaped before ownership loss.
        loop {
            let mut status = 0;
            // SAFETY: test deliberately reaps only its own actual successfully spawned child.
            let result = unsafe { libc::waitpid(child.pid, &mut status, libc::WNOHANG) };
            if result == child.pid {
                break;
            }
            assert!(result == 0 && Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            child.try_wait().unwrap_err().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert!(matches!(child.state, ChildState::Lost(libc::ECHILD)));
        assert_eq!(
            child
                .kill(Instant::now() + Duration::from_millis(500))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ECHILD)
        );
        assert!(crate::scsi_worker::UNREAPED_WORKER.load(Ordering::Acquire));
        // Pure synthetic wait observations after a real known reap exercise each error decision;
        // no OS wait/signal follows a synthetic Owned transition.
        for code in [libc::EINVAL, libc::EIO] {
            child.state = ChildState::Owned;
            assert_eq!(
                child.observe_wait(-1, 0, code).unwrap_err().raw_os_error(),
                Some(code)
            );
            assert_eq!(
                child
                    .kill(Instant::now() + Duration::from_millis(500))
                    .unwrap_err()
                    .raw_os_error(),
                Some(code)
            );
        }
        child.state = ChildState::Owned;
        assert_eq!(
            child.observe_wait(-1, 0, libc::EINTR).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        assert!(matches!(child.state, ChildState::Owned));
        child.lose(libc::ECHILD); // Disarm before Drop; PID was already reaped above.
    } else {
        let mask: u8 = if mode == "signals" {
            0
        } else {
            mode.parse().unwrap()
        };
        if mode == "signals" {
            // SAFETY: only this isolated test subprocess changes its signal dispositions/mask.
            unsafe {
                assert_ne!(libc::signal(libc::SIGTERM, libc::SIG_IGN), libc::SIG_ERR);
                let mut set = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGUSR1);
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()),
                    0
                );
            }
        }
        for slot in 0..3 {
            if mask & (1 << slot) != 0 {
                // SAFETY: this isolated fixture owns its own standard slots, never the parent runner's.
                unsafe {
                    libc::close(slot);
                }
            }
        }
        let executable = std::env::var_os("OPENRDX_TEST_SPAWN_FIXTURE").unwrap();
        let variant = if mode == "signals" {
            "signals"
        } else {
            "contract"
        };
        let SpawnedProcess {
            mut input,
            mut output,
            mut error,
            mut child,
        } = spawn_fixture(Path::new(&executable), &[variant.into(), "-1".into()], 0).unwrap();
        for slot in 0..3 {
            // SAFETY: read-only query verifies that normalization preserved each missing parent slot.
            assert_eq!(
                unsafe { libc::fcntl(slot, libc::F_GETFD) } < 0,
                mask & (1 << slot) != 0
            );
        }
        input.write_all(b"pipe-ok\n").unwrap();
        drop(input);
        assert_eq!(
            wait(&mut child, Instant::now() + Duration::from_secs(2)).code(),
            Some(37)
        );
        let mut text = String::new();
        output.read_to_string(&mut text).unwrap();
        assert!(text.ends_with("pipe-ok sigpipe-default mask-empty env-exact\n"));
        text.clear();
        error.read_to_string(&mut text).unwrap();
        assert_eq!(text, "stderr-ok\n");
    }
    std::fs::write(report, "passed").unwrap();
}

/// Actual same-executable resolver uses no launchctl and preserves the reviewed owned pipe contract.
#[test]
fn direct_current_executable_fixed_role_has_close_default_pipe_signal_contract() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("direct.c");
    std::fs::write(&source, include_str!("worker_direct_spawn_fixture.c")).unwrap();
    let bridge = Path::new(env!("CARGO_MANIFEST_DIR")).join("../native/macos");
    let executable = directory.path().join("direct");
    let result = Command::new("/usr/bin/clang")
        .args([
            "-std=c17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wpedantic",
            "-DRDX_MACOS_TEST_HOOKS=1",
            "-I",
        ])
        .arg(&bridge)
        .arg(&source)
        .arg(bridge.join("rdx_worker_spawn.c"))
        .arg("-o")
        .arg(&executable)
        .status()
        .unwrap();
    assert!(result.success());
    let result = Command::new(&executable).output().unwrap();
    assert!(result.status.success(), "{result:?}");
    assert_eq!(
        String::from_utf8(result.stdout).unwrap().trim(),
        "fixed-current-exe direct-role exact-pid pipes env fd signal exit37 reaped"
    );
}
