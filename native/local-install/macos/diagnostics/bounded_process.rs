// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded diagnostic subprocess capture and reaping of only owned children.

use std::{
    io::{ErrorKind, Read},
    os::fd::AsRawFd,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const POLL: Duration = Duration::from_millis(5);
const REAP_GRACE: Duration = Duration::from_secs(1);

/// Preserve the first operation failure; cleanup failures are secondary diagnostics.
fn report_cleanup(result: Result<(), String>) {
    if let Err(error) = result {
        eprintln!("secondary diagnostic child cleanup: {error}");
    }
}

/// Terminate only this spawned child, then poll without any blocking wait.
fn terminate(child: &mut Child) -> Result<(), String> {
    if child
        .try_wait()
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Ok(());
    }
    let kill_error = child.kill().err().map(|error| error.to_string());
    let deadline = Instant::now() + REAP_GRACE;
    loop {
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(kill_error.unwrap_or_else(|| {
                "owned subprocess remains unreaped after bounded SIGKILL cleanup".into()
            }));
        }
        thread::sleep(POLL);
    }
}

/// Own one std child; failure/early returns cannot leave cleanup waiting indefinitely.
struct OwnedCommand(Child);
impl Drop for OwnedCommand {
    /// Close inherited capture handles and reap only this child under a bounded grace.
    fn drop(&mut self) {
        report_cleanup(terminate(&mut self.0));
    }
}

/// Make the retained pipe nonblocking so neither stream can stall the other's drain.
fn nonblocking(pipe: &impl AsRawFd) -> Result<(), String> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

/// Consume at most one fixed-size chunk, sharing a combined stdout/stderr byte bound.
fn drain(pipe: &mut impl Read, total: &mut usize, cap: usize) -> Result<bool, String> {
    let mut bytes = [0; 4096];
    let allowed = cap
        .saturating_sub(*total)
        .saturating_add(1)
        .min(bytes.len());
    match pipe.read(&mut bytes[..allowed]) {
        Ok(0) => Ok(true),
        Ok(count) => {
            *total = total.saturating_add(count);
            if *total > cap {
                return Err("readonly registration evidence exceeds its bound".into());
            }
            Ok(false)
        }
        Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
            Ok(false)
        }
        Err(error) => Err(error.to_string()),
    }
}

/// Capture diagnostic output and exit under the caller's deadline and byte bound.
/// On failure, close both pipes and kill/reap only this exact child within one second;
/// the original spawn/read/deadline/size error remains the returned diagnostic.
pub(super) fn capture(
    command: &mut Command,
    deadline: Instant,
    cap: usize,
) -> Result<ExitStatus, String> {
    let mut child = OwnedCommand(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| error.to_string())?,
    );
    let mut stdout = child
        .0
        .stdout
        .take()
        .ok_or("diagnostic child stdout unavailable")?;
    let mut stderr = child
        .0
        .stderr
        .take()
        .ok_or("diagnostic child stderr unavailable")?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let (mut stdout_closed, mut stderr_closed) = (false, false);
    let mut total = 0;
    loop {
        if Instant::now() >= deadline {
            return Err("readonly launchctl probe deadline expired".into());
        }
        if !stdout_closed {
            stdout_closed = drain(&mut stdout, &mut total, cap)?;
        }
        if !stderr_closed {
            stderr_closed = drain(&mut stderr, &mut total, cap)?;
        }
        if let Some(status) = child.0.try_wait().map_err(|error| error.to_string())? {
            if stdout_closed && stderr_closed {
                return Ok(status);
            }
        }
        thread::sleep(POLL);
    }
}

/// Poll the exact forked child's exit under one absolute deadline, without waitpid(0).
fn poll_fork(pid: libc::pid_t, deadline: Instant) -> Result<Option<i32>, String> {
    if pid <= 0 {
        return Err("diagnostic cleanup refuses a non-child PID".into());
    }
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            return Ok(Some(status));
        }
        if waited < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(POLL);
    }
}

/// Stop/reap only our exact positive fork child, under a one-second cleanup grace.
/// An ownership/wait error never becomes permission to target another process.
pub(super) fn stop_fork(pid: libc::pid_t) -> Result<i32, String> {
    if let Some(status) = poll_fork(pid, Instant::now())? {
        return Ok(status);
    }
    let kill_error = if unsafe { libc::kill(pid, libc::SIGKILL) } < 0 {
        Some(std::io::Error::last_os_error().to_string())
    } else {
        None
    };
    poll_fork(pid, Instant::now() + REAP_GRACE)?.ok_or_else(|| {
        kill_error.unwrap_or_else(|| {
            "owned fork child remains unreaped after bounded SIGKILL cleanup".into()
        })
    })
}

/// Reap only the exact child returned by this process's diagnostic fork.
/// Deadline failure remains primary even if its bounded child-only cleanup also fails.
pub(super) fn reap_fork(pid: libc::pid_t, deadline: Instant) -> Result<i32, String> {
    match poll_fork(pid, deadline)? {
        Some(status) => Ok(status),
        None => {
            report_cleanup(stop_fork(pid).map(|_| ()));
            Err("diagnostic child exceeded deadline".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Normal bounded evidence retains the exact exit code used for absent launchd jobs.
    #[test]
    fn capture_preserves_exit_code_after_both_streams_close() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf stdout; printf stderr >&2; exit 113"]);
        let status = capture(&mut command, Instant::now() + Duration::from_secs(1), 64).unwrap();
        assert_eq!(status.code(), Some(113));
    }

    /// A successful tool cannot consume more than its combined stdout/stderr budget.
    #[test]
    fn capture_refuses_output_over_budget() {
        let mut command = Command::new("/usr/bin/printf");
        command.args(["%02000d", "1"]);
        let error =
            capture(&mut command, Instant::now() + Duration::from_secs(1), 1024).unwrap_err();
        assert!(error.contains("exceeds"), "{error}");
    }

    /// A live child with no output is stopped instead of blocking beyond the deadline.
    #[test]
    fn capture_stops_slow_owned_child() {
        let mut command = Command::new("/bin/sleep");
        command.arg("1");
        let started = Instant::now();
        let error = capture(&mut command, started + Duration::from_millis(20), 1024).unwrap_err();
        assert!(error.contains("deadline"), "{error}");
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    /// Fork cleanup never performs a blocking wait after the diagnostic deadline.
    #[test]
    fn reap_stops_only_owned_fork_without_blocking_wait() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let delay = libc::timespec {
                tv_sec: 0,
                tv_nsec: 200_000_000,
            };
            unsafe {
                libc::nanosleep(&delay, std::ptr::null_mut());
                libc::_exit(0);
            }
        }
        let started = Instant::now();
        let result = reap_fork(pid, started + Duration::from_millis(20));
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_millis(150));
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}
