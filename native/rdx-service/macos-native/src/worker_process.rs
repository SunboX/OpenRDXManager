// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Supported public spawn ownership; no raw process identity can enter through a public API.

use crate::{NativeError, ffi, peer_session::PeerSession};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::process::ExitStatusExt,
    },
    process::{Child, ExitStatus},
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

/// Retains the existing standard pipe or the public posix_spawn pipe with identical IO semantics.
pub(super) enum WorkerPipe<T> {
    Standard(T),
    Spawned(File),
}

impl<T: Read> Read for WorkerPipe<T> {
    /// Reads only this retained pipe; deadline policy remains at the existing IO boundary.
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Standard(pipe) => pipe.read(bytes),
            Self::Spawned(pipe) => pipe.read(bytes),
        }
    }
}

impl<T: Write> Write for WorkerPipe<T> {
    /// Writes only this retained pipe without resetting caller deadlines.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Standard(pipe) => pipe.write(bytes),
            Self::Spawned(pipe) => pipe.write(bytes),
        }
    }
    /// Preserves the underlying writer's flush contract.
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Standard(pipe) => pipe.flush(),
            Self::Spawned(pipe) => pipe.flush(),
        }
    }
}

impl<T: AsRawFd> AsRawFd for WorkerPipe<T> {
    /// Borrows the live owned descriptor; never transfers or fabricates ownership.
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Standard(pipe) => pipe.as_raw_fd(),
            Self::Spawned(pipe) => pipe.as_raw_fd(),
        }
    }
}

/// Existing Child behavior and supported posix_spawn ownership share the lease's original cleanup.
pub(super) enum WorkerProcess {
    Standard(Child),
    Spawned(OwnedSpawnedChild),
}

impl WorkerProcess {
    /// Returns only the actual PID yielded by the successful corresponding spawn API.
    pub(super) fn id(&self) -> u32 {
        match self {
            Self::Standard(child) => child.id(),
            Self::Spawned(child) => child.pid as u32,
        }
    }
    /// Polls one retained process without blocking; only this owner waits for its exact PID.
    pub(super) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match self {
            Self::Standard(child) => child.try_wait(),
            Self::Spawned(child) => child.try_wait(),
        }
    }
    /// Signals only the retained, unreaped process; new ownership loss permanently disarms signalling.
    pub(super) fn kill(&mut self, deadline: Instant) -> io::Result<()> {
        match self {
            Self::Standard(child) => child.kill(),
            Self::Spawned(child) => child.kill(deadline),
        }
    }
    /// Ends cleanup after its single bounded attempt; no Drop can start another wait budget.
    pub(super) fn abandon(&mut self) {
        if let Self::Spawned(child) = self {
            child.lose(libc::ETIMEDOUT);
        }
    }
}

/// Only successful waitpid proof permits Reaped; every uncertain wait permanently disarms PID use.
enum ChildState {
    Owned,
    Reaped(ExitStatus),
    Lost(i32),
}

/// Single exact-PID waiter, armed immediately after successful C spawn before fallible handoff.
pub(super) struct OwnedSpawnedChild {
    pid: i32,
    state: ChildState,
}

impl OwnedSpawnedChild {
    /// Borrows only the actual successfully spawned process identity for private proof binding.
    pub(super) fn id(&self) -> u32 {
        self.pid as u32
    }
    /// Creates ownership only from the successful trusted native output, never external arguments.
    fn arm(pid: i32) -> Self {
        Self {
            pid,
            state: ChildState::Owned,
        }
    }

    /// Makes ownership uncertainty permanent, preventing later reused-PID waits or signals.
    fn lose(&mut self, code: i32) {
        self.state = ChildState::Lost(code);
        crate::scsi_worker::UNREAPED_WORKER.store(true, Ordering::Release);
    }

    /// Converts one exact wait result; EINTR remains retryable only under the caller's deadline.
    fn observe_wait(
        &mut self,
        result: i32,
        status: i32,
        error: i32,
    ) -> io::Result<Option<ExitStatus>> {
        if result == self.pid && self.pid > 0 {
            let status = ExitStatus::from_raw(status);
            self.state = ChildState::Reaped(status);
            return Ok(Some(status));
        }
        if result == 0 {
            return Ok(None);
        }
        if result < 0 && error == libc::EINTR {
            return Err(io::Error::from_raw_os_error(error));
        }
        let error = if error == 0 { libc::ECHILD } else { error };
        self.lose(error);
        Err(io::Error::from_raw_os_error(error))
    }

    /// Never revives Lost or re-waits a cached status; no global waiter is used anywhere.
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match self.state {
            ChildState::Reaped(status) => return Ok(Some(status)),
            ChildState::Lost(error) => return Err(io::Error::from_raw_os_error(error)),
            ChildState::Owned => {}
        }
        let mut status = 0;
        // SAFETY: PID came only from successful posix_spawn, is positive and has this sole waiter.
        let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        let error = if result < 0 {
            io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::ECHILD)
        } else {
            0
        };
        self.observe_wait(result, status, error)
    }

    /// An exited zombie retains its PID until our own wait, closing exit/reuse signalling races.
    fn kill(&mut self, deadline: Instant) -> io::Result<()> {
        self.kill_with(deadline, Self::try_wait)
    }

    /// Retries an interrupted pre-kill poll within the same cleanup budget, never a second budget.
    fn kill_with(
        &mut self,
        deadline: Instant,
        mut poll: impl FnMut(&mut Self) -> io::Result<Option<ExitStatus>>,
    ) -> io::Result<()> {
        loop {
            match poll(self) {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
            if Instant::now() >= deadline {
                self.lose(libc::ETIMEDOUT);
                return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
            }
        }
        if Instant::now() >= deadline {
            self.lose(libc::ETIMEDOUT);
            return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        // SAFETY: the sole waiter still owns this positive unreaped PID; no external/global reaper exists.
        if unsafe { libc::kill(self.pid, libc::SIGKILL) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Follows the original 500ms cleanup budget for failures before lease handoff as well as Drop.
    fn cleanup(&mut self) {
        if !matches!(self.state, ChildState::Owned) {
            return;
        }
        let deadline = Instant::now() + Duration::from_millis(500);
        let _ = self.kill(deadline);
        loop {
            match self.try_wait() {
                Ok(Some(_)) => return,
                Err(error) if error.kind() != io::ErrorKind::Interrupted => return,
                _ => {}
            }
            if Instant::now() >= deadline {
                self.lose(libc::ETIMEDOUT);
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for OwnedSpawnedChild {
    /// Covers every fallible post-spawn setup path with bounded own-child cleanup.
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Pipes precede child so automatic field destruction closes pipes before armed child cleanup.
pub(super) struct SpawnedProcess {
    pub(super) input: File,
    pub(super) output: File,
    pub(super) error: File,
    pub(super) child: OwnedSpawnedChild,
}

#[repr(C)]
struct SpawnOutput {
    version: u32,
    size: u32,
    pid: i32,
    input_fd: i32,
    output_fd: i32,
    error_fd: i32,
}

impl SpawnOutput {
    /// Supplies no process identity until a successful native call fills the independent record.
    fn empty() -> Self {
        Self {
            version: 1,
            size: 24,
            pid: -1,
            input_fd: -1,
            output_fd: -1,
            error_fd: -1,
        }
    }

    /// Arms PID ownership first, then converts the compiler-checked native owned descriptors.
    fn take(self) -> Result<SpawnedProcess, NativeError> {
        let mut child = OwnedSpawnedChild::arm(self.pid);
        // A trusted successful C producer guarantees these invariants; do not signal malformed identity.
        if self.pid <= 0 {
            child.lose(libc::ECHILD);
        }
        let raw = [self.input_fd, self.output_fd, self.error_fd];
        if raw.iter().any(|fd| *fd < 3) || raw[0] == raw[1] || raw[0] == raw[2] || raw[1] == raw[2]
        {
            // Never construct duplicate/invalid Rust FD owners. Only distinct native output ends close.
            for (index, fd) in raw.iter().copied().enumerate() {
                if fd >= 3 && !raw[..index].contains(&fd) {
                    // SAFETY: successful native output owns its distinct live descriptor.
                    drop(unsafe { File::from_raw_fd(fd) });
                }
            }
            return Err(NativeError::TransportUnavailable);
        }
        // SAFETY: successful native spawn exclusively transferred three distinct valid descriptors.
        let (input, output, error) = unsafe {
            (
                File::from_raw_fd(raw[0]),
                File::from_raw_fd(raw[1]),
                File::from_raw_fd(raw[2]),
            )
        };
        let process = SpawnedProcess {
            input,
            output,
            error,
            child,
        };
        if self.pid <= 0 || self.version != 1 || self.size != std::mem::size_of::<Self>() as u32 {
            return Err(NativeError::TransportUnavailable);
        }
        Ok(process)
    }
}

/// Calls only the closed fixed-target C launcher after the factory's fresh native validation.
pub(super) fn spawn_gui(peer: &PeerSession) -> Result<SpawnedProcess, NativeError> {
    let mut output = SpawnOutput::empty();
    // SAFETY: complete retained record and initialized native output remain live; C owns setup cleanup.
    let status = unsafe { rdx_macos_spawn_gui_worker(peer.record(), &mut output) };
    // On error PID is undefined: never arm or inspect it, and C transferred no descriptors.
    crate::status_result(status)?;
    output.take()
}

/// Reuses the actual native primitive with a harmless fixed C protocol fixture only in unit tests.
#[cfg(all(test, feature = "test-hooks"))]
pub(crate) fn context_process_fixture(bad: bool) -> (SpawnedProcess, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let executable = tests::fixture_program(directory.path());
    let process = tests::spawn_fixture(
        &executable,
        &[
            if bad {
                "badcontext".into()
            } else {
                "context".into()
            },
            "-1".into(),
        ],
        0,
    )
    .unwrap();
    (process, directory)
}

// SAFETY: this independent compiler-checked output ABI transfers ownership only on status OK.
unsafe extern "C" {
    fn rdx_macos_spawn_gui_worker(
        peer: *const ffi::PeerSessionRecord,
        output: *mut SpawnOutput,
    ) -> u32;
    #[cfg(all(test, feature = "test-hooks"))]
    fn rdx_macos_test_spawn_worker(
        program: *const std::ffi::c_char,
        argv: *const *mut std::ffi::c_char,
        environment: *const *mut std::ffi::c_char,
        fail_step: u32,
        output: *mut SpawnOutput,
    ) -> u32;
}

#[cfg(all(test, feature = "test-hooks"))]
#[path = "worker_process_tests.rs"]
mod tests;
