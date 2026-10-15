// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Private child context preflight shares the original initialization deadline and child owner.

use super::*;
use crate::worker_context::{ContextExpectation, ContextRequest, WorkerContext};
use std::os::fd::AsRawFd;

const FRAME_CONTEXT_REQUEST: u8 = 10;
pub(super) const FRAME_CONTEXT_PROOF: u8 = 11;
const FRAME_CONTEXT_OK: u8 = 12;

/// Borrows an existing role stream without stdio buffering, which could hide bytes or retry EINTR.
struct RolePipe<'a, T: AsRawFd>(&'a T);

impl<T: AsRawFd> AsRawFd for RolePipe<'_, T> {
    /// Borrows the descriptor from a standard-stream owner retained throughout the preflight.
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}
impl<T: AsRawFd> Read for RolePipe<'_, T> {
    /// Performs one nonblocking kernel read only; caller owns all EINTR/deadline handling.
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        // SAFETY: owner remains live, and bytes supplies its exact writable capacity.
        let count = unsafe { libc::read(self.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
        if count < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(count as usize)
        }
    }
}
impl<T: AsRawFd> Write for RolePipe<'_, T> {
    /// Performs one nonblocking kernel write only; no internal buffering/poll/retry exists.
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        // SAFETY: owner remains live, and bytes supplies its exact readable length.
        let count = unsafe { libc::write(self.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        if count < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(count as usize)
        }
    }
    /// Kernel pipes have no userspace buffered bytes to flush.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl MacScsiWorkerLease {
    /// Arms the same lease immediately and shares one pre-spawn budget across setup/proof/INIT.
    pub(crate) fn initialize_context_process(
        process: crate::worker_process::SpawnedProcess,
        expected: &impl ContextExpectation,
        identity: &MacRematchIdentity,
        deadline: Instant,
        acknowledge: impl FnOnce(&mut Self) -> Result<(), NativeError>,
    ) -> Result<Self, NativeError> {
        let crate::worker_process::SpawnedProcess {
            input,
            output,
            error,
            child,
        } = process;
        let mut worker = Self {
            input: Some(WorkerPipe::Spawned(input, std::marker::PhantomData)),
            output: Some(WorkerPipe::Spawned(output, std::marker::PhantomData)),
            diagnostics: crate::scsi_worker_startup::StartupDiagnostics::from_pipe(Some(
                WorkerPipe::Spawned(error, std::marker::PhantomData),
            )),
            child: Some(WorkerProcess::Spawned(child)),
        };
        if let Err(error) = (|| {
            worker.diagnostics.nonblocking()?;
            crate::scsi_worker_io::nonblocking_io(worker.input.as_ref().expect("owned input"))?;
            crate::scsi_worker_io::nonblocking_io(worker.output.as_ref().expect("owned output"))
        })() {
            crate::scsi_worker_startup::os_failure("process-nonblocking", &error);
            return Err(NativeError::TransportUnavailable);
        }
        worker.prove_context(expected, deadline, acknowledge)?;
        worker.finish_initialization(identity, deadline)
    }

    /// Admits initialization only after actual-child proof and the final fresh connection gate.
    fn prove_context(
        &mut self,
        expected: &impl ContextExpectation,
        deadline: Instant,
        acknowledge: impl FnOnce(&mut Self) -> Result<(), NativeError>,
    ) -> Result<(), NativeError> {
        let result = (|| {
            self.write_frame_phase(
                expected.request_kind(),
                &expected.encode(),
                deadline,
                "context-request",
            )?;
            let (kind, payload) = self.read_frame_phase(
                FRAME_CONTEXT_PROOF,
                deadline,
                "context-proof",
                "context-proof",
            )?;
            if kind != FRAME_CONTEXT_PROOF {
                return Err(NativeError::AccessDenied);
            }
            let observed = WorkerContext::decode(&payload)?;
            expected.verify(
                &observed,
                self.child
                    .as_ref()
                    .ok_or(NativeError::TransportUnavailable)?
                    .id(),
            )?;
            acknowledge(self).inspect_err(|error| self.diagnostics.failure("context-ack", *error))
        })();
        if let Err(error) = result {
            self.diagnostics.failure("context-proof", error);
            self.terminate_child();
        }
        result
    }

    /// One <=PIPE_BUF nonblocking ACK attempt only; never poll/retry/drain under the admission gate.
    pub(crate) fn acknowledge_context(&mut self, deadline: Instant) -> Result<(), NativeError> {
        if Instant::now() >= deadline {
            return Err(NativeError::TimedOut);
        }
        let mut header = [0; HEADER_BYTES];
        header[..8].copy_from_slice(MAGIC);
        header[8] = FRAME_CONTEXT_OK;
        let input = self
            .input
            .as_mut()
            .ok_or(NativeError::TransportUnavailable)?;
        match RolePipe(input).write(&header) {
            Ok(HEADER_BYTES) => Ok(()),
            _ => Err(NativeError::TransportUnavailable),
        }
    }
}

/// Restores child stdio flags before the unchanged blocking command loop; errors precede IOKit.
struct StdioFlags {
    flags: [(i32, i32); 2],
    restored: bool,
}

impl StdioFlags {
    /// Captures original flags before any mutation; partial setup Drop restores the first pipe too.
    fn nonblocking(input: &impl AsRawFd, output: &impl AsRawFd) -> Result<Self, NativeError> {
        let mut guard = Self {
            flags: [(input.as_raw_fd(), -1), (output.as_raw_fd(), -1)],
            restored: false,
        };
        for (fd, flags) in &mut guard.flags {
            // SAFETY: role retains both standard stream owners throughout this guard.
            *flags = unsafe { libc::fcntl(*fd, libc::F_GETFL) };
            if *flags < 0
                || unsafe { libc::fcntl(*fd, libc::F_SETFL, *flags | libc::O_NONBLOCK) } < 0
            {
                return Err(NativeError::TransportUnavailable);
            }
        }
        Ok(guard)
    }
    /// Refuses initialization if either original child descriptor state could not be restored.
    fn restore(&mut self) -> Result<(), NativeError> {
        let mut failed = false;
        for (fd, flags) in self.flags {
            // SAFETY: borrowed standard owners remain live; only flags captured by this guard restore.
            if flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } < 0 {
                failed = true;
            }
        }
        self.restored = !failed;
        if failed {
            Err(NativeError::TransportUnavailable)
        } else {
            Ok(())
        }
    }
}

impl Drop for StdioFlags {
    /// Best-effort rollback on every early error; normal success explicitly checks restoration.
    fn drop(&mut self) {
        if !self.restored {
            let _ = self.restore();
        }
    }
}

/// Reads only expected fixed frame kinds/lengths under one deadline before allocating any payload.
fn read_bounded(
    input: &mut (impl Read + AsRawFd),
    deadline: Instant,
    expected: &[(u8, usize)],
) -> Result<(u8, Vec<u8>), NativeError> {
    let mut header = [0; HEADER_BYTES];
    crate::scsi_worker_io::read_exact_observed(input, &mut header, deadline, None)?;
    let kind = header[8];
    let length = u32::from_le_bytes(header[12..16].try_into().expect("fixed word")) as usize;
    if &header[..8] != MAGIC || header[9..12] != [0, 0, 0] || !expected.contains(&(kind, length)) {
        return Err(NativeError::InvalidRequest);
    }
    let mut payload = vec![0; length];
    crate::scsi_worker_io::read_exact_observed(input, &mut payload, deadline, None)?;
    Ok((kind, payload))
}

/// Writes one fixed-width child proof under the same deadline, with no public metadata/logging.
fn write_bounded(
    output: &mut (impl Write + AsRawFd),
    kind: u8,
    payload: &[u8],
    deadline: Instant,
) -> Result<(), NativeError> {
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.push(kind);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    crate::scsi_worker_io::write_all_observed(output, &bytes, deadline, None)
        .map_err(|(error, _)| error)
}

/// Runs no initializer; returns INIT only after actual current self-proof and final parent ACK.
fn child_preflight_role(
    input: &mut (impl Read + AsRawFd),
    output: &mut (impl Write + AsRawFd),
    deadline: Instant,
    serial_only: bool,
    sample: impl FnOnce(&ContextRequest) -> Result<WorkerContext, NativeError>,
) -> Result<(u8, Vec<u8>), NativeError> {
    let first = read_bounded(
        input,
        deadline,
        &[
            (
                FRAME_CONTEXT_REQUEST,
                crate::worker_context::EXPECTATION_BYTES,
            ),
            (
                crate::worker_context::FRAME_DIRECT_CONTEXT_REQUEST,
                crate::worker_context::DIRECT_EXPECTATION_BYTES,
            ),
        ],
    )?;
    let expected = ContextRequest::decode(first.0, &first.1, serial_only)?;
    let observed = sample(&expected)?;
    expected.verify(&observed, std::process::id())?;
    write_bounded(output, FRAME_CONTEXT_PROOF, &observed.encode(), deadline)?;
    read_bounded(input, deadline, &[(FRAME_CONTEXT_OK, 0)])?;
    read_bounded(input, deadline, &[(FRAME_INIT, IDENTITY_BYTES)])
}

/// Fixed privileged role entry; actual public self-audit precedes any existing native initializer.
pub(super) fn run_stdio(serial_only: bool) -> Result<(), NativeError> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let input = stdin.lock();
    let output = stdout.lock();
    let deadline = Instant::now() + INIT_TIMEOUT;
    if !serial_only {
        crate::enable_acquisition_diagnostics();
    }
    let mut flags = StdioFlags::nonblocking(&input, &output)?;
    let initial = crate::scsi_worker_startup::step("init-read", !serial_only, || {
        child_preflight_role(
            &mut RolePipe(&input),
            &mut RolePipe(&output),
            deadline,
            serial_only,
            |_| WorkerContext::current(),
        )
    })?;
    flags.restore()?;
    if Instant::now() >= deadline {
        return Err(NativeError::TimedOut);
    }
    run_worker_with_initial(input, output, serial_only, initial)
}

/// Shared exact preflight with non-authorizing GUI sampling only for hardware-free unit fixtures.
#[cfg(test)]
fn child_preflight(
    input: &mut (impl Read + AsRawFd),
    output: &mut (impl Write + AsRawFd),
    deadline: Instant,
    sample: impl FnOnce(&ContextRequest) -> Result<WorkerContext, NativeError>,
) -> Result<(u8, Vec<u8>), NativeError> {
    child_preflight_role(input, output, deadline, false, sample)
}

#[cfg(test)]
#[path = "scsi_worker_context_tests.rs"]
mod tests;
