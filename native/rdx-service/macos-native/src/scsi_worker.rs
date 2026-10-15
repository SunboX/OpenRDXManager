// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Disposable macOS USB-capture worker and bounded private protocol.
//!
//! `IOUSBHostObjectInitOptionsDeviceCapture` terminates its caller when capture
//! is surrendered. Keeping that capture in this child process lets the
//! long-lived hardware service survive the required storage-driver rematch.

use crate::worker_process::{WorkerPipe, WorkerProcess};
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use super::*;

const MAGIC: &[u8; 8] = b"RDXSCSI1";
const HEADER_BYTES: usize = 16;
const MAX_FRAME_BYTES: usize = 8_192;
const FRAME_INIT: u8 = 1;
const FRAME_READY: u8 = 2;
const FRAME_COMMAND: u8 = 3;
const FRAME_RESPONSE: u8 = 4;
const FRAME_SHUTDOWN: u8 = 5;
const FRAME_ACK: u8 = 6;
const FRAME_ERROR: u8 = 7;
const FRAME_USB_IDENTITY: u8 = 8;
const FRAME_USB_IDENTITY_RESPONSE: u8 = 9;
const RELEASE_TIMEOUT: Duration = Duration::from_secs(5);
const RELEASE_POLL_INTERVAL: Duration = Duration::from_millis(20);
pub(super) const INIT_TIMEOUT: Duration = Duration::from_secs(15);
const IDENTITY_TIMEOUT: Duration = Duration::from_secs(5);
const REAP_TIMEOUT: Duration = Duration::from_millis(500);
pub(super) static UNREAPED_WORKER: AtomicBool = AtomicBool::new(false);
const IDENTITY_BYTES: usize = 4 + 4 + (ffi::MAX_TEXT_BYTES + 1) * 4;

#[path = "scsi_worker_context.rs"]
mod context;

/// Parent-side proxy to one child process that exclusively owns USB capture.
pub struct MacScsiWorkerLease {
    child: Option<WorkerProcess>,
    input: Option<WorkerPipe<ChildStdin>>,
    output: Option<WorkerPipe<ChildStdout>>,
    diagnostics: crate::scsi_worker_startup::StartupDiagnostics,
}

impl MacScsiWorkerLease {
    /// Starts the current privileged executable in its fixed internal worker mode.
    ///
    /// # Errors
    ///
    /// Returns a sanitized spawn, identity, initialization, or native-open failure.
    pub fn spawn(identity: &MacRematchIdentity) -> Result<Self, NativeError> {
        use crate::scsi_worker_startup as diagnostic;
        diagnostic::reset();
        if UNREAPED_WORKER.load(Ordering::Acquire) {
            diagnostic::parent_failure("process-spawn", NativeError::Busy);
            return Err(NativeError::Busy);
        }
        let executable = std::env::current_exe().map_err(|error| {
            diagnostic::os_failure("process-current-exe", &error);
            NativeError::TransportUnavailable
        })?;
        let child = Command::new(executable)
            .arg("--openrdx-internal-macos-scsi-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                diagnostic::os_failure("process-spawn", &error);
                NativeError::TransportUnavailable
            })?;
        Self::initialize_child(child, identity)
    }

    /// Takes only a retained spawned child and initializes its existing bounded protocol.
    fn initialize_child(child: Child, identity: &MacRematchIdentity) -> Result<Self, NativeError> {
        Self::initialize_child_with(child, identity, |worker| {
            worker.diagnostics.nonblocking()?;
            crate::scsi_worker_io::nonblocking_io(worker.input.as_ref().expect("owned input"))?;
            crate::scsi_worker_io::nonblocking_io(worker.output.as_ref().expect("owned output"))
        })
    }

    /// Shares production setup ownership with hardware-free failure-injection fixtures.
    fn initialize_child_with(
        mut child: Child,
        identity: &MacRematchIdentity,
        configure: impl FnOnce(&mut Self) -> std::io::Result<()>,
    ) -> Result<Self, NativeError> {
        use crate::scsi_worker_startup as diagnostic;
        let mut worker = Self {
            input: child.stdin.take().map(WorkerPipe::Standard),
            output: child.stdout.take().map(WorkerPipe::Standard),
            diagnostics: diagnostic::StartupDiagnostics::new(child.stderr.take()),
            child: Some(WorkerProcess::Standard(child)),
        };
        if worker.input.is_none() || worker.output.is_none() || !worker.diagnostics.has_pipe() {
            diagnostic::parent_failure("process-pipes", NativeError::TransportUnavailable);
            return Err(NativeError::TransportUnavailable);
        }
        if let Err(error) = configure(&mut worker) {
            diagnostic::os_failure("process-nonblocking", &error);
            return Err(NativeError::TransportUnavailable);
        }
        worker.finish_initialization(identity, Instant::now() + INIT_TIMEOUT)
    }

    /// Keeps existing INIT/READY behavior and the caller's single absolute initialization budget.
    fn finish_initialization(
        mut self,
        identity: &MacRematchIdentity,
        deadline: Instant,
    ) -> Result<Self, NativeError> {
        let identity_payload = encode_identity(identity);
        self.write_frame(FRAME_INIT, &identity_payload, deadline)?;
        let (kind, payload) = self.read_frame(FRAME_READY, deadline)?;
        match kind {
            FRAME_READY if payload.is_empty() => {
                self.diagnostics.success();
                Ok(self)
            }
            FRAME_ERROR => {
                let error = decode_error(&payload).unwrap_or(NativeError::Other);
                self.diagnostics.failure("init-read", error);
                self.terminate_child();
                Err(error)
            }
            _ => {
                self.diagnostics
                    .failure("init-frame", NativeError::InvalidRequest);
                self.terminate_child();
                Err(NativeError::InvalidRequest)
            }
        }
    }

    /// Returns actual USB-parent properties observed by this capture owner.
    ///
    /// # Errors
    ///
    /// Missing USB properties or malformed private replies fail closed. This
    /// request performs no SCSI command. A failed pipe invalidates the lease;
    /// terminating its capture owner can reset the USB device.
    pub fn usb_identity(&mut self) -> Result<MacUsbIdentity, NativeError> {
        let deadline = Instant::now() + IDENTITY_TIMEOUT;
        self.write_frame(FRAME_USB_IDENTITY, &[], deadline)?;
        let (kind, payload) = self.read_frame(FRAME_USB_IDENTITY_RESPONSE, deadline)?;
        let result = match kind {
            FRAME_USB_IDENTITY_RESPONSE => MacUsbIdentity::decode(&payload),
            FRAME_ERROR => Err(decode_error(&payload).unwrap_or(NativeError::InvalidRequest)),
            _ => Err(NativeError::InvalidRequest),
        };
        if result.is_err() {
            self.terminate_child();
        }
        result
    }

    /// Executes one closed semantic operation in the capture-owning child.
    #[must_use]
    pub fn execute(&mut self, operation: ScsiOperation) -> Completion {
        let request = operation.into_request();
        let deadline =
            Instant::now() + Duration::from_millis(u64::from(request.timeout_ms) + 5_000);
        let payload = zeroize::Zeroizing::new(encode_request(request));
        eprintln!("openrdx-hardware: trace scsi-worker-command-write-enter");
        if let Err(error) = self.write_frame(FRAME_COMMAND, &payload, deadline) {
            eprintln!("openrdx-hardware: trace scsi-worker-command-write-error");
            self.terminate_child();
            return Completion::NotAttempted(error);
        }
        eprintln!("openrdx-hardware: trace scsi-worker-command-write-return");
        eprintln!("openrdx-hardware: trace scsi-worker-response-read-enter");
        let response = self.read_frame(FRAME_RESPONSE, deadline);
        let (kind, payload) = match response {
            Ok(response) => {
                eprintln!("openrdx-hardware: trace scsi-worker-response-read-return");
                response
            }
            Err(error) => {
                eprintln!("openrdx-hardware: trace scsi-worker-response-read-error");
                self.terminate_child();
                return Completion::AttemptedError(error);
            }
        };
        if kind != FRAME_RESPONSE {
            self.terminate_child();
            return Completion::AttemptedError(NativeError::InvalidRequest);
        }
        match decode_completion(&payload) {
            Ok(completion) => completion,
            Err(error) => {
                self.terminate_child();
                Completion::AttemptedError(error)
            }
        }
    }

    /// Requests capture surrender and waits only for the disposable child to exit.
    ///
    /// The child acknowledges before destroying capture because macOS may
    /// terminate it during that destruction. The parent therefore never owns
    /// or destroys the terminating `IOUSBHost` object.
    ///
    /// # Errors
    ///
    /// Returns a sanitized protocol, timeout, or child-process failure.
    pub fn release_for_storage_rematch(mut self) -> Result<(), NativeError> {
        let deadline = Instant::now() + RELEASE_TIMEOUT;
        self.write_frame(FRAME_SHUTDOWN, &[], deadline)?;
        self.input = None;
        let acknowledgement = self.read_frame(FRAME_ACK, deadline);
        self.output = None;
        if matches!(acknowledgement, Err(NativeError::TimedOut)) {
            return Err(NativeError::TimedOut);
        }
        let exited = self.wait_for_child_exit(deadline);
        release_outcome(
            acknowledgement,
            exited,
            UNREAPED_WORKER.load(Ordering::Acquire),
        )
    }

    /// Writes one bounded authenticated-by-parenthood private frame.
    fn write_frame(
        &mut self,
        kind: u8,
        payload: &[u8],
        deadline: Instant,
    ) -> Result<(), NativeError> {
        self.write_frame_phase(kind, payload, deadline, "init-write")
    }

    /// Shares exact write/result/cleanup semantics with the pre-admission context frame boundary.
    fn write_frame_phase(
        &mut self,
        kind: u8,
        payload: &[u8],
        deadline: Instant,
        phase: &'static str,
    ) -> Result<(), NativeError> {
        if payload.len() > MAX_FRAME_BYTES {
            return Err(NativeError::ResourceLimit);
        }
        let input = self
            .input
            .as_mut()
            .ok_or(NativeError::TransportUnavailable)?;
        let mut frame = zeroize::Zeroizing::new(vec![0; HEADER_BYTES]);
        frame[..8].copy_from_slice(MAGIC);
        frame[8] = kind;
        frame[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);
        // A child dispatches only after reading the complete frame. A failed
        // nonblocking write has supplied a strict prefix, never a complete command.
        let result = crate::scsi_worker_io::write_all_observed(
            input,
            &frame,
            deadline,
            Some(&mut self.diagnostics),
        )
        .map_err(|(error, _)| error);
        if let Err(error) = &result {
            self.diagnostics.failure(phase, *error);
            self.terminate_child();
        }
        result
    }

    /// Reads one bounded private response frame.
    fn read_frame(
        &mut self,
        expected: u8,
        deadline: Instant,
    ) -> Result<(u8, Vec<u8>), NativeError> {
        self.read_frame_phase(expected, deadline, "init-read", "init-frame")
    }

    /// Shares bounded frame/result/cleanup semantics while retaining the actual refused context phase.
    fn read_frame_phase(
        &mut self,
        expected: u8,
        deadline: Instant,
        read_phase: &'static str,
        frame_phase: &'static str,
    ) -> Result<(u8, Vec<u8>), NativeError> {
        let result = (|| {
            let output = self
                .output
                .as_mut()
                .ok_or(NativeError::TransportUnavailable)?;
            let mut header = [0; HEADER_BYTES];
            crate::scsi_worker_io::read_exact_observed(
                output,
                &mut header,
                deadline,
                Some(&mut self.diagnostics),
            )?;
            if &header[..8] != MAGIC || header[9..12] != [0, 0, 0] {
                return Err(NativeError::InvalidRequest);
            }
            let kind = header[8];
            let length =
                u32::from_le_bytes(header[12..16].try_into().expect("fixed slice")) as usize;
            if !response_length_allowed(expected, kind, length) {
                return Err(NativeError::InvalidRequest);
            }
            let mut payload = vec![0; length];
            crate::scsi_worker_io::read_exact_observed(
                output,
                &mut payload,
                deadline,
                Some(&mut self.diagnostics),
            )?;
            Ok((kind, payload))
        })();
        if let Err(error) = &result {
            self.diagnostics.failure(
                if *error == NativeError::InvalidRequest {
                    frame_phase
                } else {
                    read_phase
                },
                *error,
            );
            self.terminate_child();
        }
        result
    }

    /// Waits for the capture-owning child without blocking the service indefinitely.
    fn wait_for_child_exit(&mut self, deadline: Instant) -> Result<(), NativeError> {
        let Some(child) = self.child.as_mut() else {
            return Ok(());
        };
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    self.child = None;
                    return Ok(());
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(RELEASE_POLL_INTERVAL),
                Ok(None) => {
                    self.terminate_child();
                    return Err(NativeError::TimedOut);
                }
                Err(_) => {
                    self.terminate_child();
                    return Err(NativeError::TransportUnavailable);
                }
            }
        }
    }

    /// Terminates and reaps only this exact spawned child after a failed boundary.
    fn terminate_child(&mut self) {
        self.diagnostics.drain();
        self.diagnostics.close();
        self.input = None;
        self.output = None;
        if let Some(mut child) = self.child.take() {
            let deadline = Instant::now() + REAP_TIMEOUT;
            let _ = child.kill(deadline);
            loop {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return;
                }
                if Instant::now() >= deadline {
                    // SIGKILL may remain pending during a kernel startup stall.
                    // Never wait indefinitely or start another capture owner in
                    // this process while this child's destruction is unproven.
                    UNREAPED_WORKER.store(true, Ordering::Release);
                    child.abandon();
                    return;
                }
                thread::sleep(RELEASE_POLL_INTERVAL);
            }
        }
    }
}

impl Drop for MacScsiWorkerLease {
    /// Requests child termination with bounded reaping; capture release may reset USB.
    fn drop(&mut self) {
        self.terminate_child();
    }
}

/// Combines the private reply with independently proven capture-owner termination.
fn release_outcome(
    acknowledgement: Result<(u8, Vec<u8>), NativeError>,
    exited: Result<(), NativeError>,
    unreaped_worker: bool,
) -> Result<(), NativeError> {
    if unreaped_worker {
        return Err(NativeError::TimedOut);
    }
    match (acknowledgement, exited) {
        (Ok((FRAME_ACK, payload)), Ok(())) if payload.is_empty() => Ok(()),
        (Err(_), Ok(())) => Ok(()),
        (_, Err(error)) => Err(error),
        _ => Err(NativeError::InvalidRequest),
    }
}

/// Rejects unexpected response kinds and impossible lengths before allocating or waiting.
fn response_length_allowed(expected: u8, kind: u8, length: usize) -> bool {
    if kind == FRAME_ERROR {
        return expected != FRAME_RESPONSE && length == 1;
    }
    if kind != expected {
        return false;
    }
    match kind {
        FRAME_READY | FRAME_ACK => length == 0,
        context::FRAME_CONTEXT_PROOF => length == crate::worker_context::CONTEXT_BYTES,
        FRAME_USB_IDENTITY_RESPONSE => (9..=8 + ffi::MAX_TEXT_BYTES).contains(&length),
        FRAME_RESPONSE => {
            length == 2
                || (20..=20 + ffi::MAX_TRANSFER_BYTES + ffi::MAX_SENSE_BYTES).contains(&length)
        }
        _ => false,
    }
}

impl Debug for MacScsiWorkerLease {
    /// Redacts process, pipe, and device identity details.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MacScsiWorkerLease(<private>)")
    }
}

/// Runs the fixed internal worker protocol on already selected standard streams.
///
/// # Errors
///
/// Returns a sanitized framing, identity, device-open, or transport failure.
pub fn run_scsi_worker<R: Read, W: Write>(input: R, output: W) -> Result<(), NativeError> {
    run_worker(input, output, false)
}

/// Runs only the fixed internal stdio role with bounded private context preflight before IOKit.
/// # Errors
/// Refuses malformed context, lost credentials, expired handshake or existing native/protocol failure.
pub fn run_scsi_worker_stdio() -> Result<(), NativeError> {
    context::run_stdio()
}

/// Runs only the serial utility's inquiry, log, sector, capability, serial, and reset operations.
///
/// # Errors
/// Rejects every unrelated semantic operation before native dispatch.
pub fn run_serial_scsi_worker<R: Read, W: Write>(input: R, output: W) -> Result<(), NativeError> {
    run_worker(input, output, true)
}

/// Retains exact native authority while enforcing the selected closed worker policy.
fn run_worker<R: Read, W: Write>(
    input: R,
    output: W,
    serial_only: bool,
) -> Result<(), NativeError> {
    run_worker_with_initial(input, output, serial_only, None)
}

/// Shares all original capture/command semantics after an optional already-read INIT frame.
fn run_worker_with_initial<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    serial_only: bool,
    initial: Option<(u8, Vec<u8>)>,
) -> Result<(), NativeError> {
    use crate::scsi_worker_startup::step;
    if !serial_only && initial.is_none() {
        crate::enable_acquisition_diagnostics();
    }
    // Diagnostics precede each existing boundary, never introduce another probe.
    let initialized = (|| {
        let (kind, payload) = match initial {
            Some(frame) => frame,
            None => step("init-read", !serial_only, || read_frame(&mut input))?,
        };
        step("init-frame", !serial_only, || {
            if kind == FRAME_INIT {
                Ok(())
            } else {
                Err(NativeError::InvalidRequest)
            }
        })?;
        let identity = step("init-decode", !serial_only, || decode_identity(&payload))?;
        let candidates = step("rematch-enumerate", !serial_only, enumerate_candidates)?;
        let candidate = step("rematch-select", !serial_only, || {
            identity.select_unique(&candidates)
        })?;
        let mut authority = step("registry-open", !serial_only, || MacDevice::open(candidate))?;
        {
            let mapping = step("media-map", !serial_only, || authority.pin_media())?;
            if mapping.mounted_media_count() != 0 {
                // Preserve the original Busy reply before the retained mapping/device drop.
                write_frame(&mut output, FRAME_ERROR, &encode_error(NativeError::Busy))?;
                return Err(NativeError::Busy);
            }
        }
        // Bind topology before capture removes the mass-storage registry service.
        // SCSI-only devices remain supported, but migration requires these fields.
        let usb_identity = step("usb-identity", !serial_only, || authority.usb_identity());
        if serial_only
            && !usb_identity
                .as_ref()
                .is_ok_and(crate::serial_contract::usb_identity_is_valid)
        {
            return Err(NativeError::EvidenceIncomplete);
        }
        let scsi = step("acquire", !serial_only, || authority.acquire_scsi())?;
        Ok((authority, scsi, usb_identity))
    })();
    // Preserve all previously silent early failures and the public EOF error result.
    let (authority, mut scsi, usb_identity) = initialized?;
    step("ready-write", !serial_only, || {
        write_frame(&mut output, FRAME_READY, &[])
    })?;
    loop {
        let (kind, payload) = read_frame(&mut input)?;
        let payload = zeroize::Zeroizing::new(payload);
        match kind {
            FRAME_USB_IDENTITY if payload.is_empty() => match &usb_identity {
                Ok(identity) => {
                    write_frame(&mut output, FRAME_USB_IDENTITY_RESPONSE, &identity.encode())?
                }
                Err(error) => write_frame(&mut output, FRAME_ERROR, &encode_error(*error))?,
            },
            FRAME_COMMAND => {
                let request = decode_request(&payload)?;
                if !operation_allowed(serial_only, request.operation) {
                    return Err(NativeError::InvalidRequest);
                }
                eprintln!("openrdx-hardware: trace scsi-worker-native-enter");
                let completion = scsi.execute_request(request);
                eprintln!("openrdx-hardware: trace scsi-worker-native-return");
                eprintln!("openrdx-hardware: trace scsi-worker-response-write-enter");
                if write_frame(&mut output, FRAME_RESPONSE, &encode_completion(&completion))
                    .is_err()
                {
                    eprintln!("openrdx-hardware: trace scsi-worker-response-write-error");
                    return Err(NativeError::TransportUnavailable);
                }
                eprintln!("openrdx-hardware: trace scsi-worker-response-write-return");
            }
            FRAME_SHUTDOWN if payload.is_empty() => {
                write_frame(&mut output, FRAME_ACK, &[])?;
                drop(scsi);
                drop(authority);
                return Ok(());
            }
            _ => return Err(NativeError::InvalidRequest),
        }
    }
}

/// Keeps manufacturing restore outside the separately admitted serial utility lane.
fn operation_allowed(serial_only: bool, operation: u32) -> bool {
    !serial_only || matches!(operation, 4 | 5 | 6 | 7 | 29..=32)
}

/// Writes one magic/versioned bounded frame and flushes it before returning.
fn write_frame<W: Write>(output: &mut W, kind: u8, payload: &[u8]) -> Result<(), NativeError> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(NativeError::ResourceLimit);
    }
    let mut header = [0_u8; HEADER_BYTES];
    header[..8].copy_from_slice(MAGIC);
    header[8] = kind;
    header[12..16].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    output
        .write_all(&header)
        .and_then(|()| output.write_all(payload))
        .and_then(|()| output.flush())
        .map_err(|_| NativeError::TransportUnavailable)
}

/// Reads and validates one complete bounded frame.
fn read_frame<R: Read>(input: &mut R) -> Result<(u8, Vec<u8>), NativeError> {
    let mut header = [0_u8; HEADER_BYTES];
    input
        .read_exact(&mut header)
        .map_err(|_| NativeError::TransportUnavailable)?;
    if &header[..8] != MAGIC || header[9..12] != [0, 0, 0] {
        return Err(NativeError::InvalidRequest);
    }
    let length = u32::from_le_bytes(header[12..16].try_into().expect("fixed slice")) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(NativeError::ResourceLimit);
    }
    let mut payload = vec![0_u8; length];
    input
        .read_exact(&mut payload)
        .map_err(|_| NativeError::TransportUnavailable)?;
    Ok((header[8], payload))
}

/// Encodes stable identity fields without transient registry IDs or struct padding.
fn encode_identity(identity: &MacRematchIdentity) -> Vec<u8> {
    let record = &identity.record;
    let mut payload = Vec::with_capacity(IDENTITY_BYTES);
    payload.extend_from_slice(&record.peripheral_type.to_le_bytes());
    payload.extend_from_slice(&[
        record.has_vendor,
        record.has_product,
        record.has_revision,
        record.has_serial,
    ]);
    payload.extend_from_slice(&record.vendor);
    payload.extend_from_slice(&record.product);
    payload.extend_from_slice(&record.revision);
    payload.extend_from_slice(&record.serial);
    payload
}

/// Decodes and validates one stable identity with no native pointer material.
fn decode_identity(payload: &[u8]) -> Result<MacRematchIdentity, NativeError> {
    if payload.len() != IDENTITY_BYTES {
        return Err(NativeError::InvalidRequest);
    }
    let mut record = ffi::CandidateRecord {
        peripheral_type: u32::from_le_bytes(payload[..4].try_into().expect("fixed slice")),
        has_vendor: payload[4],
        has_product: payload[5],
        has_revision: payload[6],
        has_serial: payload[7],
        ..ffi::CandidateRecord::default()
    };
    let field_bytes = ffi::MAX_TEXT_BYTES + 1;
    record.vendor.copy_from_slice(&payload[8..8 + field_bytes]);
    record
        .product
        .copy_from_slice(&payload[8 + field_bytes..8 + field_bytes * 2]);
    record
        .revision
        .copy_from_slice(&payload[8 + field_bytes * 2..8 + field_bytes * 3]);
    record
        .serial
        .copy_from_slice(&payload[8 + field_bytes * 3..8 + field_bytes * 4]);
    if record.has_serial != 1 || !rematch_identity_record_is_valid(&record) {
        return Err(NativeError::InvalidRequest);
    }
    Ok(MacRematchIdentity { record })
}

/// Validates stable identity material while intentionally omitting registry generation.
fn rematch_identity_record_is_valid(record: &ffi::CandidateRecord) -> bool {
    record.peripheral_type == 0
        && flags_are_valid(&[
            record.has_vendor,
            record.has_product,
            record.has_revision,
            record.has_serial,
        ])
        && record_text_is_valid(record.has_vendor, &record.vendor)
        && record_text_is_valid(record.has_product, &record.product)
        && record_text_is_valid(record.has_revision, &record.revision)
        && record_text_is_valid(record.has_serial, &record.serial)
}

/// Encodes one already validated fixed request without ABI padding.
fn encode_request(request: ffi::ScsiRequest) -> Vec<u8> {
    let data_length = request.data_length as usize;
    let mut payload = Vec::with_capacity(17 + data_length);
    payload.extend_from_slice(&request.operation.to_le_bytes());
    payload.extend_from_slice(&request.timeout_ms.to_le_bytes());
    payload.extend_from_slice(&request.data_length.to_le_bytes());
    payload.extend_from_slice(&request.offset.to_le_bytes());
    payload.push(request.save_pages);
    payload.extend_from_slice(&request.data[..data_length]);
    payload
}

/// Decodes a bounded request and restores only its fixed zeroed ABI layout.
fn decode_request(payload: &[u8]) -> Result<ffi::ScsiRequest, NativeError> {
    if payload.len() < 17 {
        return Err(NativeError::InvalidRequest);
    }
    let operation = u32::from_le_bytes(payload[0..4].try_into().expect("fixed slice"));
    let timeout_ms = u32::from_le_bytes(payload[4..8].try_into().expect("fixed slice"));
    let data_length = u32::from_le_bytes(payload[8..12].try_into().expect("fixed slice"));
    let offset = u32::from_le_bytes(payload[12..16].try_into().expect("fixed slice"));
    let save_pages = payload[16];
    let length = data_length as usize;
    if !(1..=34).contains(&operation)
        || !(1..=300_000).contains(&timeout_ms)
        || length > ffi::MAX_TRANSFER_BYTES
        || payload.len() != 17 + length
        || save_pages > 1
        || (matches!(operation, 22 | 23 | 25..=28 | 30 | 32 | 33)
            && (length != 0 || offset != 0 || save_pages != 0))
        || (operation == 29 && (offset >= 32 || length != 0 || save_pages != 0))
        || (operation == 31
            && (offset != 0
                || save_pages != 0
                || !crate::serial_contract::payload_is_valid(&payload[17..])))
        || (operation == 34
            && (offset != 0
                || save_pages != 0
                || !crate::manufacturing_contract::payload_is_valid(&payload[17..])))
        || (operation == 24
            && (offset != 0
                || save_pages != 0
                || !crate::scsi::compatibility_authorization_is_valid(&payload[17..])))
    {
        return Err(NativeError::InvalidRequest);
    }
    let mut request = ffi::ScsiRequest {
        operation,
        timeout_ms,
        data_length,
        offset,
        save_pages,
        ..ffi::ScsiRequest::default()
    };
    request.data[..length].copy_from_slice(&payload[17..]);
    Ok(request)
}

/// Encodes one pointer-free completion with explicit lengths.
fn encode_completion(completion: &Completion) -> Vec<u8> {
    match completion {
        Completion::NotAttempted(error) => vec![0, encode_error_byte(*error)],
        Completion::AttemptedError(error) => vec![1, encode_error_byte(*error)],
        Completion::Device {
            scsi_status,
            service_response,
            transferred_length,
            data,
            sense_reported_length,
            sense,
        } => {
            let mut payload = Vec::with_capacity(18 + data.len() + sense.len());
            payload.extend_from_slice(&[2, *scsi_status, *service_response, 0]);
            payload.extend_from_slice(&transferred_length.to_le_bytes());
            payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
            payload.extend_from_slice(&(*sense_reported_length as u32).to_le_bytes());
            payload.extend_from_slice(&(sense.len() as u32).to_le_bytes());
            payload.extend_from_slice(data);
            payload.extend_from_slice(sense);
            payload
        }
    }
}

/// Decodes one bounded pointer-free completion.
fn decode_completion(payload: &[u8]) -> Result<Completion, NativeError> {
    match payload.first().copied() {
        Some(0) if payload.len() == 2 => {
            Ok(Completion::NotAttempted(decode_error_byte(payload[1])?))
        }
        Some(1) if payload.len() == 2 => {
            Ok(Completion::AttemptedError(decode_error_byte(payload[1])?))
        }
        Some(2) if payload.len() >= 20 && payload[3] == 0 => {
            let transferred_length =
                u32::from_le_bytes(payload[4..8].try_into().expect("fixed slice"));
            let data_length =
                u32::from_le_bytes(payload[8..12].try_into().expect("fixed slice")) as usize;
            let sense_reported_length =
                u32::from_le_bytes(payload[12..16].try_into().expect("fixed slice")) as usize;
            let sense_length =
                u32::from_le_bytes(payload[16..20].try_into().expect("fixed slice")) as usize;
            if data_length > ffi::MAX_TRANSFER_BYTES
                || sense_length > ffi::MAX_SENSE_BYTES
                || payload.len() != 20 + data_length + sense_length
            {
                return Err(NativeError::InvalidRequest);
            }
            Ok(Completion::Device {
                scsi_status: payload[1],
                service_response: payload[2],
                transferred_length,
                data: payload[20..20 + data_length].to_vec(),
                sense_reported_length,
                sense: payload[20 + data_length..].to_vec(),
            })
        }
        _ => Err(NativeError::InvalidRequest),
    }
}

/// Encodes one sanitized error as a single closed discriminant.
fn encode_error(error: NativeError) -> Vec<u8> {
    vec![encode_error_byte(error)]
}

/// Decodes a one-byte sanitized error payload.
fn decode_error(payload: &[u8]) -> Result<NativeError, NativeError> {
    if payload.len() != 1 {
        return Err(NativeError::InvalidRequest);
    }
    decode_error_byte(payload[0])
}

/// Maps one sanitized error into the private protocol's closed range.
const fn encode_error_byte(error: NativeError) -> u8 {
    match error {
        NativeError::UnsupportedPlatform => 0,
        NativeError::InvalidRequest => 1,
        NativeError::TransportUnavailable => 2,
        NativeError::AccessDenied => 3,
        NativeError::Busy => 4,
        NativeError::TimedOut => 5,
        NativeError::DeviceRemoved => 6,
        NativeError::EnumerationFailed => 7,
        NativeError::ResourceLimit => 8,
        NativeError::EvidenceIncomplete => 9,
        NativeError::Other => 10,
    }
}

/// Maps one private protocol discriminant into a sanitized error.
const fn decode_error_byte(value: u8) -> Result<NativeError, NativeError> {
    match value {
        0 => Ok(NativeError::UnsupportedPlatform),
        1 => Ok(NativeError::InvalidRequest),
        2 => Ok(NativeError::TransportUnavailable),
        3 => Ok(NativeError::AccessDenied),
        4 => Ok(NativeError::Busy),
        5 => Ok(NativeError::TimedOut),
        6 => Ok(NativeError::DeviceRemoved),
        7 => Ok(NativeError::EnumerationFailed),
        8 => Ok(NativeError::ResourceLimit),
        9 => Ok(NativeError::EvidenceIncomplete),
        10 => Ok(NativeError::Other),
        _ => Err(NativeError::InvalidRequest),
    }
}

#[cfg(test)]
#[path = "scsi_worker_tests.rs"]
mod tests;
