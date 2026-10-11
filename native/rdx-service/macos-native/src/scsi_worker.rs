// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Disposable macOS USB-capture worker and bounded private protocol.
//!
//! `IOUSBHostObjectInitOptionsDeviceCapture` terminates its caller when capture
//! is surrendered. Keeping that capture in this child process lets the
//! long-lived hardware service survive the required storage-driver rematch.

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
const INIT_TIMEOUT: Duration = Duration::from_secs(15);
const IDENTITY_TIMEOUT: Duration = Duration::from_secs(5);
const REAP_TIMEOUT: Duration = Duration::from_millis(500);
static UNREAPED_WORKER: AtomicBool = AtomicBool::new(false);
const IDENTITY_BYTES: usize = 4 + 4 + (ffi::MAX_TEXT_BYTES + 1) * 4;

/// Parent-side proxy to one child process that exclusively owns USB capture.
pub struct MacScsiWorkerLease {
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
}

impl MacScsiWorkerLease {
    /// Starts the current privileged executable in its fixed internal worker mode.
    ///
    /// # Errors
    ///
    /// Returns a sanitized spawn, identity, initialization, or native-open failure.
    pub fn spawn(identity: &MacRematchIdentity) -> Result<Self, NativeError> {
        if UNREAPED_WORKER.load(Ordering::Acquire) {
            return Err(NativeError::Busy);
        }
        let executable = std::env::current_exe().map_err(|_| NativeError::TransportUnavailable)?;
        let mut child = Command::new(executable)
            .arg("--openrdx-internal-macos-scsi-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| NativeError::TransportUnavailable)?;
        let input = child
            .stdin
            .take()
            .ok_or(NativeError::TransportUnavailable)?;
        let output = child
            .stdout
            .take()
            .ok_or(NativeError::TransportUnavailable)?;
        let mut worker = Self {
            child: Some(child),
            input: Some(input),
            output: Some(output),
        };
        crate::scsi_worker_io::nonblocking(worker.input.as_ref().expect("owned input"))?;
        crate::scsi_worker_io::nonblocking(worker.output.as_ref().expect("owned output"))?;
        let deadline = Instant::now() + INIT_TIMEOUT;
        let identity_payload = encode_identity(identity);
        worker.write_frame(FRAME_INIT, &identity_payload, deadline)?;
        let (kind, payload) = worker.read_frame(FRAME_READY, deadline)?;
        match kind {
            FRAME_READY if payload.is_empty() => Ok(worker),
            FRAME_ERROR => {
                let error = decode_error(&payload).unwrap_or(NativeError::Other);
                worker.terminate_child();
                Err(error)
            }
            _ => {
                worker.terminate_child();
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
        let result =
            crate::scsi_worker_io::write_all(input, &frame, deadline).map_err(|(error, _)| error);
        if result.is_err() {
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
        let result = (|| {
            let output = self
                .output
                .as_mut()
                .ok_or(NativeError::TransportUnavailable)?;
            let mut header = [0; HEADER_BYTES];
            crate::scsi_worker_io::read_exact(output, &mut header, deadline)?;
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
            crate::scsi_worker_io::read_exact(output, &mut payload, deadline)?;
            Ok((kind, payload))
        })();
        if result.is_err() {
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
        self.input = None;
        self.output = None;
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let deadline = Instant::now() + REAP_TIMEOUT;
            loop {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return;
                }
                if Instant::now() >= deadline {
                    // SIGKILL may remain pending during a kernel startup stall.
                    // Never wait indefinitely or start another capture owner in
                    // this process while this child's destruction is unproven.
                    UNREAPED_WORKER.store(true, Ordering::Release);
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

/// Runs only the serial utility's inquiry, log, sector, capability, serial, and reset operations.
///
/// # Errors
/// Rejects every unrelated semantic operation before native dispatch.
pub fn run_serial_scsi_worker<R: Read, W: Write>(input: R, output: W) -> Result<(), NativeError> {
    run_worker(input, output, true)
}

/// Retains exact native authority while enforcing the selected closed worker policy.
fn run_worker<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    serial_only: bool,
) -> Result<(), NativeError> {
    let (kind, payload) = read_frame(&mut input)?;
    if kind != FRAME_INIT {
        return Err(NativeError::InvalidRequest);
    }
    let identity = decode_identity(&payload)?;
    let candidates = enumerate_candidates()?;
    let candidate = identity.select_unique(&candidates)?;
    let mut authority = MacDevice::open(candidate)?;
    {
        let mapping = authority.pin_media()?;
        if mapping.mounted_media_count() != 0 {
            write_frame(&mut output, FRAME_ERROR, &encode_error(NativeError::Busy))?;
            return Err(NativeError::Busy);
        }
    }
    // Bind topology before capture removes the mass-storage registry service.
    // SCSI-only devices remain supported, but migration requires these fields.
    let usb_identity = authority.usb_identity();
    if serial_only
        && !usb_identity
            .as_ref()
            .is_ok_and(crate::serial_contract::usb_identity_is_valid)
    {
        return Err(NativeError::EvidenceIncomplete);
    }
    let mut scsi = authority.acquire_scsi()?;
    write_frame(&mut output, FRAME_READY, &[])?;
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
mod tests {
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
}
