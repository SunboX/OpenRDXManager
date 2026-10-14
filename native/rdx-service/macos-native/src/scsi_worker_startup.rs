// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded diagnostic evidence on the already-owned child pipe; never authority.

use crate::NativeError;
use std::cell::Cell;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::process::ChildStderr;

const MAX_LINE: usize = 255;
const MAX_PARSED_BYTES: usize = 8_192;
const MAX_PARSED_LINES: usize = 64;
const MAX_DRAIN: usize = 4_096;
const WORKER_STAGES: &[&str] = &[
    "process-current-exe",
    "process-spawn",
    "process-pipes",
    "process-nonblocking",
    "init-write",
    "init-read",
    "init-frame",
    "init-decode",
    "rematch-enumerate",
    "rematch-select",
    "registry-open",
    "media-map",
    "usb-identity",
    "acquire",
    "ready-write",
];
const NATIVE_STAGES: &[&str] = &[
    "legacy-create-plugin",
    "legacy-query-interface",
    "legacy-obtain-exclusive",
    "usb-check-authority",
    "usb-find-ancestor",
    "usb-validate-identity",
    "usb-capture-device",
    "usb-configure-device",
    "usb-find-bot-interface",
    "usb-open-interface",
    "usb-pipe-descriptors",
    "usb-pipe-endpoints",
    "usb-open-bulk-in",
    "usb-open-bulk-out",
    "usb-allocate-lease",
    "usb-acquire-exception",
];

/// A diagnostic-only failure from the current thread's latest worker startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerStartupFailure {
    stage: &'static str,
    bucket: Bucket,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Bucket {
    Invalid,
    Unavailable,
    Denied,
    Busy,
    Timeout,
    Removed,
    Enumeration,
    Resource,
    Evidence,
    BadFd,
    Missing,
    Other,
}

impl WorkerStartupFailure {
    /// Returns a compiled path-free phase/error code; never native numeric codes or text.
    #[must_use]
    pub const fn code(self) -> &'static str {
        macro_rules! code {
            ($phase:literal) => {
                match self.bucket {
                    Bucket::Invalid => concat!("candidate-worker-", $phase, "-invalid"),
                    Bucket::Unavailable => {
                        concat!("candidate-worker-", $phase, "-transport-unavailable")
                    }
                    Bucket::Denied => concat!("candidate-worker-", $phase, "-access-denied"),
                    Bucket::Busy => concat!("candidate-worker-", $phase, "-busy"),
                    Bucket::Timeout => concat!("candidate-worker-", $phase, "-timed-out"),
                    Bucket::Removed => concat!("candidate-worker-", $phase, "-device-removed"),
                    Bucket::Enumeration => {
                        concat!("candidate-worker-", $phase, "-enumeration-failed")
                    }
                    Bucket::Resource => concat!("candidate-worker-", $phase, "-resource-limit"),
                    Bucket::Evidence => {
                        concat!("candidate-worker-", $phase, "-evidence-incomplete")
                    }
                    Bucket::BadFd => concat!("candidate-worker-", $phase, "-bad-fd"),
                    Bucket::Missing => concat!("candidate-worker-", $phase, "-missing-executable"),
                    Bucket::Other => concat!("candidate-worker-", $phase, "-other"),
                }
            };
        }
        match self.stage.as_bytes() {
            b"process-current-exe" => code!("process-current-exe"),
            b"process-spawn" => code!("process-spawn"),
            b"process-pipes" => code!("process-pipes"),
            b"process-nonblocking" => code!("process-nonblocking"),
            b"init-write" => code!("init-write"),
            b"init-read" => code!("init-read"),
            b"init-frame" => code!("init-frame"),
            b"init-decode" => code!("init-decode"),
            b"rematch-enumerate" => code!("rematch-enumerate"),
            b"rematch-select" => code!("rematch-select"),
            b"registry-open" => code!("registry-open"),
            b"media-map" => code!("media-map"),
            b"usb-identity" => code!("usb-identity"),
            b"acquire" => code!("acquire"),
            b"ready-write" => code!("ready-write"),
            b"legacy-create-plugin" => code!("legacy-create-plugin"),
            b"legacy-query-interface" => code!("legacy-query-interface"),
            b"legacy-obtain-exclusive" => code!("legacy-obtain-exclusive"),
            b"usb-check-authority" => code!("usb-check-authority"),
            b"usb-find-ancestor" => code!("usb-find-ancestor"),
            b"usb-validate-identity" => code!("usb-validate-identity"),
            b"usb-capture-device" => code!("usb-capture-device"),
            b"usb-configure-device" => code!("usb-configure-device"),
            b"usb-find-bot-interface" => code!("usb-find-bot-interface"),
            b"usb-open-interface" => code!("usb-open-interface"),
            b"usb-pipe-descriptors" => code!("usb-pipe-descriptors"),
            b"usb-pipe-endpoints" => code!("usb-pipe-endpoints"),
            b"usb-open-bulk-in" => code!("usb-open-bulk-in"),
            b"usb-open-bulk-out" => code!("usb-open-bulk-out"),
            b"usb-allocate-lease" => code!("usb-allocate-lease"),
            b"usb-acquire-exception" => code!("usb-acquire-exception"),
            _ => "candidate-worker-acquisition-failed",
        }
    }
}

thread_local! {
    static LAST_FAILURE: Cell<Option<WorkerStartupFailure>> = const { Cell::new(None) };
}

/// Takes diagnostic-only evidence; resets it and performs no OS/device work.
#[must_use]
pub fn take_last_worker_startup_failure() -> Option<WorkerStartupFailure> {
    LAST_FAILURE.with(|value| value.take())
}

/// Clears stale failure evidence before any new spawn attempt.
pub(super) fn reset() {
    LAST_FAILURE.with(|value| value.set(None));
}

/// Records only the supplied closed parent phase and sanitized failure.
pub(super) fn parent_failure(stage: &'static str, error: NativeError) {
    publish(WorkerStartupFailure {
        stage,
        bucket: bucket(error),
    });
}

/// Classifies a parent spawn/setup errno without returning arbitrary OS text or codes.
pub(super) fn os_failure(stage: &'static str, error: &std::io::Error) {
    let bucket = match error.raw_os_error() {
        Some(libc::EBADF) => Bucket::BadFd,
        Some(libc::ENOENT) => Bucket::Missing,
        Some(libc::EACCES | libc::EPERM) => Bucket::Denied,
        Some(libc::EMFILE | libc::ENFILE) => Bucket::Resource,
        _ => Bucket::Other,
    };
    publish(WorkerStartupFailure { stage, bucket });
}

/// Publishes only a completed failure, never a speculative acquisition breadcrumb.
fn publish(failure: WorkerStartupFailure) {
    LAST_FAILURE.with(|value| value.set(Some(failure)));
}

/// Maps the existing sanitized result without changing its returned semantics.
fn bucket(error: NativeError) -> Bucket {
    match error {
        NativeError::InvalidRequest => Bucket::Invalid,
        NativeError::TransportUnavailable => Bucket::Unavailable,
        NativeError::AccessDenied => Bucket::Denied,
        NativeError::Busy => Bucket::Busy,
        NativeError::TimedOut => Bucket::Timeout,
        NativeError::DeviceRemoved => Bucket::Removed,
        NativeError::EnumerationFailed => Bucket::Enumeration,
        NativeError::ResourceLimit => Bucket::Resource,
        NativeError::EvidenceIncomplete => Bucket::Evidence,
        _ => Bucket::Other,
    }
}

/// Emits a fixed phase before dispatch and its sanitized result before Rust cleanup.
pub(super) fn step<T>(
    stage: &'static str,
    enabled: bool,
    operation: impl FnOnce() -> Result<T, NativeError>,
) -> Result<T, NativeError> {
    if enabled {
        progress(stage, 0);
    }
    let result = operation();
    if enabled {
        if let Err(error) = &result {
            progress(stage, error_status(*error));
        }
    }
    result
}

/// Writes only a compiled worker phase and closed numeric status to private stderr.
fn progress(stage: &'static str, status: u8) {
    debug_assert!(WORKER_STAGES.contains(&stage));
    eprintln!("{{\"diagnostic\":\"worker-startup\",\"stage\":\"{stage}\",\"status\":{status}}}");
}

/// Encodes success separately from every existing NativeError for private diagnostics.
fn error_status(error: NativeError) -> u8 {
    match error {
        NativeError::UnsupportedPlatform => 11,
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

#[derive(Clone, Copy, Debug)]
struct NativeDiagnostic {
    failure: WorkerStartupFailure,
    // Kept private for evidence only. These never select policy, operations or wire values.
    _code_kind: u8,
    _native_code: i64,
}

/// Owns a bounded stderr parser and continuously drains its pipe without background threads.
#[derive(Default)]
pub(super) struct StartupDiagnostics {
    pipe: Option<ChildStderr>,
    pipe_nonblocking: bool,
    line: Vec<u8>,
    dropping_line: bool,
    bytes: usize,
    lines: usize,
    observing: bool,
    active: bool,
    phase: Option<(&'static str, Option<NativeError>)>,
    native: Option<NativeDiagnostic>,
}

impl StartupDiagnostics {
    /// Takes only the stderr descriptor from this exact already-spawned child.
    pub(super) fn new(pipe: Option<ChildStderr>) -> Self {
        Self {
            pipe,
            observing: true,
            active: true,
            ..Self::default()
        }
    }

    /// Checks ownership before setup without ever reading a possibly blocking pipe.
    pub(super) fn has_pipe(&self) -> bool {
        self.pipe.is_some()
    }

    /// Borrows only a proven nonblocking descriptor; EOF removes it from poll.
    pub(super) fn fd(&self) -> Option<i32> {
        if self.pipe_nonblocking {
            self.pipe.as_ref().map(AsRawFd::as_raw_fd)
        } else {
            None
        }
    }

    /// Sets nonblocking on the retained pipe and captures errno before any other call.
    pub(super) fn nonblocking(&mut self) -> std::io::Result<()> {
        if let Some(pipe) = &self.pipe {
            crate::scsi_worker_io::nonblocking_io(pipe)?;
        }
        self.pipe_nonblocking = true;
        Ok(())
    }

    /// Drops the held diagnostic descriptor during the existing child termination boundary.
    pub(super) fn close(&mut self) {
        self.pipe = None;
    }

    /// Drains at most 4KiB per wakeup; byte/line caps stop parsing, never draining.
    pub(super) fn drain(&mut self) {
        // Failed setup/drop must never read a pipe whose fcntl proof did not succeed.
        if !self.pipe_nonblocking {
            return;
        }
        let mut left = MAX_DRAIN;
        let mut buffer = [0; 512];
        while left > 0 {
            let Some(pipe) = self.pipe.as_mut() else {
                break;
            };
            match pipe.read(&mut buffer[..left.min(512)]) {
                Ok(0) => {
                    self.pipe = None;
                    break;
                }
                Ok(count) => {
                    left -= count;
                    self.consume(&buffer[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.pipe = None;
                    break;
                }
            }
        }
    }

    /// Consumes bounded lines; malformed/unbounded text is discarded without publication.
    fn consume(&mut self, bytes: &[u8]) {
        if !self.observing {
            return;
        }
        for &byte in bytes {
            self.bytes += 1;
            if self.bytes > MAX_PARSED_BYTES || self.lines >= MAX_PARSED_LINES {
                self.observing = false;
                self.line.clear();
                return;
            }
            if byte == b'\n' {
                self.lines += 1;
                if !self.dropping_line {
                    if let Ok(line) = std::str::from_utf8(&self.line) {
                        if let Some(record) = parse_native(line) {
                            self.native = Some(record);
                        } else if let Some((stage, status)) = parse_progress(line) {
                            // New worker progress invalidates every historical native failure.
                            if status.is_none()
                                || self.phase.is_some_and(|(previous, _)| previous != stage)
                            {
                                self.native = None;
                            }
                            self.phase = Some((stage, status));
                        }
                    }
                }
                self.line.clear();
                self.dropping_line = false;
            } else if self.line.len() < MAX_LINE && !self.dropping_line {
                self.line.push(byte);
            } else {
                self.line.clear();
                self.dropping_line = true;
            }
        }
    }

    /// Publishes final failure evidence without mistaking legacy fallback for terminal failure.
    pub(super) fn failure(&mut self, parent_phase: &'static str, error: NativeError) {
        if !self.active {
            return;
        }
        self.drain();
        let fallback = WorkerStartupFailure {
            stage: parent_phase,
            bucket: bucket(error),
        };
        let phase = self
            .phase
            .map_or(fallback, |(stage, status)| WorkerStartupFailure {
                stage,
                bucket: bucket(status.unwrap_or(error)),
            });
        if parent_phase == "init-write" || parent_phase == "init-frame" {
            // Parent framing/write failure is final even when the child emitted earlier progress.
            publish(fallback);
            self.observing = false;
            self.active = false;
            return;
        }
        let native = self.native.filter(|record| {
            // USB records are emitted immediately before failing capture cleanup. Legacy
            // unavailable records may precede successful USB acquisition and are never causal.
            record.failure.stage.starts_with("usb-")
                || (record.failure.bucket != Bucket::Unavailable
                    && record.failure.bucket == phase.bucket)
        });
        publish(native.map_or(phase, |record| record.failure));
        self.observing = false;
        self.active = false;
    }

    /// Successful READY clears all transient failures but keeps draining owned stderr.
    pub(super) fn success(&mut self) {
        self.drain();
        self.observing = false;
        self.active = false;
        self.phase = None;
        self.native = None;
        self.line.clear();
        reset();
    }
}

/// Accepts the exact existing native formatter, never arbitrary JSON properties/text.
fn parse_native(line: &str) -> Option<NativeDiagnostic> {
    let body =
        line.strip_prefix("{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"")?;
    let (stage, body) = body.split_once("\",\"nativeStatus\":")?;
    let stage = *NATIVE_STAGES
        .iter()
        .find(|&&candidate| candidate == stage)?;
    let (status, body) = body.split_once(",\"nativeCodeKind\":\"")?;
    let status = canonical_status(status)?;
    if !(1..=10).contains(&status) {
        return None;
    }
    let (kind, body) = body.split_once("\",\"nativeCode\":")?;
    let kind = match kind {
        "none" => 0,
        "ioreturn" => 1,
        "hresult" => 2,
        "nserror" => 3,
        _ => return None,
    };
    let code = canonical_code(body.strip_suffix('}')?)?;
    if kind == 0 && code != 0 {
        return None;
    }
    Some(NativeDiagnostic {
        failure: WorkerStartupFailure {
            stage,
            bucket: bucket(crate::boundary::status_error(status)),
        },
        _code_kind: kind,
        _native_code: code,
    })
}

/// Accepts only the closed worker progress formatter and its existing error discriminants.
fn parse_progress(line: &str) -> Option<(&'static str, Option<NativeError>)> {
    let body = line.strip_prefix("{\"diagnostic\":\"worker-startup\",\"stage\":\"")?;
    let (stage, body) = body.split_once("\",\"status\":")?;
    let stage = *WORKER_STAGES
        .iter()
        .find(|&&candidate| candidate == stage)?;
    let status = canonical_status(body.strip_suffix('}')?)?;
    match status {
        0 => Some((stage, None)),
        1..=10 => Some((stage, Some(crate::boundary::status_error(status)))),
        11 => Some((stage, Some(NativeError::UnsupportedPlatform))),
        _ => None,
    }
}

/// Requires the formatter's canonical unsigned decimal grammar, without signs or whitespace.
fn canonical_status(text: &str) -> Option<u32> {
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse().ok()
}

/// Requires the formatter's canonical signed decimal grammar and i64 bound.
fn canonical_code(text: &str) -> Option<i64> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
        || text == "-0"
    {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPTURE: &str = "{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"usb-capture-device\",\"nativeStatus\":3,\"nativeCodeKind\":\"nserror\",\"nativeCode\":42}\n";
    const LEGACY: &str = "{\"diagnostic\":\"snapshot-native-acquisition\",\"substage\":\"legacy-create-plugin\",\"nativeStatus\":2,\"nativeCodeKind\":\"ioreturn\",\"nativeCode\":-1}\n";

    /// A parser accepts only the exact private formatter and every field is bounded/closed.
    #[test]
    fn native_formatter_is_strict_and_public_codes_are_private() {
        let record = parse_native(CAPTURE.trim_end()).unwrap();
        assert_eq!(
            record.failure.code(),
            "candidate-worker-usb-capture-device-access-denied"
        );
        assert_eq!(record._native_code, 42);
        for hostile in [
            CAPTURE.replace("usb-capture-device", "/dev/secret"),
            CAPTURE.replace("\"nserror\"", "\"arbitrary\""),
            CAPTURE.replace("\"nativeStatus\":3", "\"nativeStatus\":999"),
            CAPTURE.replace("\"nativeCode\":42", "\"nativeCode\":9223372036854775808"),
            CAPTURE.replace("\"nativeCode\":42", "\"nativeCode\":42,\"text\":\"secret\""),
            CAPTURE.replace("\"nserror\"", "\"none\""),
            CAPTURE.replace("\"nativeStatus\":3", "\"nativeStatus\":0"),
            CAPTURE.replace("\"nativeStatus\":3", "\"nativeStatus\":+3"),
            CAPTURE.replace("\"nativeStatus\":3", "\"nativeStatus\":03"),
            CAPTURE.replace("\"nativeCode\":42", "\"nativeCode\":+42"),
        ] {
            assert!(parse_native(hostile.trim_end()).is_none());
        }
        for &stage in WORKER_STAGES.iter().chain(NATIVE_STAGES) {
            for error in [
                NativeError::Other,
                NativeError::TimedOut,
                NativeError::AccessDenied,
            ] {
                let code = WorkerStartupFailure {
                    stage,
                    bucket: bucket(error),
                }
                .code();
                assert!(
                    code.len() <= 128
                        && code
                            .bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
                );
                assert!(!code.contains("42") && !code.contains('/'));
            }
        }
    }

    /// Only the exact worker stage/error grammar changes diagnostic progress.
    #[test]
    fn unknown_progress_and_unbounded_text_do_not_become_evidence() {
        assert!(
            parse_progress(
                "{\"diagnostic\":\"worker-startup\",\"stage\":\"acquire\",\"status\":3}"
            )
            .is_some()
        );
        for line in [
            "{\"diagnostic\":\"worker-startup\",\"stage\":\"secret\",\"status\":3}",
            "{\"diagnostic\":\"worker-startup\",\"stage\":\"acquire\",\"status\":999}",
            "{\"diagnostic\":\"worker-startup\",\"stage\":\"acquire\",\"status\":3,\"path\":\"secret\"}",
        ] {
            assert!(parse_progress(line).is_none());
        }
        let mut observer = StartupDiagnostics::new(None);
        observer.consume(&vec![b'x'; MAX_LINE + 20]);
        observer.consume(b"\n");
        observer.consume(CAPTURE.as_bytes());
        assert!(observer.native.is_some());
        let mut bounded = StartupDiagnostics::new(None);
        bounded.consume(&vec![b'x'; MAX_PARSED_BYTES + 1]);
        bounded.consume(CAPTURE.as_bytes());
        assert!(bounded.native.is_none() && bounded.line.is_empty());
        let mut bounded = StartupDiagnostics::new(None);
        bounded.consume(&[b'\n'; MAX_PARSED_LINES]);
        bounded.consume(CAPTURE.as_bytes());
        assert!(bounded.native.is_none());
    }

    /// Failure EOF never attributes an intermediate legacy fallback to the terminal cause.
    #[test]
    fn legacy_history_clears_on_success_or_new_phase_and_never_explains_eof() {
        reset();
        let mut observer = StartupDiagnostics::new(None);
        observer
            .consume(b"{\"diagnostic\":\"worker-startup\",\"stage\":\"acquire\",\"status\":0}\n");
        observer.consume(LEGACY.as_bytes());
        observer.failure("init-read", NativeError::TransportUnavailable);
        assert_eq!(
            take_last_worker_startup_failure().unwrap().code(),
            "candidate-worker-acquire-transport-unavailable"
        );
        let mut observer = StartupDiagnostics::new(None);
        observer.consume(CAPTURE.as_bytes());
        observer.consume(
            b"{\"diagnostic\":\"worker-startup\",\"stage\":\"ready-write\",\"status\":0}\n",
        );
        observer.failure("init-read", NativeError::TimedOut);
        assert_eq!(
            take_last_worker_startup_failure().unwrap().code(),
            "candidate-worker-ready-write-timed-out"
        );
        let mut observer = StartupDiagnostics::new(None);
        observer.consume(CAPTURE.as_bytes());
        observer.success();
        observer.failure("init-read", NativeError::Other);
        assert!(take_last_worker_startup_failure().is_none());
    }

    /// Native evidence survives the Rust error marker and never changes the returned error.
    #[test]
    fn capture_error_record_survives_return_marker_and_take_resets_it() {
        reset();
        let mut observer = StartupDiagnostics::new(None);
        observer
            .consume(b"{\"diagnostic\":\"worker-startup\",\"stage\":\"acquire\",\"status\":0}\n");
        observer.consume(CAPTURE.as_bytes());
        observer
            .consume(b"{\"diagnostic\":\"worker-startup\",\"stage\":\"acquire\",\"status\":3}\n");
        observer.failure("init-read", NativeError::TransportUnavailable);
        assert_eq!(
            take_last_worker_startup_failure().unwrap().code(),
            "candidate-worker-usb-capture-device-access-denied"
        );
        assert!(take_last_worker_startup_failure().is_none());
    }

    /// Startup OS errors use closed buckets; opaque native error text never escapes.
    #[test]
    fn spawn_errno_buckets_are_closed() {
        for (errno, suffix) in [
            (libc::EBADF, "bad-fd"),
            (libc::ENOENT, "missing-executable"),
            (libc::EACCES, "access-denied"),
            (libc::EMFILE, "resource-limit"),
            (libc::EINVAL, "other"),
        ] {
            os_failure("process-spawn", &std::io::Error::from_raw_os_error(errno));
            assert!(
                take_last_worker_startup_failure()
                    .unwrap()
                    .code()
                    .ends_with(suffix)
            );
            assert!(take_last_worker_startup_failure().is_none());
        }
    }
}
