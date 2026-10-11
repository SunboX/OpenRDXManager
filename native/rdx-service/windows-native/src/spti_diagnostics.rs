// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opt-in, bounded header-only observations at the native SPTI call boundary.

use std::fmt::Write as _;
#[cfg(windows)]
use std::io::Write as _;
#[cfg(windows)]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

const LIMIT_PER_KIND: usize = 128;
#[cfg(windows)]
static STATE: OnceLock<CaptureState> = OnceLock::new();

/// Separate quotas keep discovery traffic from consuming the firmware budget.
struct CaptureState {
    enabled: bool,
    reads: AtomicUsize,
    firmware: AtomicUsize,
    sequence: AtomicUsize,
}

impl CaptureState {
    /// Creates bounded counters without reading environment or touching hardware.
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            reads: AtomicUsize::new(0),
            firmware: AtomicUsize::new(0),
            sequence: AtomicUsize::new(0),
        }
    }

    /// Reserves one pair only for a closed, non-secret command-header family.
    fn reserve(&self, cdb: &[u8], direction: u8, length: u32) -> Option<Observation> {
        if !self.enabled || !allowed_header(cdb, direction, length) {
            return None;
        }
        let quota = if cdb[0] == 0x3B {
            &self.firmware
        } else {
            &self.reads
        };
        quota
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < LIMIT_PER_KIND).then_some(n + 1)
            })
            .ok()?;
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let mut frame = String::with_capacity(cdb.len() * 2);
        for byte in cdb {
            let _ = write!(frame, "{byte:02X}");
        }
        Some(Observation {
            sequence,
            frame,
            direction,
            length,
        })
    }
}

/// Rejects security, manufacturing, media writes and all unknown header shapes.
/// Direction values are the Windows SCSI_IOCTL_DATA_OUT/IN/UNSPECIFIED constants.
fn allowed_header(cdb: &[u8], direction: u8, length: u32) -> bool {
    if length > 4096 || cdb.is_empty() || cdb.len() > 16 {
        return false;
    }
    let base = if cdb[0] == 0x12 { 6 } else { 10 };
    if cdb.len() < base || cdb[base..].iter().any(|b| *b != 0) {
        return false;
    }
    match &cdb[..base] {
        [0x12, 0, 0, 0, 0xFE, 0] => direction == 1 && length == 254,
        [0x12, 1, 0x83, 0, 0xFE, 0] => direction == 1 && length == 254,
        [0x4D | 0x5A, 0, _, 0, 0, 0, 0, 0, 0xFE, 0] => direction == 1 && length == 254,
        [0x3B, mode, 0, _, _, _, _, _, _, _] if mode & 0x1F == 4 => direction == 0 && length > 0,
        [0x3B, mode, 0, _, _, _, _, _, _, _] if mode & 0x1F == 5 => direction == 2 && length == 0,
        _ => false,
    }
}

/// One admitted request: it owns header metadata, never the data buffer or handle.
pub(super) struct Observation {
    sequence: usize,
    frame: String,
    direction: u8,
    length: u32,
}

impl Observation {
    /// Snapshots the assembled SPTI header immediately before the native call.
    /// Logging is disabled by default and in release builds; errors are nonfatal.
    #[cfg(windows)]
    pub(super) fn begin(cdb: &[u8], direction: u8, length: u32) -> Option<Self> {
        let state = STATE.get_or_init(|| {
            CaptureState::new(
                cfg!(debug_assertions)
                    && std::env::var_os("OPENRDX_SPTI_DIAGNOSTICS").is_some_and(|v| v == "1"),
            )
        });
        let observation = state.reserve(cdb, direction, length)?;
        observation.emit("submit", "pending", "null", "null", "null", 0, 0, "null");
        Some(observation)
    }

    /// Records only bounded completion fields; no raw sense or returned data.
    #[cfg(windows)]
    pub(super) fn complete(
        &self,
        status: u8,
        transferred: u32,
        reported_sense: usize,
        sense: &[u8],
        returned: u32,
    ) {
        let decoded = decode_sense(status, reported_sense, sense);
        self.emit(
            "complete",
            "device",
            &status.to_string(),
            &transferred.to_string(),
            &decoded,
            reported_sense.min(252),
            sense.len().min(252),
            &returned.to_string(),
        );
    }

    /// Records a fixed failure class without native messages or memory contents.
    #[cfg(windows)]
    pub(super) fn failed(&self, invalid_response: bool, returned: u32) {
        self.emit(
            "complete",
            if invalid_response {
                "invalid-response"
            } else {
                "io-error"
            },
            "null",
            "null",
            "null",
            0,
            0,
            &returned.to_string(),
        );
    }

    /// Writes one small atomic stderr line; failure never changes SCSI outcomes.
    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    fn emit(
        &self,
        phase: &str,
        host: &str,
        status: &str,
        completed: &str,
        sense: &str,
        reported: usize,
        copied: usize,
        returned: &str,
    ) {
        let line = self.line(
            phase, host, status, completed, sense, reported, copied, returned,
        );
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
    }

    /// Serializes only private typed inputs into the fixed wire schema.
    #[allow(clippy::too_many_arguments)]
    fn line(
        &self,
        phase: &str,
        host: &str,
        status: &str,
        completed: &str,
        sense: &str,
        reported: usize,
        copied: usize,
        returned: &str,
    ) -> String {
        format!(
            "openrdx-hardware: spti-v1 {{\"v\":1,\"seq\":{},\"phase\":\"{}\",\"frame\":\"{}\",\"dir\":{},\"requested\":{},\"completed\":{},\"status\":{},\"sense\":{},\"reported\":{},\"copied\":{},\"returned\":{},\"host\":\"{}\"}}\n",
            self.sequence,
            phase,
            self.frame,
            self.direction,
            self.length,
            completed,
            status,
            sense,
            reported,
            copied,
            returned,
            host
        )
    }
}

/// Decodes only complete standard fixed/descriptor sense headers. A GOOD status,
/// unknown format, truncated header or inconsistent reported bound reveals nothing.
fn decode_sense(status: u8, reported: usize, sense: &[u8]) -> String {
    let length = reported.min(sense.len()).min(252);
    if status != 2 || length < 8 {
        return "null".into();
    }
    let sense = &sense[..length];
    let format = sense[0] & 0x7F;
    let available = length.min(8 + usize::from(sense[7]));
    let (code, asc, ascq) = match format {
        0x70 | 0x71 if available >= 14 => (sense[2] & 0x0F, sense[12], sense[13]),
        0x72 | 0x73 => (sense[1] & 0x0F, sense[2], sense[3]),
        _ => return "null".into(),
    };
    // Fixed-format illegal-request SKS identifies a rejected command field.
    // Other sense-specific data may carry device information and is not logged.
    let field =
        if matches!(format, 0x70 | 0x71) && code == 5 && available >= 18 && sense[15] & 0x80 != 0 {
            format!(
                "{{\"inHeader\":{},\"offset\":{},\"bit\":{}}}",
                sense[15] & 0x40 != 0,
                u16::from_be_bytes([sense[16], sense[17]]),
                if sense[15] & 8 != 0 {
                    (sense[15] & 7).to_string()
                } else {
                    "null".into()
                }
            )
        } else {
            "null".into()
        };
    format!(
        "{{\"format\":{format},\"code\":{code},\"asc\":{asc},\"ascq\":{ascq},\"field\":{field}}}"
    )
}

#[cfg(test)]
mod tests;
