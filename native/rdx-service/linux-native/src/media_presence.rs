// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fresh TEST UNIT READY evidence gates cartridge-specific cached VPD pages.

use crate::Completion;

/// Accepts only a complete successful no-data readiness response.
fn ready(completion: &Completion) -> bool {
    matches!(completion, Completion::Device {
        status: 0, masked_status: 0, message_status: 0, host_status: 0,
        driver_status: 0, info, residual: 0, data,
        sense_reported_length: 0, sense,
    } if info & 1 == 0 && data.is_empty() && sense.is_empty())
}

/// Recognizes bounded current UNIT ATTENTION sense, allowing a fresh read-only retry.
fn unit_attention(completion: &Completion) -> bool {
    let Completion::Device {
        status: 2,
        host_status: 0,
        sense_reported_length,
        sense,
        ..
    } = completion
    else {
        return false;
    };
    if *sense_reported_length != sense.len() {
        return false;
    }
    match sense.first().map(|byte| byte & 0x7f) {
        Some(0x70 | 0x71) if sense.len() >= 14 => sense[2] & 0x0f == 6,
        Some(0x72 | 0x73) if sense.len() >= 4 => sense[1] & 0x0f == 6,
        _ => false,
    }
}

/// Returns the actual readiness failure instead of dispatching a cached VPD query.
/// Only UNIT ATTENTION is retried, at most twice; no eject or mutation is replayed.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn require_cartridge_ready(mut probe: impl FnMut() -> Completion) -> Option<Completion> {
    for attempt in 0..3 {
        let completion = probe();
        if ready(&completion) {
            return None;
        }
        if attempt == 2 || !unit_attention(&completion) {
            return Some(completion);
        }
    }
    unreachable!("bounded readiness attempts return a result")
}
