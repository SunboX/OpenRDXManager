// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Focused checks for native discovery identity and capacity guards.

use super::*;
use crate::transport::TransportResponse;

/// The production backend allows bounded manual USB reattachment after activation.
#[test]
fn production_firmware_reconnect_wait_allows_two_minutes() {
    let backend = super::linux::LinuxBackend::native();
    assert!(!backend.supports_manufacturing_sector_read());
    assert_eq!(
        backend.firmware_reconnect_timeout(),
        std::time::Duration::from_secs(120)
    );
}

/// Records the effective command timeout without touching host hardware.
struct RecordingHandle {
    timeout_ms: Option<u32>,
}

impl PlatformDeviceHandle for RecordingHandle {
    fn execute(&mut self, command: &Command) -> CommandDispatch {
        self.timeout_ms = Some(command.timeout_ms());
        CommandDispatch::Succeeded(TransportResponse::empty())
    }
}

/// Keeps discovery reads well inside the enclosing client scan deadline.
#[test]
fn discovery_probes_use_short_bounded_timeout() {
    let mut handle = RecordingHandle { timeout_ms: None };

    assert_eq!(
        execute_probe(
            &mut handle,
            DiscoveryProbe::StandardInquiry,
            inquiry(InquiryPage::Standard),
        ),
        Some(Vec::new())
    );
    assert_eq!(handle.timeout_ms, Some(2_000));
}
