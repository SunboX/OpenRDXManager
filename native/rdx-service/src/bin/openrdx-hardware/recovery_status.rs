// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fixed offline status mode; this module cannot construct a hardware backend.

use rdx_service::migration::{MigrationError, MigrationRecoveryStatus};
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::process::ExitCode;

/// Handles only the fixed one-shot status flag before normal service startup.
pub(super) fn run_if_requested(arguments: impl IntoIterator<Item = OsString>) -> Option<ExitCode> {
    run(
        arguments,
        rdx_service::migration::recovery_status,
        &mut io::stdout().lock(),
    )
    .map(ExitCode::from)
}

/// Serializes only the redacted result; malformed flags never invoke the reader.
fn run(
    arguments: impl IntoIterator<Item = OsString>,
    status: impl FnOnce() -> Result<Vec<MigrationRecoveryStatus>, MigrationError>,
    output: &mut impl Write,
) -> Option<u8> {
    let mut arguments = arguments.into_iter();
    if arguments.next().as_deref() != Some(OsStr::new("--migration-recovery-status")) {
        return None;
    }
    let (result, exit) = if arguments.next().is_some() {
        (
            serde_json::json!({"ok": false, "code": "migration-status-arguments-invalid"}),
            2,
        )
    } else {
        match status() {
            Ok(bundles) => (serde_json::json!({"ok": true, "bundles": bundles}), 0),
            Err(error) => (serde_json::json!({"ok": false, "code": error.code()}), 3),
        }
    };
    let written = serde_json::to_writer(&mut *output, &result).is_ok()
        && output.write_all(b"\n").is_ok()
        && output.flush().is_ok();
    Some(if written { exit } else { 3 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdx_service::migration::MigrationEvent;

    /// Exact one-flag mode returns closed status JSON through an offline callback.
    #[test]
    fn status_has_only_redacted_fields() {
        let mut output = Vec::new();
        assert_eq!(
            run(
                [OsString::from("--migration-recovery-status")],
                || Ok(vec![MigrationRecoveryStatus {
                    bundle_id: "migration-1-0".into(),
                    events: vec![MigrationEvent::Prepared],
                    integrity: true,
                }]),
                &mut output
            ),
            Some(0)
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output).unwrap(),
            serde_json::json!({
                "ok": true, "bundles": [{"bundleId": "migration-1-0", "events": ["prepared"], "integrity": true}]
            })
        );
    }

    /// Additional path/device arguments are rejected without running any callback.
    #[test]
    fn status_rejects_extra_arguments_before_reader() {
        let mut output = Vec::new();
        assert_eq!(
            run(
                [
                    OsString::from("--migration-recovery-status"),
                    OsString::from("/private/foreign")
                ],
                || panic!("reader must remain unused"),
                &mut output
            ),
            Some(2)
        );
        assert!(!String::from_utf8(output).unwrap().contains("foreign"));
        assert_eq!(
            run([], || panic!("reader must remain unused"), &mut Vec::new()),
            None
        );
    }

    /// Privilege and storage failures emit only a stable bounded failure code.
    #[test]
    fn status_failure_is_sanitized() {
        let mut output = Vec::new();
        assert_eq!(
            run(
                [OsString::from("--migration-recovery-status")],
                || Err(MigrationError::StorageUnavailable),
                &mut output
            ),
            Some(3)
        );
        assert_eq!(
            output,
            b"{\"code\":\"migration-private-recovery-unavailable\",\"ok\":false}\n"
        );
    }
}
