// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use rdx_macos_native::NativeError;
use rdx_service::service::{ServiceExit, ServiceProtocolError};

/// The diagnostic brackets backend construction/session work and retains the existing exit/error mapping.
#[test]
fn macos_framed_session_diagnostics_retain_single_execution_and_outcome() {
    for (result, label, expected) in [
        (
            Ok(ServiceExit::EndOfInput),
            "framed-session-end-of-input",
            Ok(ServiceExit::EndOfInput),
        ),
        (
            Ok(ServiceExit::ShutdownRequested),
            "framed-session-shutdown",
            Ok(ServiceExit::ShutdownRequested),
        ),
        (
            Err(ServiceProtocolError::Io),
            "framed-session-failed",
            Err(NativeError::Other),
        ),
    ] {
        let trace = std::cell::RefCell::new(Vec::new());
        let outcome = super::observe_macos_framed_session(
            || {
                trace.borrow_mut().push(("session-operation", None));
                result
            },
            &mut |phase, error| trace.borrow_mut().push((phase, error)),
        );
        assert_eq!(outcome, expected);
        assert_eq!(
            *trace.borrow(),
            [
                ("framed-session-start", None),
                ("session-operation", None),
                (label, expected.err()),
            ]
        );
    }
}
