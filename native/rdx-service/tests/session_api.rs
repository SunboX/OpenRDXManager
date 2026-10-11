// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

#[path = "support/compile_contract.rs"]
mod compile_contract;

/// Proves device/session ownership capabilities cannot be copied or manufactured.
#[test]
fn session_ownership_api_is_linear_and_service_issued() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/device_session_clone.rs");
    cases.compile_fail("tests/ui/device_session_execute.rs");
    cases.compile_fail("tests/ui/installable_firmware_clone.rs");
    cases.compile_fail("tests/ui/installable_firmware_reuse.rs");
}

/// Preserves primary access-control contracts across Rust diagnostic wording
/// changes. Existing human-readable snapshots remain historical references.
#[test]
fn session_forgery_and_split_transport_remain_compiler_rejected() {
    use compile_contract::{Rejection, check_cases};
    check_cases(&[
        (
            "device_session_construct.rs",
            &[Rejection {
                code: None,
                line: 4,
                message_parts: &["DeviceSession", "private fields"],
            }],
        ),
        (
            "operation_owner_constructor.rs",
            &[Rejection {
                code: Some("E0599"),
                line: 7,
                message_parts: &["new", "OperationOwner"],
            }],
        ),
        (
            "split_host_transport.rs",
            &[
                Rejection {
                    code: Some("E0432"),
                    line: 1,
                    message_parts: &["unresolved import", "HostOperations"],
                },
                Rejection {
                    code: Some("E0432"),
                    line: 2,
                    message_parts: &["unresolved import", "Transport"],
                },
            ],
        ),
    ]);
}
