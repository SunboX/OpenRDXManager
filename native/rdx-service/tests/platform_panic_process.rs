// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::process::Command;

/// A panicking adapter crashes only its supervised process with one fixed diagnostic.
#[test]
fn panicking_platform_process_redacts_payload_and_keeps_protocol_stdout_empty() {
    let binary = match option_env!("CARGO_BIN_EXE_openrdx-platform-panic-fixture") {
        Some(binary) => binary,
        None => panic!("cargo test must provide the exact panic-fixture binary"),
    };
    let output = Command::new(binary)
        .output()
        .expect("panic fixture process starts");
    let stderr = String::from_utf8(output.stderr).expect("fixed diagnostic is UTF-8");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(stderr, "openrdx-hardware: fatal native service failure\n");
    assert!(stderr.len() < 128);
    for secret in ["/private/", "/dev/", "panic-secret", "adapter payload"] {
        assert!(!stderr.contains(secret));
    }
}
