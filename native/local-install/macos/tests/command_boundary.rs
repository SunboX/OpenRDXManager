// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Run the actual CLI argument/privilege boundary without system or device writes.

use std::process::Command;

/// Arbitrary path/SID/requirement arguments are rejected before privileged dispatch.
#[test]
fn executable_rejects_untrusted_command_arguments() {
    for arguments in [
        vec!["enroll", "/tmp/foreign"],
        vec!["install", "/tmp/foreign"],
        vec!["repair", "S-1-5-18"],
        vec!["verify", "identifier com.attacker"],
        vec![],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_openrdx-local-install"))
            .args(&arguments)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("setup refused"));
    }
}

/// Ordinary users cannot execute any fixed elevated action, including verify.
#[cfg(target_os = "macos")]
#[test]
fn executable_denies_all_elevated_actions_to_ordinary_user() {
    // Root CI must not accidentally invoke any system mutation during this test.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    for action in ["prepare", "install", "verify", "repair", "remove"] {
        let result = Command::new(env!("CARGO_BIN_EXE_openrdx-local-install"))
            .arg(action)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("administrator approval"));
    }
}
