// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Diagnostic CLI fixtures stop before any native device discovery.

use std::process::Command;

/// Invalid private input must produce only bounded fixed argument-stage metadata.
#[test]
fn invalid_input_diagnostics_are_staged_and_redacted() {
    let output = Command::new(env!("CARGO_BIN_EXE_openrdx-factory-snapshot"))
        .args([
            "--usb-serial",
            "PRIVATE-INVALID-SERIAL",
            "--output",
            "/private/secret-path",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.len() < 384);
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["code"], "snapshot-invalid-arguments");
    assert_eq!(error["stage"], "arguments");
    assert!(error.get("nativeError").is_none());
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("PRIVATE")
    );
}

/// Existing-output diagnostics identify preflight and never attempt device reads.
#[test]
fn existing_output_diagnostics_identify_preflight() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("private-existing.json");
    std::fs::write(&path, b"private evidence").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_openrdx-factory-snapshot"))
        .args(["--usb-serial", "001234567890", "--output"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["code"], "snapshot-private-output-unavailable");
    assert_eq!(error["stage"], "output-preflight");
    assert_eq!(std::fs::read(path).unwrap(), b"private evidence");
}
